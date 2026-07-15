//! WebSocket support for open-re API

use crate::{AppState, ApiError, ApiResult};
use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;
use tracing::{debug, info, warn};

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    // Client -> Server
    Subscribe { channels: Vec<String> },
    Unsubscribe { channels: Vec<String> },
    Ping,
    Auth { token: String },
    
    // Server -> Client
    Subscribed { channels: Vec<String> },
    Unsubscribed { channels: Vec<String> },
    Pong,
    AuthSuccess { user_id: String },
    AuthError { message: String },
    Progress { job_id: String, progress: JobProgressUpdate },
    AnalysisUpdate { job_id: String, stage: String, message: String },
    Notification { title: String, message: String, level: NotificationLevel },
    Error { code: String, message: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgressUpdate {
    pub overall: f32,
    pub current_stage: Option<String>,
    pub stages_completed: u32,
    pub total_stages: u32,
    pub estimated_remaining_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotificationLevel {
    Info,
    Warning,
    Error,
    Success,
}

/// WebSocket connection handler
pub struct WsConnection {
    socket: WebSocket,
    state: Arc<AppState>,
    subscriptions: Vec<String>,
    user_id: Option<String>,
    tx: broadcast::Sender<WsMessage>,
}

impl WsConnection {
    pub fn new(socket: WebSocket, state: Arc<AppState>) -> Self {
        let (tx, _) = broadcast::channel(100);
        Self {
            socket,
            state,
            subscriptions: Vec::new(),
            user_id: None,
            tx,
        }
    }

    pub async fn run(mut self) {
        // Subscribe to progress updates
        let progress_rx = self.state.progress_tracker.subscribe();
        let mut progress_rx = progress_rx;
        
        let mut rx = self.tx.subscribe();
        
        loop {
            tokio::select! {
                // Handle incoming messages
                msg = self.socket.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            if let Err(e) = self.handle_text(text).await {
                                warn!("WebSocket error: {}", e);
                                break;
                            }
                        }
                        Some(Ok(Message::Binary(_))) => {
                            // Ignore binary messages
                        }
                        Some(Ok(Message::Ping(data))) => {
                            if self.socket.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        Some(Ok(Message::Pong(_))) => {
                            // Pong received
                        }
                        Some(Ok(Message::Close(_))) => {
                            info!("WebSocket closed by client");
                            break;
                        }
                        Some(Err(e)) => {
                            warn!("WebSocket error: {}", e);
                            break;
                        }
                        None => {
                            info!("WebSocket stream ended");
                            break;
                        }
                    }
                }
                
                // Handle progress updates
                Ok(update) = progress_rx.recv() => {
                    if self.is_subscribed(&format!("job:{}", update.job_id)) {
                        let msg = WsMessage::Progress {
                            job_id: update.job_id.to_string(),
                            progress: JobProgressUpdate {
                                overall: update.progress.overall_progress,
                                current_stage: update.progress.current_stage,
                                stages_completed: update.progress.stages_completed,
                                total_stages: update.progress.total_stages,
                                estimated_remaining_seconds: update.progress.estimated_remaining.map(|d| d.num_seconds() as u64),
                            },
                        };
                        if self.send(msg).await.is_err() {
                            break;
                        }
                    }
                }
                
                // Handle broadcast messages
                Ok(msg) = rx.recv() => {
                    if self.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    async fn handle_text(&mut self, text: String) -> ApiResult<()> {
        let msg: WsMessage = serde_json::from_str(&text)
            .map_err(|e| ApiError::BadRequest(format!("Invalid message format: {}", e)))?;
        
        match msg {
            WsMessage::Subscribe { channels } => {
                self.subscribe(channels).await;
            }
            WsMessage::Unsubscribe { channels } => {
                self.unsubscribe(channels).await;
            }
            WsMessage::Ping => {
                self.send(WsMessage::Pong).await?;
            }
            WsMessage::Auth { token } => {
                self.authenticate(token).await?;
            }
            _ => {
                // Ignore server-to-client messages from client
            }
        }
        
        Ok(())
    }

    async fn subscribe(&mut self, channels: Vec<String>) {
        for channel in &channels {
            if !self.subscriptions.contains(channel) {
                self.subscriptions.push(channel.clone());
            }
        }
        
        let _ = self.send(WsMessage::Subscribed { channels }).await;
    }

    async fn unsubscribe(&mut self, channels: Vec<String>) {
        self.subscriptions.retain(|c| !channels.contains(c));
        
        let _ = self.send(WsMessage::Unsubscribed { channels }).await;
    }

    fn is_subscribed(&self, channel: &str) -> bool {
        self.subscriptions.iter().any(|c| c == channel || c == "*")
    }

    async fn authenticate(&mut self, token: String) -> ApiResult<()> {
        let claims = self.state.auth_service.validate_access_token(&token)?;
        self.user_id = Some(claims.sub.clone());
        
        // Auto-subscribe to user's channels
        self.subscriptions.push(format!("user:{}", claims.sub));
        if let Some(project_id) = claims.project_id {
            self.subscriptions.push(format!("project:{}", project_id));
        }
        
        self.send(WsMessage::AuthSuccess { user_id: claims.sub }).await
    }

    async fn send(&mut self, msg: WsMessage) -> ApiResult<()> {
        let text = serde_json::to_string(&msg)
            .map_err(|e| ApiError::Internal(format!("Failed to serialize message: {}", e)))?;
        
        self.socket.send(Message::Text(text)).await
            .map_err(|e| ApiError::Internal(format!("Failed to send message: {}", e)))?;
        
        Ok(())
    }
}

/// WebSocket upgrade handler
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| {
        let conn = WsConnection::new(socket, state);
        conn.run()
    })
}

/// WebSocket manager for broadcasting messages
pub struct WsManager {
    connections: Arc<RwLock<HashMap<String, broadcast::Sender<WsMessage>>>>,
    global_tx: broadcast::Sender<WsMessage>,
}

impl WsManager {
    pub fn new() -> Self {
        let (global_tx, _) = broadcast::channel(1000);
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            global_tx,
        }
    }

    pub fn register(&self, connection_id: String, tx: broadcast::Sender<WsMessage>) {
        self.connections.write().await.insert(connection_id, tx);
    }

    pub fn unregister(&self, connection_id: &str) {
        self.connections.write().await.remove(connection_id);
    }

    /// Broadcast to all connections
    pub async fn broadcast(&self, msg: WsMessage) {
        let _ = self.global_tx.send(msg);
    }

    /// Broadcast to specific user
    pub async fn broadcast_to_user(&self, user_id: &str, msg: WsMessage) {
        let channel = format!("user:{}", user_id);
        self.broadcast_to_channel(&channel, msg).await;
    }

    /// Broadcast to project
    pub async fn broadcast_to_project(&self, project_id: &str, msg: WsMessage) {
        let channel = format!("project:{}", project_id);
        self.broadcast_to_channel(&channel, msg).await;
    }

    /// Broadcast to job subscribers
    pub async fn broadcast_to_job(&self, job_id: &str, msg: WsMessage) {
        let channel = format!("job:{}", job_id);
        self.broadcast_to_channel(&channel, msg).await;
    }

    async fn broadcast_to_channel(&self, channel: &str, msg: WsMessage) {
        // In a real implementation, we'd use Redis Pub/Sub for multi-instance support
        // For now, just broadcast globally and let connections filter
        let _ = self.global_tx.send(msg);
    }

    /// Get connection count
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }
}

impl Default for WsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress update message for broadcasting
#[derive(Debug, Clone)]
pub struct ProgressBroadcast {
    pub job_id: String,
    pub progress: f32,
    pub stage: Option<String>,
    pub message: Option<String>,
}

/// Notification message for broadcasting
#[derive(Debug, Clone)]
pub struct NotificationBroadcast {
    pub user_id: Option<String>,
    pub project_id: Option<String>,
    pub title: String,
    pub message: String,
    pub level: NotificationLevel,
}