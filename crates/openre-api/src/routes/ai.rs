//! AI routes

use crate::{AppState, ApiResult, ValidatedJson};
use axum::{
    extract::{State, Extension},
    routing::{get, post},
    Json,
    Router,
    response::{sse::Event, Sse},
};
use futures::stream::Stream;
use openre_core::ids::{FunctionId, ProjectId};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// AI routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/chat", post(chat_completion))
        .route("/chat/stream", post(chat_completion_stream))
        .route("/analyze", post(analyze_function))
        .route("/analyze/stream", post(analyze_function_stream))
        .route("/templates", get(list_templates))
        .route("/templates/:name", get(get_template))
        .with_state(state)
}

/// Chat completion
#[utoipa::path(
    post,
    path = "/api/ai/chat",
    request_body = ChatCompletionRequest,
    responses(
        (status = 200, description = "Chat completion", body = ChatCompletionResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "ai"
)]
async fn chat_completion(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ChatCompletionRequest>,
) -> ApiResult<Json<ChatCompletionResponse>> {
    let request = openre_ai::providers::CompletionRequest {
        messages: payload.messages.into_iter().map(|m| m.into()).collect(),
        tools: payload.tools,
        tool_choice: payload.tool_choice,
        temperature: payload.temperature,
        max_tokens: payload.max_tokens,
        top_p: payload.top_p,
        stop: payload.stop,
        response_format: payload.response_format,
        stream: false,
        metadata: HashMap::new(),
    };

    let response = state.ai_service.complete(request).await?;

    Ok(Json(ChatCompletionResponse::from(response)))
}

/// Chat completion streaming
async fn chat_completion_stream(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<ChatCompletionRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let request = openre_ai::providers::CompletionRequest {
        messages: payload.messages.into_iter().map(|m| m.into()).collect(),
        tools: payload.tools,
        tool_choice: payload.tool_choice,
        temperature: payload.temperature,
        max_tokens: payload.max_tokens,
        top_p: payload.top_p,
        stop: payload.stop,
        response_format: payload.response_format,
        stream: true,
        metadata: HashMap::new(),
    };

    let stream = state.ai_service.stream(request).await?;

    let event_stream = async_stream::stream! {
        let mut rx = stream.stream;
        while let Some(chunk) = rx.recv().await {
            let event = match chunk {
                openre_ai::providers::StreamChunk::Content(text) => {
                    Event::default().data(serde_json::json!({
                        "type": "content",
                        "content": text,
                    }).to_string())
                }
                openre_ai::providers::StreamChunk::ToolCall(tool_call) => {
                    Event::default().data(serde_json::json!({
                        "type": "tool_call",
                        "tool_call": {
                            "id": tool_call.id,
                            "name": tool_call.name,
                            "arguments": tool_call.arguments,
                        },
                    }).to_string())
                }
                openre_ai::providers::StreamChunk::Finish(reason) => {
                    Event::default().data(serde_json::json!({
                        "type": "finish",
                        "reason": format!("{:?}", reason),
                    }).to_string())
                }
            };
            yield Ok(event);
        }
    };

    Ok(Sse::new(event_stream))
}

/// Analyze function with AI
#[utoipa::path(
    post,
    path = "/api/ai/analyze",
    request_body = AnalyzeFunctionRequest,
    responses(
        (status = 200, description = "Function analysis", body = AnalyzeFunctionResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "ai"
)]
async fn analyze_function(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<AnalyzeFunctionRequest>,
) -> ApiResult<Json<AnalyzeFunctionResponse>> {
    let function_id: FunctionId = payload.function_id.parse()?;
    
    // Get project store
    let project_store = state.get_project_store(payload.project_id.parse()?).await?;
    
    let response = state.ai_service.execute_template(
        "analyze_function",
        HashMap::new(),
        Some(project_store),
        Some(function_id),
    ).await?;

    Ok(Json(AnalyzeFunctionResponse::from(response)))
}

/// Analyze function with AI streaming
async fn analyze_function_stream(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<AnalyzeFunctionRequest>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let function_id: FunctionId = payload.function_id.parse()?;
    
    let project_store = state.get_project_store(payload.project_id.parse()?).await?;
    
    let stream = state.ai_service.execute_template_stream(
        "analyze_function",
        HashMap::new(),
        Some(project_store),
        Some(function_id),
    ).await?;

    let event_stream = async_stream::stream! {
        let mut rx = stream.stream;
        while let Some(chunk) = rx.recv().await {
            let event = match chunk {
                openre_ai::providers::StreamChunk::Content(text) => {
                    Event::default().data(serde_json::json!({
                        "type": "content",
                        "content": text,
                    }).to_string())
                }
                openre_ai::providers::StreamChunk::ToolCall(tool_call) => {
                    Event::default().data(serde_json::json!({
                        "type": "tool_call",
                        "tool_call": {
                            "id": tool_call.id,
                            "name": tool_call.name,
                            "arguments": tool_call.arguments,
                        },
                    }).to_string())
                }
                openre_ai::providers::StreamChunk::Finish(reason) => {
                    Event::default().data(serde_json::json!({
                        "type": "finish",
                        "reason": format!("{:?}", reason),
                    }).to_string())
                }
            };
            yield Ok(event);
        }
    };

    Ok(Sse::new(event_stream))
}

/// List prompt templates
async fn list_templates(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<TemplateListResponse>> {
    let templates = state.ai_service.prompt_compiler().list_templates();
    
    Ok(Json(TemplateListResponse {
        templates: templates.into_iter().map(|t| TemplateInfo {
            name: t.name.clone(),
            description: t.description.clone(),
            variables: t.variables.clone(),
        }).collect(),
    }))
}

/// Get prompt template
async fn get_template(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    Path(name): Path<String>,
) -> ApiResult<Json<TemplateInfo>> {
    let template = state.ai_service.prompt_compiler().get_template(&name)
        .ok_or_else(|| crate::error::ApiError::NotFound("Template not found".into()))?;
    
    Ok(Json(TemplateInfo {
        name: template.name.clone(),
        description: template.description.clone(),
        variables: template.variables.clone(),
    }))
}

// Request/Response types

use std::collections::HashMap;
use axum::extract::Path;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChatCompletionRequest {
    #[validate(length(min = 1))]
    pub messages: Vec<ChatMessage>,
    
    pub tools: Option<Vec<ToolDefinition>>,
    pub tool_choice: Option<ToolChoice>,
    
    #[validate(range(min = 0.0, max = 2.0))]
    pub temperature: Option<f32>,
    
    #[validate(range(min = 1, max = 8192))]
    pub max_tokens: Option<u32>,
    
    #[validate(range(min = 0.0, max = 1.0))]
    pub top_p: Option<f32>,
    
    pub stop: Option<Vec<String>>,
    pub response_format: Option<ResponseFormat>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChatMessage {
    pub role: MessageRole,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCall>>,
    pub tool_call_id: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
    pub required: Vec<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Specific(String),
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseFormat {
    Text,
    JsonObject,
    JsonSchema(serde_json::Value),
}

impl From<ChatMessage> for openre_ai::providers::Message {
    fn from(m: ChatMessage) -> Self {
        match m.role {
            MessageRole::System => openre_ai::providers::Message::system(m.content.unwrap_or_default()),
            MessageRole::User => openre_ai::providers::Message::user(m.content.unwrap_or_default()),
            MessageRole::Assistant => openre_ai::providers::Message::assistant(m.content.unwrap_or_default()),
            MessageRole::Tool => openre_ai::providers::Message::tool_result(
                m.tool_call_id.unwrap_or_default(),
                m.content.unwrap_or_default(),
            ),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
    pub created: u64,
}

impl From<openre_ai::providers::CompletionResponse> for ChatCompletionResponse {
    fn from(r: openre_ai::providers::CompletionResponse) -> Self {
        Self {
            id: r.id,
            model: r.model,
            choices: r.choices.into_iter().map(|c| c.into()).collect(),
            usage: r.usage.into(),
            created: r.created,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessageResponse,
    pub finish_reason: String,
}

impl From<openre_ai::providers::Choice> for ChatChoice {
    fn from(c: openre_ai::providers::Choice) -> Self {
        Self {
            index: c.index,
            message: c.message.into(),
            finish_reason: format!("{:?}", c.finish_reason),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChatMessageResponse {
    pub role: String,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCallResponse>>,
}

impl From<openre_ai::providers::Message> for ChatMessageResponse {
    fn from(m: openre_ai::providers::Message) -> Self {
        Self {
            role: format!("{:?}", m.role).to_lowercase(),
            content: m.content,
            tool_calls: m.tool_calls.map(|tc| tc.into_iter().map(|t| t.into()).collect()),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ToolCallResponse {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

impl From<openre_ai::providers::ToolCall> for ToolCallResponse {
    fn from(t: openre_ai::providers::ToolCall) -> Self {
        Self {
            id: t.id,
            name: t.name,
            arguments: t.arguments,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

impl From<openre_ai::providers::Usage> for Usage {
    fn from(u: openre_ai::providers::Usage) -> Self {
        Self {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AnalyzeFunctionRequest {
    #[validate(custom(function = "crate::validation::rules::validate_uuid"))]
    pub function_id: String,
    
    pub project_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AnalyzeFunctionResponse {
    pub analysis: String,
    pub model: String,
    pub usage: Usage,
}

impl From<openre_ai::providers::CompletionResponse> for AnalyzeFunctionResponse {
    fn from(r: openre_ai::providers::CompletionResponse) -> Self {
        let content = r.choices.first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();
        
        Self {
            analysis: content,
            model: r.model,
            usage: r.usage.into(),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TemplateInfo {
    pub name: String,
    pub description: String,
    pub variables: Vec<String>,
}