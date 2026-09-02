//! Event system for the TUI

use crate::state::{
    AIAnalysis, AIViewMode, ChatMessage, ChatRole, FindingsGroupBy, JobStatus, KeyBindings,
    LogEntry, LogLevel, Notification, PanelType, PluginInfo, ProjectInfo, QueueStats, REViewMode,
    ReportInfo, ReportType, ScanStatus, Theme, Workflow, WorkflowExecution, WorkflowViewMode,
};
use openre_core::ids::{JobId, ProjectId, ScanId};
use openre_core::result::{Category, Confidence, Finding, Severity};
use openre_queue::{Job, Priority};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Events that can be sent through the event bus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    // Panel navigation
    PanelChanged(PanelType),
    PanelFocused(PanelType),

    // Project events
    ProjectCreated(ProjectId),
    ProjectUpdated(ProjectId),
    ProjectDeleted(ProjectId),
    ProjectSelected(ProjectId),
    ProjectRefreshed,
    ProjectsRefreshed(Vec<ProjectInfo>),

    // Job events
    JobCreated(Job),
    JobUpdated(Job),
    JobDeleted(JobId),
    JobStatusChanged(JobId, JobStatus),
    JobProgressUpdated(JobId, f32, String),
    JobSelected(JobId),
    JobsRefreshed,

    // Scan events
    ScanStarted(ScanInfo),
    ScanProgress(ScanId, String, usize, usize, usize),
    ScanCompleted(ScanResult),
    ScanFailed(ScanId, String),
    ScanCancelled(ScanId),
    ScanSelected(ScanId),
    ScansRefreshed,

    // Reverse Engineering events
    REProjectLoaded(REProject),
    REProjectAnalysisStarted(ProjectId),
    REProjectAnalysisProgress(ProjectId, f32, String),
    REProjectAnalysisCompleted(ProjectId),
    REFunctionSelected(u64),
    REViewModeChanged(REViewMode),

    // Findings events
    FindingsLoaded(Vec<Finding>),
    FindingSelected(usize),
    FindingExpanded(usize),
    FindingFiltered(Option<Severity>, Option<Category>, Option<Confidence>, String),
    FindingsGroupedBy(FindingsGroupBy),
    FindingsExported(String),
    FindingDetailOpened(usize),

    // Workflow events
    WorkflowCreated(Workflow),
    WorkflowUpdated(Workflow),
    WorkflowDeleted(String),
    WorkflowExecutionStarted(String),
    WorkflowExecutionProgress(String, f32, String),
    WorkflowExecutionCompleted(String),
    WorkflowExecutionFailed(String, String),
    WorkflowSelected(String),

    // AI events
    AIAnalysisStarted(AIAnalysis),
    AIAnalysisProgress(String, f32, String),
    AIAnalysisCompleted(String, serde_json::Value),
    AIAnalysisFailed(String, String),
    AIChatMessageAdded(ChatMessage),
    AIModelChanged(String),
    AIViewModeChanged(AIViewMode),

    // Plugin events
    PluginLoaded(PluginInfo),
    PluginEnabled(String),
    PluginDisabled(String),
    PluginUnloaded(String),
    PluginConfigChanged(String, serde_json::Value),

    // Log events
    LogEntryAdded(LogEntry),
    LogsCleared,
    LogFilterChanged(Option<LogLevel>, String, String),
    LogFollowToggled(bool),

    // Report events
    ReportGenerated(ReportInfo),
    ReportGenerationProgress(String, f32),
    ReportGenerationCompleted(String, String),
    ReportGenerationFailed(String, String),
    ReportSelected(String),
    ReportPreviewRequested(String),

    // Queue events
    QueueStatsUpdated(QueueStats),
    WorkerStatusChanged(String, bool),

    // Global events
    ThemeChanged(Theme),
    KeyBindingsChanged(KeyBindings),
    NotificationAdded(Notification),
    ErrorOccurred(String),
    RefreshRequested,
    ShutdownRequested,
}

/// Simplified scan info for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    pub id: ScanId,
    pub target: String,
    pub profile: String,
    pub project_id: Option<ProjectId>,
}

/// Scan result for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: ScanId,
    pub findings: Vec<Finding>,
    pub duration_ms: u64,
    pub checks_run: usize,
}

/// RE Project for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct REProject {
    pub id: ProjectId,
    pub name: String,
    pub binary_path: String,
}

/// Event handler trait
pub trait EventHandler: Send + Sync {
    fn handle_event(&mut self, event: Event) -> anyhow::Result<()>;
}

/// Event bus for distributing events
pub struct EventBus {
    sender: tokio::sync::broadcast::Sender<Event>,
}

impl EventBus {
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = tokio::sync::broadcast::channel(capacity);
        Self { sender }
    }

    pub fn sender(&self) -> tokio::sync::broadcast::Sender<Event> {
        self.sender.clone()
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Event> {
        self.sender.subscribe()
    }

    pub fn emit(&self, event: Event) {
        let _ = self.sender.send(event);
    }

    pub fn emit_blocking(
        &self,
        event: Event,
    ) -> Result<usize, tokio::sync::broadcast::error::SendError<Event>> {
        self.sender.send(event)
    }
}

impl Clone for EventBus {
    fn clone(&self) -> Self {
        Self { sender: self.sender.clone() }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(1024)
    }
}
