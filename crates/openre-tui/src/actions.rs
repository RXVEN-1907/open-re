//! Action system for the TUI

use crate::state::{
    AIViewMode, FindingsGroupBy, JobStatus, KeyBindings, LogLevel, Notification, PanelType,
    PluginViewMode, REViewMode, ReportType, ReportViewMode, ScanStatus, Theme, WorkflowViewMode,
};
use openre_core::ids::{JobId, ProjectId, ScanId};
use openre_core::result::{Category, Confidence, Finding, Severity};
use openre_queue::{Job, Priority};
use serde::{Deserialize, Serialize};

/// Actions that can be dispatched to the application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Action {
    // Navigation
    NavigateToPanel(PanelType),
    NavigateNextPanel,
    NavigatePrevPanel,

    // Project actions
    CreateProject {
        name: String,
        path: String,
    },
    DeleteProject(ProjectId),
    SelectProject(ProjectId),
    RefreshProjects,
    RenameProject {
        id: ProjectId,
        new_name: String,
    },
    SetActiveProject(ProjectId),

    // Job actions
    CreateJob {
        job_type: String,
        payload: serde_json::Value,
        priority: Priority,
    },
    CancelJob(JobId),
    PauseJob(JobId),
    ResumeJob(JobId),
    RetryJob(JobId),
    DeleteJob(JobId),
    SelectJob(JobId),
    RefreshJobs,
    FilterJobs {
        status: Option<JobStatus>,
        priority: Option<Priority>,
        text: String,
    },
    SetJobsAutoRefresh {
        enabled: bool,
        interval_ms: u64,
    },

    // Scan actions
    StartScan {
        target: String,
        profile: String,
        project_id: Option<ProjectId>,
    },
    StopScan(ScanId),
    PauseScan(ScanId),
    ResumeScan(ScanId),
    SelectScan(ScanId),
    RefreshScans,
    FilterScans {
        status: Option<ScanStatus>,
        text: String,
    },
    ExportScanResults {
        scan_id: ScanId,
        format: String,
        path: String,
    },

    // Reverse Engineering actions
    LoadREProject(ProjectId),
    StartREAnalysis(ProjectId),
    StopREAnalysis(ProjectId),
    SelectREFunction(u64),
    ChangeREViewMode(REViewMode),
    ExportREData {
        project_id: ProjectId,
        format: String,
        path: String,
    },

    // Findings actions
    SelectFinding(usize),
    ExpandFinding(usize),
    CollapseFinding(usize),
    FilterFindings {
        severity: Option<Severity>,
        category: Option<Category>,
        confidence: Option<Confidence>,
        text: String,
    },
    GroupFindings(FindingsGroupBy),
    ExportFindings {
        format: String,
        path: String,
    },
    CopyFinding(usize),
    OpenFindingDetail(usize),
    ShowRemediation(usize),

    // Workflow actions
    CreateWorkflow {
        name: String,
        description: String,
        stages: Vec<WorkflowStageAction>,
    },
    UpdateWorkflow {
        id: String,
        name: String,
        description: String,
    },
    DeleteWorkflow(String),
    ExecuteWorkflow(String),
    CancelWorkflowExecution(String),
    SelectWorkflow(String),
    RefreshWorkflows,
    ViewWorkflowVisual(String),

    // AI actions
    StartAIAnalysis {
        target_id: String,
        analysis_type: String,
    },
    CancelAIAnalysis(String),
    SendChatMessage(String),
    ChangeAIModel(String),
    ChangeAIViewMode(AIViewMode),
    ClearAIChatHistory,

    // Plugin actions
    LoadPlugin(String),
    EnablePlugin(String),
    DisablePlugin(String),
    UnloadPlugin(String),
    ConfigurePlugin {
        name: String,
        config: serde_json::Value,
    },
    RefreshPlugins,
    OpenPluginMarketplace,
    SelectPlugin(String),

    // Log actions
    ClearLogs,
    FilterLogs {
        level: Option<LogLevel>,
        source: String,
        text: String,
    },
    ToggleLogFollow(bool),
    ToggleLogAutoScroll(bool),
    ExportLogs {
        path: String,
    },

    // Report actions
    GenerateReport {
        report_type: ReportType,
        scan_ids: Vec<ScanId>,
        project_ids: Vec<ProjectId>,
    },
    CancelReportGeneration(String),
    SelectReport(String),
    PreviewReport(String),
    ExportReport {
        report_id: String,
        format: String,
        path: String,
    },
    DeleteReport(String),
    RefreshReports,

    // Queue actions
    RefreshQueueStats,
    ScaleWorkers {
        count: usize,
    },
    PauseQueue,
    ResumeQueue,
    ClearDeadLetterQueue,

    // Global actions
    SetTheme(Theme),
    UpdateKeyBindings(KeyBindings),
    ShowNotification(Notification),
    DismissNotification(String),
    RequestRefresh,
    Shutdown,
}

/// Workflow stage action for creating workflows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStageAction {
    pub id: String,
    pub name: String,
    pub job_type: String,
    pub depends_on: Vec<String>,
    pub config: serde_json::Value,
}

/// Action handler trait
pub trait ActionHandler: Send + Sync {
    fn handle_action(&mut self, action: Action) -> anyhow::Result<()>;
}

/// Action dispatcher
pub struct ActionDispatcher {
    sender: tokio::sync::mpsc::UnboundedSender<Action>,
}

impl ActionDispatcher {
    pub fn new(sender: tokio::sync::mpsc::UnboundedSender<Action>) -> Self {
        Self { sender }
    }

    pub fn dispatch(
        &self,
        action: Action,
    ) -> Result<(), tokio::sync::mpsc::error::SendError<Action>> {
        self.sender.send(action)
    }
}

impl Clone for ActionDispatcher {
    fn clone(&self) -> Self {
        Self { sender: self.sender.clone() }
    }
}
