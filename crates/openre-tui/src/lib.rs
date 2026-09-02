//! openre-tui - Full-screen interactive TUI for open-re platform
//!
//! A comprehensive terminal user interface with panels for:
//! - Projects, Jobs, Scans, Reverse Engineering
//! - Findings, Workflows, AI, Plugins, Logs, Reports

pub mod actions;
pub mod app;
pub mod components;
pub mod events;
pub mod panels;
pub mod services;
pub mod state;
pub mod utils;

pub use actions::{Action, ActionDispatcher, ActionHandler};
pub use app::{run_tui, App};
pub use components::*;
pub use events::{Event, EventBus, EventHandler};
pub use openre_core::result::{Category, Confidence, Severity};
pub use openre_queue::Priority;
pub use panels::{get_all_panels, Panel};
pub use services::{DataFetcher, Services};
pub use state::{
    AIAnalysis, AIViewMode, ActiveScanInfo, AppState, ChatMessage, ChatRole, DisplayFinding,
    EvidenceDetail, FindingDetail, FindingsGroupBy, FunctionSummary, JobStatus, KeyBindings,
    LogEntry, LogLevel, Notification, PanelType, PluginInfo, PluginViewMode, ProjectInfo,
    ProjectSortBy, QueueStats, REProject, REViewMode, RemediationDetail, ReportInfo, ReportType,
    ReportViewMode, ScanStatus, Theme, ThemeColors, Workflow, WorkflowExecution, WorkflowViewMode,
};
pub use utils::*;

/// Initialize the TUI application
pub async fn init() -> anyhow::Result<App> {
    App::new().await
}
