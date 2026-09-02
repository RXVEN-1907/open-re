//! Application state management

use crate::actions::Action;
use crate::app::App;
use crate::events::Event;
use crate::services::Services;
use chrono::{DateTime, Utc};
use openre_core::ids::{FileId, JobId, ProjectId, ScanId};
use openre_core::result::{Category, Confidence, Finding, Severity};
use openre_queue::{Job, JobStatus as QueueJobStatus, Priority};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};

/// Main panel types in the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PanelType {
    Projects,
    Jobs,
    Scans,
    ReverseEngineering,
    Findings,
    Workflows,
    AI,
    Plugins,
    Logs,
    Reports,
}

impl PanelType {
    pub const ALL: [PanelType; 10] = [
        PanelType::Projects,
        PanelType::Jobs,
        PanelType::Scans,
        PanelType::ReverseEngineering,
        PanelType::Findings,
        PanelType::Workflows,
        PanelType::AI,
        PanelType::Plugins,
        PanelType::Logs,
        PanelType::Reports,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            PanelType::Projects => "Projects",
            PanelType::Jobs => "Jobs",
            PanelType::Scans => "Scans",
            PanelType::ReverseEngineering => "Reverse Engineering",
            PanelType::Findings => "Findings",
            PanelType::Workflows => "Workflows",
            PanelType::AI => "AI",
            PanelType::Plugins => "Plugins",
            PanelType::Logs => "Logs",
            PanelType::Reports => "Reports",
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            PanelType::Projects => "Proj",
            PanelType::Jobs => "Jobs",
            PanelType::Scans => "Scan",
            PanelType::ReverseEngineering => "RE",
            PanelType::Findings => "Find",
            PanelType::Workflows => "Flow",
            PanelType::AI => "AI",
            PanelType::Plugins => "Plug",
            PanelType::Logs => "Logs",
            PanelType::Reports => "Rpts",
        }
    }

    pub fn next(&self) -> PanelType {
        let idx = Self::ALL.iter().position(|p| p == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn prev(&self) -> PanelType {
        let idx = Self::ALL.iter().position(|p| p == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// Project information displayed in the Projects panel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub id: ProjectId,
    pub name: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub file_count: usize,
    pub scan_count: usize,
    pub finding_count: usize,
    pub is_active: bool,
}

/// Job status for display (extends queue JobStatus)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
    Scheduled,
}

impl From<QueueJobStatus> for JobStatus {
    fn from(status: QueueJobStatus) -> Self {
        match status {
            QueueJobStatus::Pending => JobStatus::Pending,
            QueueJobStatus::Queued => JobStatus::Queued,
            QueueJobStatus::Running => JobStatus::Running,
            QueueJobStatus::Completed => JobStatus::Completed,
            QueueJobStatus::Failed => JobStatus::Failed,
            QueueJobStatus::Cancelled => JobStatus::Cancelled,
            QueueJobStatus::Scheduled => JobStatus::Scheduled,
        }
    }
}

/// Scan status for display
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStatus {
    NotStarted,
    Running { current_check: String, progress: usize, total: usize },
    Completed,
    Failed(String),
    Cancelled,
}

/// Workflow definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stages: Vec<WorkflowStage>,
    pub created_at: DateTime<Utc>,
    pub enabled: bool,
}

/// Workflow stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStage {
    pub id: String,
    pub name: String,
    pub job_type: String,
    pub depends_on: Vec<String>,
    pub config: serde_json::Value,
    pub status: JobStatus,
    pub progress: f32,
}

/// AI Analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysis {
    pub id: String,
    pub target_id: String,
    pub analysis_type: String,
    pub status: JobStatus,
    pub result: Option<serde_json::Value>,
    pub progress: f32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Plugin information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub enabled: bool,
    pub plugin_type: String,
    pub capabilities: Vec<String>,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub source: String,
    pub message: String,
    pub context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

/// Report information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportInfo {
    pub id: String,
    pub title: String,
    pub report_type: ReportType,
    pub status: JobStatus,
    pub created_at: DateTime<Utc>,
    pub file_path: Option<String>,
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportType {
    SARIF,
    HTML,
    PDF,
    JSON,
    Markdown,
}

impl std::fmt::Display for ReportType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportType::SARIF => write!(f, "SARIF"),
            ReportType::HTML => write!(f, "HTML"),
            ReportType::PDF => write!(f, "PDF"),
            ReportType::JSON => write!(f, "JSON"),
            ReportType::Markdown => write!(f, "Markdown"),
        }
    }
}

/// Reverse Engineering project data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct REProject {
    pub id: ProjectId,
    pub name: String,
    pub binary_path: String,
    pub architecture: String,
    pub functions: usize,
    pub strings: usize,
    pub imports: usize,
    pub exports: usize,
    pub analysis_status: JobStatus,
    pub last_analyzed: Option<DateTime<Utc>>,
}

/// Finding with additional display metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayFinding {
    pub finding: Finding,
    pub scan_id: ScanId,
    pub project_id: Option<ProjectId>,
    pub is_expanded: bool,
    pub is_selected: bool,
}

/// Queue statistics for display
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueueStats {
    pub total_queued: usize,
    pub jobs_queued_by_priority: HashMap<Priority, usize>,
    pub jobs_running: usize,
    pub jobs_scheduled: usize,
    pub jobs_dlq: usize,
    pub workers_active: usize,
    pub workers_idle: usize,
}

/// Application theme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    Dark,
    Light,
    HighContrast,
    SolarizedDark,
    SolarizedLight,
    Dracula,
    Nord,
    Gruvbox,
}

impl Theme {
    pub const ALL: [Theme; 8] = [
        Theme::Dark,
        Theme::Light,
        Theme::HighContrast,
        Theme::SolarizedDark,
        Theme::SolarizedLight,
        Theme::Dracula,
        Theme::Nord,
        Theme::Gruvbox,
    ];

    pub fn colors(&self) -> ThemeColors {
        match self {
            Theme::Dark => ThemeColors {
                bg: ratatui::style::Color::Rgb(28, 28, 28),
                fg: ratatui::style::Color::Rgb(220, 220, 220),
                accent: ratatui::style::Color::Rgb(0, 180, 180),
                accent_bold: ratatui::style::Color::Rgb(0, 220, 220),
                border: ratatui::style::Color::Rgb(80, 80, 80),
                selected_bg: ratatui::style::Color::Rgb(60, 60, 60),
                selected_fg: ratatui::style::Color::Rgb(255, 220, 0),
                success: ratatui::style::Color::Rgb(80, 200, 80),
                warning: ratatui::style::Color::Rgb(255, 200, 0),
                error: ratatui::style::Color::Rgb(255, 80, 80),
                info: ratatui::style::Color::Rgb(80, 160, 255),
                muted: ratatui::style::Color::Rgb(120, 120, 120),
                critical: ratatui::style::Color::Rgb(255, 50, 50),
                high: ratatui::style::Color::Rgb(255, 140, 0),
                medium: ratatui::style::Color::Rgb(255, 215, 0),
                low: ratatui::style::Color::Rgb(50, 200, 50),
                panel_bg: ratatui::style::Color::Rgb(35, 35, 35),
                panel_border: ratatui::style::Color::Rgb(70, 70, 70),
                scrollbar: ratatui::style::Color::Rgb(80, 80, 80),
                scrollbar_thumb: ratatui::style::Color::Rgb(120, 120, 120),
            },
            Theme::Light => ThemeColors {
                bg: ratatui::style::Color::Rgb(245, 245, 245),
                fg: ratatui::style::Color::Rgb(40, 40, 40),
                accent: ratatui::style::Color::Rgb(0, 100, 100),
                accent_bold: ratatui::style::Color::Rgb(0, 80, 80),
                border: ratatui::style::Color::Rgb(180, 180, 180),
                selected_bg: ratatui::style::Color::Rgb(200, 200, 200),
                selected_fg: ratatui::style::Color::Rgb(0, 80, 80),
                success: ratatui::style::Color::Rgb(0, 150, 0),
                warning: ratatui::style::Color::Rgb(200, 150, 0),
                error: ratatui::style::Color::Rgb(200, 0, 0),
                info: ratatui::style::Color::Rgb(0, 0, 200),
                muted: ratatui::style::Color::Rgb(120, 120, 120),
                critical: ratatui::style::Color::Rgb(200, 0, 0),
                high: ratatui::style::Color::Rgb(200, 100, 0),
                medium: ratatui::style::Color::Rgb(200, 150, 0),
                low: ratatui::style::Color::Rgb(0, 150, 0),
                panel_bg: ratatui::style::Color::Rgb(255, 255, 255),
                panel_border: ratatui::style::Color::Rgb(200, 200, 200),
                scrollbar: ratatui::style::Color::Rgb(200, 200, 200),
                scrollbar_thumb: ratatui::style::Color::Rgb(160, 160, 160),
            },
            Theme::HighContrast => ThemeColors {
                bg: ratatui::style::Color::Black,
                fg: ratatui::style::Color::White,
                accent: ratatui::style::Color::Yellow,
                accent_bold: ratatui::style::Color::Yellow,
                border: ratatui::style::Color::White,
                selected_bg: ratatui::style::Color::Yellow,
                selected_fg: ratatui::style::Color::Black,
                success: ratatui::style::Color::Green,
                warning: ratatui::style::Color::Yellow,
                error: ratatui::style::Color::Red,
                info: ratatui::style::Color::Cyan,
                muted: ratatui::style::Color::Gray,
                critical: ratatui::style::Color::Red,
                high: ratatui::style::Color::Red,
                medium: ratatui::style::Color::Yellow,
                low: ratatui::style::Color::Green,
                panel_bg: ratatui::style::Color::Black,
                panel_border: ratatui::style::Color::White,
                scrollbar: ratatui::style::Color::Gray,
                scrollbar_thumb: ratatui::style::Color::White,
            },
            Theme::SolarizedDark => ThemeColors {
                bg: ratatui::style::Color::Rgb(0, 43, 54),
                fg: ratatui::style::Color::Rgb(131, 148, 150),
                accent: ratatui::style::Color::Rgb(38, 139, 210),
                accent_bold: ratatui::style::Color::Rgb(42, 161, 152),
                border: ratatui::style::Color::Rgb(7, 54, 66),
                selected_bg: ratatui::style::Color::Rgb(7, 54, 66),
                selected_fg: ratatui::style::Color::Rgb(181, 137, 0),
                success: ratatui::style::Color::Rgb(133, 153, 0),
                warning: ratatui::style::Color::Rgb(181, 137, 0),
                error: ratatui::style::Color::Rgb(220, 50, 47),
                info: ratatui::style::Color::Rgb(38, 139, 210),
                muted: ratatui::style::Color::Rgb(101, 123, 131),
                critical: ratatui::style::Color::Rgb(220, 50, 47),
                high: ratatui::style::Color::Rgb(211, 54, 130),
                medium: ratatui::style::Color::Rgb(181, 137, 0),
                low: ratatui::style::Color::Rgb(133, 153, 0),
                panel_bg: ratatui::style::Color::Rgb(0, 43, 54),
                panel_border: ratatui::style::Color::Rgb(7, 54, 66),
                scrollbar: ratatui::style::Color::Rgb(7, 54, 66),
                scrollbar_thumb: ratatui::style::Color::Rgb(101, 123, 131),
            },
            Theme::SolarizedLight => ThemeColors {
                bg: ratatui::style::Color::Rgb(253, 246, 227),
                fg: ratatui::style::Color::Rgb(101, 123, 131),
                accent: ratatui::style::Color::Rgb(38, 139, 210),
                accent_bold: ratatui::style::Color::Rgb(42, 161, 152),
                border: ratatui::style::Color::Rgb(238, 232, 213),
                selected_bg: ratatui::style::Color::Rgb(238, 232, 213),
                selected_fg: ratatui::style::Color::Rgb(181, 137, 0),
                success: ratatui::style::Color::Rgb(133, 153, 0),
                warning: ratatui::style::Color::Rgb(181, 137, 0),
                error: ratatui::style::Color::Rgb(220, 50, 47),
                info: ratatui::style::Color::Rgb(38, 139, 210),
                muted: ratatui::style::Color::Rgb(147, 161, 161),
                critical: ratatui::style::Color::Rgb(220, 50, 47),
                high: ratatui::style::Color::Rgb(211, 54, 130),
                medium: ratatui::style::Color::Rgb(181, 137, 0),
                low: ratatui::style::Color::Rgb(133, 153, 0),
                panel_bg: ratatui::style::Color::Rgb(253, 246, 227),
                panel_border: ratatui::style::Color::Rgb(238, 232, 213),
                scrollbar: ratatui::style::Color::Rgb(238, 232, 213),
                scrollbar_thumb: ratatui::style::Color::Rgb(147, 161, 161),
            },
            Theme::Dracula => ThemeColors {
                bg: ratatui::style::Color::Rgb(40, 42, 54),
                fg: ratatui::style::Color::Rgb(248, 248, 242),
                accent: ratatui::style::Color::Rgb(189, 147, 249),
                accent_bold: ratatui::style::Color::Rgb(255, 121, 198),
                border: ratatui::style::Color::Rgb(68, 71, 90),
                selected_bg: ratatui::style::Color::Rgb(68, 71, 90),
                selected_fg: ratatui::style::Color::Rgb(248, 248, 242),
                success: ratatui::style::Color::Rgb(80, 250, 123),
                warning: ratatui::style::Color::Rgb(241, 250, 140),
                error: ratatui::style::Color::Rgb(255, 85, 85),
                info: ratatui::style::Color::Rgb(139, 233, 253),
                muted: ratatui::style::Color::Rgb(98, 114, 164),
                critical: ratatui::style::Color::Rgb(255, 85, 85),
                high: ratatui::style::Color::Rgb(255, 184, 108),
                medium: ratatui::style::Color::Rgb(241, 250, 140),
                low: ratatui::style::Color::Rgb(80, 250, 123),
                panel_bg: ratatui::style::Color::Rgb(40, 42, 54),
                panel_border: ratatui::style::Color::Rgb(68, 71, 90),
                scrollbar: ratatui::style::Color::Rgb(68, 71, 90),
                scrollbar_thumb: ratatui::style::Color::Rgb(98, 114, 164),
            },
            Theme::Nord => ThemeColors {
                bg: ratatui::style::Color::Rgb(46, 52, 64),
                fg: ratatui::style::Color::Rgb(216, 222, 233),
                accent: ratatui::style::Color::Rgb(129, 161, 193),
                accent_bold: ratatui::style::Color::Rgb(94, 129, 172),
                border: ratatui::style::Color::Rgb(59, 66, 82),
                selected_bg: ratatui::style::Color::Rgb(59, 66, 82),
                selected_fg: ratatui::style::Color::Rgb(229, 192, 123),
                success: ratatui::style::Color::Rgb(163, 190, 140),
                warning: ratatui::style::Color::Rgb(235, 203, 139),
                error: ratatui::style::Color::Rgb(191, 97, 106),
                info: ratatui::style::Color::Rgb(129, 161, 193),
                muted: ratatui::style::Color::Rgb(76, 86, 106),
                critical: ratatui::style::Color::Rgb(191, 97, 106),
                high: ratatui::style::Color::Rgb(208, 135, 112),
                medium: ratatui::style::Color::Rgb(235, 203, 139),
                low: ratatui::style::Color::Rgb(163, 190, 140),
                panel_bg: ratatui::style::Color::Rgb(46, 52, 64),
                panel_border: ratatui::style::Color::Rgb(59, 66, 82),
                scrollbar: ratatui::style::Color::Rgb(59, 66, 82),
                scrollbar_thumb: ratatui::style::Color::Rgb(76, 86, 106),
            },
            Theme::Gruvbox => ThemeColors {
                bg: ratatui::style::Color::Rgb(40, 40, 40),
                fg: ratatui::style::Color::Rgb(235, 219, 178),
                accent: ratatui::style::Color::Rgb(251, 73, 52),
                accent_bold: ratatui::style::Color::Rgb(254, 128, 25),
                border: ratatui::style::Color::Rgb(87, 87, 87),
                selected_bg: ratatui::style::Color::Rgb(87, 87, 87),
                selected_fg: ratatui::style::Color::Rgb(254, 128, 25),
                success: ratatui::style::Color::Rgb(184, 187, 38),
                warning: ratatui::style::Color::Rgb(254, 128, 25),
                error: ratatui::style::Color::Rgb(251, 73, 52),
                info: ratatui::style::Color::Rgb(131, 165, 152),
                muted: ratatui::style::Color::Rgb(146, 131, 116),
                critical: ratatui::style::Color::Rgb(251, 73, 52),
                high: ratatui::style::Color::Rgb(254, 128, 25),
                medium: ratatui::style::Color::Rgb(250, 189, 47),
                low: ratatui::style::Color::Rgb(184, 187, 38),
                panel_bg: ratatui::style::Color::Rgb(40, 40, 40),
                panel_border: ratatui::style::Color::Rgb(87, 87, 87),
                scrollbar: ratatui::style::Color::Rgb(87, 87, 87),
                scrollbar_thumb: ratatui::style::Color::Rgb(146, 131, 116),
            },
        }
    }
}

/// Theme color palette
#[derive(Debug, Clone, Copy)]
pub struct ThemeColors {
    pub bg: ratatui::style::Color,
    pub fg: ratatui::style::Color,
    pub accent: ratatui::style::Color,
    pub accent_bold: ratatui::style::Color,
    pub border: ratatui::style::Color,
    pub selected_bg: ratatui::style::Color,
    pub selected_fg: ratatui::style::Color,
    pub success: ratatui::style::Color,
    pub warning: ratatui::style::Color,
    pub error: ratatui::style::Color,
    pub info: ratatui::style::Color,
    pub muted: ratatui::style::Color,
    pub critical: ratatui::style::Color,
    pub high: ratatui::style::Color,
    pub medium: ratatui::style::Color,
    pub low: ratatui::style::Color,
    pub panel_bg: ratatui::style::Color,
    pub panel_border: ratatui::style::Color,
    pub scrollbar: ratatui::style::Color,
    pub scrollbar_thumb: ratatui::style::Color,
}

/// Keyboard shortcuts configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyBindings {
    pub quit: String,
    pub next_panel: String,
    pub prev_panel: String,
    pub next_item: String,
    pub prev_item: String,
    pub goto_top: String,
    pub goto_bottom: String,
    pub select: String,
    pub back: String,
    pub help: String,
    pub search: String,
    pub filter: String,
    pub refresh: String,
    pub cancel_job: String,
    pub pause_job: String,
    pub resume_job: String,
    pub start_scan: String,
    pub stop_scan: String,
    pub export: String,
    pub copy: String,
    pub detail: String,
    pub theme_cycle: String,
}

impl Default for KeyBindings {
    fn default() -> Self {
        Self {
            quit: "q".to_string(),
            next_panel: "Tab".to_string(),
            prev_panel: "Shift+Tab".to_string(),
            next_item: "j".to_string(),
            prev_item: "k".to_string(),
            goto_top: "g".to_string(),
            goto_bottom: "G".to_string(),
            select: "Enter".to_string(),
            back: "Esc".to_string(),
            help: "F1".to_string(),
            search: "/".to_string(),
            filter: "f".to_string(),
            refresh: "r".to_string(),
            cancel_job: "x".to_string(),
            pause_job: "p".to_string(),
            resume_job: "P".to_string(),
            start_scan: "s".to_string(),
            stop_scan: "S".to_string(),
            export: "e".to_string(),
            copy: "c".to_string(),
            detail: "d".to_string(),
            theme_cycle: "F2".to_string(),
        }
    }
}

/// Main application state shared across all panels
#[derive(Debug)]
pub struct AppState {
    /// Currently active panel
    pub active_panel: PanelType,

    /// Panel-specific states
    pub projects_state: ProjectsState,
    pub jobs_state: JobsState,
    pub scans_state: ScansState,
    pub re_state: ReverseEngineeringState,
    pub findings_state: FindingsState,
    pub workflows_state: WorkflowsState,
    pub ai_state: AIState,
    pub plugins_state: PluginsState,
    pub logs_state: LogsState,
    pub reports_state: ReportsState,

    /// Global state
    pub theme: Theme,
    pub key_bindings: KeyBindings,
    pub queue_stats: QueueStats,
    pub notifications: VecDeque<Notification>,

    /// Services
    pub services: Option<Arc<Services>>,

    /// Event channels
    pub event_tx: broadcast::Sender<Event>,
    pub action_tx: mpsc::UnboundedSender<Action>,
}

impl AppState {
    pub fn new(
        event_tx: broadcast::Sender<Event>,
        action_tx: mpsc::UnboundedSender<Action>,
        services: Option<Arc<Services>>,
    ) -> Self {
        Self {
            active_panel: PanelType::Projects,
            projects_state: ProjectsState::default(),
            jobs_state: JobsState::default(),
            scans_state: ScansState::default(),
            re_state: ReverseEngineeringState::default(),
            findings_state: FindingsState::default(),
            workflows_state: WorkflowsState::default(),
            ai_state: AIState::default(),
            plugins_state: PluginsState::default(),
            logs_state: LogsState::default(),
            reports_state: ReportsState::default(),
            theme: Theme::Dark,
            key_bindings: KeyBindings::default(),
            queue_stats: QueueStats::default(),
            notifications: VecDeque::with_capacity(100),
            services,
            event_tx,
            action_tx,
        }
    }

    pub fn add_notification(&mut self, notification: Notification) {
        if self.notifications.len() >= 100 {
            self.notifications.pop_front();
        }
        self.notifications.push_back(notification);
    }

    pub fn get_active_panel_state(&mut self) -> &mut dyn PanelState {
        match self.active_panel {
            PanelType::Projects => &mut self.projects_state,
            PanelType::Jobs => &mut self.jobs_state,
            PanelType::Scans => &mut self.scans_state,
            PanelType::ReverseEngineering => &mut self.re_state,
            PanelType::Findings => &mut self.findings_state,
            PanelType::Workflows => &mut self.workflows_state,
            PanelType::AI => &mut self.ai_state,
            PanelType::Plugins => &mut self.plugins_state,
            PanelType::Logs => &mut self.logs_state,
            PanelType::Reports => &mut self.reports_state,
        }
    }
}

/// Trait for panel-specific state
pub trait PanelState: std::fmt::Debug {
    fn selected_index(&self) -> usize;
    fn set_selected_index(&mut self, index: usize);
    fn item_count(&self) -> usize;
    fn is_loading(&self) -> bool;
    fn set_loading(&mut self, loading: bool);
}

/// Notification for toast display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub level: NotificationLevel,
    pub title: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// Projects panel state
#[derive(Debug, Default)]
pub struct ProjectsState {
    pub projects: Vec<ProjectInfo>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter: String,
    pub sort_by: ProjectSortBy,
    pub sort_ascending: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ProjectSortBy {
    #[default]
    Name,
    CreatedAt,
    UpdatedAt,
    FileCount,
    ScanCount,
    FindingCount,
}

impl PanelState for ProjectsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.projects.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Jobs panel state
#[derive(Debug, Default)]
pub struct JobsState {
    pub jobs: Vec<Job>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter_status: Option<JobStatus>,
    pub filter_priority: Option<Priority>,
    pub filter_text: String,
    pub auto_refresh: bool,
    pub refresh_interval_ms: u64,
}

impl PanelState for JobsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.jobs.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Scans panel state
#[derive(Debug, Default)]
pub struct ScansState {
    pub scans: Vec<ScanInfo>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter_status: Option<ScanStatus>,
    pub filter_text: String,
    pub active_scan: Option<ActiveScanInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    pub id: ScanId,
    pub project_id: Option<ProjectId>,
    pub target: String,
    pub profile: String,
    pub status: ScanStatus,
    pub findings_count: usize,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveScanInfo {
    pub scan_id: ScanId,
    pub target: String,
    pub current_check: String,
    pub progress: usize,
    pub total: usize,
    pub findings_so_far: usize,
    pub started_at: DateTime<Utc>,
    pub estimated_remaining: Option<u64>,
}

impl PanelState for ScansState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.scans.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Reverse Engineering panel state
#[derive(Debug, Default)]
pub struct ReverseEngineeringState {
    pub projects: Vec<REProject>,
    pub selected_index: usize,
    pub loading: bool,
    pub selected_project: Option<REProject>,
    pub functions: Vec<FunctionSummary>,
    pub selected_function: Option<FunctionSummary>,
    pub view_mode: REViewMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSummary {
    pub address: u64,
    pub name: Option<String>,
    pub size: u32,
    pub complexity: Option<u32>,
    pub block_count: Option<u32>,
    pub instruction_count: Option<u32>,
    pub is_thunk: bool,
    pub is_library: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum REViewMode {
    #[default]
    ProjectList,
    FunctionList,
    FunctionDetail,
    GraphView,
    StringsView,
    ImportsView,
    ExportsView,
}

impl PanelState for ReverseEngineeringState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        match self.view_mode {
            REViewMode::ProjectList => self.projects.len(),
            REViewMode::FunctionList => self.functions.len(),
            _ => 0,
        }
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Findings panel state
#[derive(Debug, Default)]
pub struct FindingsState {
    pub findings: Vec<DisplayFinding>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter_severity: Option<Severity>,
    pub filter_category: Option<Category>,
    pub filter_confidence: Option<Confidence>,
    pub filter_text: String,
    pub group_by: FindingsGroupBy,
    pub show_remediation: bool,
    pub detail_view: Option<FindingDetail>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingsGroupBy {
    #[default]
    None,
    Severity,
    Category,
    Check,
    Project,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetail {
    pub finding: DisplayFinding,
    pub evidence: Vec<EvidenceDetail>,
    pub remediation: Option<RemediationDetail>,
    pub related_findings: Vec<DisplayFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceDetail {
    pub evidence_type: String,
    pub description: String,
    pub data: Option<serde_json::Value>,
    pub location: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDetail {
    pub summary: String,
    pub steps: Vec<String>,
    pub code_examples: Vec<String>,
    pub references: Vec<String>,
    pub effort: String,
    pub priority: String,
}

impl PanelState for FindingsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.findings.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Workflows panel state
#[derive(Debug, Default)]
pub struct WorkflowsState {
    pub workflows: Vec<Workflow>,
    pub selected_index: usize,
    pub loading: bool,
    pub selected_workflow: Option<Workflow>,
    pub execution_history: Vec<WorkflowExecution>,
    pub view_mode: WorkflowViewMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowExecution {
    pub id: String,
    pub workflow_id: String,
    pub status: JobStatus,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub current_stage: Option<String>,
    pub stages_completed: usize,
    pub total_stages: usize,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkflowViewMode {
    #[default]
    List,
    Detail,
    ExecutionHistory,
    Visual,
}

impl PanelState for WorkflowsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.workflows.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// AI panel state
#[derive(Debug, Default)]
pub struct AIState {
    pub analyses: Vec<AIAnalysis>,
    pub selected_index: usize,
    pub loading: bool,
    pub selected_analysis: Option<AIAnalysis>,
    pub chat_history: Vec<ChatMessage>,
    pub current_prompt: String,
    pub model: String,
    pub view_mode: AIViewMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatRole {
    User,
    Assistant,
    System,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AIViewMode {
    #[default]
    Analyses,
    Chat,
    Models,
    Settings,
}

impl PanelState for AIState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.analyses.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Plugins panel state
#[derive(Debug, Default)]
pub struct PluginsState {
    pub plugins: Vec<PluginInfo>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter_enabled: Option<bool>,
    pub filter_type: Option<String>,
    pub view_mode: PluginViewMode,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginViewMode {
    #[default]
    List,
    Detail,
    Marketplace,
    Settings,
}

impl PanelState for PluginsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.plugins.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Logs panel state
#[derive(Debug, Default)]
pub struct LogsState {
    pub logs: VecDeque<LogEntry>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter_level: Option<LogLevel>,
    pub filter_source: String,
    pub filter_text: String,
    pub auto_scroll: bool,
    pub follow: bool,
    pub max_entries: usize,
}

impl PanelState for LogsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.logs.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}

/// Reports panel state
#[derive(Debug, Default)]
pub struct ReportsState {
    pub reports: Vec<ReportInfo>,
    pub selected_index: usize,
    pub loading: bool,
    pub filter_type: Option<ReportType>,
    pub filter_status: Option<JobStatus>,
    pub view_mode: ReportViewMode,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportViewMode {
    #[default]
    List,
    Detail,
    Preview,
    Settings,
}

impl PanelState for ReportsState {
    fn selected_index(&self) -> usize {
        self.selected_index
    }
    fn set_selected_index(&mut self, index: usize) {
        self.selected_index = index;
    }
    fn item_count(&self) -> usize {
        self.reports.len()
    }
    fn is_loading(&self) -> bool {
        self.loading
    }
    fn set_loading(&mut self, loading: bool) {
        self.loading = loading;
    }
}
