//! Main TUI application

use crate::{
    actions::{Action, ActionDispatcher},
    components::*,
    events::{Event, EventBus},
    panels::{get_all_panels, Panel},
    services::{DataFetcher, Services},
    state::{
        AIAnalysis, AIViewMode, ActiveScanInfo, AppState, ChatMessage, ChatRole, DisplayFinding,
        FindingsGroupBy, FunctionSummary, JobStatus, KeyBindings, LogEntry, LogLevel, Notification,
        PanelType, PluginInfo, PluginViewMode, ProjectInfo, ProjectSortBy, QueueStats, REProject,
        REViewMode, ReportInfo, ReportType, ReportViewMode, ScanStatus, Theme, ThemeColors,
        Workflow, WorkflowExecution, WorkflowViewMode,
    },
    utils::*,
};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event as CrosstermEvent, KeyCode,
        KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use openre_config::Config;
use openre_core::ids::{JobId, ProjectId, ScanId};
use openre_core::result::Finding;
use openre_core::result::{Category, Confidence, Severity};
use openre_queue::Job;
use openre_queue::Priority;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Gauge, Paragraph, Tabs},
    Frame, Terminal,
};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{debug, error, info, warn};

/// Main application struct
pub struct App {
    state: Arc<RwLock<AppState>>,
    event_bus: EventBus,
    action_dispatcher: ActionDispatcher,
    action_rx: Option<mpsc::UnboundedReceiver<Action>>,
    panels: Vec<Box<dyn Panel>>,
    terminal: Option<Terminal<CrosstermBackend<io::Stdout>>>,
    running: bool,
    last_tick: Instant,
    tick_rate: Duration,
    show_help: bool,
    help_scroll: usize,
    services: Option<Arc<Services>>,
    data_fetcher: Option<DataFetcher>,
}

impl App {
    /// Create a new application instance
    pub async fn new() -> anyhow::Result<Self> {
        let (event_tx, _) = broadcast::channel(1024);
        let (action_tx, action_rx) = mpsc::unbounded_channel();

        // Load configuration
        let config = Config::load().unwrap_or_default();

        // Initialize services
        let services = match Services::new(config).await {
            Ok(s) => {
                info!("Services initialized successfully");
                Some(Arc::new(s))
            }
            Err(e) => {
                warn!("Failed to initialize services: {}", e);
                None
            }
        };

        let event_bus = EventBus::new(1024);
        let action_dispatcher = ActionDispatcher::new(action_tx.clone());

        // Create data fetcher if services are available
        let data_fetcher = services.as_ref().map(|s| {
            let fetcher = DataFetcher::new(s.clone(), event_bus.sender());
            fetcher.start();
            fetcher
        });

        let state = Arc::new(RwLock::new(AppState::new(event_tx.clone(), action_tx.clone(), services.clone())));

        // Load initial data
        let mut panels = get_all_panels();

        // Load initial projects if services available
        if let Some(svc) = &services {
            if let Ok(projects) = svc.get_projects().await {
                let mut state_guard = state.write().await;
                state_guard.projects_state.projects = projects;
            }
        }

        // Load initial RE projects if services available
        if let Some(svc) = &services {
            if let Ok(re_projects) = svc.get_re_projects().await {
                let mut state_guard = state.write().await;
                state_guard.re_state.projects = re_projects;
            }
        }

        Ok(Self {
            state,
            event_bus,
            action_dispatcher,
            action_rx: Some(action_rx),
            panels,
            terminal: None,
            running: true,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(50),
            show_help: false,
            help_scroll: 0,
            services,
            data_fetcher,
        })
    }

    /// Run the TUI application
    pub async fn run(&mut self) -> anyhow::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        self.terminal = Some(terminal);

        // Start background tasks
        self.start_background_tasks();

        // Main event loop
        let result = self.main_loop().await;

        // Cleanup
        self.cleanup().await?;

        result
    }

    /// Start background tasks for data updates
    fn start_background_tasks(&mut self) {
        // Data fetcher handles queue stats, project refresh, scan progress, and logs
        // Action processing is done in the main loop
    }

    /// Process an action and emit resulting events
    async fn process_action(
        action: Action,
        state: &Arc<RwLock<AppState>>,
        event_tx: &broadcast::Sender<Event>,
    ) -> anyhow::Result<()> {
        let mut state_guard = state.write().await;

        match action {
            Action::NavigateToPanel(panel) => {
                state_guard.active_panel = panel;
                let _ = event_tx.send(Event::PanelChanged(panel));
            }
            Action::NavigateNextPanel => {
                state_guard.active_panel = state_guard.active_panel.next();
                let _ = event_tx.send(Event::PanelChanged(state_guard.active_panel));
            }
            Action::NavigatePrevPanel => {
                state_guard.active_panel = state_guard.active_panel.prev();
                let _ = event_tx.send(Event::PanelChanged(state_guard.active_panel));
            }
            Action::SetTheme(theme) => {
                state_guard.theme = theme;
                let _ = event_tx.send(Event::ThemeChanged(theme));
            }
            Action::ShowNotification(notification) => {
                state_guard.add_notification(notification);
            }
            Action::RequestRefresh => {
                let _ = event_tx.send(Event::RefreshRequested);
            }
            Action::Shutdown => {
                let _ = event_tx.send(Event::ShutdownRequested);
            }
            // Project actions
            Action::CreateProject { name, path } => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(project_id) = svc.create_project(name.clone(), path.clone()).await {
                        let _ = event_tx.send(Event::ProjectCreated(project_id));
                        state_guard.add_notification(Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            level: crate::state::NotificationLevel::Success,
                            title: "Project Created".to_string(),
                            message: format!("Created project '{}' with ID {}", name, project_id),
                            timestamp: chrono::Utc::now(),
                            duration_ms: 3000,
                        });
                    } else {
                        state_guard.add_notification(Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            level: crate::state::NotificationLevel::Error,
                            title: "Project Creation Failed".to_string(),
                            message: format!("Failed to create project '{}'", name),
                            timestamp: chrono::Utc::now(),
                            duration_ms: 3000,
                        });
                    }
                }
            }
            Action::DeleteProject(id) => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if svc.delete_project(id).await.is_ok() {
                        state_guard.projects_state.projects.retain(|p| p.id != id);
                        if state_guard.projects_state.selected_index >= state_guard.projects_state.projects.len() {
                            state_guard.projects_state.selected_index = state_guard.projects_state.projects.len().saturating_sub(1);
                        }
                        let _ = event_tx.send(Event::ProjectDeleted(id));
                        state_guard.add_notification(Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            level: crate::state::NotificationLevel::Success,
                            title: "Project Deleted".to_string(),
                            message: "Project has been deleted".to_string(),
                            timestamp: chrono::Utc::now(),
                            duration_ms: 3000,
                        });
                    }
                }
            }
            Action::SelectProject(id) => {
                if let Some(idx) = state_guard.projects_state.projects.iter().position(|p| p.id == id) {
                    state_guard.projects_state.selected_index = idx;
                    let _ = event_tx.send(Event::ProjectSelected(id));
                }
            }
            Action::RefreshProjects => {
                if let Some(svc) = &state_guard.services {
                    if let Ok(projects) = svc.get_projects().await {
                        state_guard.projects_state.projects = projects;
                        let _ = event_tx.send(Event::ProjectRefreshed);
                    }
                }
            }
            // Job actions
            Action::CancelJob(id) => {
                if let Some(svc) = &state_guard.services {
                    if let Some(qm) = &svc.queue_manager {
                        if qm.cancel(id).await.unwrap_or(false) {
                            let _ = event_tx.send(Event::JobStatusChanged(id, JobStatus::Cancelled));
                            state_guard.add_notification(Notification {
                                id: uuid::Uuid::new_v4().to_string(),
                                level: crate::state::NotificationLevel::Info,
                                title: "Job Cancelled".to_string(),
                                message: format!("Job {} cancellation requested", id),
                                timestamp: chrono::Utc::now(),
                                duration_ms: 3000,
                            });
                        }
                    }
                }
            }
            Action::PauseJob(id) => {
                state_guard.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Job Paused".to_string(),
                    message: format!("Job {} pause requested", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::ResumeJob(id) => {
                state_guard.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Success,
                    title: "Job Resumed".to_string(),
                    message: format!("Job {} resume requested", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::RefreshJobs => {
                // Would need queue integration to list jobs
                let _ = event_tx.send(Event::JobsRefreshed);
            }
            Action::FilterJobs { status, priority, text } => {
                state_guard.jobs_state.filter_status = status;
                state_guard.jobs_state.filter_priority = priority;
                state_guard.jobs_state.filter_text = text;
            }
            // Scan actions
            Action::StartScan { target, profile, project_id } => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(scan_id) = svc.start_scan(target.clone(), profile.clone(), project_id).await {
                        state_guard.scans_state.active_scan = Some(crate::state::ActiveScanInfo {
                            scan_id,
                            target: target.clone(),
                            current_check: "Initializing...".to_string(),
                            progress: 0,
                            total: 0,
                            findings_so_far: 0,
                            started_at: chrono::Utc::now(),
                            estimated_remaining: None,
                        });
                        let _ = event_tx.send(Event::ScanStarted(crate::events::ScanInfo {
                            id: scan_id,
                            target,
                            profile,
                            project_id,
                        }));
                    }
                }
            }
            Action::StopScan(id) => {
                state_guard.scans_state.active_scan = None;
                let _ = event_tx.send(Event::ScanCancelled(id));
                state_guard.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Warning,
                    title: "Scan Stopped".to_string(),
                    message: format!("Scan {} stopped", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::SelectScan(id) => {
                if let Some(idx) = state_guard.scans_state.scans.iter().position(|s| s.id == id) {
                    state_guard.scans_state.selected_index = idx;
                    let _ = event_tx.send(Event::ScanSelected(id));
                }
            }
            Action::RefreshScans => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(scans) = svc.get_scans().await {
                        state_guard.scans_state.scans = scans;
                        let _ = event_tx.send(Event::ScansRefreshed);
                    }
                }
            }
            Action::FilterScans { status, text } => {
                state_guard.scans_state.filter_status = status;
                state_guard.scans_state.filter_text = text;
            }
            // RE actions
            Action::LoadREProject(id) => {
                if let Some(svc) = &state_guard.services {
                    if let Ok(functions) = svc.get_functions(id).await {
                        state_guard.re_state.functions = functions;
                        state_guard.re_state.view_mode = REViewMode::FunctionList;
                        state_guard.add_notification(Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            level: crate::state::NotificationLevel::Info,
                            title: "RE Project Loaded".to_string(),
                            message: format!("Loaded functions for project {}", id),
                            timestamp: chrono::Utc::now(),
                            duration_ms: 3000,
                        });
                    }
                }
            }
            Action::StartREAnalysis(id) => {
                state_guard.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Analysis Started".to_string(),
                    message: format!("Reverse engineering analysis started for project {}", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::ChangeREViewMode(mode) => {
                state_guard.re_state.view_mode = mode;
            }
            // Findings actions
            Action::SelectFinding(idx) => {
                state_guard.findings_state.selected_index = idx;
                let _ = event_tx.send(Event::FindingSelected(idx));
            }
            Action::ExpandFinding(idx) => {
                if let Some(finding) = state_guard.findings_state.findings.get_mut(idx) {
                    finding.is_expanded = true;
                    let _ = event_tx.send(Event::FindingExpanded(idx));
                }
            }
            Action::CollapseFinding(idx) => {
                if let Some(finding) = state_guard.findings_state.findings.get_mut(idx) {
                    finding.is_expanded = false;
                }
            }
            Action::FilterFindings { severity, category, confidence, text } => {
                state_guard.findings_state.filter_severity = severity;
                state_guard.findings_state.filter_category = category.clone();
                state_guard.findings_state.filter_confidence = confidence;
                state_guard.findings_state.filter_text = text.clone();
                let _ = event_tx.send(Event::FindingFiltered(severity, category, confidence, text));
            }
            Action::GroupFindings(mode) => {
                state_guard.findings_state.group_by = mode;
                let _ = event_tx.send(Event::FindingsGroupedBy(mode));
            }
            Action::ExportFindings { format, path } => {
                state_guard.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Success,
                    title: "Export Started".to_string(),
                    message: format!("Exporting findings as {} to {}", format, path),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
                let _ = event_tx.send(Event::FindingsExported(path));
            }
            Action::CopyFinding(idx) => {
                // Would copy finding details to clipboard
            }
            Action::OpenFindingDetail(idx) => {
                if let Some(finding) = state_guard.findings_state.findings.get(idx) {
                    state_guard.findings_state.detail_view = Some(crate::state::FindingDetail {
                        finding: finding.clone(),
                        evidence: finding.finding.evidence.iter().map(|e| crate::state::EvidenceDetail {
                            evidence_type: format!("{:?}", e.evidence_type),
                            description: e.description.clone(),
                            data: e.data.clone(),
                            location: e.location.clone(),
                        }).collect(),
                        remediation: finding.finding.remediation.as_ref().map(|r| crate::state::RemediationDetail {
                            summary: r.summary.clone(),
                            steps: r.steps.clone(),
                            code_examples: r.code_examples.iter().map(|ce| format!("{}: {} -> {}", ce.language, ce.vulnerable, ce.fixed)).collect(),
                            references: r.references.iter().map(|ref_| format!("{}: {}", ref_.title, ref_.url)).collect(),
                            effort: format!("{:?}", r.effort),
                            priority: format!("{:?}", r.priority),
                        }),
                        related_findings: vec![],
                    });
                    let _ = event_tx.send(Event::FindingDetailOpened(idx));
                }
            }
            Action::ShowRemediation(idx) => {
                // Would show remediation detail
            }
            // Workflow actions (require intelligence feature)
            #[cfg(feature = "intelligence")]
            Action::CreateWorkflow { name, description, stages } => {
                if let Some(svc) = &state_guard.services {
                    if let Some(wm) = &svc.workflow_manager {
                        // Would need to add create_workflow to WorkflowManager
                    }
                }
            }
            #[cfg(feature = "intelligence")]
            Action::ExecuteWorkflow(id) => {
                if let Some(svc) = &state_guard.services {
                    if let Ok(exec_id) = svc.execute_workflow(id.clone()).await {
                        let _ = event_tx.send(Event::WorkflowExecutionStarted(exec_id));
                        state_guard.add_notification(Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            level: crate::state::NotificationLevel::Info,
                            title: "Workflow Started".to_string(),
                            message: format!("Executing workflow {}", id),
                            timestamp: chrono::Utc::now(),
                            duration_ms: 3000,
                        });
                    }
                }
            }
            #[cfg(feature = "intelligence")]
            Action::RefreshWorkflows => {
                if let Some(svc) = &state_guard.services {
                    if let Ok(workflows) = svc.get_workflows().await {
                        state_guard.workflows_state.workflows = workflows;
                    }
                }
            }
            // AI actions
            Action::SendChatMessage(msg) => {
                state_guard.ai_state.chat_history.push(ChatMessage {
                    role: ChatRole::User,
                    content: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    metadata: None,
                });
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(response) = svc.send_chat_message(msg).await {
                        state_guard.ai_state.chat_history.push(ChatMessage {
                            role: ChatRole::Assistant,
                            content: response,
                            timestamp: chrono::Utc::now(),
                            metadata: None,
                        });
                    }
                }
            }
            Action::ChangeAIModel(model) => {
                state_guard.ai_state.model = model.clone();
                let _ = event_tx.send(Event::AIModelChanged(model));
            }
            Action::ChangeAIViewMode(mode) => {
                state_guard.ai_state.view_mode = mode;
                let _ = event_tx.send(Event::AIViewModeChanged(mode));
            }
            Action::ClearAIChatHistory => {
                state_guard.ai_state.chat_history.clear();
            }
            // Plugin actions
            Action::EnablePlugin(name) => {
                if let Some(plugin) = state_guard.plugins_state.plugins.iter_mut().find(|p| p.name == name) {
                    plugin.enabled = true;
                    let _ = event_tx.send(Event::PluginEnabled(name));
                }
            }
            Action::DisablePlugin(name) => {
                if let Some(plugin) = state_guard.plugins_state.plugins.iter_mut().find(|p| p.name == name) {
                    plugin.enabled = false;
                    let _ = event_tx.send(Event::PluginDisabled(name));
                }
            }
            Action::RefreshPlugins => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(plugins) = svc.get_plugins().await {
                        state_guard.plugins_state.plugins = plugins;
                    }
                }
            }
            // Log actions
            Action::ClearLogs => {
                state_guard.logs_state.logs.clear();
                let _ = event_tx.send(Event::LogsCleared);
            }
            Action::FilterLogs { level, source, text } => {
                state_guard.logs_state.filter_level = level;
                state_guard.logs_state.filter_source = source.clone();
                state_guard.logs_state.filter_text = text.clone();
                let _ = event_tx.send(Event::LogFilterChanged(level, source, text));
            }
            Action::ToggleLogFollow(follow) => {
                state_guard.logs_state.follow = follow;
                let _ = event_tx.send(Event::LogFollowToggled(follow));
            }
            Action::ToggleLogAutoScroll(auto_scroll) => {
                state_guard.logs_state.auto_scroll = auto_scroll;
            }
            Action::ExportLogs { path } => {
                state_guard.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Success,
                    title: "Export Started".to_string(),
                    message: format!("Exporting logs to {}", path),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            // Report actions
            Action::GenerateReport { report_type, scan_ids, project_ids } => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(report_id) = svc.generate_report(report_type, scan_ids, project_ids).await {
                        state_guard.add_notification(Notification {
                            id: uuid::Uuid::new_v4().to_string(),
                            level: crate::state::NotificationLevel::Info,
                            title: "Report Generation".to_string(),
                            message: format!("Generating report {}", report_id),
                            timestamp: chrono::Utc::now(),
                            duration_ms: 3000,
                        });
                        let _ = event_tx.send(Event::ReportGenerated(crate::state::ReportInfo {
                            id: report_id,
                            title: format!("{:?} Report", report_type),
                            report_type,
                            status: JobStatus::Running,
                            created_at: chrono::Utc::now(),
                            file_path: None,
                            size_bytes: None,
                        }));
                    }
                }
            }
            Action::RefreshReports => {
                #[cfg(feature = "intelligence")]
                if let Some(svc) = &state_guard.services {
                    if let Ok(reports) = svc.get_reports().await {
                        state_guard.reports_state.reports = reports;
                    }
                }
            }
            // Queue actions
            Action::RefreshQueueStats => {
                if let Some(svc) = &state_guard.services {
                    if let Ok(stats) = svc.get_queue_stats().await {
                        let _ = event_tx.send(Event::QueueStatsUpdated(stats));
                    }
                }
            }
            // Global actions
            Action::SetTheme(theme) => {
                state_guard.theme = theme;
                let _ = event_tx.send(Event::ThemeChanged(theme));
            }
            Action::UpdateKeyBindings(key_bindings) => {
                state_guard.key_bindings = key_bindings.clone();
                let _ = event_tx.send(Event::KeyBindingsChanged(key_bindings));
            }
            _ => {}
        }

        Ok(())
    }

    /// Main event loop
    async fn main_loop(&mut self) -> anyhow::Result<()> {
        let mut event_rx = self.event_bus.subscribe();

        while self.running {
            // Handle terminal events
            if let Some(terminal) = &mut self.terminal {
                // Draw UI - extract data needed for rendering
                let (active_panel, theme, queue_stats, notifications, size) = {
                    let state = self.state.blocking_read();
                    let size = terminal.size()?;
                    (
                        state.active_panel,
                        state.theme,
                        state.queue_stats.clone(),
                        state.notifications.clone(),
                        size,
                    )
                };
                let colors = theme.colors();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Tab bar
                        Constraint::Min(10),   // Main content
                        Constraint::Length(3), // Status bar
                    ])
                    .split(size);

                terminal.draw(|f| {
                    // Render tab bar
                    let tabs: Vec<Line> = PanelType::ALL
                        .iter()
                        .map(|panel| {
                            let is_active = *panel == active_panel;
                            let style = if is_active {
                                Style::default()
                                    .fg(colors.selected_fg)
                                    .bg(colors.selected_bg)
                                    .add_modifier(Modifier::BOLD)
                            } else {
                                Style::default().fg(colors.fg)
                            };
                            let label = if size.width < 120 {
                                panel.short_label()
                            } else {
                                panel.label()
                            };
                            Line::from(Span::styled(format!(" {} ", label), style))
                        })
                        .collect();

                    let tabs_widget = Tabs::new(tabs)
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(colors.border))
                                .style(Style::default().bg(colors.panel_bg)),
                        )
                        .select(active_panel as usize);
                    f.render_widget(tabs_widget, chunks[0]);

                    // Render active panel - need mutable state
                    if let Some(panel) = self.panels.iter_mut().find(|p| p.panel_type() == active_panel) {
                        let mut state = self.state.blocking_write();
                        panel.render(f, chunks[1], &mut *state, &colors, true);
                    }

                    // Render status bar
                    let status_parts = vec![
                        Span::styled(
                            format!(" {} ", active_panel.label()),
                            Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(" | ", Style::default().fg(colors.muted)),
                        Span::styled(
                            format!(" Queued: {} ", queue_stats.total_queued),
                            Style::default().fg(colors.info),
                        ),
                        Span::styled(" | ", Style::default().fg(colors.muted)),
                        Span::styled(
                            format!(" Running: {} ", queue_stats.jobs_running),
                            Style::default().fg(colors.accent),
                        ),
                        Span::styled(" | ", Style::default().fg(colors.muted)),
                        Span::styled(
                            format!(
                                " Workers: {}/{} ",
                                queue_stats.workers_active,
                                queue_stats.workers_active + queue_stats.workers_idle
                            ),
                            Style::default().fg(colors.success),
                        ),
                        Span::styled(" | ", Style::default().fg(colors.muted)),
                        Span::styled(format!(" Theme: {:?} ", theme), Style::default().fg(colors.muted)),
                    ];
                    let status_text = Line::from(status_parts);
                    let status_bar = Paragraph::new(status_text)
                        .style(Style::default().bg(colors.panel_bg).fg(colors.fg))
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(Style::default().fg(colors.border)),
                        );
                    f.render_widget(status_bar, chunks[2]);

                    // Render notifications
                    let notifications: Vec<&Notification> = notifications.iter().rev().take(5).collect();
                    if !notifications.is_empty() {
                        let notif_height = (notifications.len() * 3).min(size.height as usize / 3) as u16;
                        let notif_area = Rect {
                            x: size.width.saturating_sub(50),
                            y: size.height.saturating_sub(notif_height + 3),
                            width: 48.min(size.width),
                            height: notif_height,
                        };

                        for (i, notif) in notifications.iter().enumerate() {
                            let (icon, color) = match notif.level {
                                crate::state::NotificationLevel::Info => ("ℹ️", colors.info),
                                crate::state::NotificationLevel::Success => ("✅", colors.success),
                                crate::state::NotificationLevel::Warning => ("⚠️", colors.warning),
                                crate::state::NotificationLevel::Error => ("❌", colors.error),
                            };

                            let y = notif_area.y + (i as u16 * 3);
                            if y + 2 >= notif_area.y + notif_height {
                                break;
                            }

                            let notif_rect = Rect { x: notif_area.x, y, width: notif_area.width, height: 3 };

                            f.render_widget(ratatui::widgets::Clear, notif_rect);

                            let text = Text::from(vec![
                                Line::from(vec![
                                    Span::styled(icon, Style::default().fg(color)),
                                    Span::styled(
                                        format!(" {}", notif.title),
                                        Style::default().fg(colors.fg).add_modifier(Modifier::BOLD),
                                    ),
                                ]),
                                Line::from(vec![Span::styled(
                                    &notif.message,
                                    Style::default().fg(colors.muted),
                                )]),
                            ]);

                            let paragraph = Paragraph::new(text).block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_style(Style::default().fg(color))
                                    .style(Style::default().bg(colors.panel_bg)),
                            );

                            f.render_widget(paragraph, notif_rect);
                        }
                    }

                    // Render help overlay
                    if self.show_help {
                        let overlay_area = centered_rect(70, 80, size);
                        f.render_widget(ratatui::widgets::Clear, overlay_area);

                        let help_text = vec![
                            Line::from(vec![Span::styled(
                                "openre-tui - Keyboard Shortcuts",
                                Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Global Navigation:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  Tab / Shift+Tab", Style::default().fg(colors.warning)),
                                Span::raw(" - Switch panels"),
                            ]),
                            Line::from(vec![
                                Span::styled("  F1", Style::default().fg(colors.warning)),
                                Span::raw(" - Toggle this help"),
                            ]),
                            Line::from(vec![
                                Span::styled("  F2", Style::default().fg(colors.warning)),
                                Span::raw(" - Cycle theme"),
                            ]),
                            Line::from(vec![
                                Span::styled("  Ctrl+Q / Ctrl+C / q", Style::default().fg(colors.warning)),
                                Span::raw(" - Quit"),
                            ]),
                            Line::from(vec![
                                Span::styled("  r", Style::default().fg(colors.warning)),
                                Span::raw(" - Refresh current panel"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Panel-Specific (varies by panel):",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  j / k / ↓ / ↑", Style::default().fg(colors.warning)),
                                Span::raw(" - Navigate up/down"),
                            ]),
                            Line::from(vec![
                                Span::styled("  g / G", Style::default().fg(colors.warning)),
                                Span::raw(" - Go to top/bottom"),
                            ]),
                            Line::from(vec![
                                Span::styled("  Enter", Style::default().fg(colors.warning)),
                                Span::raw(" - Select/activate item"),
                            ]),
                            Line::from(vec![
                                Span::styled("  /", Style::default().fg(colors.warning)),
                                Span::raw(" - Search (where applicable)"),
                            ]),
                            Line::from(vec![
                                Span::styled("  f", Style::default().fg(colors.warning)),
                                Span::raw(" - Filter (where applicable)"),
                            ]),
                            Line::from(vec![
                                Span::styled("  e", Style::default().fg(colors.warning)),
                                Span::raw(" - Export (where applicable)"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Projects Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  n", Style::default().fg(colors.warning)),
                                Span::raw(" - New project"),
                            ]),
                            Line::from(vec![
                                Span::styled("  d / Del", Style::default().fg(colors.warning)),
                                Span::raw(" - Delete project"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Jobs Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  x", Style::default().fg(colors.warning)),
                                Span::raw(" - Cancel job"),
                            ]),
                            Line::from(vec![
                                Span::styled("  p", Style::default().fg(colors.warning)),
                                Span::raw(" - Pause job"),
                            ]),
                            Line::from(vec![
                                Span::styled("  P", Style::default().fg(colors.warning)),
                                Span::raw(" - Resume job"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Scans Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  s", Style::default().fg(colors.warning)),
                                Span::raw(" - Start scan"),
                            ]),
                            Line::from(vec![
                                Span::styled("  S", Style::default().fg(colors.warning)),
                                Span::raw(" - Stop scan"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Findings Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  /", Style::default().fg(colors.warning)),
                                Span::raw(" - Search findings"),
                            ]),
                            Line::from(vec![
                                Span::styled("  s", Style::default().fg(colors.warning)),
                                Span::raw(" - Cycle severity filter"),
                            ]),
                            Line::from(vec![
                                Span::styled("  g", Style::default().fg(colors.warning)),
                                Span::raw(" - Cycle group by"),
                            ]),
                            Line::from(vec![
                                Span::styled("  d", Style::default().fg(colors.warning)),
                                Span::raw(" - View detail"),
                            ]),
                            Line::from(vec![
                                Span::styled("  e", Style::default().fg(colors.warning)),
                                Span::raw(" - Export findings"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Reverse Engineering Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  1-7", Style::default().fg(colors.warning)),
                                Span::raw(" - Switch views (Projects, Functions, Detail, Graph, Strings, Imports, Exports)"),
                            ]),
                            Line::from(vec![
                                Span::styled("  a", Style::default().fg(colors.warning)),
                                Span::raw(" - Start analysis"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "AI Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  1-4", Style::default().fg(colors.warning)),
                                Span::raw(" - Switch views (Analyses, Chat, Models, Settings)"),
                            ]),
                            Line::from(vec![
                                Span::styled("  Type + Enter", Style::default().fg(colors.warning)),
                                Span::raw(" - Send chat message"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Logs Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  F", Style::default().fg(colors.warning)),
                                Span::raw(" - Toggle follow mode"),
                            ]),
                            Line::from(vec![
                                Span::styled("  c", Style::default().fg(colors.warning)),
                                Span::raw(" - Clear logs"),
                            ]),
                            Line::from(""),
                            Line::from(vec![Span::styled(
                                "Reports Panel:",
                                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                            )]),
                            Line::from(vec![
                                Span::styled("  g", Style::default().fg(colors.warning)),
                                Span::raw(" - Generate report"),
                            ]),
                            Line::from(vec![
                                Span::styled("  1-4", Style::default().fg(colors.warning)),
                                Span::raw(" - Switch views (List, Detail, Preview, Settings)"),
                            ]),
                        ];

                        let help = Paragraph::new(Text::from(help_text))
                            .style(Style::default().fg(colors.fg))
                            .block(
                                Block::default()
                                    .borders(Borders::ALL)
                                    .border_style(Style::default().fg(colors.accent))
                                    .title(" Help (F1/Esc to close, j/k to scroll) ")
                                    .title_style(Style::default().fg(colors.accent_bold)),
                            )
                            .wrap(ratatui::widgets::Wrap { trim: true });

                        f.render_widget(help, overlay_area);
                    }
                })?;
            }

            // Handle input with timeout
            let timeout = self.tick_rate.saturating_sub(self.last_tick.elapsed());
            if event::poll(timeout)? {
                if let CrosstermEvent::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        if let Some(should_quit) = self.handle_key(key).await? {
                            if should_quit {
                                break;
                            }
                        }
                    }
                }
            }

            // Handle events from event bus
            while let Ok(event) = event_rx.try_recv() {
                self.handle_event(event).await?;
            }

            // Process actions from the action channel
            while let Some(action) = self.action_rx.as_mut().and_then(|rx| rx.try_recv().ok()) {
                if let Err(e) = Self::process_action(action, &self.state, &self.event_bus.sender()).await {
                    error!("Action processing error: {}", e);
                }
            }

            // Tick
            if self.last_tick.elapsed() >= self.tick_rate {
                self.last_tick = Instant::now();
                self.tick().await?;
            }
        }

        Ok(())
    }

    /// Handle a key event
    async fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> anyhow::Result<Option<bool>> {
        // Global keys
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), KeyModifiers::CONTROL) => return Ok(Some(true)),
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(Some(true)),
            (KeyCode::Char('q'), _) if !self.show_help => return Ok(Some(true)),
            (KeyCode::Esc, _) if self.show_help => {
                self.show_help = false;
                return Ok(Some(false));
            }
            (KeyCode::F(1), _) => {
                self.show_help = !self.show_help;
                return Ok(Some(false));
            }
            (KeyCode::F(2), _) => {
                let mut state = self.state.write().await;
                state.theme = match state.theme {
                    Theme::Dark => Theme::Light,
                    Theme::Light => Theme::HighContrast,
                    Theme::HighContrast => Theme::SolarizedDark,
                    Theme::SolarizedDark => Theme::SolarizedLight,
                    Theme::SolarizedLight => Theme::Dracula,
                    Theme::Dracula => Theme::Nord,
                    Theme::Nord => Theme::Gruvbox,
                    Theme::Gruvbox => Theme::Dark,
                };
                return Ok(Some(false));
            }
            _ => {}
        }

        // Help scrolling
        if self.show_help {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1)
                }
                KeyCode::PageDown => self.help_scroll = self.help_scroll.saturating_add(10),
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(10),
                _ => {}
            }
            return Ok(Some(false));
        }

        // Panel navigation
        match key.code {
            KeyCode::Tab => {
                let mut state = self.state.write().await;
                state.active_panel = state.active_panel.next();
                return Ok(Some(false));
            }
            KeyCode::BackTab => {
                let mut state = self.state.write().await;
                state.active_panel = state.active_panel.prev();
                return Ok(Some(false));
            }
            _ => {}
        }

        // Delegate to active panel
        let panel_type = {
            let state = self.state.read().await;
            state.active_panel
        };

        if let Some(panel) = self.panels.iter_mut().find(|p| p.panel_type() == panel_type) {
            let actions = panel.handle_key(key, &mut *self.state.write().await)?;
            for action in actions {
                self.action_dispatcher.dispatch(action)?;
            }
        }

        Ok(Some(false))
    }

    /// Handle an event from the event bus
    async fn handle_event(&mut self, event: Event) -> anyhow::Result<()> {
        let mut state = self.state.write().await;

        match event {
            Event::PanelChanged(panel) => {
                state.active_panel = panel;
            }
            Event::QueueStatsUpdated(stats) => {
                state.queue_stats = stats;
            }
            Event::LogEntryAdded(log) => {
                state.logs_state.logs.push_back(log);
                if state.logs_state.logs.len() > state.logs_state.max_entries {
                    state.logs_state.logs.pop_front();
                }
            }
            Event::ScanProgress(scan_id, current_check, progress, total, findings_so_far) => {
                state.scans_state.active_scan = Some(ActiveScanInfo {
                    scan_id,
                    target: "".to_string(),
                    current_check,
                    progress,
                    total,
                    findings_so_far,
                    started_at: chrono::Utc::now(),
                    estimated_remaining: None,
                });
            }
            Event::ScanCompleted(result) => {
                state.scans_state.active_scan = None;
                state.scans_state.scans.push(crate::state::ScanInfo {
                    id: result.scan_id,
                    project_id: None,
                    target: "".to_string(),
                    profile: "".to_string(),
                    status: ScanStatus::Completed,
                    findings_count: result.findings.len(),
                    started_at: chrono::Utc::now() - chrono::Duration::milliseconds(result.duration_ms as i64),
                    completed_at: Some(chrono::Utc::now()),
                    duration_ms: Some(result.duration_ms),
                });
            }
            Event::ProjectsRefreshed(projects) => {
                state.projects_state.projects = projects;
                // Also update RE projects
                if let Some(svc) = &state.services {
                    if let Ok(re_projects) = svc.get_re_projects().await {
                        state.re_state.projects = re_projects;
                    }
                }
            }
            Event::ProjectCreated(id) => {
                // Project will be added on next refresh
            }
            Event::ProjectDeleted(id) => {
                state.projects_state.projects.retain(|p| p.id != id);
            }
            Event::ProjectSelected(id) => {
                if let Some(idx) = state.projects_state.projects.iter().position(|p| p.id == id) {
                    state.projects_state.selected_index = idx;
                }
            }
            Event::NotificationAdded(notification) => {
                state.add_notification(notification);
            }
            Event::ShutdownRequested => {
                self.running = false;
            }
            _ => {}
        }

        Ok(())
    }

    /// Tick - periodic updates
    async fn tick(&mut self) -> anyhow::Result<()> {
        // Update active panel if it has periodic updates
        let panel_type = {
            let state = self.state.read().await;
            state.active_panel
        };

        // Update scan progress if active
        {
            let mut state = self.state.write().await;
            if let Some(active) = &mut state.scans_state.active_scan {
                // Progress updates come from ScanProgress events
            }
        }

        Ok(())
    }

    /// Cleanup terminal
    async fn cleanup(&mut self) -> anyhow::Result<()> {
        disable_raw_mode()?;
        if let Some(terminal) = &mut self.terminal {
            execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
            terminal.show_cursor()?;
        }
        Ok(())
    }
}

/// Run the TUI application
pub async fn run_tui() -> anyhow::Result<()> {
    let mut app = App::new().await?;
    app.run().await
}
