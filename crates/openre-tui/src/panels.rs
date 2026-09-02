//! Panel implementations for the TUI

use crate::actions::Action;
use crate::events::Event;
use crate::{
    components::*,
    state::{
        AIAnalysis, AIState, AIViewMode, AppState, ChatMessage, ChatRole, DisplayFinding,
        FindingsGroupBy, FindingsState, FunctionSummary, JobStatus, JobsState, LogEntry, LogLevel,
        LogsState, Notification, PanelType, PluginInfo, PluginViewMode, PluginsState, ProjectInfo,
        ProjectSortBy, ProjectsState, QueueStats, REProject, REViewMode, ReportInfo, ReportType,
        ReportViewMode, ReportsState, ReverseEngineeringState, ScanStatus, ScansState, ThemeColors,
        Workflow, WorkflowExecution, WorkflowViewMode, WorkflowsState,
    },
};
use openre_core::ids::{JobId, ProjectId, ScanId};
use openre_core::result::{Category, Confidence, Finding, Severity};
use openre_queue::{Job, Priority};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Gauge, List, ListItem, ListState, Paragraph, Row, Table, TableState,
        Tabs,
    },
    Frame,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for panel rendering and interaction
pub trait Panel: Send + Sync {
    fn panel_type(&self) -> PanelType;
    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    );
    fn handle_action(&mut self, action: Action, state: &mut AppState)
        -> anyhow::Result<Vec<Event>>;
    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>>;
    fn on_focus(&mut self, state: &mut AppState) {}
    fn on_blur(&mut self, state: &mut AppState) {}
}

/// Projects panel
pub struct ProjectsPanel;

impl Panel for ProjectsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Projects
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let projects_state = &mut state.projects_state;
        let projects = &projects_state.projects;

        if projects.is_empty() && !projects_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "📁 No Projects",
                "Create a new project to get started",
                Some("Press 'n' to create a project"),
            );
            return;
        }

        if projects_state.loading {
            render_loading(f, area, colors, "Loading projects...");
            return;
        }

        // Build table rows
        let header = Row::new(vec![
            header_cell("Name", colors),
            header_cell("Path", colors),
            header_cell("Files", colors),
            header_cell("Scans", colors),
            header_cell("Findings", colors),
            header_cell("Updated", colors),
            header_cell("Status", colors),
        ]);

        let rows: Vec<Row> = projects
            .iter()
            .enumerate()
            .map(|(i, project)| {
                let selected = projects_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let status_text = if project.is_active {
                    Span::styled(
                        "● Active",
                        Style::default().fg(colors.success).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled("○ Inactive", Style::default().fg(colors.muted))
                };

                Row::new(vec![
                    cell(crate::utils::truncate(&project.name, 30), base_style),
                    cell(crate::utils::truncate(&project.path, 40), base_style),
                    cell(project.file_count.to_string(), base_style),
                    cell(project.scan_count.to_string(), base_style),
                    cell(project.finding_count.to_string(), base_style),
                    cell(crate::utils::format_relative_time(project.updated_at), base_style),
                    cell("", base_style), // Status will be rendered separately
                ])
                .style(base_style)
            })
            .collect();

        // We need custom rendering for the status column with colored badges
        // For now, use the table with a workaround
        let table = Table::new(
            rows,
            [
                Constraint::Length(30),
                Constraint::Min(30),
                Constraint::Length(8),
                Constraint::Length(8),
                Constraint::Length(10),
                Constraint::Length(15),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} (n=new, Enter=select, Del=delete) ", "Projects"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state
            .select(Some(projects_state.selected_index.min(projects.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::CreateProject { name, path } => {
                // TODO: Implement project creation via storage
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Project Creation".to_string(),
                    message: format!("Creating project '{}' at '{}'", name, path),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::DeleteProject(id) => {
                state.projects_state.projects.retain(|p| p.id != id);
                if state.projects_state.selected_index >= state.projects_state.projects.len() {
                    state.projects_state.selected_index =
                        state.projects_state.projects.len().saturating_sub(1);
                }
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Success,
                    title: "Project Deleted".to_string(),
                    message: "Project has been deleted".to_string(),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::SelectProject(id) => {
                if let Some(idx) = state.projects_state.projects.iter().position(|p| p.id == id) {
                    state.projects_state.selected_index = idx;
                }
            }
            Action::RefreshProjects => {
                // Trigger refresh via event
                return Ok(vec![Event::ProjectRefreshed]);
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::{KeyCode, KeyModifiers};

        let projects_state = &mut state.projects_state;
        let len = projects_state.projects.len();

        match key.code {
            KeyCode::Char('n') => {
                return Ok(vec![Action::CreateProject {
                    name: "New Project".to_string(),
                    path: std::env::current_dir()?.to_string_lossy().to_string(),
                }]);
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(project) = projects_state.projects.get(projects_state.selected_index) {
                    return Ok(vec![Action::DeleteProject(project.id)]);
                }
            }
            KeyCode::Enter => {
                if let Some(project) = projects_state.projects.get(projects_state.selected_index) {
                    return Ok(vec![Action::SelectProject(project.id)]);
                }
            }
            KeyCode::Char('r') => {
                return Ok(vec![Action::RefreshProjects]);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    projects_state.selected_index =
                        (projects_state.selected_index + 1).min(len - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if len > 0 && projects_state.selected_index > 0 {
                    projects_state.selected_index -= 1;
                }
            }
            KeyCode::Char('g') => {
                projects_state.selected_index = 0;
            }
            KeyCode::Char('G') => {
                if len > 0 {
                    projects_state.selected_index = len - 1;
                }
            }
            KeyCode::Char('/') => {
                // TODO: Implement search filter
            }
            _ => {}
        }
        Ok(vec![])
    }
}

/// Jobs panel
pub struct JobsPanel;

impl Panel for JobsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Jobs
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let jobs_state = &mut state.jobs_state;
        let jobs = &jobs_state.jobs;

        if jobs.is_empty() && !jobs_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "⚙️ No Jobs",
                "Jobs will appear here when tasks are queued",
                Some("Press 'r' to refresh"),
            );
            return;
        }

        if jobs_state.loading {
            render_loading(f, area, colors, "Loading jobs...");
            return;
        }

        // Build table
        let header = Row::new(vec![
            header_cell("ID", colors),
            header_cell("Type", colors),
            header_cell("Status", colors),
            header_cell("Priority", colors),
            header_cell("Progress", colors),
            header_cell("Worker", colors),
            header_cell("Queued", colors),
            header_cell("Started", colors),
        ]);

        let rows: Vec<Row> = jobs
            .iter()
            .enumerate()
            .map(|(i, job)| {
                let selected = jobs_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let status_badge = status_badge(job.status.into(), colors);
                let priority_badge = priority_badge(job.priority, colors);
                let progress_text =
                    job.progress.map_or("—".to_string(), |p| format!("{:.0}%", p * 100.0));
                let worker_text = job.worker_id.as_deref().unwrap_or("—");
                let queued_text = job
                    .queued_at
                    .map(crate::utils::format_relative_time)
                    .unwrap_or("—".to_string());
                let started_text = job
                    .started_at
                    .map(crate::utils::format_relative_time)
                    .unwrap_or("—".to_string());

                Row::new(vec![
                    cell(crate::utils::truncate(&job.id.to_string(), 12), base_style),
                    cell(crate::utils::truncate(&job.job_type.to_string(), 20), base_style),
                    cell("", base_style), // Status badge
                    cell("", base_style), // Priority badge
                    cell(progress_text, base_style),
                    cell(worker_text, base_style),
                    cell(queued_text, base_style),
                    cell(started_text, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(14),
                Constraint::Length(22),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} (x=cancel, p=pause, P=resume, r=refresh) ", "Jobs"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state.select(Some(jobs_state.selected_index.min(jobs.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::CancelJob(id) => {
                // TODO: Implement via queue
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Job Cancelled".to_string(),
                    message: format!("Job {} cancellation requested", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::PauseJob(id) => {
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Job Paused".to_string(),
                    message: format!("Job {} pause requested", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::ResumeJob(id) => {
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Success,
                    title: "Job Resumed".to_string(),
                    message: format!("Job {} resume requested", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::RefreshJobs => {
                return Ok(vec![Event::JobsRefreshed]);
            }
            Action::FilterJobs { status, priority, text } => {
                state.jobs_state.filter_status = status;
                state.jobs_state.filter_priority = priority;
                state.jobs_state.filter_text = text;
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::{KeyCode, KeyModifiers};

        let jobs_state = &mut state.jobs_state;
        let len = jobs_state.jobs.len();

        match key.code {
            KeyCode::Char('x') => {
                if let Some(job) = jobs_state.jobs.get(jobs_state.selected_index) {
                    return Ok(vec![Action::CancelJob(job.id)]);
                }
            }
            KeyCode::Char('p') => {
                if let Some(job) = jobs_state.jobs.get(jobs_state.selected_index) {
                    if matches!(job.status, openre_queue::JobStatus::Running) {
                        return Ok(vec![Action::PauseJob(job.id)]);
                    }
                }
            }
            KeyCode::Char('P') => {
                if let Some(job) = jobs_state.jobs.get(jobs_state.selected_index) {
                    if matches!(
                        job.status,
                        openre_queue::JobStatus::Failed | openre_queue::JobStatus::Cancelled
                    ) {
                        return Ok(vec![Action::ResumeJob(job.id)]);
                    }
                }
            }
            KeyCode::Char('r') => {
                return Ok(vec![Action::RefreshJobs]);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    jobs_state.selected_index = (jobs_state.selected_index + 1).min(len - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if len > 0 && jobs_state.selected_index > 0 {
                    jobs_state.selected_index -= 1;
                }
            }
            KeyCode::Char('g') => {
                jobs_state.selected_index = 0;
            }
            KeyCode::Char('G') => {
                if len > 0 {
                    jobs_state.selected_index = len - 1;
                }
            }
            KeyCode::Char('f') => {
                // Toggle filter
            }
            _ => {}
        }
        Ok(vec![])
    }
}

/// Scans panel
pub struct ScansPanel;

impl Panel for ScansPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Scans
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let scans_state = &mut state.scans_state;

        // Check for active scan - need to clone to avoid borrow issues
        let active_scan = scans_state.active_scan.clone();

        if let Some(active) = active_scan {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(8), Constraint::Min(10)])
                .split(area);

            // Active scan progress
            let progress_text = Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        "🔍 Active Scan: ",
                        Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(&active.target, Style::default().fg(colors.fg)),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Current: ", Style::default().fg(colors.muted)),
                    Span::styled(&active.current_check, Style::default().fg(colors.fg)),
                ]),
                Line::from(""),
                Line::from(progress_line(
                    active.progress as f32 / active.total.max(1) as f32,
                    (chunks[0].width.saturating_sub(4)) as u16,
                    colors,
                )),
                Line::from(vec![
                    Span::styled("Findings: ", Style::default().fg(colors.muted)),
                    Span::styled(
                        active.findings_so_far.to_string(),
                        Style::default().fg(colors.warning).add_modifier(Modifier::BOLD),
                    ),
                ]),
            ]);

            let progress_widget = Paragraph::new(progress_text).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(colors.accent))
                    .title(" Active Scan ")
                    .title_style(
                        Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                    )
                    .style(Style::default().bg(colors.panel_bg)),
            );
            f.render_widget(progress_widget, chunks[0]);

            // Render scan list below
            render_scan_list(
                f,
                chunks[1],
                &scans_state.scans,
                scans_state.selected_index,
                colors,
                focused,
            );
        } else if scans_state.scans.is_empty() && !scans_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "🔍 No Scans",
                "Start a scan from the Scans panel or via CLI",
                Some("Press 's' to start a new scan"),
            );
        } else if scans_state.loading {
            render_loading(f, area, colors, "Loading scans...");
        } else {
            render_scan_list(
                f,
                area,
                &scans_state.scans,
                scans_state.selected_index,
                colors,
                focused,
            );
        }
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::StartScan { target, profile, project_id } => {
                state.scans_state.active_scan = Some(crate::state::ActiveScanInfo {
                    scan_id: ScanId::new(),
                    target: target.clone(),
                    current_check: "Initializing...".to_string(),
                    progress: 0,
                    total: 0,
                    findings_so_far: 0,
                    started_at: chrono::Utc::now(),
                    estimated_remaining: None,
                });
                return Ok(vec![Event::ScanStarted(crate::events::ScanInfo {
                    id: state.scans_state.active_scan.as_ref().unwrap().scan_id,
                    target,
                    profile,
                    project_id,
                })]);
            }
            Action::StopScan(id) => {
                state.scans_state.active_scan = None;
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Warning,
                    title: "Scan Stopped".to_string(),
                    message: format!("Scan {} stopped", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::SelectScan(id) => {
                if let Some(idx) = state.scans_state.scans.iter().position(|s| s.id == id) {
                    state.scans_state.selected_index = idx;
                }
            }
            Action::RefreshScans => {
                return Ok(vec![Event::ScansRefreshed]);
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::{KeyCode, KeyModifiers};

        let scans_state = &mut state.scans_state;
        let len = scans_state.scans.len();

        match key.code {
            KeyCode::Char('s') => {
                return Ok(vec![Action::StartScan {
                    target: "https://example.com".to_string(), // Would prompt for input
                    profile: "standard".to_string(),
                    project_id: None,
                }]);
            }
            KeyCode::Char('S') => {
                if let Some(active) = &scans_state.active_scan {
                    return Ok(vec![Action::StopScan(active.scan_id)]);
                }
            }
            KeyCode::Char('r') => {
                return Ok(vec![Action::RefreshScans]);
            }
            KeyCode::Enter => {
                if let Some(scan) = scans_state.scans.get(scans_state.selected_index) {
                    return Ok(vec![Action::SelectScan(scan.id)]);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    scans_state.selected_index = (scans_state.selected_index + 1).min(len - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if len > 0 && scans_state.selected_index > 0 {
                    scans_state.selected_index -= 1;
                }
            }
            KeyCode::Char('g') => {
                scans_state.selected_index = 0;
            }
            KeyCode::Char('G') => {
                if len > 0 {
                    scans_state.selected_index = len - 1;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

fn render_scan_list(
    f: &mut Frame,
    area: Rect,
    scans: &[crate::state::ScanInfo],
    selected_index: usize,
    colors: &ThemeColors,
    focused: bool,
) {
    let header = Row::new(vec![
        header_cell("Target", colors),
        header_cell("Profile", colors),
        header_cell("Status", colors),
        header_cell("Findings", colors),
        header_cell("Started", colors),
        header_cell("Duration", colors),
    ]);

    let rows: Vec<Row> = scans
        .iter()
        .enumerate()
        .map(|(i, scan)| {
            let selected = selected_index == i;
            let base_style = if selected {
                Style::default()
                    .fg(colors.selected_fg)
                    .bg(colors.selected_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(colors.fg)
            };

            let status_text = match &scan.status {
                ScanStatus::NotStarted => "⏳ Pending".to_string(),
                ScanStatus::Running { current_check, progress, total } => {
                    format!("🔄 {} ({}/{})", current_check, progress, total)
                }
                ScanStatus::Completed => "✅ Done".to_string(),
                ScanStatus::Failed(e) => format!("❌ {}", e),
                ScanStatus::Cancelled => "🚫 Cancelled".to_string(),
            };

            let duration_text =
                scan.duration_ms.map(crate::utils::format_duration_ms).unwrap_or("—".to_string());

            Row::new(vec![
                cell(crate::utils::truncate(&scan.target, 40), base_style),
                cell(crate::utils::truncate(&scan.profile, 15), base_style),
                cell(status_text, base_style),
                cell(scan.findings_count.to_string(), base_style),
                cell(crate::utils::format_relative_time(scan.started_at), base_style),
                cell(duration_text, base_style),
            ])
            .style(base_style)
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Min(30),
            Constraint::Length(18),
            Constraint::Length(25),
            Constraint::Length(10),
            Constraint::Length(15),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if focused { colors.accent } else { colors.border }))
            .title(Span::styled(
                format!(" {} (s=start, S=stop, r=refresh, Enter=select) ", "Scans"),
                Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
    )
    .column_spacing(1)
    .highlight_style(
        Style::default().bg(colors.selected_bg).fg(colors.selected_fg).add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ");

    let mut table_state = TableState::default();
    table_state.select(Some(selected_index.min(scans.len().saturating_sub(1))));

    f.render_stateful_widget(table, area, &mut table_state);
}

/// Reverse Engineering panel
pub struct ReverseEngineeringPanel;

impl Panel for ReverseEngineeringPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::ReverseEngineering
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let re_state = &mut state.re_state;

        match re_state.view_mode {
            REViewMode::ProjectList => self.render_project_list(f, area, re_state, colors, focused),
            REViewMode::FunctionList => {
                self.render_function_list(f, area, re_state, colors, focused)
            }
            REViewMode::FunctionDetail => {
                self.render_function_detail(f, area, re_state, colors, focused)
            }
            REViewMode::GraphView => self.render_graph_view(f, area, re_state, colors, focused),
            REViewMode::StringsView => self.render_strings_view(f, area, re_state, colors, focused),
            REViewMode::ImportsView => self.render_imports_view(f, area, re_state, colors, focused),
            REViewMode::ExportsView => self.render_exports_view(f, area, re_state, colors, focused),
        }
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::LoadREProject(id) => {
                // TODO: Load project from storage
            }
            Action::StartREAnalysis(id) => {
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Analysis Started".to_string(),
                    message: format!("Reverse engineering analysis started for project {}", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            Action::ChangeREViewMode(mode) => {
                state.re_state.view_mode = mode;
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let re_state = &mut state.re_state;

        match key.code {
            KeyCode::Char('1') => {
                return Ok(vec![Action::ChangeREViewMode(REViewMode::ProjectList)])
            }
            KeyCode::Char('2') => {
                return Ok(vec![Action::ChangeREViewMode(REViewMode::FunctionList)])
            }
            KeyCode::Char('3') => {
                return Ok(vec![Action::ChangeREViewMode(REViewMode::FunctionDetail)])
            }
            KeyCode::Char('4') => return Ok(vec![Action::ChangeREViewMode(REViewMode::GraphView)]),
            KeyCode::Char('5') => {
                return Ok(vec![Action::ChangeREViewMode(REViewMode::StringsView)])
            }
            KeyCode::Char('6') => {
                return Ok(vec![Action::ChangeREViewMode(REViewMode::ImportsView)])
            }
            KeyCode::Char('7') => {
                return Ok(vec![Action::ChangeREViewMode(REViewMode::ExportsView)])
            }
            KeyCode::Enter => {
                if re_state.view_mode == REViewMode::ProjectList {
                    if let Some(project) = re_state.projects.get(re_state.selected_index) {
                        return Ok(vec![Action::LoadREProject(project.id)]);
                    }
                }
            }
            KeyCode::Char('a') => {
                if let Some(project) = re_state.projects.get(re_state.selected_index) {
                    return Ok(vec![Action::StartREAnalysis(project.id)]);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = match re_state.view_mode {
                    REViewMode::ProjectList => re_state.projects.len(),
                    REViewMode::FunctionList => re_state.functions.len(),
                    _ => 0,
                };
                if len > 0 {
                    re_state.selected_index = (re_state.selected_index + 1).min(len - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if re_state.selected_index > 0 {
                    re_state.selected_index -= 1;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl ReverseEngineeringPanel {
    fn render_project_list(
        &self,
        f: &mut Frame,
        area: Rect,
        re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let projects = &re_state.projects;

        if projects.is_empty() && !re_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "🔧 No RE Projects",
                "Load a binary to start reverse engineering",
                Some("Press 'o' to open a binary"),
            );
            return;
        }

        if re_state.loading {
            render_loading(f, area, colors, "Loading RE projects...");
            return;
        }

        let header = Row::new(vec![
            header_cell("Name", colors),
            header_cell("Binary", colors),
            header_cell("Arch", colors),
            header_cell("Functions", colors),
            header_cell("Strings", colors),
            header_cell("Imports", colors),
            header_cell("Status", colors),
        ]);

        let rows: Vec<Row> = projects
            .iter()
            .enumerate()
            .map(|(i, project)| {
                let selected = re_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let status = match project.analysis_status {
                    JobStatus::Running => "🔄 Analyzing",
                    JobStatus::Completed => "✅ Done",
                    JobStatus::Failed => "❌ Failed",
                    _ => "⏳ Pending",
                };

                Row::new(vec![
                    cell(crate::utils::truncate(&project.name, 25), base_style),
                    cell(crate::utils::truncate(&project.binary_path, 35), base_style),
                    cell(&project.architecture, base_style),
                    cell(project.functions.to_string(), base_style),
                    cell(project.strings.to_string(), base_style),
                    cell(project.imports.to_string(), base_style),
                    cell(status, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(25),
                Constraint::Min(30),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(15),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} [1-7=views, Enter=select, a=analyze] ", "Reverse Engineering"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state.select(Some(re_state.selected_index.min(projects.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_function_list(
        &self,
        f: &mut Frame,
        area: Rect,
        re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let functions = &re_state.functions;

        if functions.is_empty() {
            render_empty_state(
                f,
                area,
                colors,
                "🔧 No Functions",
                "Select a project and run analysis first",
                Some("Press '1' for project list"),
            );
            return;
        }

        let header = Row::new(vec![
            header_cell("Address", colors),
            header_cell("Name", colors),
            header_cell("Size", colors),
            header_cell("Complexity", colors),
            header_cell("Blocks", colors),
            header_cell("Instructions", colors),
        ]);

        let rows: Vec<Row> = functions
            .iter()
            .enumerate()
            .map(|(i, func)| {
                let selected = re_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let name = func.name.as_deref().unwrap_or("<unnamed>");
                let complexity = func.complexity.map_or("—".to_string(), |c| c.to_string());
                let blocks = func.block_count.map_or("—".to_string(), |c| c.to_string());
                let instructions =
                    func.instruction_count.map_or("—".to_string(), |c| c.to_string());

                Row::new(vec![
                    cell(format!("0x{:x}", func.address), base_style),
                    cell(crate::utils::truncate(name, 35), base_style),
                    cell(crate::utils::format_bytes(func.size as u64), base_style),
                    cell(complexity, base_style),
                    cell(blocks, base_style),
                    cell(instructions, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Min(30),
                Constraint::Length(12),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(14),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} [1-7=views, Enter=detail] ", "Functions"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state.select(Some(re_state.selected_index.min(functions.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_function_detail(
        &self,
        f: &mut Frame,
        area: Rect,
        re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        if let Some(func) = &re_state.selected_function {
            let text = Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        "Function: ",
                        Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        func.name.as_deref().unwrap_or("<unnamed>"),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Address: ", Style::default().fg(colors.accent)),
                    Span::styled(format!("0x{:x}", func.address), Style::default().fg(colors.fg)),
                ]),
                Line::from(vec![
                    Span::styled("Size: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        crate::utils::format_bytes(func.size as u64),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Complexity: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        func.complexity.map_or("—".to_string(), |c| c.to_string()),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Blocks: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        func.block_count.map_or("—".to_string(), |c| c.to_string()),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Instructions: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        func.instruction_count.map_or("—".to_string(), |c| c.to_string()),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Press '2' to return to function list",
                    Style::default().fg(colors.muted),
                )]),
            ]);

            let paragraph = Paragraph::new(text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if focused {
                            colors.accent
                        } else {
                            colors.border
                        }))
                        .title(" Function Detail ")
                        .title_style(
                            Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                        )
                        .style(Style::default().bg(colors.panel_bg)),
                )
                .wrap(ratatui::widgets::Wrap { trim: true });

            f.render_widget(paragraph, area);
        } else {
            render_empty_state(
                f,
                area,
                colors,
                "No Function Selected",
                "Select a function from the list",
                Some("Press '2' for function list"),
            );
        }
    }

    fn render_graph_view(
        &self,
        f: &mut Frame,
        area: Rect,
        _re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "📊 Graph View",
            "Control flow graph visualization",
            Some("Not yet implemented - press '1' for project list"),
        );
    }

    fn render_strings_view(
        &self,
        f: &mut Frame,
        area: Rect,
        _re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "📝 Strings View",
            "Extracted strings from binary",
            Some("Not yet implemented - press '1' for project list"),
        );
    }

    fn render_imports_view(
        &self,
        f: &mut Frame,
        area: Rect,
        _re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "📥 Imports View",
            "Imported functions and libraries",
            Some("Not yet implemented - press '1' for project list"),
        );
    }

    fn render_exports_view(
        &self,
        f: &mut Frame,
        area: Rect,
        _re_state: &mut ReverseEngineeringState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "📤 Exports View",
            "Exported functions and symbols",
            Some("Not yet implemented - press '1' for project list"),
        );
    }
}

/// Findings panel
pub struct FindingsPanel;

impl Panel for FindingsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Findings
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let findings_state = &mut state.findings_state;
        let findings = &findings_state.findings;

        // Check for detail view
        if let Some(detail) = &findings_state.detail_view {
            render_finding_detail(f, area, detail, colors, focused);
            return;
        }

        if findings.is_empty() && !findings_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "🔍 No Findings",
                "Run a scan to discover vulnerabilities",
                Some("Press 's' to start a scan, '/' to search"),
            );
            return;
        }

        if findings_state.loading {
            render_loading(f, area, colors, "Loading findings...");
            return;
        }

        // Render findings table
        let header = Row::new(vec![
            header_cell("Sev", colors),
            header_cell("Title", colors),
            header_cell("Category", colors),
            header_cell("Check", colors),
            header_cell("Confidence", colors),
            header_cell("Project", colors),
        ]);

        let rows: Vec<Row> = findings
            .iter()
            .enumerate()
            .map(|(i, finding)| {
                let selected = findings_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let sev_badge = severity_badge(finding.finding.severity, colors);
                let title = crate::utils::truncate(&finding.finding.title, 50);
                let category = format!("{:?}", finding.finding.category);
                let check = crate::utils::truncate(&finding.finding.plugin_source, 20);
                let confidence = format!("{:?}", finding.finding.confidence);
                let project = finding.project_id.map_or("—".to_string(), |id| id.to_string());

                Row::new(vec![
                    cell("", base_style), // Severity badge
                    cell(title, base_style),
                    cell(category, base_style),
                    cell(check, base_style),
                    cell(confidence, base_style),
                    cell(crate::utils::truncate(&project, 15), base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(6),
                Constraint::Min(35),
                Constraint::Length(20),
                Constraint::Length(22),
                Constraint::Length(14),
                Constraint::Length(18),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(
                        " {} [/=search, s=severity, f=filter, g=group, e=export, d=detail] ",
                        "Findings"
                    ),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state
            .select(Some(findings_state.selected_index.min(findings.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::SelectFinding(idx) => {
                state.findings_state.selected_index = idx;
            }
            Action::ExpandFinding(idx) => {
                if let Some(finding) = state.findings_state.findings.get_mut(idx) {
                    finding.is_expanded = true;
                }
            }
            Action::CollapseFinding(idx) => {
                if let Some(finding) = state.findings_state.findings.get_mut(idx) {
                    finding.is_expanded = false;
                }
            }
            Action::FilterFindings { severity, category, confidence, text } => {
                state.findings_state.filter_severity = severity;
                state.findings_state.filter_category = category;
                state.findings_state.filter_confidence = confidence;
                state.findings_state.filter_text = text;
            }
            Action::GroupFindings(mode) => {
                state.findings_state.group_by = mode;
            }
            Action::OpenFindingDetail(idx) => {
                if let Some(finding) = state.findings_state.findings.get(idx) {
                    state.findings_state.detail_view = Some(crate::state::FindingDetail {
                        finding: finding.clone(),
                        evidence: finding
                            .finding
                            .evidence
                            .iter()
                            .map(|e| crate::state::EvidenceDetail {
                                evidence_type: format!("{:?}", e.evidence_type),
                                description: e.description.clone(),
                                data: e.data.clone(),
                                location: e.location.clone(),
                            })
                            .collect(),
                        remediation: finding.finding.remediation.as_ref().map(|r| {
                            crate::state::RemediationDetail {
                                summary: r.summary.clone(),
                                steps: r.steps.clone(),
                                code_examples: r
                                    .code_examples
                                    .iter()
                                    .map(|ce| {
                                        format!(
                                            "{}: {} -> {}",
                                            ce.language, ce.vulnerable, ce.fixed
                                        )
                                    })
                                    .collect(),
                                references: r.references.iter().map(|ref_| format!("{}: {}", ref_.title, ref_.url)).collect(),
                                effort: format!("{:?}", r.effort),
                                priority: format!("{:?}", r.priority),
                            }
                        }),
                        related_findings: vec![],
                    });
                }
            }
            Action::ExportFindings { format, path } => {
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Success,
                    title: "Export Started".to_string(),
                    message: format!("Exporting findings as {} to {}", format, path),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let findings_state = &mut state.findings_state;
        let len = findings_state.findings.len();

        match key.code {
            KeyCode::Char('/') => {
                // TODO: Show search overlay
            }
            KeyCode::Char('s') => {
                // Cycle severity filter
                findings_state.filter_severity = match findings_state.filter_severity {
                    None => Some(Severity::Critical),
                    Some(Severity::Critical) => Some(Severity::High),
                    Some(Severity::High) => Some(Severity::Medium),
                    Some(Severity::Medium) => Some(Severity::Low),
                    Some(Severity::Low) => Some(Severity::Info),
                    Some(Severity::Info) => None,
                };
            }
            KeyCode::Char('f') => {
                // Cycle filter mode
                findings_state.group_by = match findings_state.group_by {
                    FindingsGroupBy::None => FindingsGroupBy::Severity,
                    FindingsGroupBy::Severity => FindingsGroupBy::Category,
                    FindingsGroupBy::Category => FindingsGroupBy::Check,
                    FindingsGroupBy::Check => FindingsGroupBy::Project,
                    FindingsGroupBy::Project => FindingsGroupBy::None,
                };
            }
            KeyCode::Char('e') => {
                return Ok(vec![Action::ExportFindings {
                    format: "json".to_string(),
                    path: "findings.json".to_string(),
                }]);
            }
            KeyCode::Char('d') => {
                return Ok(vec![Action::OpenFindingDetail(findings_state.selected_index)]);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if len > 0 {
                    findings_state.selected_index =
                        (findings_state.selected_index + 1).min(len - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if len > 0 && findings_state.selected_index > 0 {
                    findings_state.selected_index -= 1;
                }
            }
            KeyCode::Char('g') => {
                findings_state.selected_index = 0;
            }
            KeyCode::Char('G') => {
                if len > 0 {
                    findings_state.selected_index = len - 1;
                }
            }
            KeyCode::Esc => {
                findings_state.detail_view = None;
            }
            _ => {}
        }
        Ok(vec![])
    }
}

fn render_finding_detail(
    f: &mut Frame,
    area: Rect,
    detail: &crate::state::FindingDetail,
    colors: &ThemeColors,
    _focused: bool,
) {
    let finding = &detail.finding.finding;
    let sev_badge = severity_badge(finding.severity, colors);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("  ", Style::default()),
            sev_badge,
            Span::styled(" ", Style::default()),
            Span::styled(
                &finding.title,
                Style::default().fg(colors.fg).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Category: ", Style::default().fg(colors.accent)),
            Span::styled(format!("{:?}", finding.category), Style::default().fg(colors.fg)),
            Span::styled("  Check: ", Style::default().fg(colors.accent)),
            Span::styled(&finding.plugin_source, Style::default().fg(colors.fg)),
            Span::styled("  Confidence: ", Style::default().fg(colors.accent)),
            Span::styled(format!("{:?}", finding.confidence), Style::default().fg(colors.fg)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Description:",
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        )]),
        Line::from(vec![Span::styled(&finding.description, Style::default().fg(colors.fg))]),
        Line::from(""),
    ];

    // Evidence
    if !detail.evidence.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "Evidence:",
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        )]));
        for ev in &detail.evidence {
            lines.push(Line::from(vec![
                Span::styled("  • ", Style::default().fg(colors.muted)),
                Span::styled(&ev.description, Style::default().fg(colors.fg)),
            ]));
            if let Some(loc) = &ev.location {
                lines.push(Line::from(vec![
                    Span::styled("    Location: ", Style::default().fg(colors.muted)),
                    Span::styled(loc, Style::default().fg(colors.fg)),
                ]));
            }
        }
        lines.push(Line::from(""));
    }

    // Remediation
    if let Some(rem) = &detail.remediation {
        lines.push(Line::from(vec![Span::styled(
            "Remediation:",
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        )]));
        lines.push(Line::from(vec![
            Span::styled("  Summary: ", Style::default().fg(colors.muted)),
            Span::styled(&rem.summary, Style::default().fg(colors.fg)),
        ]));
        for step in &rem.steps {
            lines.push(Line::from(vec![
                Span::styled("  - ", Style::default().fg(colors.muted)),
                Span::styled(step, Style::default().fg(colors.fg)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::styled("  Effort: ", Style::default().fg(colors.muted)),
            Span::styled(&rem.effort, Style::default().fg(colors.fg)),
            Span::styled("  Priority: ", Style::default().fg(colors.muted)),
            Span::styled(&rem.priority, Style::default().fg(colors.fg)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "[e] Export  [c] Copy  [Esc] Close",
        Style::default().fg(colors.warning),
    )]));

    let text = Text::from(lines);
    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.accent))
                .title(" Finding Detail ")
                .title_style(Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD))
                .style(Style::default().bg(colors.panel_bg)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    f.render_widget(ratatui::widgets::Clear, area);
    f.render_widget(paragraph, area);
}

/// Workflows panel
pub struct WorkflowsPanel;

impl Panel for WorkflowsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Workflows
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let workflows_state = &mut state.workflows_state;

        match workflows_state.view_mode {
            WorkflowViewMode::List => {
                self.render_workflow_list(f, area, workflows_state, colors, focused)
            }
            WorkflowViewMode::Detail => {
                self.render_workflow_detail(f, area, workflows_state, colors, focused)
            }
            WorkflowViewMode::ExecutionHistory => {
                self.render_execution_history(f, area, workflows_state, colors, focused)
            }
            WorkflowViewMode::Visual => {
                self.render_visual(f, area, workflows_state, colors, focused)
            }
        }
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::ExecuteWorkflow(id) => {
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Workflow Started".to_string(),
                    message: format!("Executing workflow {}", id),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let workflows_state = &mut state.workflows_state;

        match key.code {
            KeyCode::Char('1') => workflows_state.view_mode = WorkflowViewMode::List,
            KeyCode::Char('2') => workflows_state.view_mode = WorkflowViewMode::Detail,
            KeyCode::Char('3') => workflows_state.view_mode = WorkflowViewMode::ExecutionHistory,
            KeyCode::Char('4') => workflows_state.view_mode = WorkflowViewMode::Visual,
            KeyCode::Char('e') => {
                if let Some(wf) = workflows_state.workflows.get(workflows_state.selected_index) {
                    return Ok(vec![Action::ExecuteWorkflow(wf.id.clone())]);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !workflows_state.workflows.is_empty() {
                    workflows_state.selected_index = (workflows_state.selected_index + 1)
                        .min(workflows_state.workflows.len() - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if workflows_state.selected_index > 0 {
                    workflows_state.selected_index -= 1;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl WorkflowsPanel {
    fn render_workflow_list(
        &self,
        f: &mut Frame,
        area: Rect,
        workflows_state: &mut WorkflowsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let workflows = &workflows_state.workflows;

        if workflows.is_empty() && !workflows_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "🔄 No Workflows",
                "Create workflows to automate tasks",
                Some("Press 'n' to create a workflow"),
            );
            return;
        }

        let header = Row::new(vec![
            header_cell("Name", colors),
            header_cell("Description", colors),
            header_cell("Stages", colors),
            header_cell("Status", colors),
            header_cell("Enabled", colors),
        ]);

        let rows: Vec<Row> = workflows
            .iter()
            .enumerate()
            .map(|(i, wf)| {
                let selected = workflows_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let enabled = if wf.enabled { "✅ Yes" } else { "❌ No" };

                Row::new(vec![
                    cell(crate::utils::truncate(&wf.name, 25), base_style),
                    cell(crate::utils::truncate(&wf.description, 40), base_style),
                    cell(wf.stages.len().to_string(), base_style),
                    cell("Ready", base_style),
                    cell(enabled, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(25),
                Constraint::Min(30),
                Constraint::Length(10),
                Constraint::Length(15),
                Constraint::Length(10),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} [1-4=views, e=execute] ", "Workflows"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state
            .select(Some(workflows_state.selected_index.min(workflows.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_workflow_detail(
        &self,
        f: &mut Frame,
        area: Rect,
        workflows_state: &mut WorkflowsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        if let Some(wf) = &workflows_state.selected_workflow {
            let mut lines = vec![
                Line::from(vec![Span::styled(
                    &wf.name,
                    Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Description: ", Style::default().fg(colors.accent)),
                    Span::styled(&wf.description, Style::default().fg(colors.fg)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Stages:",
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                )]),
            ];

            for (i, stage) in wf.stages.iter().enumerate() {
                let status_badge = status_badge(stage.status, colors);
                lines.push(Line::from(vec![
                    Span::styled(format!("  {}. ", i + 1), Style::default().fg(colors.muted)),
                    status_badge,
                    Span::styled(format!(" {}", stage.name), Style::default().fg(colors.fg)),
                    Span::styled(
                        format!(" ({})", stage.job_type),
                        Style::default().fg(colors.muted),
                    ),
                ]));
                if !stage.depends_on.is_empty() {
                    lines.push(Line::from(vec![
                        Span::styled("     Depends on: ", Style::default().fg(colors.muted)),
                        Span::styled(stage.depends_on.join(", "), Style::default().fg(colors.fg)),
                    ]));
                }
            }

            let text = Text::from(lines);
            let paragraph = Paragraph::new(text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if focused {
                            colors.accent
                        } else {
                            colors.border
                        }))
                        .title(" Workflow Detail ")
                        .title_style(
                            Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                        )
                        .style(Style::default().bg(colors.panel_bg)),
                )
                .wrap(ratatui::widgets::Wrap { trim: true });

            f.render_widget(paragraph, area);
        } else {
            render_empty_state(
                f,
                area,
                colors,
                "No Workflow Selected",
                "Select a workflow from the list",
                Some("Press '1' for workflow list"),
            );
        }
    }

    fn render_execution_history(
        &self,
        f: &mut Frame,
        area: Rect,
        workflows_state: &mut WorkflowsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let history = &workflows_state.execution_history;

        if history.is_empty() {
            render_empty_state(
                f,
                area,
                colors,
                "📋 No Executions",
                "Execute a workflow to see history",
                Some("Press '1' for workflow list"),
            );
            return;
        }

        let header = Row::new(vec![
            header_cell("Workflow", colors),
            header_cell("Status", colors),
            header_cell("Started", colors),
            header_cell("Completed", colors),
            header_cell("Stages", colors),
            header_cell("Current", colors),
        ]);

        let rows: Vec<Row> = history
            .iter()
            .enumerate()
            .map(|(i, exec)| {
                let selected = workflows_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let status_badge = status_badge(exec.status, colors);
                let completed = exec
                    .completed_at
                    .map(crate::utils::format_relative_time)
                    .unwrap_or("—".to_string());
                let current = exec.current_stage.as_deref().unwrap_or("—");
                let stages = format!("{}/{}", exec.stages_completed, exec.total_stages);

                Row::new(vec![
                    cell(crate::utils::truncate(&exec.workflow_id, 20), base_style),
                    cell("", base_style),
                    cell(crate::utils::format_relative_time(exec.started_at), base_style),
                    cell(completed, base_style),
                    cell(stages, base_style),
                    cell(current, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(22),
                Constraint::Length(14),
                Constraint::Length(15),
                Constraint::Length(15),
                Constraint::Length(12),
                Constraint::Min(20),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(" Execution History ")
                .title_style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state
            .select(Some(workflows_state.selected_index.min(history.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_visual(
        &self,
        f: &mut Frame,
        area: Rect,
        _workflows_state: &mut WorkflowsState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "📊 Visual Workflow",
            "Graphical workflow visualization",
            Some("Not yet implemented - press '1' for list"),
        );
    }
}

/// AI panel
pub struct AIPanel;

impl Panel for AIPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::AI
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let ai_state = &mut state.ai_state;

        match ai_state.view_mode {
            AIViewMode::Analyses => self.render_analyses(f, area, ai_state, colors, focused),
            AIViewMode::Chat => self.render_chat(f, area, ai_state, colors, focused),
            AIViewMode::Models => self.render_models(f, area, ai_state, colors, focused),
            AIViewMode::Settings => self.render_settings(f, area, ai_state, colors, focused),
        }
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::SendChatMessage(msg) => {
                state.ai_state.chat_history.push(ChatMessage {
                    role: ChatRole::User,
                    content: msg.clone(),
                    timestamp: chrono::Utc::now(),
                    metadata: None,
                });
                // TODO: Send to AI backend
            }
            Action::ChangeAIModel(model) => {
                state.ai_state.model = model;
            }
            Action::ChangeAIViewMode(mode) => {
                state.ai_state.view_mode = mode;
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let ai_state = &mut state.ai_state;

        match key.code {
            KeyCode::Char('1') => ai_state.view_mode = AIViewMode::Analyses,
            KeyCode::Char('2') => ai_state.view_mode = AIViewMode::Chat,
            KeyCode::Char('3') => ai_state.view_mode = AIViewMode::Models,
            KeyCode::Char('4') => ai_state.view_mode = AIViewMode::Settings,
            KeyCode::Enter => {
                if ai_state.view_mode == AIViewMode::Chat && !ai_state.current_prompt.is_empty() {
                    let msg = ai_state.current_prompt.clone();
                    ai_state.current_prompt.clear();
                    return Ok(vec![Action::SendChatMessage(msg)]);
                }
            }
            KeyCode::Char(c) => {
                if ai_state.view_mode == AIViewMode::Chat {
                    ai_state.current_prompt.push(c);
                }
            }
            KeyCode::Backspace => {
                if ai_state.view_mode == AIViewMode::Chat {
                    ai_state.current_prompt.pop();
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl AIPanel {
    fn render_analyses(
        &self,
        f: &mut Frame,
        area: Rect,
        ai_state: &mut AIState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let analyses = &ai_state.analyses;

        if analyses.is_empty() && !ai_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "🤖 No AI Analyses",
                "Start an AI analysis to see results",
                Some("Press '2' for chat, '3' for models"),
            );
            return;
        }

        let header = Row::new(vec![
            header_cell("Target", colors),
            header_cell("Type", colors),
            header_cell("Status", colors),
            header_cell("Progress", colors),
            header_cell("Started", colors),
        ]);

        let rows: Vec<Row> = analyses
            .iter()
            .enumerate()
            .map(|(i, analysis)| {
                let selected = ai_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let status_badge = status_badge(analysis.status, colors);
                let progress = format!("{:.0}%", analysis.progress * 100.0);
                let started = analysis
                    .started_at
                    .map(crate::utils::format_relative_time)
                    .unwrap_or("—".to_string());

                Row::new(vec![
                    cell(crate::utils::truncate(&analysis.target_id, 25), base_style),
                    cell(crate::utils::truncate(&analysis.analysis_type, 20), base_style),
                    cell("", base_style),
                    cell(progress, base_style),
                    cell(started, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(25),
                Constraint::Length(22),
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(15),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} [1-4=views] ", "AI Analyses"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state.select(Some(ai_state.selected_index.min(analyses.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_chat(
        &self,
        f: &mut Frame,
        area: Rect,
        ai_state: &mut AIState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(5), Constraint::Length(5)])
            .split(area);

        // Chat history
        let mut lines = Vec::new();
        for msg in &ai_state.chat_history {
            let (prefix, color) = match msg.role {
                ChatRole::User => ("You: ", colors.accent),
                ChatRole::Assistant => ("AI: ", colors.success),
                ChatRole::System => ("System: ", colors.info),
            };
            lines.push(Line::from(vec![
                Span::styled(prefix, Style::default().fg(color).add_modifier(Modifier::BOLD)),
                Span::styled(&msg.content, Style::default().fg(colors.fg)),
            ]));
            lines.push(Line::from(""));
        }

        let chat_text = Text::from(lines);
        let chat_widget = Paragraph::new(chat_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if focused {
                        colors.accent
                    } else {
                        colors.border
                    }))
                    .title(" Chat ")
                    .title_style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))
                    .style(Style::default().bg(colors.panel_bg)),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });
        f.render_widget(chat_widget, chunks[0]);

        // Input area
        let input_text = Text::from(vec![Line::from(vec![
            Span::styled("> ", Style::default().fg(colors.accent)),
            Span::styled(&ai_state.current_prompt, Style::default().fg(colors.fg)),
            Span::styled("█", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        ])]);

        let input_widget = Paragraph::new(input_text).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.accent))
                .title(" Input (Enter to send) ")
                .title_style(Style::default().fg(colors.accent))
                .style(Style::default().bg(colors.panel_bg)),
        );
        f.render_widget(input_widget, chunks[1]);
    }

    fn render_models(
        &self,
        f: &mut Frame,
        area: Rect,
        ai_state: &mut AIState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let models = vec![
            ("GPT-4", "OpenAI", true),
            ("GPT-3.5-Turbo", "OpenAI", false),
            ("Claude-3-Opus", "Anthropic", false),
            ("Claude-3-Sonnet", "Anthropic", false),
            ("Local-Llama-3", "Local", false),
        ];

        let header = Row::new(vec![
            header_cell("Model", colors),
            header_cell("Provider", colors),
            header_cell("Selected", colors),
        ]);

        let rows: Vec<Row> = models
            .iter()
            .enumerate()
            .map(|(i, (name, provider, selected))| {
                let sel_style = if ai_state.model == *name {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let selected_text = if *selected { "✓" } else { " " };

                Row::new(vec![
                    cell(*name, sel_style),
                    cell(*provider, sel_style),
                    cell(selected_text, sel_style),
                ])
                .style(sel_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [Constraint::Length(30), Constraint::Length(20), Constraint::Length(10)],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(" Models ")
                .title_style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))
                .style(Style::default().bg(colors.panel_bg)),
        )
        .column_spacing(1);

        let mut table_state = TableState::default();
        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_settings(
        &self,
        f: &mut Frame,
        area: Rect,
        ai_state: &mut AIState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let text = Text::from(vec![
            Line::from(vec![Span::styled(
                "AI Settings",
                Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
            )]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Current Model: ", Style::default().fg(colors.accent)),
                Span::styled(&ai_state.model, Style::default().fg(colors.fg)),
            ]),
            Line::from(""),
            Line::from(vec![Span::styled(
                "Press '2' for chat, '3' to select model",
                Style::default().fg(colors.muted),
            )]),
        ]);

        let paragraph = Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if focused {
                        colors.accent
                    } else {
                        colors.border
                    }))
                    .title(" AI Settings ")
                    .title_style(
                        Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                    )
                    .style(Style::default().bg(colors.panel_bg)),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Plugins panel
pub struct PluginsPanel;

impl Panel for PluginsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Plugins
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let plugins_state = &mut state.plugins_state;

        match plugins_state.view_mode {
            PluginViewMode::List => {
                self.render_plugin_list(f, area, plugins_state, colors, focused)
            }
            PluginViewMode::Detail => {
                self.render_plugin_detail(f, area, plugins_state, colors, focused)
            }
            PluginViewMode::Marketplace => {
                self.render_marketplace(f, area, plugins_state, colors, focused)
            }
            PluginViewMode::Settings => {
                self.render_settings(f, area, plugins_state, colors, focused)
            }
        }
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::EnablePlugin(name) => {
                if let Some(plugin) =
                    state.plugins_state.plugins.iter_mut().find(|p| p.name == name)
                {
                    plugin.enabled = true;
                }
            }
            Action::DisablePlugin(name) => {
                if let Some(plugin) =
                    state.plugins_state.plugins.iter_mut().find(|p| p.name == name)
                {
                    plugin.enabled = false;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let plugins_state = &mut state.plugins_state;

        match key.code {
            KeyCode::Char('1') => plugins_state.view_mode = PluginViewMode::List,
            KeyCode::Char('2') => plugins_state.view_mode = PluginViewMode::Detail,
            KeyCode::Char('3') => plugins_state.view_mode = PluginViewMode::Marketplace,
            KeyCode::Char('4') => plugins_state.view_mode = PluginViewMode::Settings,
            KeyCode::Char('e') => {
                if let Some(plugin) = plugins_state.plugins.get(plugins_state.selected_index) {
                    if plugin.enabled {
                        return Ok(vec![Action::DisablePlugin(plugin.name.clone())]);
                    } else {
                        return Ok(vec![Action::EnablePlugin(plugin.name.clone())]);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !plugins_state.plugins.is_empty() {
                    plugins_state.selected_index =
                        (plugins_state.selected_index + 1).min(plugins_state.plugins.len() - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if plugins_state.selected_index > 0 {
                    plugins_state.selected_index -= 1;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl PluginsPanel {
    fn render_plugin_list(
        &self,
        f: &mut Frame,
        area: Rect,
        plugins_state: &mut PluginsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let plugins = &plugins_state.plugins;

        if plugins.is_empty() && !plugins_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "🔌 No Plugins",
                "Load plugins to extend functionality",
                Some("Press '3' for marketplace"),
            );
            return;
        }

        let header = Row::new(vec![
            header_cell("Name", colors),
            header_cell("Version", colors),
            header_cell("Type", colors),
            header_cell("Status", colors),
            header_cell("Description", colors),
        ]);

        let rows: Vec<Row> = plugins
            .iter()
            .enumerate()
            .map(|(i, plugin)| {
                let selected = plugins_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let status = if plugin.enabled {
                    Span::styled(
                        "✅ Enabled",
                        Style::default().fg(colors.success).add_modifier(Modifier::BOLD),
                    )
                } else {
                    Span::styled("❌ Disabled", Style::default().fg(colors.muted))
                };

                Row::new(vec![
                    cell(crate::utils::truncate(&plugin.name, 25), base_style),
                    cell(&plugin.version, base_style),
                    cell(crate::utils::truncate(&plugin.plugin_type, 15), base_style),
                    cell("", base_style),
                    cell(crate::utils::truncate(&plugin.description, 40), base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(25),
                Constraint::Length(12),
                Constraint::Length(18),
                Constraint::Length(14),
                Constraint::Min(30),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} [1-4=views, e=toggle] ", "Plugins"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state.select(Some(plugins_state.selected_index.min(plugins.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_plugin_detail(
        &self,
        f: &mut Frame,
        area: Rect,
        plugins_state: &mut PluginsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        if let Some(plugin) = plugins_state.plugins.get(plugins_state.selected_index) {
            let text = Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        &plugin.name,
                        Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(" v{}", plugin.version),
                        Style::default().fg(colors.muted),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Description: ", Style::default().fg(colors.accent)),
                    Span::styled(&plugin.description, Style::default().fg(colors.fg)),
                ]),
                Line::from(vec![
                    Span::styled("Author: ", Style::default().fg(colors.accent)),
                    Span::styled(&plugin.author, Style::default().fg(colors.fg)),
                ]),
                Line::from(vec![
                    Span::styled("Type: ", Style::default().fg(colors.accent)),
                    Span::styled(&plugin.plugin_type, Style::default().fg(colors.fg)),
                ]),
                Line::from(vec![
                    Span::styled("Status: ", Style::default().fg(colors.accent)),
                    if plugin.enabled {
                        Span::styled(
                            "✅ Enabled",
                            Style::default().fg(colors.success).add_modifier(Modifier::BOLD),
                        )
                    } else {
                        Span::styled("❌ Disabled", Style::default().fg(colors.muted))
                    },
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Capabilities:",
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                )]),
            ]);

            let mut lines = text.lines;
            for cap in &plugin.capabilities {
                lines.push(Line::from(vec![
                    Span::styled("  • ", Style::default().fg(colors.muted)),
                    Span::styled(cap, Style::default().fg(colors.fg)),
                ]));
            }

            let paragraph = Paragraph::new(Text::from(lines))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if focused {
                            colors.accent
                        } else {
                            colors.border
                        }))
                        .title(" Plugin Detail ")
                        .title_style(
                            Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                        )
                        .style(Style::default().bg(colors.panel_bg)),
                )
                .wrap(ratatui::widgets::Wrap { trim: true });

            f.render_widget(paragraph, area);
        } else {
            render_empty_state(
                f,
                area,
                colors,
                "No Plugin Selected",
                "Select a plugin from the list",
                Some("Press '1' for plugin list"),
            );
        }
    }

    fn render_marketplace(
        &self,
        f: &mut Frame,
        area: Rect,
        _plugins_state: &mut PluginsState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "🏪 Plugin Marketplace",
            "Browse and install plugins",
            Some("Not yet implemented - press '1' for installed plugins"),
        );
    }

    fn render_settings(
        &self,
        f: &mut Frame,
        area: Rect,
        _plugins_state: &mut PluginsState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "⚙️ Plugin Settings",
            "Configure plugin behavior",
            Some("Not yet implemented"),
        );
    }
}

/// Logs panel
pub struct LogsPanel;

impl Panel for LogsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Logs
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let logs_state = &mut state.logs_state;
        let logs: Vec<&LogEntry> = logs_state.logs.iter().collect();

        if logs.is_empty() && !logs_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "📋 No Logs",
                "Logs will appear here as events occur",
                Some("Press 'f' to filter, 'F' to follow"),
            );
            return;
        }

        let items: Vec<ListItem> = logs
            .iter()
            .enumerate()
            .map(|(i, log)| {
                let selected = logs_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let level_badge = log_level_badge(log.level, colors);
                let time = log.timestamp.format("%H:%M:%S%.3f").to_string();

                ListItem::new(Line::from(vec![
                    Span::styled(format!("{} ", time), Style::default().fg(colors.muted)),
                    level_badge,
                    Span::styled(format!(" [{}] ", log.source), Style::default().fg(colors.accent)),
                    Span::styled(&log.message, base_style),
                ]))
                .style(base_style)
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if focused {
                        colors.accent
                    } else {
                        colors.border
                    }))
                    .title(Span::styled(
                        format!(" {} [f=filter, F=follow, c=clear] ", "Logs"),
                        Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                    ))
                    .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
            )
            .highlight_style(
                Style::default()
                    .bg(colors.selected_bg)
                    .fg(colors.selected_fg)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let mut list_state = ListState::default();
        if logs_state.follow && !logs.is_empty() {
            list_state.select(Some(logs.len() - 1));
        } else {
            list_state.select(Some(logs_state.selected_index.min(logs.len().saturating_sub(1))));
        }

        f.render_stateful_widget(list, area, &mut list_state);
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::ClearLogs => {
                state.logs_state.logs.clear();
            }
            Action::FilterLogs { level, source, text } => {
                state.logs_state.filter_level = level;
                state.logs_state.filter_source = source;
                state.logs_state.filter_text = text;
            }
            Action::ToggleLogFollow(follow) => {
                state.logs_state.follow = follow;
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let logs_state = &mut state.logs_state;

        match key.code {
            KeyCode::Char('c') => {
                return Ok(vec![Action::ClearLogs]);
            }
            KeyCode::Char('F') => {
                return Ok(vec![Action::ToggleLogFollow(!logs_state.follow)]);
            }
            KeyCode::Char('f') => {
                // TODO: Show filter overlay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = logs_state.logs.len();
                if len > 0 {
                    logs_state.selected_index = (logs_state.selected_index + 1).min(len - 1);
                    logs_state.follow = false;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if logs_state.selected_index > 0 {
                    logs_state.selected_index -= 1;
                    logs_state.follow = false;
                }
            }
            KeyCode::Char('g') => {
                logs_state.selected_index = 0;
                logs_state.follow = false;
            }
            KeyCode::Char('G') => {
                let len = logs_state.logs.len();
                if len > 0 {
                    logs_state.selected_index = len - 1;
                    logs_state.follow = true;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

/// Reports panel
pub struct ReportsPanel;

impl Panel for ReportsPanel {
    fn panel_type(&self) -> PanelType {
        PanelType::Reports
    }

    fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &mut AppState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let reports_state = &mut state.reports_state;

        match reports_state.view_mode {
            ReportViewMode::List => {
                self.render_report_list(f, area, reports_state, colors, focused)
            }
            ReportViewMode::Detail => {
                self.render_report_detail(f, area, reports_state, colors, focused)
            }
            ReportViewMode::Preview => self.render_preview(f, area, reports_state, colors, focused),
            ReportViewMode::Settings => {
                self.render_settings(f, area, reports_state, colors, focused)
            }
        }
    }

    fn handle_action(
        &mut self,
        action: Action,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Event>> {
        match action {
            Action::GenerateReport { report_type, scan_ids, project_ids } => {
                state.add_notification(Notification {
                    id: uuid::Uuid::new_v4().to_string(),
                    level: crate::state::NotificationLevel::Info,
                    title: "Report Generation".to_string(),
                    message: format!("Generating {} report...", report_type),
                    timestamp: chrono::Utc::now(),
                    duration_ms: 3000,
                });
            }
            _ => {}
        }
        Ok(vec![])
    }

    fn handle_key(
        &mut self,
        key: crossterm::event::KeyEvent,
        state: &mut AppState,
    ) -> anyhow::Result<Vec<Action>> {
        use crossterm::event::KeyCode;

        let reports_state = &mut state.reports_state;

        match key.code {
            KeyCode::Char('1') => reports_state.view_mode = ReportViewMode::List,
            KeyCode::Char('2') => reports_state.view_mode = ReportViewMode::Detail,
            KeyCode::Char('3') => reports_state.view_mode = ReportViewMode::Preview,
            KeyCode::Char('4') => reports_state.view_mode = ReportViewMode::Settings,
            KeyCode::Char('g') => {
                return Ok(vec![Action::GenerateReport {
                    report_type: ReportType::HTML,
                    scan_ids: vec![],
                    project_ids: vec![],
                }]);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !reports_state.reports.is_empty() {
                    reports_state.selected_index =
                        (reports_state.selected_index + 1).min(reports_state.reports.len() - 1);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if reports_state.selected_index > 0 {
                    reports_state.selected_index -= 1;
                }
            }
            _ => {}
        }
        Ok(vec![])
    }
}

impl ReportsPanel {
    fn render_report_list(
        &self,
        f: &mut Frame,
        area: Rect,
        reports_state: &mut ReportsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        let reports = &reports_state.reports;

        if reports.is_empty() && !reports_state.loading {
            render_empty_state(
                f,
                area,
                colors,
                "📄 No Reports",
                "Generate reports from scan results",
                Some("Press 'g' to generate a report"),
            );
            return;
        }

        let header = Row::new(vec![
            header_cell("Title", colors),
            header_cell("Type", colors),
            header_cell("Status", colors),
            header_cell("Created", colors),
            header_cell("Size", colors),
        ]);

        let rows: Vec<Row> = reports
            .iter()
            .enumerate()
            .map(|(i, report)| {
                let selected = reports_state.selected_index == i;
                let base_style = if selected {
                    Style::default()
                        .fg(colors.selected_fg)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(colors.fg)
                };

                let type_badge = report_type_badge(report.report_type, colors);
                let status_badge = status_badge(report.status, colors);
                let size =
                    report.size_bytes.map(crate::utils::format_bytes).unwrap_or("—".to_string());

                Row::new(vec![
                    cell(crate::utils::truncate(&report.title, 35), base_style),
                    cell("", base_style),
                    cell("", base_style),
                    cell(crate::utils::format_relative_time(report.created_at), base_style),
                    cell(size, base_style),
                ])
                .style(base_style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Min(30),
                Constraint::Length(10),
                Constraint::Length(14),
                Constraint::Length(15),
                Constraint::Length(12),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} [1-4=views, g=generate] ", "Reports"),
                    Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg).fg(colors.fg)),
        )
        .column_spacing(1)
        .highlight_style(
            Style::default()
                .bg(colors.selected_bg)
                .fg(colors.selected_fg)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

        let mut table_state = TableState::default();
        table_state.select(Some(reports_state.selected_index.min(reports.len().saturating_sub(1))));

        f.render_stateful_widget(table, area, &mut table_state);
    }

    fn render_report_detail(
        &self,
        f: &mut Frame,
        area: Rect,
        reports_state: &mut ReportsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        if let Some(report) = reports_state.reports.get(reports_state.selected_index) {
            let text = Text::from(vec![
                Line::from(vec![Span::styled(
                    &report.title,
                    Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                )]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("Type: ", Style::default().fg(colors.accent)),
                    report_type_badge(report.report_type, colors),
                ]),
                Line::from(vec![
                    Span::styled("Status: ", Style::default().fg(colors.accent)),
                    status_badge(report.status, colors),
                ]),
                Line::from(vec![
                    Span::styled("Created: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        crate::utils::format_relative_time(report.created_at),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("Size: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        report
                            .size_bytes
                            .map(crate::utils::format_bytes)
                            .unwrap_or("—".to_string()),
                        Style::default().fg(colors.fg),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Press '3' to preview, '1' for list",
                    Style::default().fg(colors.muted),
                )]),
            ]);

            let paragraph = Paragraph::new(text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if focused {
                            colors.accent
                        } else {
                            colors.border
                        }))
                        .title(" Report Detail ")
                        .title_style(
                            Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                        )
                        .style(Style::default().bg(colors.panel_bg)),
                )
                .wrap(ratatui::widgets::Wrap { trim: true });

            f.render_widget(paragraph, area);
        } else {
            render_empty_state(
                f,
                area,
                colors,
                "No Report Selected",
                "Select a report from the list",
                Some("Press '1' for report list"),
            );
        }
    }

    fn render_preview(
        &self,
        f: &mut Frame,
        area: Rect,
        reports_state: &mut ReportsState,
        colors: &ThemeColors,
        focused: bool,
    ) {
        if let Some(report) = reports_state.reports.get(reports_state.selected_index) {
            let text = Text::from(vec![
                Line::from(vec![
                    Span::styled("Preview: ", Style::default().fg(colors.accent)),
                    Span::styled(
                        &report.title,
                        Style::default().fg(colors.fg).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Report preview not yet implemented",
                    Style::default().fg(colors.muted),
                )]),
                Line::from(vec![Span::styled(
                    report.file_path.as_deref().unwrap_or("No file path"),
                    Style::default().fg(colors.info),
                )]),
            ]);

            let paragraph = Paragraph::new(text)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(if focused {
                            colors.accent
                        } else {
                            colors.border
                        }))
                        .title(" Report Preview ")
                        .title_style(
                            Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                        )
                        .style(Style::default().bg(colors.panel_bg)),
                )
                .wrap(ratatui::widgets::Wrap { trim: true });

            f.render_widget(paragraph, area);
        } else {
            render_empty_state(
                f,
                area,
                colors,
                "No Report Selected",
                "Select a report from the list",
                Some("Press '1' for report list"),
            );
        }
    }

    fn render_settings(
        &self,
        f: &mut Frame,
        area: Rect,
        _reports_state: &mut ReportsState,
        colors: &ThemeColors,
        _focused: bool,
    ) {
        render_empty_state(
            f,
            area,
            colors,
            "⚙️ Report Settings",
            "Configure report generation",
            Some("Not yet implemented"),
        );
    }
}

/// Get all panels
pub fn get_all_panels() -> Vec<Box<dyn Panel>> {
    vec![
        Box::new(ProjectsPanel),
        Box::new(JobsPanel),
        Box::new(ScansPanel),
        Box::new(ReverseEngineeringPanel),
        Box::new(FindingsPanel),
        Box::new(WorkflowsPanel),
        Box::new(AIPanel),
        Box::new(PluginsPanel),
        Box::new(LogsPanel),
        Box::new(ReportsPanel),
    ]
}
