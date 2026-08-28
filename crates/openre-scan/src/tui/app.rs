//! TUI application for openre-scan

#[cfg(feature = "tui")]
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
#[cfg(feature = "tui")]
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap, Table, Row, Cell, Tabs, Clear, TableState},
    Frame, Terminal,
};
#[cfg(feature = "tui")]
use std::{io, sync::Arc, time::Duration};
#[cfg(feature = "tui")]
use tokio::sync::{mpsc, Mutex};
#[cfg(feature = "tui")]
use tokio::time::sleep;

#[cfg(feature = "tui")]
use crate::{Check, ScanProfile, OutputFormat, Finding, Severity};
#[cfg(feature = "tui")]
use url::Url;

#[cfg(feature = "tui")]
#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    NotStarted,
    Running {
        current: String,
        progress: usize,
        total: usize,
    },
    Completed,
    Error(String),
}

#[cfg(feature = "tui")]
enum ScanMsg {
    Progress(String, usize, usize),
    Done(TuiScanResult),
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone)]
pub struct TuiScanResult {
    pub target: String,
    pub profile: ScanProfile,
    pub findings: Vec<crate::Finding>,
    pub duration: Duration,
    pub checks_run: usize,
    pub status: ScanStatus,
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Theme {
    Dark,
    Light,
    HighContrast,
}

impl Theme {
    pub fn colors(&self) -> ThemeColors {
        match self {
            Theme::Dark => ThemeColors {
                bg: Color::Rgb(30, 30, 30),
                fg: Color::Rgb(220, 220, 220),
                accent: Color::Cyan,
                accent_bold: Color::Rgb(0, 200, 200),
                border: Color::Rgb(80, 80, 80),
                selected_bg: Color::Rgb(60, 60, 60),
                selected_fg: Color::Yellow,
                success: Color::Green,
                warning: Color::Yellow,
                error: Color::Red,
                info: Color::Blue,
                muted: Color::Rgb(120, 120, 120),
                critical: Color::Rgb(255, 50, 50),
                high: Color::Rgb(255, 140, 0),
                medium: Color::Rgb(255, 215, 0),
                low: Color::Rgb(50, 200, 50),
            },
            Theme::Light => ThemeColors {
                bg: Color::Rgb(240, 240, 240),
                fg: Color::Rgb(40, 40, 40),
                accent: Color::Rgb(0, 100, 100),
                accent_bold: Color::Rgb(0, 80, 80),
                border: Color::Rgb(180, 180, 180),
                selected_bg: Color::Rgb(200, 200, 200),
                selected_fg: Color::Rgb(0, 80, 80),
                success: Color::Rgb(0, 150, 0),
                warning: Color::Rgb(200, 150, 0),
                error: Color::Rgb(200, 0, 0),
                info: Color::Rgb(0, 0, 200),
                muted: Color::Rgb(120, 120, 120),
                critical: Color::Rgb(200, 0, 0),
                high: Color::Rgb(200, 100, 0),
                medium: Color::Rgb(200, 150, 0),
                low: Color::Rgb(0, 150, 0),
            },
            Theme::HighContrast => ThemeColors {
                bg: Color::Black,
                fg: Color::White,
                accent: Color::Yellow,
                accent_bold: Color::Yellow,
                border: Color::White,
                selected_bg: Color::Yellow,
                selected_fg: Color::Black,
                success: Color::Green,
                warning: Color::Yellow,
                error: Color::Red,
                info: Color::Cyan,
                muted: Color::Gray,
                critical: Color::Red,
                high: Color::Red,
                medium: Color::Yellow,
                low: Color::Green,
            },
        }
    }
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone)]
pub struct ThemeColors {
    pub bg: Color,
    pub fg: Color,
    pub accent: Color,
    pub accent_bold: Color,
    pub border: Color,
    pub selected_bg: Color,
    pub selected_fg: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub muted: Color,
    pub critical: Color,
    pub high: Color,
    pub medium: Color,
    pub low: Color,
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Target = 0,
    Scans = 1,
    Findings = 2,
    Settings = 3,
    Help = 4,
}

impl Tab {
    pub const ALL: [Tab; 5] = [Tab::Target, Tab::Scans, Tab::Findings, Tab::Settings, Tab::Help];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Target => "Target",
            Tab::Scans => "Scans",
            Tab::Findings => "Findings",
            Tab::Settings => "Settings",
            Tab::Help => "Help",
        }
    }

    pub fn next(&self) -> Tab {
        match self {
            Tab::Target => Tab::Scans,
            Tab::Scans => Tab::Findings,
            Tab::Findings => Tab::Settings,
            Tab::Settings => Tab::Help,
            Tab::Help => Tab::Target,
        }
    }

    pub fn prev(&self) -> Tab {
        match self {
            Tab::Target => Tab::Help,
            Tab::Scans => Tab::Target,
            Tab::Findings => Tab::Scans,
            Tab::Settings => Tab::Findings,
            Tab::Help => Tab::Settings,
        }
    }
}

#[cfg(feature = "tui")]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterMode {
    None,
    BySeverity,
    ByCategory,
    ByCheck,
}

#[cfg(feature = "tui")]
pub struct App {
    pub target_input: String,
    pub profile: ScanProfile,
    pub output_format: OutputFormat,
    pub scan_results: Option<TuiScanResult>,
    pub status: ScanStatus,
    pub show_help: bool,
    pub selected_tab: Tab,
    pub list_state: ListState,
    pub findings_table_state: TableState,
    pub scroll_offset: usize,
    pub theme: Theme,
    pub filter_mode: FilterMode,
    pub severity_filter: Option<Severity>,
    pub search_query: String,
    pub show_search: bool,
    pub show_detail: bool,
    pub selected_finding_idx: usize,
    pub last_scan_time: Option<chrono::DateTime<chrono::Utc>>,
    pub scan_history: Vec<TuiScanResult>,
}

#[cfg(feature = "tui")]
impl Default for App {
    fn default() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        let mut findings_table_state = TableState::default();
        findings_table_state.select(Some(0));

        Self {
            target_input: String::new(),
            profile: ScanProfile::Standard,
            output_format: OutputFormat::Table,
            scan_results: None,
            status: ScanStatus::NotStarted,
            show_help: false,
            selected_tab: Tab::Target,
            list_state,
            findings_table_state,
            scroll_offset: 0,
            theme: Theme::Dark,
            filter_mode: FilterMode::None,
            severity_filter: None,
            search_query: String::new(),
            show_search: false,
            show_detail: false,
            selected_finding_idx: 0,
            last_scan_time: None,
            scan_history: Vec::new(),
        }
    }
}

#[cfg(feature = "tui")]
impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = self.selected_tab.next();
        self.list_state.select(Some(0));
    }

    pub fn previous_tab(&mut self) {
        self.selected_tab = self.selected_tab.prev();
        self.list_state.select(Some(0));
    }

    pub fn next_item(&mut self) {
        let len = self.get_current_list_len();
        if len > 0 {
            if self.selected_tab == Tab::Findings {
                let i = self.get_table_state().selected().unwrap_or(0);
                self.get_table_state().select(Some((i + 1) % len));
            } else {
                let i = self.get_list_state().selected().unwrap_or(0);
                self.get_list_state().select(Some((i + 1) % len));
            }
        }
    }

    pub fn previous_item(&mut self) {
        let len = self.get_current_list_len();
        if len > 0 {
            if self.selected_tab == Tab::Findings {
                let i = self.get_table_state().selected().unwrap_or(0);
                self.get_table_state().select(Some(if i == 0 { len - 1 } else { i - 1 }));
            } else {
                let i = self.get_list_state().selected().unwrap_or(0);
                self.get_list_state().select(Some(if i == 0 { len - 1 } else { i - 1 }));
            }
        }
    }

    pub fn goto_top(&mut self) {
        let len = self.get_current_list_len();
        if len > 0 {
            if self.selected_tab == Tab::Findings {
                self.get_table_state().select(Some(0));
            } else {
                self.get_list_state().select(Some(0));
            }
        }
    }

    pub fn goto_bottom(&mut self) {
        let len = self.get_current_list_len();
        if len > 0 {
            if self.selected_tab == Tab::Findings {
                self.get_table_state().select(Some(len - 1));
            } else {
                self.get_list_state().select(Some(len - 1));
            }
        }
    }

    fn get_current_list_len(&self) -> usize {
        match self.selected_tab {
            Tab::Target => 1,
            Tab::Scans => self.scan_history.len().max(1),
            Tab::Findings => self.get_filtered_findings().len().max(1),
            Tab::Settings => 8,
            Tab::Help => 1,
        }
    }

    fn get_list_state(&mut self) -> &mut ListState {
        &mut self.list_state
    }

    fn get_table_state(&mut self) -> &mut TableState {
        &mut self.findings_table_state
    }

    fn get_filtered_findings(&self) -> Vec<&crate::Finding> {
        if let Some(results) = &self.scan_results {
            let mut findings: Vec<&crate::Finding> = results.findings.iter().collect();

            // Apply severity filter
            if let Some(sev) = self.severity_filter {
                findings.retain(|f| f.severity == sev);
            }

            // Apply search query
            if !self.search_query.is_empty() {
                let query = self.search_query.to_lowercase();
                findings.retain(|f| {
                    f.title.to_lowercase().contains(&query)
                        || f.description.to_lowercase().contains(&query)
                        || f.plugin_source.to_lowercase().contains(&query)
                });
            }

            findings
        } else {
            Vec::new()
        }
    }

    pub async fn run_scan(&mut self) -> anyhow::Result<()> {
        if self.target_input.trim().is_empty() {
            self.status = ScanStatus::Error("Target cannot be empty".to_string());
            return Ok(());
        }

        let target = self.target_input.trim().to_string();
        let profile = self.profile.clone();
        let format = self.output_format.clone();

        self.status = ScanStatus::Running {
            current: "Initializing...".to_string(),
            progress: 0,
            total: 0,
        };

        // Create a channel for progress updates
        let (tx, mut rx) = mpsc::channel(32);
        let status = Arc::new(Mutex::new(self.status.clone()));

        let status_clone = status.clone();
        let tx_clone = tx.clone();

        let handle = tokio::spawn(async move {
            let tx_for_progress = tx_clone.clone();
            match run_scan_with_progress(target, profile, format, tx_for_progress).await {
                Ok(result) => {
                    let mut s = status_clone.lock().await;
                    *s = ScanStatus::Completed;
                    let _ = tx_clone.send(ScanMsg::Done(result)).await;
                }
                Err(e) => {
                    let mut s = status_clone.lock().await;
                    *s = ScanStatus::Error(e.to_string());
                }
            }
        });

        // Update UI with progress
        while let Some(msg) = rx.recv().await {
            match msg {
                ScanMsg::Progress(current, progress, total) => {
                    self.status = ScanStatus::Running {
                        current,
                        progress,
                        total,
                    };
                }
                ScanMsg::Done(result) => {
                    self.scan_results = Some(result.clone());
                    self.scan_history.push(result);
                    self.last_scan_time = Some(chrono::Utc::now());
                    self.status = ScanStatus::Completed;
                    // Switch to findings tab after scan
                    self.selected_tab = Tab::Findings;
                    self.findings_table_state.select(Some(0));
                    break;
                }
            }
        }

        handle.await?;
        Ok(())
    }
}

#[cfg(feature = "tui")]
async fn run_scan_with_progress(
    target: String,
    profile: ScanProfile,
    _format: OutputFormat,
    tx: mpsc::Sender<ScanMsg>,
) -> anyhow::Result<TuiScanResult> {
    let target_url = if target.starts_with("http://") || target.starts_with("https://") {
        target.parse::<Url>()?
    } else {
        format!("https://{}", target).parse::<Url>()?
    };

    let client = crate::build_client(10, 10, false, "openre-scan/0.1.0".to_string(), None)?;

    let all_checks = crate::get_all_checks(&profile);
    let checks_to_run: Vec<Check> = all_checks
        .into_iter()
        .filter(|c| c.name() != "sensitive-files") // Skip slow check by default
        .collect();

    let checks_count = checks_to_run.len();

    let start_time = std::time::Instant::now();
    let mut all_findings = Vec::new();

    for (i, check) in checks_to_run.iter().enumerate() {
        let _ = tx
            .send(ScanMsg::Progress(check.name().to_string(), i, checks_count))
            .await;

        match check.run(&client, &target_url).await {
            Ok(findings) => all_findings.extend(findings),
            Err(e) => eprintln!("Check {} failed: {}", check.name(), e),
        }
    }

    let duration = start_time.elapsed();

    Ok(TuiScanResult {
        target,
        profile,
        findings: all_findings,
        duration,
        checks_run: checks_count,
        status: ScanStatus::Completed,
    })
}

#[cfg(feature = "tui")]
pub async fn run_tui() -> anyhow::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_app(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

#[cfg(feature = "tui")]
async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> anyhow::Result<()> {
    let tick_rate = Duration::from_millis(50);
    let mut last_tick = std::time::Instant::now();

    loop {
        terminal.draw(|f| ui(f, app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if handle_key_event(key, app).await? {
                        break;
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }

    Ok(())
}

#[cfg(feature = "tui")]
async fn handle_key_event(key: crossterm::event::KeyEvent, app: &mut App) -> anyhow::Result<bool> {
    // Global keys
    match (key.code, key.modifiers) {
        (KeyCode::Char('q'), KeyModifiers::CONTROL) => return Ok(true), // Ctrl+Q to quit
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => return Ok(true), // Ctrl+C to quit
        (KeyCode::Esc, _) if app.show_help => {
            app.show_help = false;
            return Ok(false);
        }
        (KeyCode::Esc, _) if app.show_detail => {
            app.show_detail = false;
            return Ok(false);
        }
        (KeyCode::Esc, _) if app.show_search => {
            app.show_search = false;
            app.search_query.clear();
            return Ok(false);
        }
        _ => {}
    }

    // Search mode
    if app.show_search {
        match key.code {
            KeyCode::Char(c) => {
                app.search_query.push(c);
            }
            KeyCode::Backspace => {
                app.search_query.pop();
            }
            KeyCode::Enter => {
                app.show_search = false;
            }
            _ => {}
        }
        return Ok(false);
    }

    // Detail view
    if app.show_detail {
        match key.code {
            KeyCode::Char('e') => {
                // Export finding
                // TODO: Implement export
            }
            KeyCode::Char('c') => {
                // Copy finding details
                // TODO: Implement copy
            }
            _ => {}
        }
        return Ok(false);
    }

    // Normal navigation
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => {
            if matches!(app.status, ScanStatus::Running { .. }) {
                // Don't quit during scan
            } else {
                return Ok(true);
            }
        }
        KeyCode::Tab => app.next_tab(),
        KeyCode::BackTab => app.previous_tab(),
        KeyCode::Down | KeyCode::Char('j') => app.next_item(),
        KeyCode::Up | KeyCode::Char('k') => app.previous_item(),
        KeyCode::Char('g') => app.goto_top(),
        KeyCode::Char('G') => app.goto_bottom(),
        KeyCode::Enter => {
            match app.selected_tab {
                Tab::Target if app.status == ScanStatus::NotStarted => {
                    app.run_scan().await?;
                }
                Tab::Scans => {
                    // Load selected scan
                    if let Some(idx) = app.list_state.selected() {
                        if idx < app.scan_history.len() {
                            app.scan_results = Some(app.scan_history[idx].clone());
                            app.selected_tab = Tab::Findings;
                            app.findings_table_state.select(Some(0));
                        }
                    }
                }
                Tab::Findings => {
                    // Show detail for selected finding
                    if let Some(idx) = app.findings_table_state.selected() {
                        let findings = app.get_filtered_findings();
                        if idx < findings.len() {
                            app.selected_finding_idx = idx;
                            app.show_detail = true;
                        }
                    }
                }
                Tab::Settings => {
                    handle_settings_enter(app);
                }
                _ => {}
            }
        }
        KeyCode::Char(c) => {
            if app.selected_tab == Tab::Target && app.status == ScanStatus::NotStarted {
                app.target_input.push(c);
            } else if app.selected_tab == Tab::Findings {
                match c {
                    '/' => {
                        app.show_search = true;
                        app.search_query.clear();
                    }
                    's' => {
                        // Cycle severity filter
                        app.severity_filter = match app.severity_filter {
                            None => Some(Severity::Critical),
                            Some(Severity::Critical) => Some(Severity::High),
                            Some(Severity::High) => Some(Severity::Medium),
                            Some(Severity::Medium) => Some(Severity::Low),
                            Some(Severity::Low) => Some(Severity::Info),
                            Some(Severity::Info) => None,
                        };
                    }
                    'f' => {
                        // Toggle filter mode
                        app.filter_mode = match app.filter_mode {
                            FilterMode::None => FilterMode::BySeverity,
                            FilterMode::BySeverity => FilterMode::ByCategory,
                            FilterMode::ByCategory => FilterMode::ByCheck,
                            FilterMode::ByCheck => FilterMode::None,
                        };
                    }
                    'e' => {
                        // Export findings
                        // TODO: Implement export
                    }
                    'r' => {
                        // Rescan current target
                        app.status = ScanStatus::NotStarted;
                    }
                    _ => {}
                }
            } else if app.selected_tab == Tab::Settings {
                handle_settings_keys(app, c);
            }
        }
        KeyCode::Backspace => {
            if app.selected_tab == Tab::Target && app.status == ScanStatus::NotStarted {
                app.target_input.pop();
            }
        }
        KeyCode::F(1) => app.show_help = !app.show_help,
        KeyCode::F(2) => {
            // Cycle theme
            app.theme = match app.theme {
                Theme::Dark => Theme::Light,
                Theme::Light => Theme::HighContrast,
                Theme::HighContrast => Theme::Dark,
            };
        }
        _ => {}
    }

    Ok(false)
}

#[cfg(feature = "tui")]
fn handle_settings_keys(app: &mut App, key: char) {
    match key {
        '1' => app.profile = ScanProfile::Quick,
        '2' => app.profile = ScanProfile::Standard,
        '3' => app.profile = ScanProfile::Full,
        '4' => app.output_format = OutputFormat::Table,
        '5' => app.output_format = OutputFormat::Json,
        '6' => app.output_format = OutputFormat::Sarif,
        't' => {
            app.theme = match app.theme {
                Theme::Dark => Theme::Light,
                Theme::Light => Theme::HighContrast,
                Theme::HighContrast => Theme::Dark,
            };
        }
        _ => {}
    }
}

#[cfg(feature = "tui")]
fn handle_settings_enter(_app: &mut App) {
    // Settings are changed via number keys
}

#[cfg(feature = "tui")]
fn ui(f: &mut Frame, app: &mut App) {
    let colors = app.theme.colors();
    let size = f.size();

    // Main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),   // Banner area
            Constraint::Length(3),   // Tabs
            Constraint::Min(10),     // Main content
            Constraint::Length(3),   // Status bar
        ])
        .split(size);

    // Render banner
    render_banner(f, app, chunks[0], &colors);

    // Render tabs
    render_tabs(f, app, chunks[1], &colors);

    // Render main content based on selected tab
    match app.selected_tab {
        Tab::Target => render_target_tab(f, app, chunks[2], &colors),
        Tab::Scans => render_scans_tab(f, app, chunks[2], &colors),
        Tab::Findings => render_findings_tab(f, app, chunks[2], &colors),
        Tab::Settings => render_settings_tab(f, app, chunks[2], &colors),
        Tab::Help => render_help_tab(f, app, chunks[2], &colors),
    }

    // Render status bar
    render_status_bar(f, app, chunks[3], &colors);

    // Render overlays
    if app.show_help {
        render_help_overlay(f, app, &colors);
    }

    if app.show_search {
        render_search_overlay(f, app, &colors);
    }

    if app.show_detail {
        render_detail_overlay(f, app, &colors);
    }
}

#[cfg(feature = "tui")]
fn render_banner(f: &mut Frame, _app: &App, area: Rect, colors: &ThemeColors) {
    let banner_text = if area.width >= 100 {
        vec![
            Line::from(vec![
                Span::styled(" ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗", Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled(" ╚═════╝ ╚══╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled("███████╗██████╗ ██████╗  ██████╗ ███████╗███████╗", Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("█████╗  ██████╔╝██████╔╝██║   ██║███████╗█████╗", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║╚════██║██╔══╝", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("███████╗██║  ██║██║     ╚██████╔╝███████╗███████╗", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
            ]),
        ]
    };

    let banner = Paragraph::new(banner_text)
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(colors.border)));

    f.render_widget(banner, area);
}

#[cfg(feature = "tui")]
fn render_tabs(f: &mut Frame, app: &App, area: Rect, colors: &ThemeColors) {
    let tabs: Vec<Line> = Tab::ALL.iter().map(|tab| {
        let style = if *tab == app.selected_tab {
            Style::default().fg(colors.selected_fg).bg(colors.selected_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(colors.fg)
        };
        Line::from(Span::styled(format!(" {} ", tab.label()), style))
    }).collect();

    let tabs_widget = Tabs::new(tabs)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(colors.border)))
        .style(Style::default().fg(colors.fg))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .select(app.selected_tab as usize);

    f.render_widget(tabs_widget, area);
}

#[cfg(feature = "tui")]
fn render_target_tab(f: &mut Frame, app: &App, area: Rect, colors: &ThemeColors) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(area);

    // Target input
    let input = Paragraph::new(app.target_input.as_str())
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.selected_tab == Tab::Target { colors.accent } else { colors.border }))
            .title(" Target URL ")
            .title_style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)));
    f.render_widget(input, chunks[0]);

    // Profile selector
    let profile_text = match app.profile {
        ScanProfile::Quick => "Quick (6 checks) - Essential checks only, ~2-3s",
        ScanProfile::Standard => "Standard (15 checks) - Balanced scan, ~10-15s",
        ScanProfile::Full => "Full (18 checks) - Comprehensive audit, ~30-60s",
    };
    let profile = Paragraph::new(profile_text)
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Scan Profile ")
            .title_style(Style::default().fg(colors.accent)));
    f.render_widget(profile, chunks[1]);

    // Output format
    let format_text = match app.output_format {
        OutputFormat::Table => "Table - Human-readable colorized output",
        OutputFormat::Json => "JSON - Machine-readable structured output",
        OutputFormat::Sarif => "SARIF - CI/CD integration format",
    };
    let format = Paragraph::new(format_text)
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Output Format ")
            .title_style(Style::default().fg(colors.accent)));
    f.render_widget(format, chunks[2]);

    // Quick actions
    let actions = Paragraph::new("Press [Enter] to start scan  |  [Tab] to switch tabs  |  [1-3] for profile  |  [4-6] for format  |  [F1] Help")
        .style(Style::default().fg(colors.muted))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Actions ")
            .title_style(Style::default().fg(colors.accent)));
    f.render_widget(actions, chunks[3]);

    // Status
    let status_text = match &app.status {
        ScanStatus::NotStarted => "Ready - Enter target and press Enter to scan".to_string(),
        ScanStatus::Running { current, progress, total } => {
            format!("Scanning: {} ({}/{})", current, progress, total)
        }
        ScanStatus::Completed => "Scan completed! Press Tab to view findings.".to_string(),
        ScanStatus::Error(e) => format!("Error: {}", e),
    };
    let status = Paragraph::new(status_text)
        .style(Style::default().fg(if matches!(app.status, ScanStatus::Error(_)) { colors.error } else { colors.success }))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Status ")
            .title_style(Style::default().fg(colors.accent)));
    f.render_widget(status, chunks[4]);
}

#[cfg(feature = "tui")]
fn render_scans_tab(f: &mut Frame, app: &App, area: Rect, colors: &ThemeColors) {
    if app.scan_history.is_empty() {
        let empty = Paragraph::new("No scans yet. Go to Target tab and run a scan.")
            .style(Style::default().fg(colors.muted))
            .alignment(Alignment::Center)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.border))
                .title(" Scan History ")
                .title_style(Style::default().fg(colors.accent)));
        f.render_widget(empty, area);
        return;
    }

    let items: Vec<ListItem> = app.scan_history.iter().enumerate().map(|(i, scan)| {
        let selected = app.list_state.selected() == Some(i);
        let style = if selected {
            Style::default().fg(colors.selected_fg).bg(colors.selected_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(colors.fg)
        };

        let severity_counts = count_severities(&scan.findings);
        let severity_str = format!("🔴{} 🟠{} 🟡{} 🟢{} 🔵{}",
            severity_counts.get(&Severity::Critical).unwrap_or(&0),
            severity_counts.get(&Severity::High).unwrap_or(&0),
            severity_counts.get(&Severity::Medium).unwrap_or(&0),
            severity_counts.get(&Severity::Low).unwrap_or(&0),
            severity_counts.get(&Severity::Info).unwrap_or(&0),
        );

        let time_str = scan.duration.as_secs_f32();
        ListItem::new(Line::from(vec![
            Span::styled(format!("{:3}. ", i + 1), style),
            Span::styled(&scan.target, style),
            Span::styled(format!("  [{}] ", format!("{:?}", scan.profile)), Style::default().fg(colors.accent)),
            Span::styled(format!("{:.1}s ", time_str), Style::default().fg(colors.muted)),
            Span::styled(severity_str, style),
        ]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Scan History (Enter to load, j/k to navigate) ")
            .title_style(Style::default().fg(colors.accent)))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_stateful_widget(list, area, &mut app.list_state.clone());
}

#[cfg(feature = "tui")]
fn render_findings_tab(f: &mut Frame, app: &mut App, area: Rect, colors: &ThemeColors) {
    let findings = app.get_filtered_findings();

    if findings.is_empty() {
        let msg = if app.scan_results.is_none() {
            "No scan results. Run a scan from the Target tab."
        } else if app.severity_filter.is_some() || !app.search_query.is_empty() {
            "No findings match current filters."
        } else {
            "No findings detected in the last scan."
        };

        let empty = Paragraph::new(msg)
            .style(Style::default().fg(colors.muted))
            .alignment(Alignment::Center)
            .block(Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.border))
                .title(" Findings ")
                .title_style(Style::default().fg(colors.accent)));
        f.render_widget(empty, area);
        return;
    }

    // Build table
    let header = Row::new(vec![
        Cell::from("Sev").style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        Cell::from("Title").style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        Cell::from("Check").style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        Cell::from("Conf").style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
    ]).style(Style::default().bg(colors.selected_bg));

    let rows: Vec<Row> = findings.iter().enumerate().map(|(i, finding)| {
        let selected = app.findings_table_state.selected() == Some(i);
        let base_style = if selected {
            Style::default().fg(colors.selected_fg).bg(colors.selected_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(colors.fg)
        };

        let (sev_icon, sev_color) = severity_style(&finding.severity, colors);
        let title = if finding.title.len() > 50 {
            format!("{}...", &finding.title[..47])
        } else {
            finding.title.clone()
        };

        Row::new(vec![
            Cell::from(sev_icon).style(Style::default().fg(sev_color)),
            Cell::from(title).style(base_style),
            Cell::from(finding.plugin_source.clone()).style(base_style),
            Cell::from(format!("{:?}", finding.confidence)).style(base_style),
        ]).style(base_style)
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(4),
        Constraint::Min(30),
        Constraint::Length(20),
        Constraint::Length(10),
    ])
        .header(header)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(format!(" Findings ({} total) [s=filter / =search e=export r=rescan] ", findings.len()))
            .title_style(Style::default().fg(colors.accent)))
        .column_spacing(1)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");

    f.render_stateful_widget(table, area, &mut app.findings_table_state);

    // Show filter status
    if app.severity_filter.is_some() || !app.search_query.is_empty() {
        let filter_info = format!(
            "Filters: Severity={} Search='{}'",
            app.severity_filter.map(|s| format!("{:?}", s)).unwrap_or("All".to_string()),
            app.search_query
        );
        let filter_area = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(1)])
            .split(area)[1];
        let filter_widget = Paragraph::new(filter_info)
            .style(Style::default().fg(colors.warning))
            .alignment(Alignment::Left);
        f.render_widget(filter_widget, filter_area);
    }
}

#[cfg(feature = "tui")]
fn render_settings_tab(f: &mut Frame, app: &App, area: Rect, colors: &ThemeColors) {
    let settings = vec![
        ("1", "Scan Profile", format!("{:?}", app.profile)),
        ("2", "", "Quick (6 checks)".to_string()),
        ("3", "", "Standard (15 checks)".to_string()),
        ("4", "", "Full (18 checks)".to_string()),
        ("5", "Output Format", format!("{:?}", app.output_format)),
        ("6", "", "Table / JSON / SARIF".to_string()),
        ("t", "Theme", format!("{:?}", app.theme)),
    ];

    let items: Vec<ListItem> = settings.iter().enumerate().map(|(i, (key, label, value))| {
        let selected = app.list_state.selected() == Some(i);
        let style = if selected {
            Style::default().fg(colors.selected_fg).bg(colors.selected_bg).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(colors.fg)
        };

        let key_span = Span::styled(format!(" [{}] ", key), Style::default().fg(colors.accent).add_modifier(Modifier::BOLD));
        let label_span = Span::styled(format!("{:<20}", label), style);
        let value_span = Span::styled(value, Style::default().fg(colors.muted));

        ListItem::new(Line::from(vec![key_span, label_span, value_span]))
    }).collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Settings (Press key to change, F2 to cycle theme) ")
            .title_style(Style::default().fg(colors.accent)))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    f.render_stateful_widget(list, area, &mut app.list_state.clone());
}

#[cfg(feature = "tui")]
fn render_help_tab(f: &mut Frame, _app: &App, area: Rect, colors: &ThemeColors) {
    let help_text = vec![
        Line::from(vec![Span::styled("openre-scan TUI Help", Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD))]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Navigation:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  Tab / Shift+Tab", Style::default().fg(colors.warning)), Span::raw(" - Switch tabs"),
        ]),
        Line::from(vec![
            Span::styled("  j / k / ↓ / ↑", Style::default().fg(colors.warning)), Span::raw(" - Navigate up/down"),
        ]),
        Line::from(vec![
            Span::styled("  g / G", Style::default().fg(colors.warning)), Span::raw(" - Go to top/bottom"),
        ]),
        Line::from(vec![
            Span::styled("  Enter", Style::default().fg(colors.warning)), Span::raw(" - Start scan / Select item / Show detail"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Findings Tab:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  /", Style::default().fg(colors.warning)), Span::raw(" - Search findings"),
        ]),
        Line::from(vec![
            Span::styled("  s", Style::default().fg(colors.warning)), Span::raw(" - Cycle severity filter"),
        ]),
        Line::from(vec![
            Span::styled("  f", Style::default().fg(colors.warning)), Span::raw(" - Toggle filter mode"),
        ]),
        Line::from(vec![
            Span::styled("  e", Style::default().fg(colors.warning)), Span::raw(" - Export findings (TODO)"),
        ]),
        Line::from(vec![
            Span::styled("  r", Style::default().fg(colors.warning)), Span::raw(" - Rescan current target"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Settings Tab:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  1/2/3", Style::default().fg(colors.warning)), Span::raw(" - Quick/Standard/Full profile"),
        ]),
        Line::from(vec![
            Span::styled("  4/5/6", Style::default().fg(colors.warning)), Span::raw(" - Table/JSON/SARIF format"),
        ]),
        Line::from(vec![
            Span::styled("  t", Style::default().fg(colors.warning)), Span::raw(" - Cycle theme (Dark/Light/HighContrast)"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Global:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  F1", Style::default().fg(colors.warning)), Span::raw(" - Toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("  F2", Style::default().fg(colors.warning)), Span::raw(" - Cycle theme"),
        ]),
        Line::from(vec![
            Span::styled("  Ctrl+Q / Ctrl+C / Esc", Style::default().fg(colors.warning)), Span::raw(" - Quit"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Scan Profiles:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("  Quick  - Essential checks only (~6)"),
        Line::from("  Standard - Common security checks (~15)"),
        Line::from("  Full - All available checks (~18)"),
    ];

    let help = Paragraph::new(Text::from(help_text))
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Help (F1 to close) ")
            .title_style(Style::default().fg(colors.accent)))
        .wrap(Wrap { trim: true });

    f.render_widget(help, area);
}

#[cfg(feature = "tui")]
fn render_status_bar(f: &mut Frame, app: &App, area: Rect, colors: &ThemeColors) {
    let status_text = match &app.status {
        ScanStatus::NotStarted => "Ready - Enter target and press Enter to scan".to_string(),
        ScanStatus::Running { current, progress, total } => {
            format!("Scanning: {} ({}/{})", current, progress, total)
        }
        ScanStatus::Completed => "Scan completed! Press Tab for Findings, F1 for Help".to_string(),
        ScanStatus::Error(e) => format!("Error: {}", e),
    };

    let theme_indicator = format!("Theme: {:?}", app.theme);
    let filter_indicator = if app.severity_filter.is_some() {
        format!(" | Filter: {:?}", app.severity_filter.unwrap())
    } else {
        String::new()
    };

    let full_status = format!("{} | {} {}", status_text, theme_indicator, filter_indicator);

    let status = Paragraph::new(full_status)
        .style(Style::default().fg(if matches!(app.status, ScanStatus::Error(_)) { colors.error } else { colors.success }))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .title(" Status ")
            .title_style(Style::default().fg(colors.accent)));
    f.render_widget(status, area);
}

#[cfg(feature = "tui")]
fn render_help_overlay(f: &mut Frame, _app: &App, colors: &ThemeColors) {
    let area = centered_rect(70, 80, f.size());
    f.render_widget(Clear, area);

    let help_text = vec![
        Line::from(vec![Span::styled("openre-scan TUI - Keyboard Shortcuts", Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD))]),
        Line::from(""),
        Line::from(vec![Span::styled("Navigation:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("  Tab / Shift+Tab", Style::default().fg(colors.warning)), Span::raw(" - Switch between tabs")]),
        Line::from(vec![Span::styled("  j / k / ↓ / ↑", Style::default().fg(colors.warning)), Span::raw(" - Navigate lists up/down")]),
        Line::from(vec![Span::styled("  g / G", Style::default().fg(colors.warning)), Span::raw(" - Go to top/bottom of list")]),
        Line::from(vec![Span::styled("  Enter", Style::default().fg(colors.warning)), Span::raw(" - Start scan / Select item / View detail")]),
        Line::from(""),
        Line::from(vec![Span::styled("Findings Tab:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("  /", Style::default().fg(colors.warning)), Span::raw(" - Search findings by title/description")]),
        Line::from(vec![Span::styled("  s", Style::default().fg(colors.warning)), Span::raw(" - Cycle severity filter (Critical → High → Medium → Low → Info → Off)")]),
        Line::from(vec![Span::styled("  f", Style::default().fg(colors.warning)), Span::raw(" - Toggle filter mode")]),
        Line::from(vec![Span::styled("  e", Style::default().fg(colors.warning)), Span::raw(" - Export findings (TODO)")]),
        Line::from(vec![Span::styled("  r", Style::default().fg(colors.warning)), Span::raw(" - Rescan current target")]),
        Line::from(""),
        Line::from(vec![Span::styled("Settings Tab:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("  1/2/3", Style::default().fg(colors.warning)), Span::raw(" - Quick/Standard/Full scan profile")]),
        Line::from(vec![Span::styled("  4/5/6", Style::default().fg(colors.warning)), Span::raw(" - Table/JSON/SARIF output format")]),
        Line::from(vec![Span::styled("  t", Style::default().fg(colors.warning)), Span::raw(" - Cycle theme")]),
        Line::from(""),
        Line::from(vec![Span::styled("Global:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))]),
        Line::from(vec![Span::styled("  F1", Style::default().fg(colors.warning)), Span::raw(" - Toggle this help")]),
        Line::from(vec![Span::styled("  F2", Style::default().fg(colors.warning)), Span::raw(" - Cycle theme (Dark/Light/HighContrast)")]),
        Line::from(vec![Span::styled("  Ctrl+Q / Ctrl+C", Style::default().fg(colors.warning)), Span::raw(" - Quit application")]),
        Line::from(vec![Span::styled("  Esc", Style::default().fg(colors.warning)), Span::raw(" - Close dialog/overlay")]),
    ];

    let help = Paragraph::new(Text::from(help_text))
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.accent))
            .title(" Help (F1/Esc to close) ")
            .title_style(Style::default().fg(colors.accent_bold)))
        .wrap(Wrap { trim: true });

    f.render_widget(help, area);
}

#[cfg(feature = "tui")]
fn render_search_overlay(f: &mut Frame, app: &App, colors: &ThemeColors) {
    let area = centered_rect(60, 20, f.size());
    f.render_widget(Clear, area);

    let search_text = format!("Search: {}{}", app.search_query, if app.search_query.len() % 2 == 0 { "█" } else { "" });

    let search = Paragraph::new(search_text)
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.accent))
            .title(" Search (Enter to confirm, Esc to cancel) ")
            .title_style(Style::default().fg(colors.accent_bold)));

    f.render_widget(search, area);
}

#[cfg(feature = "tui")]
fn render_detail_overlay(f: &mut Frame, app: &App, colors: &ThemeColors) {
    let findings = app.get_filtered_findings();
    if app.selected_finding_idx >= findings.len() {
        return;
    }

    let finding = findings[app.selected_finding_idx];
    let area = centered_rect(80, 70, f.size());
    f.render_widget(Clear, area);

    let (sev_icon, sev_color) = severity_style(&finding.severity, colors);

    let detail_text = vec![
        Line::from(vec![
            Span::styled(sev_icon, Style::default().fg(sev_color)),
            Span::raw(" "),
            Span::styled(&finding.title, Style::default().fg(colors.fg).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("Severity: ", Style::default().fg(colors.accent)),
            Span::styled(format!("{:?}", finding.severity), Style::default().fg(sev_color)),
            Span::raw("  "),
            Span::styled("Confidence: ", Style::default().fg(colors.accent)),
            Span::styled(format!("{:?}", finding.confidence), Style::default().fg(colors.fg)),
        ]),
        Line::from(vec![
            Span::styled("Category: ", Style::default().fg(colors.accent)),
            Span::styled(format!("{:?}", finding.category), Style::default().fg(colors.fg)),
            Span::raw("  "),
            Span::styled("Check: ", Style::default().fg(colors.accent)),
            Span::styled(&finding.plugin_source, Style::default().fg(colors.fg)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled("Description:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))]),
        Line::from(finding.description.clone()),
        Line::from(""),
        Line::from(vec![Span::styled("Evidence:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))]),
        Line::from(""),
    ];

    // Add evidence
    let mut detail_lines = detail_text;
    for evidence in &finding.evidence {
        detail_lines.push(Line::from(vec![
            Span::styled("  • ", Style::default().fg(colors.muted)),
            Span::styled(&evidence.description, Style::default().fg(colors.fg)),
        ]));
        if let Some(location) = &evidence.location {
            detail_lines.push(Line::from(vec![
                Span::styled("    Location: ", Style::default().fg(colors.muted)),
                Span::styled(location, Style::default().fg(colors.fg)),
            ]));
        }
    }

    detail_lines.push(Line::from(""));
    detail_lines.push(Line::from(vec![
        Span::styled("Remediation:", Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)),
    ]));

    if let Some(remediation) = &finding.remediation {
        detail_lines.push(Line::from(vec![
            Span::styled("  Summary: ", Style::default().fg(colors.muted)),
            Span::styled(&remediation.summary, Style::default().fg(colors.fg)),
        ]));
        for step in &remediation.steps {
            detail_lines.push(Line::from(vec![
                Span::styled("  - ", Style::default().fg(colors.muted)),
                Span::styled(step, Style::default().fg(colors.fg)),
            ]));
        }
        detail_lines.push(Line::from(vec![
            Span::styled(format!("  Effort: {:?}, Priority: {:?}", remediation.effort, remediation.priority), Style::default().fg(colors.muted)),
        ]));
    }

    detail_lines.push(Line::from(""));
    detail_lines.push(Line::from(vec![
        Span::styled("[e] Export  [c] Copy  [Esc] Close", Style::default().fg(colors.warning)),
    ]));

    let detail = Paragraph::new(Text::from(detail_lines))
        .style(Style::default().fg(colors.fg))
        .block(Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.accent))
            .title(" Finding Detail ")
            .title_style(Style::default().fg(colors.accent_bold)))
        .wrap(Wrap { trim: true });

    f.render_widget(detail, area);
}

#[cfg(feature = "tui")]
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(feature = "tui")]
fn count_severities(findings: &[crate::Finding]) -> std::collections::HashMap<Severity, usize> {
    let mut counts = std::collections::HashMap::new();
    for f in findings {
        *counts.entry(f.severity).or_insert(0) += 1;
    }
    counts
}

#[cfg(feature = "tui")]
fn severity_style(sev: &Severity, colors: &ThemeColors) -> (&'static str, Color) {
    match sev {
        Severity::Critical => ("🔴", colors.critical),
        Severity::High => ("🟠", colors.high),
        Severity::Medium => ("🟡", colors.medium),
        Severity::Low => ("🟢", colors.low),
        Severity::Info => ("🔵", colors.info),
    }
}