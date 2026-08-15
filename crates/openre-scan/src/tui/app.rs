//! TUI application for openre-scan

#[cfg(feature = "tui")]
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
#[cfg(feature = "tui")]
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
#[cfg(feature = "tui")]
use std::{
    io,
    sync::Arc,
    time::Duration,
};
#[cfg(feature = "tui")]
use tokio::sync::{mpsc, Mutex};

#[cfg(feature = "tui")]
use crate::{run_scan_internal, Check, ScanProfile};
#[cfg(feature = "tui")]
use url::Url;

#[cfg(feature = "tui")]
#[derive(Debug, Clone, PartialEq)]
pub enum ScanStatus {
    NotStarted,
    Running { current: String, progress: usize, total: usize },
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
pub struct App {
    pub target_input: String,
    pub profile: ScanProfile,
    pub output_format: crate::OutputFormat,
    pub scan_results: Option<TuiScanResult>,
    pub status: ScanStatus,
    pub show_help: bool,
    pub selected_tab: usize,
    pub list_state: ListState,
    pub scroll_offset: usize,
}

#[cfg(feature = "tui")]
impl Default for App {
    fn default() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));
        Self {
            target_input: String::new(),
            profile: ScanProfile::Standard,
            output_format: crate::OutputFormat::Table,
            scan_results: None,
            status: ScanStatus::NotStarted,
            show_help: false,
            selected_tab: 0,
            list_state,
            scroll_offset: 0,
        }
    }
}

#[cfg(feature = "tui")]
impl App {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn next_tab(&mut self) {
        self.selected_tab = (self.selected_tab + 1) % 3;
    }

    pub fn previous_tab(&mut self) {
        self.selected_tab = if self.selected_tab == 0 { 2 } else { self.selected_tab - 1 };
    }

    pub fn next_item(&mut self) {
        let len = self.get_current_list_len();
        if len > 0 {
            let i = self.list_state.selected().unwrap_or(0);
            self.list_state.select(Some((i + 1) % len));
        }
    }

    pub fn previous_item(&mut self) {
        let len = self.get_current_list_len();
        if len > 0 {
            let i = self.list_state.selected().unwrap_or(0);
            self.list_state.select(Some(if i == 0 { len - 1 } else { i - 1 }));
        }
    }

    fn get_current_list_len(&self) -> usize {
        match self.selected_tab {
            0 => 1, // Target input
            1 => 3, // Profiles
            2 => 4, // Output formats
            _ => 0,
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
                    self.scan_results = Some(result);
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
    _format: crate::OutputFormat,
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
        .filter(|c| c.name().to_string() != "sensitive-files") // Skip slow check by default
        .collect();

    let checks_count = checks_to_run.len();
    
    let start_time = std::time::Instant::now();
    let mut all_findings = Vec::new();

    for (i, check) in checks_to_run.iter().enumerate() {
        let _ = tx.send(ScanMsg::Progress(
            check.name().to_string(),
            i,
            checks_count,
        )).await;

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
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        if app.show_help {
                            app.show_help = false;
                        } else if matches!(app.status, ScanStatus::Running { .. }) {
                            // Don't quit during scan
                        } else {
                            return Ok(());
                        }
                    }
                    KeyCode::Tab => app.next_tab(),
                    KeyCode::BackTab => app.previous_tab(),
                    KeyCode::Down => app.next_item(),
                    KeyCode::Up => app.previous_item(),
                    KeyCode::Enter => {
                        if app.selected_tab == 0 && app.status == ScanStatus::NotStarted {
                            app.run_scan().await?;
                        }
                    }
                    KeyCode::Char(c) => {
                        if app.selected_tab == 0 && app.status == ScanStatus::NotStarted {
                            app.target_input.push(c);
                        }
                    }
                    KeyCode::Backspace => {
                        if app.selected_tab == 0 && app.status == ScanStatus::NotStarted {
                            app.target_input.pop();
                        }
                    }
                    KeyCode::F(1) => app.show_help = !app.show_help,
                    _ => {}
                }
            }
        }
    }
}

#[cfg(feature = "tui")]
fn ui(f: &mut ratatui::Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3), // Tabs
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(f.size());

    // Title
    let title = Paragraph::new("openre-scan - Lightweight Security Scanner")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    // Tabs
    let tabs = vec!["Target", "Profile", "Output"];
    let tab_items: Vec<ListItem> = tabs
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let style = if i == app.selected_tab {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(Line::from(Span::styled(*t, style)))
        })
        .collect();
    
    let tabs_widget = List::new(tab_items)
        .block(Block::default().borders(Borders::ALL).title("Tabs"))
        .style(Style::default())
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    f.render_widget(tabs_widget, chunks[1]);

    // Main content
    match app.selected_tab {
        0 => render_target_tab(f, app, chunks[2]),
        1 => render_profile_tab(f, app, chunks[2]),
        2 => render_output_tab(f, app, chunks[2]),
        _ => {}
    }

    // Status bar
    let status_text = match &app.status {
        ScanStatus::NotStarted => "Ready - Enter target and press Enter to scan".to_string(),
        ScanStatus::Running { current, progress, total } => {
            format!("Scanning: {} ({}/{})", current, progress, total)
        }
        ScanStatus::Completed => "Scan completed!".to_string(),
        ScanStatus::Error(e) => format!("Error: {}", e),
    };

    let status = Paragraph::new(status_text)
        .style(Style::default().fg(Color::Green))
        .block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, chunks[3]);

    if app.show_help {
        render_help(f);
    }
}

#[cfg(feature = "tui")]
fn render_target_tab(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
        ])
        .split(area);

    let input = Paragraph::new(app.target_input.as_str())
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Target URL"));
    f.render_widget(input, chunks[0]);

    let help = Paragraph::new(
        "Enter a target URL (e.g., https://example.com or example.com)\nPress Enter to start scan | Tab to switch tabs | F1 for help"
    )
    .style(Style::default().fg(Color::Gray))
    .wrap(Wrap { trim: true })
    .block(Block::default().borders(Borders::ALL).title("Help"));
    f.render_widget(help, chunks[1]);
}

#[cfg(feature = "tui")]
fn render_profile_tab(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let profiles = vec![
        ("Quick", "Fast scan with essential checks (~6 checks)"),
        ("Standard", "Balanced scan with common security checks (~15 checks)"),
        ("Full", "Comprehensive scan with all available checks (~18 checks)"),
    ];

    let items: Vec<ListItem> = profiles
        .iter()
        .enumerate()
        .map(|(i, (name, desc))| {
            let selected = matches!(app.profile, crate::ScanProfile::Quick) && i == 0
                || matches!(app.profile, crate::ScanProfile::Standard) && i == 1
                || matches!(app.profile, crate::ScanProfile::Full) && i == 2;
            
            let style = if selected {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            
            let prefix = if selected { "► " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(*name, style),
                Span::styled(format!(" - {}", desc), Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Scan Profile (Up/Down to select, Enter to confirm)"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_stateful_widget(list, area, &mut app.list_state.clone());
}

#[cfg(feature = "tui")]
fn render_output_tab(f: &mut ratatui::Frame, app: &App, area: Rect) {
    let formats = vec![
        ("Table", "Human-readable table output"),
        ("JSON", "Machine-readable JSON output"),
        ("SARIF", "Static Analysis Results Interchange Format"),
    ];

    let items: Vec<ListItem> = formats
        .iter()
        .enumerate()
        .map(|(i, (name, desc))| {
            let selected = matches!(app.output_format, crate::OutputFormat::Table) && i == 0
                || matches!(app.output_format, crate::OutputFormat::Json) && i == 1
                || matches!(app.output_format, crate::OutputFormat::Sarif) && i == 2;
            
            let style = if selected {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            
            let prefix = if selected { "► " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(*name, style),
                Span::styled(format!(" - {}", desc), Style::default().fg(Color::Gray)),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Output Format (Up/Down to select, Enter to confirm)"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_stateful_widget(list, area, &mut app.list_state.clone());
}

#[cfg(feature = "tui")]
fn render_help(f: &mut ratatui::Frame) {
    let help_text = vec![
        Line::from("openre-scan TUI Help"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" - Switch between tabs"),
        ]),
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(" - Start scan (Target tab) / Select option (Profile/Output tabs)"),
        ]),
        Line::from(vec![
            Span::styled("Up/Down", Style::default().fg(Color::Yellow)),
            Span::raw(" - Navigate lists"),
        ]),
        Line::from(vec![
            Span::styled("F1", Style::default().fg(Color::Yellow)),
            Span::raw(" - Toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("Esc/q", Style::default().fg(Color::Yellow)),
            Span::raw(" - Quit / Close help"),
        ]),
        Line::from(""),
        Line::from("Scan Profiles:"),
        Line::from("  Quick  - Essential checks only (~6)"),
        Line::from("  Standard - Common security checks (~15)"),
        Line::from("  Full - All available checks (~18)"),
    ];

    let help = Paragraph::new(Text::from(help_text))
        .style(Style::default().fg(Color::White))
        .block(Block::default().borders(Borders::ALL).title("Help (F1 to close)"))
        .wrap(Wrap { trim: true });

    let area = centered_rect(60, 70, f.size());
    f.render_widget(help, area);
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