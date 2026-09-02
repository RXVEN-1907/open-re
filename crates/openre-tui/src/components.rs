//! Reusable UI components for the TUI

use crate::state::{JobStatus, LogLevel, ReportType, ScanStatus, ThemeColors};
use openre_core::result::Severity;
use openre_queue::Priority;
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

/// Render a styled block with title
pub fn render_block(
    f: &mut Frame,
    area: Rect,
    title: &str,
    content: impl ratatui::widgets::Widget,
    colors: &ThemeColors,
    focused: bool,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if focused { colors.accent } else { colors.border }))
        .title(Span::styled(
            format!(" {} ", title),
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Left)
        .style(Style::default().bg(colors.panel_bg).fg(colors.fg));

    let inner_area = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(content, inner_area);
}

/// Render a centered popup
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

/// Render a loading indicator
pub fn render_loading(f: &mut Frame, area: Rect, colors: &ThemeColors, message: &str) {
    let text = Text::from(vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            "⠋",
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(message, Style::default().fg(colors.muted))]),
    ])
    .alignment(Alignment::Center);

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .style(Style::default().bg(colors.panel_bg)),
    );
    f.render_widget(paragraph, area);
}

/// Render an empty state
pub fn render_empty_state(
    f: &mut Frame,
    area: Rect,
    colors: &ThemeColors,
    title: &str,
    message: &str,
    hint: Option<&str>,
) {
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            title,
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![Span::styled(message, Style::default().fg(colors.muted))]),
    ];

    if let Some(hint) = hint {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![Span::styled(hint, Style::default().fg(colors.info))]));
    }

    let text = Text::from(lines).alignment(Alignment::Center);
    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.border))
            .style(Style::default().bg(colors.panel_bg)),
    );
    f.render_widget(paragraph, area);
}

/// Render a status badge
pub fn status_badge(status: JobStatus, colors: &ThemeColors) -> Span<'static> {
    let (icon, color, text) = match status {
        JobStatus::Pending => ("⏳", colors.muted, "Pending"),
        JobStatus::Queued => ("📋", colors.info, "Queued"),
        JobStatus::Running => ("🔄", colors.accent, "Running"),
        JobStatus::Completed => ("✅", colors.success, "Completed"),
        JobStatus::Failed => ("❌", colors.error, "Failed"),
        JobStatus::Cancelled => ("🚫", colors.warning, "Cancelled"),
        JobStatus::Scheduled => ("📅", colors.info, "Scheduled"),
    };

    Span::styled(
        format!("{} {}", icon, text),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

/// Render a scan status badge
pub fn scan_status_badge(status: &ScanStatus, colors: &ThemeColors) -> Span<'static> {
    match status {
        ScanStatus::NotStarted => Span::styled(
            "⏳ Not Started",
            Style::default().fg(colors.muted).add_modifier(Modifier::BOLD),
        ),
        ScanStatus::Running { current_check, progress, total } => Span::styled(
            format!("🔄 {} ({}/{})", current_check, progress, total),
            Style::default().fg(colors.accent).add_modifier(Modifier::BOLD),
        ),
        ScanStatus::Completed => Span::styled(
            "✅ Completed",
            Style::default().fg(colors.success).add_modifier(Modifier::BOLD),
        ),
        ScanStatus::Failed(e) => Span::styled(
            format!("❌ Failed: {}", e),
            Style::default().fg(colors.error).add_modifier(Modifier::BOLD),
        ),
        ScanStatus::Cancelled => Span::styled(
            "🚫 Cancelled",
            Style::default().fg(colors.warning).add_modifier(Modifier::BOLD),
        ),
    }
}

/// Render a severity badge
pub fn severity_badge(severity: Severity, colors: &ThemeColors) -> Span<'static> {
    let (icon, color, text) = match severity {
        Severity::Critical => ("🔴", colors.critical, "CRITICAL"),
        Severity::High => ("🟠", colors.high, "HIGH"),
        Severity::Medium => ("🟡", colors.medium, "MEDIUM"),
        Severity::Low => ("🟢", colors.low, "LOW"),
        Severity::Info => ("🔵", colors.info, "INFO"),
    };

    Span::styled(
        format!("{} {}", icon, text),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

/// Render a priority badge
pub fn priority_badge(priority: Priority, colors: &ThemeColors) -> Span<'static> {
    let (text, color) = match priority {
        Priority::High => ("HIGH", colors.error),
        Priority::Default => ("NORMAL", colors.info),
        Priority::Low => ("LOW", colors.muted),
    };

    Span::styled(format!("● {}", text), Style::default().fg(color).add_modifier(Modifier::BOLD))
}

/// Render a log level badge
pub fn log_level_badge(level: LogLevel, colors: &ThemeColors) -> Span<'static> {
    let (text, color) = match level {
        LogLevel::Trace => ("TRACE", colors.muted),
        LogLevel::Debug => ("DEBUG", colors.info),
        LogLevel::Info => ("INFO", colors.success),
        LogLevel::Warn => ("WARN", colors.warning),
        LogLevel::Error => ("ERROR", colors.error),
    };

    Span::styled(format!("[{}]", text), Style::default().fg(color).add_modifier(Modifier::BOLD))
}

/// Render a report type badge
pub fn report_type_badge(report_type: ReportType, colors: &ThemeColors) -> Span<'static> {
    let (text, color) = match report_type {
        ReportType::SARIF => ("SARIF", colors.accent),
        ReportType::HTML => ("HTML", colors.info),
        ReportType::PDF => ("PDF", colors.warning),
        ReportType::JSON => ("JSON", colors.success),
        ReportType::Markdown => ("MD", colors.muted),
    };

    Span::styled(format!("[{}]", text), Style::default().fg(color).add_modifier(Modifier::BOLD))
}

/// Render a progress bar
pub fn render_progress_bar(
    f: &mut Frame,
    area: Rect,
    progress: f32,
    label: &str,
    colors: &ThemeColors,
) {
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.border))
                .style(Style::default().bg(colors.panel_bg)),
        )
        .gauge_style(Style::default().fg(colors.accent).bg(colors.selected_bg))
        .label(label)
        .ratio(progress.clamp(0.0, 1.0) as f64)
        .use_unicode(true);
    f.render_widget(gauge, area);
}

/// Render a horizontal progress bar in a line
pub fn progress_line(progress: f32, width: u16, colors: &ThemeColors) -> Line<'static> {
    let filled = ((progress.clamp(0.0, 1.0) * width as f32) as u16).min(width);
    let empty = width.saturating_sub(filled);

    Line::from(vec![
        Span::styled("█".repeat(filled as usize), Style::default().fg(colors.accent)),
        Span::styled("░".repeat(empty as usize), Style::default().fg(colors.muted)),
        Span::styled(
            format!(" {:.0}%", progress * 100.0),
            Style::default().fg(colors.fg).add_modifier(Modifier::BOLD),
        ),
    ])
}

/// Render a table with selection
pub fn render_table<'a>(
    f: &mut Frame,
    area: Rect,
    header: Row<'a>,
    rows: Vec<Row<'a>>,
    widths: &'a [Constraint],
    state: &mut TableState,
    colors: &ThemeColors,
    title: &str,
    focused: bool,
) {
    let table = Table::new(rows, widths)
        .header(header.style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD)))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if focused {
                    colors.accent
                } else {
                    colors.border
                }))
                .title(Span::styled(
                    format!(" {} ", title),
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

    f.render_stateful_widget(table, area, state);
}

/// Render a list with selection
pub fn render_list(
    f: &mut Frame,
    area: Rect,
    items: Vec<ListItem>,
    state: &mut ListState,
    colors: &ThemeColors,
    title: &str,
    focused: bool,
) {
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
                    format!(" {} ", title),
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

    f.render_stateful_widget(list, area, state);
}

/// Render a tab bar
pub fn render_tab_bar(
    f: &mut Frame,
    area: Rect,
    tabs: &[&str],
    selected: usize,
    colors: &ThemeColors,
) {
    let tab_lines: Vec<Line> = tabs
        .iter()
        .enumerate()
        .map(|(i, tab)| {
            let style = if i == selected {
                Style::default()
                    .fg(colors.selected_fg)
                    .bg(colors.selected_bg)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(colors.fg)
            };
            Line::from(Span::styled(format!(" {} ", tab), style))
        })
        .collect();

    let tabs_widget = Tabs::new(tab_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.border))
                .style(Style::default().bg(colors.panel_bg)),
        )
        .select(selected);

    f.render_widget(tabs_widget, area);
}

/// Render a help bar at the bottom
pub fn render_help_bar(
    f: &mut Frame,
    area: Rect,
    shortcuts: &[(&str, &str)],
    colors: &ThemeColors,
) {
    let help_text = shortcuts
        .iter()
        .map(|(key, desc)| {
            vec![
                Span::styled(
                    format!(" {} ", key),
                    Style::default()
                        .fg(colors.accent_bold)
                        .bg(colors.selected_bg)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {} ", desc), Style::default().fg(colors.muted)),
            ]
        })
        .flatten()
        .collect::<Vec<_>>();

    let paragraph = Paragraph::new(Line::from(help_text))
        .alignment(Alignment::Center)
        .style(Style::default().bg(colors.panel_bg));

    f.render_widget(paragraph, area);
}

/// Render a notification toast
pub fn render_notification(
    f: &mut Frame,
    area: Rect,
    notification: &crate::state::Notification,
    colors: &ThemeColors,
) {
    let (icon, color) = match notification.level {
        crate::state::NotificationLevel::Info => ("ℹ️", colors.info),
        crate::state::NotificationLevel::Success => ("✅", colors.success),
        crate::state::NotificationLevel::Warning => ("⚠️", colors.warning),
        crate::state::NotificationLevel::Error => ("❌", colors.error),
    };

    let text = Text::from(vec![
        Line::from(vec![
            Span::styled(icon, Style::default().fg(color)),
            Span::styled(
                format!(" {}", notification.title),
                Style::default().fg(colors.fg).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![Span::styled(&notification.message, Style::default().fg(colors.muted))]),
    ]);

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(color))
            .style(Style::default().bg(colors.panel_bg)),
    );

    f.render_widget(paragraph, area);
}

/// Render a search/input overlay
pub fn render_input_overlay(
    f: &mut Frame,
    area: Rect,
    prompt: &str,
    input: &str,
    colors: &ThemeColors,
    cursor_pos: usize,
) {
    let overlay_area = centered_rect(60, 15, area);
    f.render_widget(ratatui::widgets::Clear, overlay_area);

    let display_input = format!("{}█", &input[cursor_pos.min(input.len())..]);
    let text = Text::from(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(prompt, Style::default().fg(colors.accent)),
            Span::styled(display_input, Style::default().fg(colors.fg)),
        ]),
        Line::from(""),
        Line::from(vec![Span::styled(
            "Enter to confirm, Esc to cancel",
            Style::default().fg(colors.muted),
        )]),
    ]);

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.accent))
            .title(" Input ")
            .title_style(Style::default().fg(colors.accent_bold))
            .style(Style::default().bg(colors.panel_bg)),
    );

    f.render_widget(paragraph, overlay_area);
}

/// Render a confirmation dialog
pub fn render_confirmation_dialog(
    f: &mut Frame,
    area: Rect,
    title: &str,
    message: &str,
    colors: &ThemeColors,
    yes_text: &str,
    no_text: &str,
    selected_yes: bool,
) {
    let overlay_area = centered_rect(50, 25, area);
    f.render_widget(ratatui::widgets::Clear, overlay_area);

    let yes_style = if selected_yes {
        Style::default().fg(colors.selected_fg).bg(colors.selected_bg).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(colors.fg)
    };

    let no_style = if !selected_yes {
        Style::default().fg(colors.selected_fg).bg(colors.selected_bg).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(colors.fg)
    };

    let text = Text::from(vec![
        Line::from(""),
        Line::from(vec![Span::styled(message, Style::default().fg(colors.fg))]),
        Line::from(""),
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {}  ", yes_text), yes_style),
            Span::styled("    ", Style::default()),
            Span::styled(format!("  {}  ", no_text), no_style),
        ]),
    ])
    .alignment(Alignment::Center);

    let paragraph = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(colors.accent))
            .title(Span::styled(
                format!(" {} ", title),
                Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
            ))
            .style(Style::default().bg(colors.panel_bg)),
    );

    f.render_widget(paragraph, overlay_area);
}

/// Render a detail view overlay
pub fn render_detail_overlay(
    f: &mut Frame,
    area: Rect,
    title: &str,
    content: Text<'static>,
    colors: &ThemeColors,
    width_percent: u16,
    height_percent: u16,
) {
    let overlay_area = centered_rect(width_percent, height_percent, area);
    f.render_widget(ratatui::widgets::Clear, overlay_area);

    let paragraph = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(colors.accent))
                .title(Span::styled(
                    format!(" {} ", title),
                    Style::default().fg(colors.accent_bold).add_modifier(Modifier::BOLD),
                ))
                .style(Style::default().bg(colors.panel_bg)),
        )
        .wrap(ratatui::widgets::Wrap { trim: true });

    f.render_widget(paragraph, overlay_area);
}

/// Create a styled cell for table
pub fn cell(content: impl Into<String>, style: Style) -> ratatui::widgets::Cell<'static> {
    ratatui::widgets::Cell::from(content.into()).style(style)
}

/// Create a header cell
pub fn header_cell(
    content: impl Into<String>,
    colors: &ThemeColors,
) -> ratatui::widgets::Cell<'static> {
    ratatui::widgets::Cell::from(content.into())
        .style(Style::default().fg(colors.accent).add_modifier(Modifier::BOLD))
}
