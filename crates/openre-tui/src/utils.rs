//! Utility functions for the TUI

use crate::state::{Theme, ThemeColors};
use ratatui::style::Color;

/// Get theme colors for a given theme
pub fn get_theme_colors(theme: Theme) -> ThemeColors {
    theme.colors()
}

/// Format a duration in milliseconds as human readable
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else if ms < 3_600_000 {
        format!("{:.1}m", ms as f64 / 60_000.0)
    } else {
        format!("{:.1}h", ms as f64 / 3_600_000.0)
    }
}

/// Format bytes as human readable
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;

    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.1} {}", size, UNITS[unit])
    }
}

/// Format timestamp as relative time
pub fn format_relative_time(timestamp: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let diff = now.signed_duration_since(timestamp);

    if diff.num_seconds() < 60 {
        "just now".to_string()
    } else if diff.num_minutes() < 60 {
        format!("{}m ago", diff.num_minutes())
    } else if diff.num_hours() < 24 {
        format!("{}h ago", diff.num_hours())
    } else if diff.num_days() < 7 {
        format!("{}d ago", diff.num_days())
    } else {
        timestamp.format("%Y-%m-%d").to_string()
    }
}

/// Truncate string to fit width
pub fn truncate(s: &str, max_width: usize) -> String {
    if s.len() <= max_width {
        s.to_string()
    } else if max_width > 3 {
        format!("{}...", &s[..max_width - 3])
    } else {
        "...".to_string()
    }
}

/// Get color for severity
pub fn severity_color(severity: &openre_core::result::Severity, colors: &ThemeColors) -> Color {
    match severity {
        openre_core::result::Severity::Critical => colors.critical,
        openre_core::result::Severity::High => colors.high,
        openre_core::result::Severity::Medium => colors.medium,
        openre_core::result::Severity::Low => colors.low,
        openre_core::result::Severity::Info => colors.info,
    }
}

/// Get icon for severity
pub fn severity_icon(severity: &openre_core::result::Severity) -> &'static str {
    match severity {
        openre_core::result::Severity::Critical => "🔴",
        openre_core::result::Severity::High => "🟠",
        openre_core::result::Severity::Medium => "🟡",
        openre_core::result::Severity::Low => "🟢",
        openre_core::result::Severity::Info => "🔵",
    }
}

/// Get color for job status
pub fn job_status_color(status: &crate::state::JobStatus, colors: &ThemeColors) -> Color {
    match status {
        crate::state::JobStatus::Pending => colors.muted,
        crate::state::JobStatus::Queued => colors.info,
        crate::state::JobStatus::Running => colors.accent,
        crate::state::JobStatus::Completed => colors.success,
        crate::state::JobStatus::Failed => colors.error,
        crate::state::JobStatus::Cancelled => colors.warning,
        crate::state::JobStatus::Scheduled => colors.info,
    }
}

/// Get icon for job status
pub fn job_status_icon(status: &crate::state::JobStatus) -> &'static str {
    match status {
        crate::state::JobStatus::Pending => "⏳",
        crate::state::JobStatus::Queued => "📋",
        crate::state::JobStatus::Running => "🔄",
        crate::state::JobStatus::Completed => "✅",
        crate::state::JobStatus::Failed => "❌",
        crate::state::JobStatus::Cancelled => "🚫",
        crate::state::JobStatus::Scheduled => "📅",
    }
}

/// Get color for priority
pub fn priority_color(priority: &openre_queue::Priority, colors: &ThemeColors) -> Color {
    match priority {
        openre_queue::Priority::High => colors.error,
        openre_queue::Priority::Default => colors.info,
        openre_queue::Priority::Low => colors.muted,
    }
}

/// Get icon for priority
pub fn priority_icon(priority: &openre_queue::Priority) -> &'static str {
    match priority {
        openre_queue::Priority::High => "●",
        openre_queue::Priority::Default => "○",
        openre_queue::Priority::Low => "○",
    }
}

/// Calculate progress bar segments
pub fn progress_segments(progress: f32, width: u16) -> (u16, u16) {
    let progress = progress.clamp(0.0, 1.0);
    let filled = ((progress * width as f32) as u16).min(width);
    let empty = width.saturating_sub(filled);
    (filled, empty)
}

/// Create a progress line
pub fn progress_line(
    progress: f32,
    width: u16,
    colors: &ThemeColors,
) -> ratatui::text::Line<'static> {
    let (filled, empty) = progress_segments(progress, width);
    ratatui::text::Line::from(vec![
        ratatui::text::Span::styled(
            "█".repeat(filled as usize),
            ratatui::style::Style::default().fg(colors.accent),
        ),
        ratatui::text::Span::styled(
            "░".repeat(empty as usize),
            ratatui::style::Style::default().fg(colors.muted),
        ),
        ratatui::text::Span::styled(
            format!(" {:.0}%", progress * 100.0),
            ratatui::style::Style::default()
                .fg(colors.fg)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ),
    ])
}

/// Parse key event to action
pub fn key_to_action(
    key: crossterm::event::KeyEvent,
    key_bindings: &crate::state::KeyBindings,
) -> Option<crate::actions::Action> {
    use crossterm::event::{KeyCode, KeyModifiers};

    let key_str = match (key.code, key.modifiers) {
        (KeyCode::Char(c), KeyModifiers::CONTROL) => format!("Ctrl+{}", c),
        (KeyCode::Char(c), KeyModifiers::SHIFT) => format!("Shift+{}", c.to_ascii_uppercase()),
        (KeyCode::Char(c), _) => c.to_string(),
        (KeyCode::Esc, _) => "Esc".to_string(),
        (KeyCode::Enter, _) => "Enter".to_string(),
        (KeyCode::Tab, KeyModifiers::SHIFT) => "Shift+Tab".to_string(),
        (KeyCode::Tab, _) => "Tab".to_string(),
        (KeyCode::BackTab, _) => "Shift+Tab".to_string(),
        (KeyCode::Up, _) => "Up".to_string(),
        (KeyCode::Down, _) => "Down".to_string(),
        (KeyCode::Left, _) => "Left".to_string(),
        (KeyCode::Right, _) => "Right".to_string(),
        (KeyCode::Home, _) => "Home".to_string(),
        (KeyCode::End, _) => "End".to_string(),
        (KeyCode::PageUp, _) => "PageUp".to_string(),
        (KeyCode::PageDown, _) => "PageDown".to_string(),
        (KeyCode::Delete, _) => "Delete".to_string(),
        (KeyCode::Insert, _) => "Insert".to_string(),
        (KeyCode::F(n), _) => format!("F{}", n),
        _ => return None,
    };

    // Check against key bindings
    if key_str == key_bindings.quit {
        Some(crate::actions::Action::Shutdown)
    } else if key_str == key_bindings.next_panel {
        Some(crate::actions::Action::NavigateNextPanel)
    } else if key_str == key_bindings.prev_panel {
        Some(crate::actions::Action::NavigatePrevPanel)
    } else if key_str == key_bindings.help {
        // Help is handled separately
        None
    } else if key_str == key_bindings.refresh {
        Some(crate::actions::Action::RequestRefresh)
    } else if key_str == key_bindings.theme_cycle {
        // Theme cycle handled separately
        None
    } else {
        None
    }
}

/// Spawn a blocking task
pub fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// Debounce function
pub fn debounce<T>(
    duration: std::time::Duration,
    mut f: impl FnMut(T) + Send + 'static,
) -> tokio::sync::mpsc::UnboundedSender<T>
where
    T: Send + 'static,
{
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut timer = tokio::time::interval(duration);
        let mut pending: Option<T> = None;

        loop {
            tokio::select! {
                Some(item) = rx.recv() => {
                    pending = Some(item);
                }
                _ = timer.tick() => {
                    if let Some(item) = pending.take() {
                        f(item);
                    }
                }
            }
        }
    });
    tx
}
