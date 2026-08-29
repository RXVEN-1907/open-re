//! Output formatting for CLI

use crate::CliError;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use tabled::builder::Builder;
use tabled::settings::Style;

// crossterm for terminal width detection
use crossterm::terminal::size as crossterm_size;

// Check if stdout is a TTY (for animation)
pub fn is_stdout_tty() -> bool {
    atty::is(atty::Stream::Stdout)
}

// ASCII Art Banner from README (same as openre-scan)
const ASCII_BANNER: &str = r#"
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚══╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
"#;

const ASCII_BANNER_SMALL: &str = r#"
███████╗██████╗ ██████╗  ██████╗ ███████╗███████╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝
█████╗  ██████╔╝██████╔╝██║   ██║███████╗█████╗
██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║╚════██║██╔══╝
███████╗██║  ██║██║     ╚██████╔╝███████╗███████╗
╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝
"#;

/// Print the full ASCII art banner
pub fn print_banner() {
    println!("{}", ASCII_BANNER.bright_cyan().bold());
    println!("{}", "Open-source Reverse Engineering & Offensive Security Platform".bright_white());
    println!(
        "{}",
        "Modern security tools + LLMs for automated binary, web, API & app analysis".dimmed()
    );
    println!(
        "{}",
        "Discover vulnerabilities • Generate PoC exploits • Actionable remediation".dimmed()
    );
    println!();
}

/// Print a compact banner for smaller terminals
pub fn print_compact_banner() {
    println!("{}", ASCII_BANNER_SMALL.bright_cyan().bold());
    println!("{}", "open-re: Security Scanner & Reverse Engineering Platform".bright_white());
    println!();
}

/// Detect terminal width and print appropriate banner
pub fn print_smart_banner() {
    let width = terminal_width();
    if width >= 100 {
        print_banner();
    } else {
        print_compact_banner();
    }
}

/// Get terminal width (not cached - detect each time for accuracy)
fn terminal_width() -> usize {
    // Try crossterm first
    if let Ok((w, _)) = crossterm_size() {
        return w as usize;
    }
    // Fallback to env var
    std::env::var("COLUMNS").ok().and_then(|s| s.parse().ok()).unwrap_or(80)
}

/// Animated spinner for startup (matching openre-scan: ~1.6s)
/// Only runs when stdout is a TTY
pub async fn show_startup_animation() {
    // Don't show animation if stdout is not a TTY (piped/redirected)
    if !is_stdout_tty() {
        return;
    }

    let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let message = "Initializing openre...";

    for _ in 0..2 {
        for frame in frames {
            print!("\r{} {} ", frame.bright_cyan(), message.bright_white());
            if io::stdout().flush().is_err() {
                // If flush fails (e.g., broken pipe), stop animation cleanly
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
    }
    println!("\r{} {}", "✓".green(), "Ready!".green().bold());
    println!();
}

/// Print output in the specified format
pub fn print_output<T: Serialize>(value: &T, format: &OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Table => print_table(value),
        OutputFormat::Json => print_json(value),
        OutputFormat::JsonPretty => print_json_pretty(value),
        OutputFormat::Yaml => print_yaml(value),
        OutputFormat::Csv => print_csv(value),
    }
}

fn print_table<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_value(value)?;

    if let Some(array) = json.as_array() {
        if array.is_empty() {
            println!("(empty)");
            return Ok(());
        }

        // Collect union of keys across objects for the header
        let mut headers: Vec<String> = Vec::new();
        for item in array {
            if let Some(obj) = item.as_object() {
                for key in obj.keys() {
                    if !headers.iter().any(|h| h == key) {
                        headers.push(key.clone());
                    }
                }
            }
        }

        let mut builder = Builder::default();
        if !headers.is_empty() {
            builder.push_record(headers.clone());
        } else {
            builder.push_record(vec!["Value".to_string()]);
        }

        for item in array {
            if let Some(obj) = item.as_object() {
                let record: Vec<String> = headers
                    .iter()
                    .map(|h| obj.get(h).map(format_value).unwrap_or_default())
                    .collect();
                builder.push_record(record);
            } else {
                builder.push_record(vec![format_value(item)]);
            }
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);
    } else if let Some(object) = json.as_object() {
        // Single object - print as key-value table
        let mut builder = Builder::default();
        builder.push_record(vec!["Property".to_string(), "Value".to_string()]);
        for (key, val) in object {
            builder.push_record(vec![key.clone(), format_value(val)]);
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);
    } else {
        println!("{}", format_value(&json));
    }

    Ok(())
}

fn print_json<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_string(value)?;
    println!("{}", json);
    Ok(())
}

fn print_json_pretty<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{}", json);
    Ok(())
}

fn print_yaml<T: Serialize>(value: &T) -> Result<(), CliError> {
    let yaml = serde_yaml::to_string(value)?;
    println!("{}", yaml);
    Ok(())
}

fn print_csv<T: Serialize>(value: &T) -> Result<(), CliError> {
    let json = serde_json::to_value(value)?;

    if let Some(array) = json.as_array() {
        if array.is_empty() {
            return Ok(());
        }

        // Write CSV header
        if let Some(first) = array.first().and_then(|v| v.as_object()) {
            let headers: Vec<&str> = first.keys().map(|k| k.as_str()).collect();
            println!("{}", headers.join(","));

            // Write rows
            for item in array {
                if let Some(obj) = item.as_object() {
                    let row: Vec<String> = headers
                        .iter()
                        .map(|h| obj.get(*h).map(format_value).unwrap_or_default())
                        .collect();
                    println!("{}", row.join(","));
                }
            }
        }
    } else {
        return Err(CliError::InvalidInput(
            "CSV output requires an array".into(),
        ));
    }

    Ok(())
}

fn format_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "".to_string(),
        serde_json::Value::Array(arr) => {
            format!(
                "[{}]",
                arr.iter().map(format_value).collect::<Vec<_>>().join(", ")
            )
        }
        serde_json::Value::Object(obj) => {
            format!(
                "{{{}}}",
                obj.iter()
                    .map(|(k, v)| format!("{}: {}", k, format_value(v)))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// Output format enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Table,
    Json,
    #[serde(rename = "json-pretty")]
    JsonPretty,
    Yaml,
    Csv,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Table => write!(f, "table"),
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::JsonPretty => write!(f, "json-pretty"),
            OutputFormat::Yaml => write!(f, "yaml"),
            OutputFormat::Csv => write!(f, "csv"),
        }
    }
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "table" => Ok(OutputFormat::Table),
            "json" => Ok(OutputFormat::Json),
            "json-pretty" | "jsonpretty" => Ok(OutputFormat::JsonPretty),
            "yaml" => Ok(OutputFormat::Yaml),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}
