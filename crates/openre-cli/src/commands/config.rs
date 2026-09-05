//! Configuration management commands

use colored::Colorize;
use clap::{Args, Subcommand};
use openre_config::{Config, default_config_path};
use crate::{Context, CliError, print_output, OutputFormat};
use std::path::PathBuf;
use tabled::{Table, settings::Style};

#[derive(Subcommand, Debug)]
pub struct ConfigCommands {
    #[command(subcommand)]
    command: ConfigSubcommand,
}

#[derive(Subcommand, Debug)]
enum ConfigSubcommand {
    /// Show current configuration
    Show(ShowArgs),
    /// Set a configuration value
    Set(SetArgs),
    /// Get a configuration value
    Get(GetArgs),
    /// Reset configuration to defaults
    Reset(ResetArgs),
    /// Show config file path
    Path,
    /// Edit config in $EDITOR
    Edit,
    /// Initialize default config
    Init(InitArgs),
}

#[derive(Args, Debug)]
struct ShowArgs {
    /// Show only specific section
    #[arg(long)]
    section: Option<String>,

    /// Show as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
struct SetArgs {
    /// Key (dot notation: ai.provider, scan.timeout, etc.)
    key: String,

    /// Value
    value: String,
}

#[derive(Args, Debug)]
struct GetArgs {
    /// Key (dot notation)
    key: String,
}

#[derive(Args, Debug)]
struct ResetArgs {
    /// Specific section to reset (optional)
    #[arg(long)]
    section: Option<String>,

    /// Confirm without prompt
    #[arg(long)]
    yes: bool,
}


#[derive(Args, Debug)]
struct InitArgs {
    /// Overwrite existing config
    #[arg(long)]
    force: bool,
}

impl ConfigCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        let mut config = ctx.config.clone();

        match self.command {
            ConfigSubcommand::Show(args) => run_show(config, args).await,
            ConfigSubcommand::Set(args) => run_set(config, args).await,
            ConfigSubcommand::Get(args) => run_get(config, args).await,
            ConfigSubcommand::Reset(args) => run_reset(config, args).await,
            ConfigSubcommand::Path => run_path(config).await,
            ConfigSubcommand::Edit => run_edit(config).await,
            ConfigSubcommand::Init(args) => run_init(config, args).await,
        }
    }
}

async fn run_show(config: Config, args: ShowArgs) -> Result<(), CliError> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else if let Some(section) = args.section {
        print_section(&config, &section)?;
    } else {
        print_full_config(&config)?;
    }
    Ok(())
}

async fn run_set(mut config: Config, args: SetArgs) -> Result<(), CliError> {
    config.set(&args.key, &args.value)?;
    config.save()?;
    println!("{} Set {} = {}", "✓".green().bold(), args.key.bold(), args.value);
    Ok(())
}

async fn run_get(config: Config, args: GetArgs) -> Result<(), CliError> {
    if let Some(value) = config.get(&args.key) {
        println!("{}", value);
    } else {
        return Err(CliError::InvalidArgs(format!("Key '{}' not found", args.key)));
    }
    Ok(())
}

async fn run_reset(mut config: Config, args: ResetArgs) -> Result<(), CliError> {
    if !args.yes {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Reset configuration to defaults?")
            .default(false)
            .interact()?;
        if !confirm {
            println!("Cancelled");
            return Ok(());
        }
    }

    if let Some(section) = args.section {
        config.reset_section(&section);
        println!("{} Reset section: {}", "✓".green().bold(), section);
    } else {
        config.reset();
        println!("{} Configuration reset to defaults", "✓".green().bold());
    }
    config.save()?;
    Ok(())
}

async fn run_path(_config: Config) -> Result<(), CliError> {
    let path = openre_config::default_config_path();
    if path.exists() {
        println!("{}", path.display());
    } else {
        println!("{} No config file (using defaults)", "ℹ".blue());
    }
    Ok(())
}

async fn run_edit(_config: Config) -> Result<(), CliError> {
    let path = openre_config::default_config_path();
    if !path.exists() {
        return Err(CliError::Config("No config file exists. Run 'openre config init' first.".into()));
    }

    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = std::process::Command::new(&editor)
        .arg(&path)
        .status()?;

    if status.success() {
        println!("{} Config edited", "✓".green().bold());
    }
    Ok(())
}

async fn run_init(mut config: Config, args: InitArgs) -> Result<(), CliError> {
    let config_path = openre_config::default_config_path();
    if config_path.exists() && !args.force {
        let confirm = dialoguer::Confirm::new()
            .with_prompt("Config file exists. Overwrite?")
            .default(false)
            .interact()?;
        if !confirm {
            println!("Cancelled");
            return Ok(());
        }
    }

    config.reset();
    config.save()?;
    println!("{} Initialized default configuration", "✓".green().bold());
    println!("  Location: {}", config_path.display());
    Ok(())
}

fn print_full_config(config: &Config) -> Result<(), CliError> {
    println!("\n{}", "openre Configuration".bold().cyan());
    println!("{}", "═".repeat(50).dimmed());

    let sections = [
        ("ai", "AI Configuration"),
        ("scan", "Scan Configuration"),
        ("analysis", "Binary Analysis"),
        ("output", "Output Settings"),
        ("network", "Network Settings"),
    ];

    for (key, title) in sections {
        if let Some(section) = config.get_section(key) {
            println!("\n{} {}", "▸".bold(), title.bold());
            print_section(config, key)?;
        }
    }
    Ok(())
}

fn print_section(config: &Config, section: &str) -> Result<(), CliError> {
    if let Some(value) = config.get_section(section) {
        if let Some(obj) = value.as_object() {
            let mut table = Table::new(
                obj.iter().map(|(k, v)| ConfigRow {
                    key: k.clone(),
                    value: format_value(v),
                }).collect::<Vec<_>>()
            );
            table.with(Style::modern());
            println!("{}", table);
        }
    }
    Ok(())
}

fn format_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(a) => a.iter().map(format_value).collect::<Vec<_>>().join(", "),
        serde_json::Value::Object(_) => "{...}".to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

#[derive(tabled::Tabled)]
struct ConfigRow {
    #[tabled(rename = "KEY")]
    key: String,
    #[tabled(rename = "VALUE")]
    value: String,
}