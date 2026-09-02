//! Agent Management command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::AgentId;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct AgentCommand {
    #[command(subcommand)]
    action: AgentAction,
}

#[derive(Subcommand)]
pub enum AgentAction {
    /// List all agents
    List {
        /// Filter by agent type
        #[arg(short, long, value_enum)]
        r#type: Option<AgentTypeFilter>,

        /// Filter by status
        #[arg(short, long, value_enum)]
        status: Option<AgentStatusFilter>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "table")]
        output: AgentOutputFormat,
    },

    /// Start a new agent
    Start {
        /// Agent type to start
        #[arg(value_enum)]
        r#type: AgentType,

        /// Agent configuration (JSON file or inline)
        #[arg(short, long)]
        config: Option<String>,

        /// Agent name
        #[arg(short, long)]
        name: Option<String>,

        /// Run in background
        #[arg(long)]
        background: bool,
    },

    /// Stop an agent
    Stop {
        /// Agent ID to stop
        #[arg(value_name = "AGENT_ID")]
        agent_id: String,

        /// Force stop (SIGKILL)
        #[arg(long)]
        force: bool,
    },

    /// Get agent status
    Status {
        /// Agent ID
        #[arg(value_name = "AGENT_ID")]
        agent_id: String,

        /// Watch for status changes
        #[arg(long)]
        watch: bool,
    },

    /// Get agent logs
    Logs {
        /// Agent ID
        #[arg(value_name = "AGENT_ID")]
        agent_id: String,

        /// Number of lines to show
        #[arg(short, long, default_value = "100")]
        lines: usize,

        /// Follow logs (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Filter by log level
        #[arg(long, value_enum)]
        level: Option<LogLevelFilter>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AgentType {
    Recon,
    WebAnalysis,
    ApiAnalysis,
    Correlation,
    Verification,
    Remediation,
    Reporting,
    Research,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AgentTypeFilter {
    Recon,
    WebAnalysis,
    ApiAnalysis,
    Correlation,
    Verification,
    Remediation,
    Reporting,
    Research,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AgentStatusFilter {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Idle,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum LogLevelFilter {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AgentOutputFormat {
    Json,
    Table,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentListResponse {
    agents: Vec<AgentInfo>,
    total: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentInfo {
    id: AgentId,
    name: String,
    agent_type: String,
    status: String,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    config: serde_json::Value,
    metadata: AgentMetadata,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentMetadata {
    cpu_usage: Option<f32>,
    memory_usage: Option<u64>,
    tasks_completed: u64,
    tasks_failed: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentStartResponse {
    agent_id: AgentId,
    name: String,
    agent_type: String,
    status: String,
    started_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentStatusResponse {
    agent_id: AgentId,
    name: String,
    agent_type: String,
    status: String,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    last_heartbeat: Option<chrono::DateTime<chrono::Utc>>,
    current_task: Option<String>,
    metadata: AgentMetadata,
}

#[derive(Debug, Deserialize, Serialize)]
struct AgentLogsResponse {
    agent_id: AgentId,
    logs: Vec<LogEntry>,
    total: usize,
}

#[derive(Debug, Deserialize, Serialize)]
struct LogEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    level: String,
    message: String,
    fields: Option<serde_json::Value>,
}

impl AgentCommand {
    pub async fn execute(mut self, mut ctx: Context) -> Result<(), CliError> {
        let action = std::mem::replace(
            &mut self.action,
            AgentAction::List { r#type: None, status: None, output: AgentOutputFormat::Table },
        );

        match action {
            AgentAction::List { r#type, status, output } => {
                self.list_agents(&mut ctx, r#type, status, output).await
            }
            AgentAction::Start { r#type, config, name, background } => {
                self.start_agent(&mut ctx, r#type, config, name, background).await
            }
            AgentAction::Stop { agent_id, force } => {
                self.stop_agent(&mut ctx, &agent_id, force).await
            }
            AgentAction::Status { agent_id, watch } => {
                self.get_status(&mut ctx, &agent_id, watch).await
            }
            AgentAction::Logs { agent_id, lines, follow, level } => {
                self.get_logs(&mut ctx, &agent_id, lines, follow, level).await
            }
        }
    }

    async fn list_agents(
        &self,
        ctx: &mut Context,
        agent_type: Option<AgentTypeFilter>,
        status_filter: Option<AgentStatusFilter>,
        output: AgentOutputFormat,
    ) -> Result<(), CliError> {
        let mut url = "/api/agents".to_string();
        let mut params = Vec::new();

        if let Some(t) = agent_type {
            params.push(format!("type={:?}", t).to_lowercase());
        }
        if let Some(s) = status_filter {
            params.push(format!("status={:?}", s).to_lowercase());
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = ctx.get(&url).await?;
        let data: AgentListResponse = response.json().await?;

        match output {
            AgentOutputFormat::Table => self.print_agent_table(&data.agents),
            AgentOutputFormat::Json => print_output(&data.agents, &OutputFormat::Json)?,
        }

        Ok(())
    }

    fn print_agent_table(&self, agents: &[AgentInfo]) {
        println!("\n{}", format!("Agents ({})", agents.len()).bold().underline());

        if agents.is_empty() {
            println!("No agents found.");
            return;
        }

        let mut builder = tabled::builder::Builder::default();
        builder.push_record(vec![
            "ID".to_string(),
            "Name".to_string(),
            "Type".to_string(),
            "Status".to_string(),
            "Started".to_string(),
            "Last Heartbeat".to_string(),
            "Tasks (OK/Failed)".to_string(),
        ]);

        for agent in agents {
            let status_str = format_agent_status(&agent.status);
            let started = agent
                .started_at
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let heartbeat = agent
                .last_heartbeat
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "N/A".to_string());

            builder.push_record(vec![
                agent.id.to_string(),
                agent.name.clone(),
                agent.agent_type.clone(),
                status_str,
                started,
                heartbeat,
                format!("{}/{}", agent.metadata.tasks_completed, agent.metadata.tasks_failed),
            ]);
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);
    }

    async fn start_agent(
        &self,
        ctx: &mut Context,
        agent_type: AgentType,
        config: Option<String>,
        name: Option<String>,
        background: bool,
    ) -> Result<(), CliError> {
        let mut payload = serde_json::json!({
            "type": format!("{:?}", agent_type).to_lowercase(),
            "background": background,
        });

        if let Some(n) = name {
            payload["name"] = serde_json::json!(n);
        }

        if let Some(config_str) = config {
            let config_value: serde_json::Value = if config_str.starts_with('{') {
                serde_json::from_str(&config_str)?
            } else {
                // Load from file
                let content = tokio::fs::read_to_string(&config_str).await?;
                serde_json::from_str(&content)?
            };
            payload["config"] = config_value;
        }

        let response = ctx.post("/api/agents/start", &payload).await?;
        let data: AgentStartResponse = response.json().await?;

        println!("{} Agent started successfully!", "✓".green());
        println!("  Agent ID: {}", data.agent_id);
        println!("  Name: {}", data.name);
        println!("  Type: {}", data.agent_type);
        println!("  Status: {}", data.status);
        println!("  Started: {}", data.started_at.format("%Y-%m-%d %H:%M:%S"));

        if background {
            println!(
                "  Running in background. Use 'openre agent status {}' to check status.",
                data.agent_id
            );
        }

        Ok(())
    }

    async fn stop_agent(
        &self,
        ctx: &mut Context,
        agent_id: &str,
        force: bool,
    ) -> Result<(), CliError> {
        let id = AgentId::from_str(agent_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid agent ID: {}", agent_id)))?;

        let mut url = format!("/api/agents/{}/stop", id);
        if force {
            url.push_str("?force=true");
        }

        let response = ctx.post(&url, &serde_json::json!({})).await?;

        if response.status().is_success() {
            println!("{} Agent {} stopped successfully", "✓".green(), agent_id);
        } else {
            return Err(CliError::ApiError("Failed to stop agent".to_string()));
        }

        Ok(())
    }

    async fn get_status(
        &self,
        ctx: &mut Context,
        agent_id: &str,
        watch: bool,
    ) -> Result<(), CliError> {
        let id = AgentId::from_str(agent_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid agent ID: {}", agent_id)))?;

        if watch {
            println!("{} Watching agent {} (press Ctrl+C to stop)...", "👁".blue(), agent_id);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));
            loop {
                interval.tick().await;
                let response = ctx.get(&format!("/api/agents/{}/status", id)).await?;
                let data: AgentStatusResponse = response.json().await?;
                self.print_agent_status(&data);

                if matches!(data.status.as_str(), "stopped" | "failed") {
                    break;
                }
            }
        } else {
            let response = ctx.get(&format!("/api/agents/{}/status", id)).await?;
            let data: AgentStatusResponse = response.json().await?;
            self.print_agent_status(&data);
        }

        Ok(())
    }

    fn print_agent_status(&self, data: &AgentStatusResponse) {
        println!("\n{}", format!("Agent Status: {}", data.name).bold().underline());
        let status_str = format_agent_status(&data.status);
        println!("  ID: {}", data.agent_id);
        println!("  Type: {}", data.agent_type);
        println!("  Status: {}", status_str);
        println!(
            "  Started: {}",
            data.started_at
                .map_or("N/A".to_string(), |d| d.format("%Y-%m-%d %H:%M:%S").to_string())
        );
        println!(
            "  Last heartbeat: {}",
            data.last_heartbeat
                .map_or("N/A".to_string(), |d| d.format("%Y-%m-%d %H:%M:%S").to_string())
        );
        if let Some(task) = &data.current_task {
            println!("  Current task: {}", task);
        }
        println!(
            "  CPU: {}",
            data.metadata.cpu_usage.map_or("N/A".to_string(), |c| format!("{:.1}%", c))
        );
        println!(
            "  Memory: {}",
            data.metadata
                .memory_usage
                .map_or("N/A".to_string(), |m| format!("{} MB", m / 1024 / 1024))
        );
        println!("  Tasks completed: {}", data.metadata.tasks_completed);
        println!("  Tasks failed: {}", data.metadata.tasks_failed);
    }

    async fn get_logs(
        &self,
        ctx: &mut Context,
        agent_id: &str,
        lines: usize,
        follow: bool,
        level: Option<LogLevelFilter>,
    ) -> Result<(), CliError> {
        let id = AgentId::from_str(agent_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid agent ID: {}", agent_id)))?;

        let mut url = format!("/api/agents/{}/logs?lines={}", id, lines);
        if let Some(l) = level {
            url.push_str(&format!("&level={:?}", l).to_lowercase());
        }

        if follow {
            println!(
                "{} Following logs for agent {} (press Ctrl+C to stop)...",
                "📜".blue(),
                agent_id
            );
            let mut last_count = 0;
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let response = ctx.get(&format!("{}", url)).await?;
                let data: AgentLogsResponse = response.json().await?;

                for log in data.logs.iter().skip(last_count) {
                    println!(
                        "[{}] {} {}",
                        log.timestamp.format("%H:%M:%S"),
                        format_log_level(&log.level),
                        log.message
                    );
                }
                last_count = data.logs.len();
            }
        } else {
            let response = ctx.get(&url).await?;
            let data: AgentLogsResponse = response.json().await?;

            println!(
                "\n{}",
                format!("Logs for Agent {} (last {} lines)", agent_id, data.logs.len())
                    .bold()
                    .underline()
            );

            for log in &data.logs {
                println!(
                    "[{}] {} {}",
                    log.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    format_log_level(&log.level),
                    log.message
                );
            }
        }

        Ok(())
    }
}

fn format_agent_status(status: &str) -> String {
    match status {
        "starting" => format!("{} Starting", "⏳".yellow()),
        "running" => format!("{} Running", "✓".green()),
        "stopping" => format!("{} Stopping", "⏳".yellow()),
        "stopped" => format!("{} Stopped", "⊘".bright_black()),
        "failed" => format!("{} Failed", "✗".red()),
        "idle" => format!("{} Idle", "⏸".blue()),
        _ => status.to_string(),
    }
}

fn format_log_level(level: &str) -> String {
    match level.to_lowercase().as_str() {
        "trace" => format!("{}", "TRACE".purple()),
        "debug" => format!("{}", "DEBUG".blue()),
        "info" => format!("{}", "INFO".green()),
        "warn" => format!("{}", "WARN".yellow()),
        "error" => format!("{}", "ERROR".red()),
        _ => level.to_uppercase(),
    }
}

/// Type alias for compatibility with main.rs
pub type AgentCommands = AgentCommand;

