//! Scan commands

use crate::{print_output, CliError, Context, OfflineScan};
use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_core::ids::ScanId;
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};
use urlencoding;

#[derive(Subcommand)]
pub enum ScanCommands {
    /// Create a new scan
    Create {
        /// Project name or ID
        #[arg(long)]
        project: String,

        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Scan profile
        #[arg(short, long, default_value = "standard")]
        profile: String,

        /// Scan name
        #[arg(short, long)]
        name: Option<String>,

        /// Scan description
        #[arg(long)]
        description: Option<String>,

        /// Schedule scan (cron expression)
        #[arg(long)]
        schedule: Option<String>,

        /// Run immediately after creation
        #[arg(long, default_value = "true")]
        run: bool,
    },

    /// Run a scan
    Run {
        #[arg(short, long)]
        id: String,

        /// Run in background
        #[arg(long)]
        background: bool,
    },

    /// List scans for a project
    List {
        /// Project name or ID
        #[arg(long)]
        project: String,

        #[arg(long, default_value = "1")]
        page: u32,

        #[arg(long, default_value = "50")]
        per_page: u32,

        #[arg(long)]
        status: Option<String>,
    },

    /// Get scan details
    Show {
        #[arg(short, long)]
        id: String,
    },

    /// Delete a scan
    Delete {
        #[arg(short, long)]
        id: String,

        #[arg(long)]
        force: bool,
    },

    /// Cancel a running scan
    Cancel {
        #[arg(short, long)]
        id: String,
    },

    /// Resume a cancelled/failed scan
    Resume {
        #[arg(short, long)]
        id: String,
    },

    /// Get scan status
    Status {
        #[arg(short, long)]
        id: String,

        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Export scan results
    Export {
        #[arg(short, long)]
        id: String,

        #[arg(short, long, default_value = "json")]
        format: String,

        #[arg(short, long)]
        output: Option<String>,
    },
}

impl ScanCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        // Check if offline mode
        if ctx.offline {
            return self.execute_offline(ctx).await;
        }

        match self {
            ScanCommands::Create {
                project,
                target,
                profile,
                name,
                description,
                schedule,
                run,
            } => {
                // First, resolve project ID if name given
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let mut payload = serde_json::json!({
                    "project_id": project_id,
                    "target": target,
                    "profile": profile,
                });

                if let Some(name) = name {
                    payload["name"] = serde_json::json!(name);
                }
                if let Some(description) = description {
                    payload["description"] = serde_json::json!(description);
                }
                if let Some(schedule) = schedule {
                    payload["schedule"] = serde_json::json!(schedule);
                }

                let response = ctx.post("/api/scans", &payload).await?;
                let scan: ScanResponse = response.json().await?;
                print_output(&scan, &ctx.output_format)?;
                println!("Scan created successfully!");

                if run {
                    // Auto-run the scan
                    println!("Starting scan...");
                    let run_response = ctx.post(&format!("/api/scans/{}/run", scan.id), &serde_json::json!({})).await?;
                    let run_result: ScanRunResponse = run_response.json().await?;
                    print_output(&run_result, &ctx.output_format)?;
                }
            }

            ScanCommands::Run { id, background } => {
                let response = ctx.post(&format!("/api/scans/{}/run", id), &serde_json::json!({})).await?;
                let run_result: ScanRunResponse = response.json().await?;
                print_output(&run_result, &ctx.output_format)?;

                if background {
                    println!("Scan started in background. Use 'openre scan status --id {}' to check progress.", id);
                } else {
                    // Poll for completion
                    println!("Waiting for scan to complete...");
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
                    loop {
                        interval.tick().await;
                        let status_response = ctx.get(&format!("/api/scans/{}/status", id)).await?;
                        let status: ScanStatusResponse = status_response.json().await?;

                        print!("\rStatus: {} | Progress: {}% | Findings: {}",
                            status.status, status.progress, status.findings_count);
                        use std::io::{self, Write};
                        io::stdout().flush()?;

                        if matches!(status.status.as_str(), "completed" | "failed" | "cancelled") {
                            println!();
                            break;
                        }
                    }
                }
            }

            ScanCommands::List {
                project,
                page,
                per_page,
                status,
            } => {
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let mut url = format!("/api/scans?project_id={}&page={}&per_page={}", project_id, page, per_page);
                if let Some(status) = status {
                    url.push_str(&format!("&status={}", status));
                }

                let response = ctx.get(&url).await?;
                let list: ScanListResponse = response.json().await?;
                print_output(&list.scans, &ctx.output_format)?;
                println!(
                    "Page {} of {} (total: {})",
                    list.page,
                    (list.total + list.per_page as u64 - 1) / list.per_page as u64,
                    list.total
                );
            }

            ScanCommands::Show { id } => {
                let response = ctx.get(&format!("/api/scans/{}", id)).await?;
                let scan: ScanResponse = response.json().await?;
                print_output(&scan, &ctx.output_format)?;
            }

            ScanCommands::Delete { id, force } => {
                if !force {
                    print!("Are you sure you want to delete scan {}? (y/N): ", id);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                ctx.delete(&format!("/api/scans/{}", id)).await?;
                println!("Scan deleted successfully!");
            }

            ScanCommands::Cancel { id } => {
                let response = ctx.post(&format!("/api/scans/{}/cancel", id), &serde_json::json!({})).await?;
                let result: ScanCancelResponse = response.json().await?;
                println!("Scan cancelled successfully!");
                print_output(&result, &ctx.output_format)?;
            }

            ScanCommands::Resume { id } => {
                let response = ctx.post(&format!("/api/scans/{}/resume", id), &serde_json::json!({})).await?;
                let result: ScanRunResponse = response.json().await?;
                println!("Scan resumed successfully!");
                print_output(&result, &ctx.output_format)?;
            }

            ScanCommands::Status { id, interval } => {
                println!("Monitoring scan {} (press Ctrl+C to stop)...", id);
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval));
                loop {
                    interval.tick().await;
                    let response = ctx.get(&format!("/api/scans/{}/status", id)).await?;
                    let status: ScanStatusResponse = response.json().await?;

                    print!("\r\x1b[2KStatus: {} | Progress: {}% | Checks: {}/{} | Findings: {}",
                        status.status,
                        status.progress,
                        status.checks_completed,
                        status.checks_total,
                        status.findings_count);
                    use std::io::{self, Write};
                    io::stdout().flush()?;

                    if matches!(status.status.as_str(), "completed" | "failed" | "cancelled") {
                        println!("\nScan {}!", status.status);
                        break;
                    }
                }
            }

            ScanCommands::Export { id, format, output } => {
                let response = ctx.get(&format!("/api/scans/{}/export?format={}", id, format)).await?;
                let export: ScanExportResponse = response.json().await?;

                if let Some(output_path) = output {
                    tokio::fs::write(&output_path, &export.data).await?;
                    println!("Export saved to {}", output_path);
                } else {
                    println!("{}", export.data);
                }
            }
        }

        Ok(())
    }

    async fn execute_offline(self, ctx: Context) -> Result<(), CliError> {
        let store = ctx.local_store().ok_or(CliError::OfflineMode("Offline store not available".to_string()))?;

        match self {
            ScanCommands::Create {
                project,
                target,
                profile,
                name,
                description,
                schedule: _,
                run: _,
            } => {
                // Resolve project ID
                let project_id = store.resolve_project_id(&project).await?;

                let scan = OfflineScan {
                    id: ScanId::new(),
                    project_id,
                    name: name.unwrap_or_else(|| format!("scan-{}", chrono::Utc::now().timestamp())),
                    target,
                    profile,
                    status: "pending".to_string(),
                    progress: 0.0,
                    findings_count: 0,
                    checks_total: 0,
                    checks_completed: 0,
                    started_at: None,
                    completed_at: None,
                    created_at: chrono::Utc::now(),
                    updated_at: chrono::Utc::now(),
                };

                store.create_scan(scan.clone()).await?;
                let response = ScanResponse {
                    id: scan.id,
                    project_id: scan.project_id.to_string(),
                    name: scan.name,
                    target: scan.target,
                    profile: scan.profile,
                    status: scan.status,
                    progress: scan.progress,
                    findings_count: scan.findings_count,
                    checks_total: scan.checks_total,
                    checks_completed: scan.checks_completed,
                    started_at: scan.started_at,
                    completed_at: scan.completed_at,
                    created_at: scan.created_at,
                    updated_at: scan.updated_at,
                };
                print_output(&response, &ctx.output_format)?;
                println!("Scan created successfully (offline)!");
            }

            ScanCommands::Run { id, background: _ } => {
                let scan_id = id.parse::<ScanId>()
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?;
                let scan = store.update_scan(
                    &scan_id,
                    Some("running".to_string()),
                    Some(0.0),
                    None,
                    None,
                    Some(chrono::Utc::now()),
                    None,
                ).await?
                    .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", id)))?;

                let response = ScanRunResponse {
                    scan_id: scan.id,
                    status: scan.status,
                    message: "Scan started (offline)".to_string(),
                };
                print_output(&response, &ctx.output_format)?;
                println!("Scan started (offline mode - simulation)");
            }

            ScanCommands::List {
                project,
                page,
                per_page,
                status,
            } => {
                let project_id = store.resolve_project_id(&project).await?;
                let scans = store.list_scans(&project_id, page, per_page, status).await?;
                let total = store.count_scans(&project_id, None).await?;
                let total_pages = (total + per_page as u64 - 1) / per_page as u64;

                let responses: Vec<ScanResponse> = scans
                    .into_iter()
                    .map(|s| ScanResponse {
                        id: s.id,
                        project_id: s.project_id.to_string(),
                        name: s.name,
                        target: s.target,
                        profile: s.profile,
                        status: s.status,
                        progress: s.progress,
                        findings_count: s.findings_count,
                        checks_total: s.checks_total,
                        checks_completed: s.checks_completed,
                        started_at: s.started_at,
                        completed_at: s.completed_at,
                        created_at: s.created_at,
                        updated_at: s.updated_at,
                    })
                    .collect();

                print_output(&responses, &ctx.output_format)?;
                println!("Page {} of {} (total: {})", page, total_pages, total);
            }

            ScanCommands::Show { id } => {
                let scan_id = id.parse::<ScanId>()
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?;
                let scan = store.get_scan(&scan_id).await?
                    .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", id)))?;

                let response = ScanResponse {
                    id: scan.id,
                    project_id: scan.project_id.to_string(),
                    name: scan.name,
                    target: scan.target,
                    profile: scan.profile,
                    status: scan.status,
                    progress: scan.progress,
                    findings_count: scan.findings_count,
                    checks_total: scan.checks_total,
                    checks_completed: scan.checks_completed,
                    started_at: scan.started_at,
                    completed_at: scan.completed_at,
                    created_at: scan.created_at,
                    updated_at: scan.updated_at,
                };
                print_output(&response, &ctx.output_format)?;
            }

            ScanCommands::Delete { id, force } => {
                if !force {
                    print!("Are you sure you want to delete scan {}? (y/N): ", id);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                let scan_id = id.parse::<ScanId>()
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?;
                let deleted = store.delete_scan(&scan_id).await?;
                if deleted {
                    println!("Scan deleted successfully (offline)!");
                } else {
                    return Err(CliError::NotFound(format!("Scan not found: {}", id)));
                }
            }

            ScanCommands::Cancel { id } => {
                let scan_id = id.parse::<ScanId>()
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?;
                let scan = store.update_scan(
                    &scan_id,
                    Some("cancelled".to_string()),
                    None,
                    None,
                    None,
                    None,
                    Some(chrono::Utc::now()),
                ).await?
                    .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", id)))?;

                let response = ScanCancelResponse {
                    scan_id: scan.id,
                    status: scan.status,
                };
                println!("Scan cancelled successfully (offline)!");
                print_output(&response, &ctx.output_format)?;
            }

            ScanCommands::Resume { id } => {
                let scan_id = id.parse::<ScanId>()
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?;
                let scan = store.update_scan(
                    &scan_id,
                    Some("running".to_string()),
                    None,
                    None,
                    None,
                    Some(chrono::Utc::now()),
                    None,
                ).await?
                    .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", id)))?;

                let response = ScanRunResponse {
                    scan_id: scan.id,
                    status: scan.status,
                    message: "Scan resumed (offline)".to_string(),
                };
                println!("Scan resumed successfully (offline)!");
                print_output(&response, &ctx.output_format)?;
            }

            ScanCommands::Status { id, interval } => {
                let scan_id = id.parse::<ScanId>()
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?;
                println!("Monitoring scan {} (offline mode - press Ctrl+C to stop)...", id);
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval));
                loop {
                    interval.tick().await;
                    let scan = store.get_scan(&scan_id).await?
                        .ok_or_else(|| CliError::NotFound(format!("Scan not found: {}", id)))?;

                    print!("\r\x1b[2KStatus: {} | Progress: {}% | Checks: {}/{} | Findings: {}",
                        scan.status,
                        scan.progress,
                        scan.checks_completed,
                        scan.checks_total,
                        scan.findings_count);
                    use std::io::{self, Write};
                    io::stdout().flush()?;

                    if matches!(scan.status.as_str(), "completed" | "failed" | "cancelled") {
                        println!("\nScan {}!", scan.status);
                        break;
                    }
                }
            }

            ScanCommands::Export { id, format, output } => {
                return Err(CliError::OfflineMode("Export not available in offline mode".to_string()));
            }
        }

        Ok(())
    }
}

// Helper to resolve project name to ID
async fn resolve_project_id(ctx: &mut Context, project: &str) -> Result<String, CliError> {
    // Try to parse as UUID first
    if uuid::Uuid::parse_str(project).is_ok() {
        return Ok(project.to_string());
    }

    // Otherwise, search by name
    let response = ctx.get(&format!("/api/projects?search={}", urlencoding::encode(project))).await?;
    let list: ProjectListResponse = response.json().await?;

    if let Some(project) = list.projects.first() {
        Ok(project.id.to_string())
    } else {
        Err(CliError::InvalidInput(format!("Project not found: {}", project)))
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanResponse {
    pub id: ScanId,
    pub project_id: String,
    pub name: String,
    pub target: String,
    pub profile: String,
    pub status: String,
    pub progress: f32,
    pub findings_count: u64,
    pub checks_total: u32,
    pub checks_completed: u32,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanListResponse {
    pub scans: Vec<ScanResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanRunResponse {
    pub scan_id: ScanId,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanStatusResponse {
    pub scan_id: ScanId,
    pub status: String,
    pub progress: f32,
    pub checks_completed: u32,
    pub checks_total: u32,
    pub findings_count: u64,
    pub current_check: Option<String>,
    pub estimated_remaining: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanCancelResponse {
    pub scan_id: ScanId,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanExportResponse {
    pub scan_id: ScanId,
    pub format: String,
    pub data: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProjectResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub is_public: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}