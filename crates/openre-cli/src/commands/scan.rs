//! Scan commands

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_core::ids::ScanId;
use openre_core::result::{Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, RemediationEffort, RemediationGuidance, RemediationPriority, Severity};
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};
use urlencoding;
use uuid::Uuid;

// Import openre-scan's run_scan_internal function
use openre_scan::{run_scan_internal, ScanProfile as OpenreScanProfile};

#[derive(Subcommand)]
pub enum ScanCommands {
    /// Create a new scan
    Create {
        /// Project name or ID
        #[arg(short = 'j', long)]
        project: String,

        /// Target URL to scan
        #[arg(short, long)]
        target: String,

        /// Scan profile
        #[arg(short = 'o', long, default_value = "standard")]
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

        /// HTTP timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Maximum HTTP redirects to follow
        #[arg(long, default_value = "10")]
        max_redirects: u32,

        /// User agent string
        #[arg(long, default_value = "openre-cli/0.1.0")]
        user_agent: String,
    },

    /// Run a scan
    Run {
        #[arg(short, long)]
        id: String,

        /// Run in background
        #[arg(long)]
        background: bool,

        /// HTTP timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,

        /// Maximum HTTP redirects to follow
        #[arg(long, default_value = "10")]
        max_redirects: u32,

        /// User agent string
        #[arg(long, default_value = "openre-cli/0.1.0")]
        user_agent: String,
    },

    /// List scans for a project
    List {
        /// Project name or ID
        #[arg(short, long)]
        project: String,

        #[arg(short = 'g', long, default_value = "1")]
        page: u32,

        #[arg(short = 'n', long, default_value = "50")]
        per_page: u32,

        #[arg(long)]
        status: Option<String>,
    },

    /// Get scan details
    Show {
        #[arg(short, long)]
        id: String,

        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Delete a scan
    Delete {
        #[arg(short, long)]
        id: String,

        #[arg(long)]
        force: bool,
    },

    /// Cancel a running scan (online only)
    Cancel {
        #[arg(short, long)]
        id: String,
    },

    /// Resume a cancelled/failed scan (online only)
    Resume {
        #[arg(short, long)]
        id: String,
    },

    /// Get scan status (online only)
    Status {
        #[arg(short, long)]
        id: String,

        #[arg(long, default_value = "5")]
        interval: u64,
    },

    /// Export scan results (online only)
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
        if ctx.is_offline() {
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
                timeout: _,
                max_redirects: _,
                user_agent: _,
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

            ScanCommands::Run { id, background, timeout: _, max_redirects: _, user_agent: _ } => {
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

            ScanCommands::Show { id, format } => {
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
        let store = ctx.local_store().await?;
        let mut store_guard = store.lock().await;
        let store = store_guard.as_mut().expect("Local store not initialized");

        match self {
            ScanCommands::Create { project, target, profile, name, description: _, schedule: _, run, timeout, max_redirects, user_agent } => {
                // Resolve project ID locally
                let project_id = resolve_project_id_offline(&store, &project).await?;

                let scan_id = Uuid::new_v4().to_string();
                let now = chrono::Utc::now().to_rfc3339();
                let scan_name = name.unwrap_or_else(|| format!("Scan of {}", target));

                store.execute(
                    "INSERT INTO scans (id, project_id, name, target, profile, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'created', ?, ?)",
                    vec![
                        serde_json::json!(scan_id.clone()),
                        serde_json::json!(project_id),
                        serde_json::json!(scan_name.clone()),
                        serde_json::json!(target.clone()),
                        serde_json::json!(profile.clone()),
                        serde_json::json!(now.clone()),
                        serde_json::json!(now),
                    ],
                ).await?;

                let scan = LocalScan {
                    id: scan_id.clone(),
                    project_id,
                    name: scan_name,
                    target,
                    profile,
                    status: "created".to_string(),
                    progress: 0.0,
                    findings_count: 0,
                    checks_total: 0,
                    checks_completed: 0,
                    created_at: now.clone(),
                    updated_at: now,
                    started_at: None,
                    completed_at: None,
                };
                print_output(&scan, &ctx.output_format)?;
                println!("Scan created successfully (offline mode)!");

                if run {
                    println!("Starting scan...");
                    Self::run_scan_offline(&ctx, &store, &scan_id, timeout, max_redirects, user_agent).await?;
                }
            }

            ScanCommands::Run { id, background, timeout, max_redirects, user_agent } => {
                if background {
                    return Err(CliError::InvalidInput("Background mode not supported in offline mode. Run without --background.".to_string()));
                }
                Self::run_scan_offline(&ctx, &store, &id, timeout, max_redirects, user_agent).await?;
            }

            ScanCommands::List { project, page, per_page, status: status_filter } => {
                let project_id = resolve_project_id_offline(&store, &project).await?;

                let mut sql = format!(
                    "SELECT id, project_id, name, target, profile, status, progress, findings_count, checks_total, checks_completed, created_at, updated_at, started_at, completed_at FROM scans WHERE project_id = ? ORDER BY created_at DESC LIMIT {} OFFSET {}",
                    per_page,
                    (page - 1) * per_page
                );

                let results = store.query(&sql, vec![serde_json::json!(project_id)]).await?;
                let scans: Vec<LocalScan> = results
                    .into_iter()
                    .filter(|v| {
                        if let Some(ref status_filter) = status_filter {
                            v["status"].as_str().unwrap_or("") == status_filter
                        } else {
                            true
                        }
                    })
                    .map(|v| LocalScan {
                        id: v["id"].as_str().unwrap_or("").to_string(),
                        project_id: v["project_id"].as_str().unwrap_or("").to_string(),
                        name: v["name"].as_str().unwrap_or("").to_string(),
                        target: v["target"].as_str().unwrap_or("").to_string(),
                        profile: v["profile"].as_str().unwrap_or("").to_string(),
                        status: v["status"].as_str().unwrap_or("").to_string(),
                        progress: v["progress"].as_f64().unwrap_or(0.0) as f32,
                        findings_count: v["findings_count"].as_u64().unwrap_or(0),
                        checks_total: v["checks_total"].as_u64().unwrap_or(0) as u32,
                        checks_completed: v["checks_completed"].as_u64().unwrap_or(0) as u32,
                        created_at: v["created_at"].as_str().unwrap_or("").to_string(),
                        updated_at: v["updated_at"].as_str().unwrap_or("").to_string(),
                        started_at: v["started_at"].as_str().map(|s| s.to_string()),
                        completed_at: v["completed_at"].as_str().map(|s| s.to_string()),
                    })
                    .collect();

                print_output(&scans, &ctx.output_format)?;
                println!("Showing page {} (offline mode)", page);
            }

            ScanCommands::Show { id, format: _ } => {
                let results = store.query(
                    "SELECT id, project_id, name, target, profile, status, progress, findings_count, checks_total, checks_completed, created_at, updated_at, started_at, completed_at FROM scans WHERE id = ?",
                    vec![serde_json::json!(id)],
                ).await?;

                if let Some(v) = results.first() {
                    let scan = LocalScan {
                        id: v["id"].as_str().unwrap_or("").to_string(),
                        project_id: v["project_id"].as_str().unwrap_or("").to_string(),
                        name: v["name"].as_str().unwrap_or("").to_string(),
                        target: v["target"].as_str().unwrap_or("").to_string(),
                        profile: v["profile"].as_str().unwrap_or("").to_string(),
                        status: v["status"].as_str().unwrap_or("").to_string(),
                        progress: v["progress"].as_f64().unwrap_or(0.0) as f32,
                        findings_count: v["findings_count"].as_u64().unwrap_or(0),
                        checks_total: v["checks_total"].as_u64().unwrap_or(0) as u32,
                        checks_completed: v["checks_completed"].as_u64().unwrap_or(0) as u32,
                        created_at: v["created_at"].as_str().unwrap_or("").to_string(),
                        updated_at: v["updated_at"].as_str().unwrap_or("").to_string(),
                        started_at: v["started_at"].as_str().map(|s| s.to_string()),
                        completed_at: v["completed_at"].as_str().map(|s| s.to_string()),
                    };
                    print_output(&scan, &ctx.output_format)?;
                } else {
                    return Err(CliError::InvalidInput(format!("Scan not found: {}", id)));
                }
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

                let rows = store.execute("DELETE FROM scans WHERE id = ?", vec![serde_json::json!(id)]).await?;

                if rows == 0 {
                    return Err(CliError::InvalidInput(format!("Scan not found: {}", id)));
                }

                println!("Scan deleted successfully (offline mode)!");
            }

            ScanCommands::Cancel { .. } => {
                return Err(CliError::InvalidInput("Cancel not available in offline mode".to_string()));
            }
            ScanCommands::Resume { .. } => {
                return Err(CliError::InvalidInput("Resume not available in offline mode".to_string()));
            }
            ScanCommands::Status { .. } => {
                return Err(CliError::InvalidInput("Status monitoring not available in offline mode".to_string()));
            }
            ScanCommands::Export { .. } => {
                return Err(CliError::InvalidInput("Export not available in offline mode".to_string()));
            }
        }

        Ok(())
    }

    async fn run_scan_offline(ctx: &Context, store: &crate::context::LocalStore, scan_id: &str, timeout: u64, max_redirects: u32, user_agent: String) -> Result<(), CliError> {
        // Get scan details
        let results = store.query(
            "SELECT id, project_id, name, target, profile FROM scans WHERE id = ?",
            vec![serde_json::json!(scan_id)],
        ).await?;

        let scan = results.first().ok_or_else(|| CliError::InvalidInput(format!("Scan not found: {}", scan_id)))?;
        let target = scan["target"].as_str().unwrap_or("");
        let profile_str = scan["profile"].as_str().unwrap_or("standard");

        // Update scan status to running
        let now = chrono::Utc::now().to_rfc3339();
        store.execute(
            "UPDATE scans SET status = 'running', progress = 0.0, started_at = ?, updated_at = ? WHERE id = ?",
            vec![serde_json::json!(now.clone()), serde_json::json!(now.clone()), serde_json::json!(scan_id)],
        ).await?;

        // Parse profile
        let profile = match profile_str.to_lowercase().as_str() {
            "quick" => OpenreScanProfile::Quick,
            "full" => OpenreScanProfile::Full,
            _ => OpenreScanProfile::Standard,
        };

        // Run the scan using openre-scan's internal function
        println!("Running scan {} on {} with {:?} profile...", scan_id, target, profile);
        let findings = run_scan_internal(
            target.to_string(),
            profile,
            openre_scan::OutputFormat::Table,
            timeout,
            max_redirects as usize,
            user_agent,
        ).await.map_err(|e| CliError::Internal(format!("Scan failed: {}", e)))?;

        // Store findings
        for finding in &findings {
            let finding_id = Uuid::new_v4().to_string();
            let now = chrono::Utc::now().to_rfc3339();

            store.execute(
                r#"INSERT INTO scan_findings (id, scan_id, title, description, severity, confidence, category, check_name, target, target_type, evidence, remediation, verified, cwe_ids, mitre_attack_ids, owasp_category, tags, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
                vec![
                    serde_json::json!(finding_id),
                    serde_json::json!(scan_id),
                    serde_json::json!(finding.title),
                    serde_json::json!(finding.description),
                    serde_json::json!(format!("{:?}", finding.severity)),
                    serde_json::json!(format!("{:?}", finding.confidence)),
                    serde_json::json!(format!("{:?}", finding.category)),
                    serde_json::json!(finding.plugin_source),
                    serde_json::json!(finding.target),
                    serde_json::json!(finding.target_type),
                    serde_json::json!(serde_json::to_string(&finding.evidence).unwrap_or_default()),
                    serde_json::json!(finding.remediation.as_ref().map(|r| serde_json::to_string(r).unwrap_or_default()).unwrap_or_default()),
                    serde_json::json!(finding.verified),
                    serde_json::json!(serde_json::to_string(&finding.cwe_ids).unwrap_or_default()),
                    serde_json::json!(serde_json::to_string(&finding.mitre_attack_ids).unwrap_or_default()),
                    serde_json::json!(finding.owasp_category.clone().unwrap_or_default()),
                    serde_json::json!(serde_json::to_string(&finding.tags).unwrap_or_default()),
                    serde_json::json!(now.clone()),
                    serde_json::json!(now),
                ],
            ).await?;
        }

        // Update scan with results
        // Note: checks_total and checks_completed are approximated as findings count.
        // Ideally run_scan_internal would return the actual number of checks performed.
        let completed_at = chrono::Utc::now().to_rfc3339();
        let checks_estimate = findings.len() as u32;
        store.execute(
            "UPDATE scans SET status = 'completed', progress = 100.0, findings_count = ?, checks_total = ?, checks_completed = ?, completed_at = ?, updated_at = ? WHERE id = ?",
            vec![
                serde_json::json!(findings.len() as u64),
                serde_json::json!(checks_estimate),
                serde_json::json!(checks_estimate),
                serde_json::json!(completed_at),
                serde_json::json!(completed_at),
                serde_json::json!(scan_id),
            ],
        ).await?;

        println!("Scan completed! Found {} findings.", findings.len());

        // Show findings
        if !findings.is_empty() {
            println!("\nFindings:");
            for finding in &findings {
                let severity_color = match finding.severity {
                    Severity::Critical => "red",
                    Severity::High => "red",
                    Severity::Medium => "yellow",
                    Severity::Low => "green",
                    Severity::Info => "blue",
                };
                println!("  {} {} [{}] ({})",
                    "▸".color(severity_color),
                    finding.title,
                    format!("{:?}", finding.severity).color(severity_color),
                    finding.plugin_source.dimmed()
                );
            }
        }

        Ok(())
    }
}

// Helper to resolve project name to ID (offline)
async fn resolve_project_id_offline(
    store: &crate::context::LocalStore,
    project: &str,
) -> Result<String, CliError> {
    // Try to parse as UUID first
    if uuid::Uuid::parse_str(project).is_ok() {
        return Ok(project.to_string());
    }

    // Otherwise, search by name
    let results = store.query(
        "SELECT id FROM projects WHERE name = ?",
        vec![serde_json::json!(project)],
    ).await?;

    if let Some(v) = results.first() {
        let id = v["id"].as_str().unwrap_or("").to_string();
        Ok(id)
    } else {
        Err(CliError::InvalidInput(format!("Project not found: {}", project)))
    }
}

// Response types for offline mode
#[derive(Debug, Serialize, Deserialize)]
struct LocalScan {
    id: String,
    project_id: String,
    name: String,
    target: String,
    profile: String,
    status: String,
    progress: f32,
    findings_count: u64,
    checks_total: u32,
    checks_completed: u32,
    created_at: String,
    updated_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
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