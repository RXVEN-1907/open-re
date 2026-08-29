//! Finding commands

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_core::ids::FindingId;
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};
use urlencoding;

#[derive(Subcommand)]
pub enum FindingCommands {
    /// List findings for a project
    List {
        /// Project name or ID
        #[arg(short, long)]
        project: String,

        /// Filter by severity (comma-separated)
        #[arg(long)]
        severity: Option<String>,

        /// Filter by category
        #[arg(long)]
        category: Option<String>,

        /// Filter by check name
        #[arg(long)]
        check: Option<String>,

        /// Filter by verified status
        #[arg(long)]
        verified: Option<bool>,

        #[arg(short, long, default_value = "1")]
        page: u32,

        #[arg(short, long, default_value = "50")]
        per_page: u32,

        /// Sort by field (severity, created_at, title)
        #[arg(long, default_value = "severity")]
        sort: String,

        /// Sort order
        #[arg(long, default_value = "desc")]
        order: String,
    },

    /// Get finding details
    Show {
        #[arg(short, long)]
        id: String,

        #[arg(short, long, default_value = "table")]
        format: String,

        /// Include evidence
        #[arg(long)]
        evidence: bool,

        /// Include remediation
        #[arg(long)]
        remediation: bool,
    },

    /// Export findings
    Export {
        /// Project name or ID
        #[arg(short, long)]
        project: String,

        #[arg(short, long, default_value = "json")]
        format: String,

        #[arg(short, long)]
        output: Option<String>,

        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,
    },

    /// Show finding statistics for a project
    Stats {
        /// Project name or ID
        #[arg(short, long)]
        project: String,
    },

    /// Mark finding as verified/unverified
    Verify {
        #[arg(short, long)]
        id: String,

        #[arg(short, long)]
        status: bool,
    },

    /// Add note to finding
    Note {
        #[arg(short, long)]
        id: String,

        #[arg(short, long)]
        text: String,
    },

    /// Bulk update findings
    Bulk {
        /// Project name or ID
        #[arg(short, long)]
        project: String,

        /// Filter by severity
        #[arg(long)]
        severity: Option<String>,

        /// Action: verify, unverify, delete
        #[arg(short, long)]
        action: String,
    },
}

impl FindingCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            FindingCommands::List {
                project,
                severity,
                category,
                check,
                verified,
                page,
                per_page,
                sort,
                order,
            } => {
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let mut url = format!("/api/security/findings?project_id={}&page={}&per_page={}&sort={}&order={}",
                    project_id, page, per_page, sort, order);

                if let Some(severity) = severity {
                    url.push_str(&format!("&severity={}", severity));
                }
                if let Some(category) = category {
                    url.push_str(&format!("&category={}", category));
                }
                if let Some(check) = check {
                    url.push_str(&format!("&check={}", check));
                }
                if let Some(verified) = verified {
                    url.push_str(&format!("&verified={}", verified));
                }

                let response = ctx.get(&url).await?;
                let list: FindingListResponse = response.json().await?;
                print_output(&list.findings, &ctx.output_format)?;
                println!(
                    "Page {} of {} (total: {})",
                    list.page,
                    (list.total + list.per_page as u64 - 1) / list.per_page as u64,
                    list.total
                );
            }

            FindingCommands::Show { id, format: _, evidence, remediation } => {
                let mut url = format!("/api/security/findings/{}", id);
                let mut params = Vec::new();
                if evidence { params.push("evidence=true"); }
                if remediation { params.push("remediation=true"); }
                if !params.is_empty() {
                    url.push_str("?");
                    url.push_str(&params.join("&"));
                }

                let response = ctx.get(&url).await?;
                let finding: FindingResponse = response.json().await?;
                print_output(&finding, &ctx.output_format)?;
            }

            FindingCommands::Export {
                project,
                format,
                output,
                severity,
            } => {
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let mut url = format!("/api/security/findings/export?project_id={}&format={}", project_id, format);
                if let Some(severity) = severity {
                    url.push_str(&format!("&severity={}", severity));
                }

                let response = ctx.get(&url).await?;
                let export: FindingExportResponse = response.json().await?;

                if let Some(output_path) = output {
                    tokio::fs::write(&output_path, &export.data).await?;
                    println!("Export saved to {}", output_path);
                } else {
                    println!("{}", export.data);
                }
            }

            FindingCommands::Stats { project } => {
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let response = ctx.get(&format!("/api/security/findings/stats?project_id={}", project_id)).await?;
                let stats: FindingStatsResponse = response.json().await?;
                print_output(&stats, &ctx.output_format)?;
            }

            FindingCommands::Verify { id, status } => {
                let response = ctx.put(
                    &format!("/api/security/findings/{}/verify", id),
                    &serde_json::json!({ "verified": status })
                ).await?;
                let finding: FindingResponse = response.json().await?;
                println!("Finding marked as {}!", if status { "verified" } else { "unverified" });
                print_output(&finding, &ctx.output_format)?;
            }

            FindingCommands::Note { id, text } => {
                let response = ctx.post(
                    &format!("/api/security/findings/{}/notes", id),
                    &serde_json::json!({ "text": text })
                ).await?;
                let note: FindingNoteResponse = response.json().await?;
                println!("Note added successfully!");
                print_output(&note, &ctx.output_format)?;
            }

            FindingCommands::Bulk { project, severity, action } => {
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let mut payload = serde_json::json!({ "action": action });
                if let Some(severity) = severity {
                    payload["severity"] = serde_json::json!(severity);
                }

                let response = ctx.post(
                    &format!("/api/security/findings/bulk?project_id={}", project_id),
                    &payload
                ).await?;
                let result: BulkActionResponse = response.json().await?;
                println!("Bulk action completed: {} findings affected", result.affected_count);
            }
        }

        Ok(())
    }
}

// Helper to resolve project name to ID
async fn resolve_project_id(ctx: &mut Context, project: &str) -> Result<String, CliError> {
    if uuid::Uuid::parse_str(project).is_ok() {
        return Ok(project.to_string());
    }

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
pub struct FindingListResponse {
    pub findings: Vec<FindingSummary>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingSummary {
    pub id: FindingId,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub check: String,
    pub target: String,
    pub verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingResponse {
    pub id: FindingId,
    pub project_id: String,
    pub scan_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub check: String,
    pub target: String,
    pub target_type: String,
    pub evidence: Vec<EvidenceResponse>,
    pub remediation: Option<RemediationResponse>,
    pub verified: bool,
    pub cwe_ids: Vec<String>,
    pub mitre_attack_ids: Vec<String>,
    pub owasp_category: Option<String>,
    pub tags: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EvidenceResponse {
    pub id: String,
    pub evidence_type: String,
    pub description: String,
    pub data: Option<serde_json::Value>,
    pub location: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RemediationResponse {
    pub summary: String,
    pub steps: Vec<String>,
    pub code_examples: Vec<String>,
    pub references: Vec<String>,
    pub effort: String,
    pub priority: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub by_check: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub unverified_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingExportResponse {
    pub project_id: String,
    pub format: String,
    pub data: String,
    pub count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingNoteResponse {
    pub id: String,
    pub finding_id: FindingId,
    pub author_id: String,
    pub text: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BulkActionResponse {
    pub affected_count: u64,
    pub action: String,
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