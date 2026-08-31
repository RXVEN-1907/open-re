//! Report commands

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use openre_core::ids::ReportId;
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};
use urlencoding;

#[derive(Subcommand)]
pub enum ReportCommands {
    /// Generate a report
    Generate {
        /// Scan ID
        #[arg(short, long)]
        scan: String,

        /// Output format
        #[arg(short, long, default_value = "html")]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Include executive summary
        #[arg(long, default_value = "true")]
        executive_summary: bool,

        /// Include technical details
        #[arg(long, default_value = "true")]
        technical_details: bool,

        /// Include remediation
        #[arg(long, default_value = "true")]
        remediation: bool,

        /// Template to use
        #[arg(long)]
        template: Option<String>,
    },

    /// List reports for a project
    List {
        /// Project name or ID
        #[arg(short, long)]
        project: String,

        #[arg(short, long, default_value = "1")]
        page: u32,

        #[arg(short, long, default_value = "50")]
        per_page: u32,
    },

    /// Get report details
    Show {
        #[arg(short, long)]
        id: String,

        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Download report
    Download {
        #[arg(short, long)]
        id: String,

        #[arg(short, long)]
        output: String,
    },

    /// Delete report
    Delete {
        #[arg(short, long)]
        id: String,

        #[arg(long)]
        force: bool,
    },

    /// List available templates
    Templates,
}

impl ReportCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            ReportCommands::Generate {
                scan,
                format,
                output,
                executive_summary,
                technical_details,
                remediation,
                template,
            } => {
                let mut payload = serde_json::json!({
                    "scan_id": scan,
                    "format": format,
                    "executive_summary": executive_summary,
                    "technical_details": technical_details,
                    "remediation": remediation,
                });

                if let Some(template) = template {
                    payload["template"] = serde_json::json!(template);
                }

                println!("Generating report...");
                let response = ctx.post("/api/reports", &payload).await?;
                let report: ReportGenerateResponse = response.json().await?;

                if let Some(output_path) = output {
                    let download_response =
                        ctx.get(&format!("/api/reports/{}/download", report.id)).await?;
                    let data = download_response.bytes().await?;
                    tokio::fs::write(&output_path, data).await?;
                    println!("Report saved to {}", output_path);
                } else {
                    print_output(&report, &ctx.output_format)?;
                    println!("Report generated! Use 'openre report download --id {} --output <file>' to save.", report.id);
                }
            }

            ReportCommands::List { project, page, per_page } => {
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let response = ctx
                    .get(&format!(
                        "/api/reports?project_id={}&page={}&per_page={}",
                        project_id, page, per_page
                    ))
                    .await?;
                let list: ReportListResponse = response.json().await?;
                print_output(&list.reports, &ctx.output_format)?;
                println!(
                    "Page {} of {} (total: {})",
                    list.page,
                    (list.total + list.per_page as u64 - 1) / list.per_page as u64,
                    list.total
                );
            }

            ReportCommands::Show { id, format: _ } => {
                let response = ctx.get(&format!("/api/reports/{}", id)).await?;
                let report: ReportResponse = response.json().await?;
                print_output(&report, &ctx.output_format)?;
            }

            ReportCommands::Download { id, output } => {
                let response = ctx.get(&format!("/api/reports/{}/download", id)).await?;
                let data = response.bytes().await?;
                tokio::fs::write(&output, data).await?;
                println!("Report downloaded to {}", output);
            }

            ReportCommands::Delete { id, force } => {
                if !force {
                    print!("Are you sure you want to delete report {}? (y/N): ", id);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }

                ctx.delete(&format!("/api/reports/{}", id)).await?;
                println!("Report deleted successfully!");
            }

            ReportCommands::Templates => {
                let response = ctx.get("/api/reports/templates").await?;
                let templates: TemplateListResponse = response.json().await?;
                print_output(&templates.templates, &ctx.output_format)?;
            }
        }

        Ok(())
    }
}

async fn resolve_project_id(ctx: &mut Context, project: &str) -> Result<String, CliError> {
    if uuid::Uuid::parse_str(project).is_ok() {
        return Ok(project.to_string());
    }

    let response =
        ctx.get(&format!("/api/projects?search={}", urlencoding::encode(project))).await?;
    let list: ProjectListResponse = response.json().await?;

    if let Some(project) = list.projects.first() {
        Ok(project.id.to_string())
    } else {
        Err(CliError::InvalidInput(format!("Project not found: {}", project)))
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportGenerateResponse {
    pub id: ReportId,
    pub scan_id: String,
    pub format: String,
    pub status: String,
    pub download_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportListResponse {
    pub reports: Vec<ReportSummary>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportSummary {
    pub id: ReportId,
    pub scan_id: String,
    pub format: String,
    pub status: String,
    pub file_size: Option<u64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportResponse {
    pub id: ReportId,
    pub scan_id: String,
    pub project_id: String,
    pub format: String,
    pub status: String,
    pub file_size: Option<u64>,
    pub template: Option<String>,
    pub executive_summary: bool,
    pub technical_details: bool,
    pub remediation: bool,
    pub download_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateListResponse {
    pub templates: Vec<ReportTemplate>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ReportTemplate {
    pub name: String,
    pub description: String,
    pub formats: Vec<String>,
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
