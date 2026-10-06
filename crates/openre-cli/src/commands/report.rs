//! Report template management commands

use crate::output::{print_output, OutputFormat};
use crate::error::CliError;
use crate::context::Context;
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::history::{HistoryStorage, ReportTemplate};
use openre_core::ids::ScanId;
use openre_core::reporting::{ReportConfig, ReportFormat};
use openre_storage::history::SqliteHistoryStorage;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use tabled::{Table, Tabled, Style};
use uuid::Uuid;

fn get_history_storage(ctx: &Context) -> SqliteHistoryStorage {
    let db_path = ctx.config.storage.local_path.join("history.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create history directory");
    }
    SqliteHistoryStorage::new(&db_path).expect("Failed to create history storage")
}

#[derive(Subcommand, Debug)]
pub enum ReportCommands {
    /// List all report templates
    List(ReportListArgs),
    /// Create a new report template
    Create(ReportCreateArgs),
    /// Delete a report template
    Delete(ReportDeleteArgs),
    /// Use a custom template for scan output
    Use(ReportUseArgs),
}

#[derive(Args, Debug)]
struct ReportListArgs {
    /// Maximum number of templates to list
    #[arg(long, default_value = "100")]
    limit: usize,

    /// Number of templates to skip
    #[arg(long, default_value = "0")]
    offset: usize,
}

#[derive(Args, Debug)]
struct ReportCreateArgs {
    /// Template name
    #[arg(short, long)]
    name: String,

    /// Template format (markdown, html, json, sarif)
    #[arg(short, long, value_enum)]
    format: ReportFormatArg,

    /// Template content (can be a file path or direct content)
    #[arg(short, long)]
    content: String,

    /// Read content from file instead of using the string directly
    #[arg(long)]
    from_file: bool,
}

#[derive(Args, Debug)]
struct ReportDeleteArgs {
    /// Template name to delete
    #[arg(short, long)]
    name: String,
}

#[derive(Args, Debug)]
struct ReportUseArgs {
    /// Template name to use
    #[arg(short, long)]
    name: String,

    /// Scan ID to generate report for
    #[arg(short, long)]
    scan_id: String,

    /// Output file path (optional)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, ValueEnum)]
enum ReportFormatArg {
    Markdown,
    Html,
    Json,
    Sarif,
}

impl From<ReportFormatArg> for ReportFormat {
    fn from(arg: ReportFormatArg) -> Self {
        match arg {
            ReportFormatArg::Markdown => ReportFormat::Markdown,
            ReportFormatArg::Html => ReportFormat::Html,
            ReportFormatArg::Json => ReportFormat::Json,
            ReportFormatArg::Sarif => ReportFormat::Sarif,
        }
    }
}

impl ReportCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ReportCommands::List(args) => list_templates(ctx, args).await,
            ReportCommands::Create(args) => create_template(ctx, args).await,
            ReportCommands::Delete(args) => delete_template(ctx, args).await,
            ReportCommands::Use(args) => use_template(ctx, args).await,
        }
    }
}

async fn list_templates(ctx: Context, args: ReportListArgs) -> Result<(), CliError> {
    let templates =
        get_history_storage(&ctx).list_report_templates(args.limit, args.offset).await?;

    if templates.is_empty() {
        println!("{}", "No report templates found.".yellow());
        return Ok(());
    }

    match ctx.format {
        OutputFormat::Table => {
            let mut table = Table::new(
                templates
                    .iter()
                    .map(|t| ReportTemplateRow {
                        name: t.name.clone(),
                        format: format!("{:?}", t.format),
                        content_preview: if t.content.len() > 50 {
                            format!("{}...", &t.content[..50])
                        } else {
                            t.content.clone()
                        },
                        created_at: t.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    })
                    .collect::<Vec<_>>(),
            );
            table.with(Style::modern());
            println!("{}", table);
        }
        OutputFormat::Json => {
            print_output(&templates, OutputFormat::Json, None)?;
        }
        _ => {
            // Default to table output for other formats
            let mut table = Table::new(
                templates
                    .iter()
                    .map(|t| ReportTemplateRow {
                        name: t.name.clone(),
                        format: format!("{:?}", t.format),
                        content_preview: if t.content.len() > 50 {
                            format!("{}...", &t.content[..50])
                        } else {
                            t.content.clone()
                        },
                        created_at: t.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                    })
                    .collect::<Vec<_>>(),
            );
            table.with(Style::modern());
            println!("{}", table);
        }
    }

    Ok(())
}

async fn create_template(ctx: Context, args: ReportCreateArgs) -> Result<(), CliError> {
    // Get template content
    let content = if args.from_file {
        std::fs::read_to_string(&args.content)
            .map_err(|e| CliError::InvalidArgs(format!("Failed to read template file: {}", e)))?
    } else {
        args.content
    };

    // Create template
    let template = ReportTemplate {
        id: Uuid::new_v4().to_string(),
        name: args.name.clone(),
        format: args.format.into(),
        content,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    // Save template
    get_history_storage(&ctx).save_report_template(&template).await?;

    println!("{} Report template '{}' created successfully.", "✓".green().bold(), args.name);

    Ok(())
}

async fn delete_template(ctx: Context, args: ReportDeleteArgs) -> Result<(), CliError> {
    // Delete template
    let deleted = get_history_storage(&ctx).delete_report_template(&args.name).await?;

    if deleted {
        println!("{} Report template '{}' deleted successfully.", "✓".green().bold(), args.name);
    } else {
        return Err(CliError::NotFound(format!("Report template '{}' not found", args.name)));
    }

    Ok(())
}

async fn use_template(ctx: Context, args: ReportUseArgs) -> Result<(), CliError> {
    // Parse scan ID
    let scan_id = ScanId::from_uuid(
        Uuid::from_str(&args.scan_id)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid scan ID: {}", e)))?,
    );

    // Get template
    let storage = get_history_storage(&ctx);

    let template_opt = storage.get_report_template(&args.name).await?;

    let template = template_opt
        .ok_or_else(|| CliError::NotFound(format!("Report template '{}' not found", args.name)))?;

    // Get scan summary
    let scan_summary_opt = storage.get_scan_summary(&scan_id).await?;

    let scan_summary = scan_summary_opt
        .ok_or_else(|| CliError::NotFound(format!("Scan with ID '{}' not found", args.scan_id)))?;

    // Create a report config with the custom template
    let mut config = ReportConfig::default();
    config.custom_template = Some(template.content.clone());

    // Generate report using the template
    // For simplicity, we'll create a basic report with just the scan summary
    // In a full implementation, we would need to gather all the findings and scan info
    // This is a simplified version for demonstration

    // Create a mock report for demonstration purposes
    // In a real implementation, we would use the actual scan data
    let report = create_mock_report_from_scan_summary(&scan_summary);

    // Render report using the template
    let generator = openre_core::reporting::ReportGenerator::new(config);
    let rendered = generator.render(&report, template.format);

    // Output the rendered report
    if let Some(path) = args.output {
        std::fs::write(&path, rendered)?;
        println!("{} Report generated and saved to {}", "✓".green().bold(), path.display());
    } else {
        // Print to stdout
        println!("{}", rendered);
    }

    Ok(())
}

// Helper struct for table display
#[derive(tabled::Tabled)]
struct ReportTemplateRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "FORMAT")]
    format: String,
    #[tabled(rename = "CONTENT PREVIEW")]
    content_preview: String,
    #[tabled(rename = "CREATED AT")]
    created_at: String,
}

// Mock function to create a report from a scan summary
// In a real implementation, this would use actual scan data
fn create_mock_report_from_scan_summary(
    _scan_summary: &openre_core::history::ScanSummary,
) -> openre_core::reporting::Report {
    // This is a simplified mock implementation
    // In a real implementation, we would need to:
    // 1. Get the actual findings for the scan
    // 2. Get scan information
    // 3. Build a proper report

    // For now, we'll create a minimal report
    use chrono::Utc;
    use openre_core::app_map::TargetInfo;
    use openre_core::ids::{ProjectId, ScanId, TargetId};
    use openre_core::reporting::{Report, ReportConfig, ReportFormat, ReportMetadata};
    use openre_core::result::FindingStats;

    Report {
        metadata: ReportMetadata {
            id: Uuid::new_v4().to_string(),
            title: "Scan Report".to_string(),
            generated_at: Utc::now(),
            generator_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_ids: vec![ScanId::new()],
            project_id: Some(ProjectId::new()),
            targets: vec![TargetInfo {
                id: TargetId::new(),
                base_url: "example.com".to_string(),
                target_type: "web".to_string(),
                scan_id: ScanId::new(),
                created_at: Utc::now(),
                tags: vec![],
            }],
            date_range: None,
            format: ReportFormat::Markdown,
            config: ReportConfig::default(),
        },
        executive_summary: None,
        findings_by_group: HashMap::new(),
        all_findings: vec![],
        statistics: FindingStats {
            total: 0,
            by_severity: HashMap::new(),
            by_confidence: HashMap::new(),
            by_category: HashMap::new(),
            by_plugin: HashMap::new(),
            verified: 0,
            false_positives: 0,
            avg_risk_score: 0.0,
            max_risk_score: 0,
            by_owasp_category: HashMap::new(),
            by_cwe: HashMap::new(),
            avg_advanced_risk_score: 0.0,
            max_advanced_risk_score: 0,
            by_remediation_priority: HashMap::new(),
            exploit_available_count: 0,
            exploited_in_wild_count: 0,
        },
        scan_comparison: None,
        appendices: vec![],
    }
}
