//! Verification command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::evidence::{
    VerificationEvidence, VerificationMethod, VerificationResult, VerificationStatus,
};
use openre_core::ids::{FindingId, ScanId, VerificationId};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct VerifyCommand {
    /// Scan ID containing findings to verify
    #[arg(value_name = "SCAN_ID")]
    scan_id: String,

    /// Specific finding ID to verify (optional, verify all if not provided)
    #[arg(short, long)]
    finding_id: Option<String>,

    /// Verify all findings in the scan
    #[arg(long)]
    all: bool,

    /// Only run safe (non-destructive) verification methods
    #[arg(long, default_value = "true")]
    safe_only: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    output: VerifyOutputFormat,

    /// Request timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Maximum concurrent verifications
    #[arg(long, default_value = "10")]
    max_concurrent: usize,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VerifyOutputFormat {
    Json,
    Table,
    Summary,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerificationResponse {
    verification_id: VerificationId,
    finding_id: FindingId,
    status: VerificationStatus,
    evidence: VerificationEvidence,
    confidence: f32,
    notes: String,
    verified_at: chrono::DateTime<chrono::Utc>,
    verified_by: String,
    method_used: VerificationMethod,
    duration_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct ScanVerificationResponse {
    scan_id: ScanId,
    results: Vec<VerificationResponse>,
    summary: VerificationSummary,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerificationSummary {
    total_verified: usize,
    confirmed: usize,
    likely: usize,
    unconfirmed: usize,
    not_reproducible: usize,
    errors: usize,
    average_confidence: f32,
    total_duration_ms: u64,
}

impl VerifyCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let scan_id = ScanId::from_str(&self.scan_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid scan ID: {}", self.scan_id)))?;

        // Build request payload
        let mut payload = serde_json::json!({
            "safe_only": self.safe_only,
            "timeout_seconds": self.timeout,
            "max_concurrent": self.max_concurrent,
        });

        if let Some(finding_id) = &self.finding_id {
            payload["finding_id"] = serde_json::json!(finding_id);
        } else if self.all {
            payload["verify_all"] = serde_json::json!(true);
        } else {
            return Err(CliError::InvalidInput("Must specify --finding-id or --all".to_string()));
        }

        // Trigger verification
        let response = ctx.post(&format!("/api/scans/{}/verify", scan_id), &payload).await?;
        let data: ScanVerificationResponse = response.json().await?;

        match self.output {
            VerifyOutputFormat::Table => self.print_table(&data.results, &data.summary),
            VerifyOutputFormat::Json => print_output(&data.results, &OutputFormat::Json)?,
            VerifyOutputFormat::Summary => self.print_summary(&data.summary),
        }

        Ok(())
    }

    fn print_table(&self, results: &[VerificationResponse], summary: &VerificationSummary) {
        println!(
            "\n{}",
            format!("Verification Results (Scan: {})", results.len()).bold().underline()
        );

        if results.is_empty() {
            println!("No verification results.");
            return;
        }

        let mut builder = tabled::builder::Builder::default();
        builder.push_record(vec![
            "Finding ID".to_string(),
            "Status".to_string(),
            "Confidence".to_string(),
            "Method".to_string(),
            "Duration (ms)".to_string(),
            "Notes".to_string(),
        ]);

        for result in results {
            let status_str = format_status(&result.status);
            let method_str = format_method(&result.method_used);
            let notes = if result.notes.len() > 60 {
                format!("{}...", &result.notes[..57])
            } else {
                result.notes.clone()
            };

            builder.push_record(vec![
                result.finding_id.to_string(),
                status_str,
                format!("{:.2}", result.confidence),
                method_str,
                result.duration_ms.to_string(),
                notes,
            ]);
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);

        // Print summary
        self.print_summary(summary);
    }

    fn print_summary(&self, summary: &VerificationSummary) {
        println!("\n{}", "Verification Summary:".bold());
        println!("  Total verified: {}", summary.total_verified);
        println!("  {} Confirmed", "✓".green());
        println!("  {} Likely", "~".yellow());
        println!("  {} Unconfirmed", "?".blue());
        println!("  {} Not Reproducible", "✗".red());
        println!("  {} Errors", "✗".red());
        println!("  Average confidence: {:.2}", summary.average_confidence);
        println!("  Total duration: {}ms", summary.total_duration_ms);
    }
}

fn format_status(status: &VerificationStatus) -> String {
    match status {
        VerificationStatus::Confirmed => format!("{} Confirmed", "✓".green()),
        VerificationStatus::Likely => format!("{} Likely", "~".yellow()),
        VerificationStatus::Unconfirmed => format!("{} Unconfirmed", "?".blue()),
        VerificationStatus::NotReproducible => format!("{} Not Reproducible", "✗".red()),
        VerificationStatus::Error => format!("{} Error", "✗".red()),
        VerificationStatus::Skipped => format!("{} Skipped", "-".dimmed()),
    }
}

fn format_method(method: &VerificationMethod) -> String {
    match method {
        VerificationMethod::SafeRequest { method, path, .. } => {
            format!("SafeRequest({} {})", method, path)
        }
        VerificationMethod::HeaderCheck { headers } => {
            format!("HeaderCheck({} headers)", headers.len())
        }
        VerificationMethod::StatusCodeCheck { expected } => {
            format!("StatusCodeCheck({:?})", expected)
        }
        VerificationMethod::BodyPatternCheck { patterns } => {
            format!("BodyPatternCheck({})", patterns.join(", "))
        }
        VerificationMethod::DifferentialCheck { baseline, modified } => {
            format!("Differential({} vs {})", baseline, modified)
        }
        VerificationMethod::ConfigurationCheck { config_key, expected } => {
            format!("ConfigurationCheck({}={})", config_key, expected)
        }
        VerificationMethod::VersionCheck { technology, min_version, max_version } => {
            format!("VersionCheck({}>={}{})", technology, min_version, max_version.as_ref().map(|v| format!("<{}", v)).unwrap_or_default())
        }
        VerificationMethod::RateLimitCheck { endpoint, requests, window_seconds } => {
            format!("RateLimit({} {} req/{}s)", endpoint, requests, window_seconds)
        }
        VerificationMethod::CorsCheck { origins, endpoint } => {
            format!("CORS({} -> {})", origins.join(", "), endpoint)
        }
        VerificationMethod::DirectoryListingCheck { path } => {
            format!("DirListing({})", path)
        }
        VerificationMethod::AuthenticationCheck { method, endpoint } => {
            format!("AuthenticationCheck({} on {})", method, endpoint)
        }
        VerificationMethod::SslTlsCheck { endpoint } => {
            format!("SslTlsCheck({})", endpoint)
        }
        VerificationMethod::Custom { description, .. } => {
            format!("Custom({})", description)
        }
    }
}

/// Type alias for compatibility with main.rs imports
pub type VerifyCommands = VerifyCommand;

