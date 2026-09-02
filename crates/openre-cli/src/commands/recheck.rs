//! Recheck command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::{FindingId, RecheckId, ScanId};
use openre_core::remediation::{
    RecheckFrequency, RecheckStatus, RemediationStatusType, ScheduledRecheck,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct RecheckCommand {
    /// Scan ID containing the finding
    #[arg(value_name = "SCAN_ID")]
    scan_id: String,

    /// Finding ID to recheck
    #[arg(value_name = "FINDING_ID")]
    finding_id: String,

    /// Schedule recurring rechecks
    #[arg(long)]
    schedule: bool,

    /// Recheck frequency (when scheduling)
    #[arg(long, value_enum, default_value = "weekly")]
    frequency: RecheckFrequencyArg,

    /// Maximum retries for scheduled rechecks
    #[arg(long, default_value = "3")]
    max_retries: u32,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    output: RecheckOutputFormat,

    /// List scheduled rechecks for scan
    #[arg(long)]
    list: bool,

    /// Cancel a scheduled recheck
    #[arg(long)]
    cancel: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RecheckFrequencyArg {
    Once,
    Daily,
    Weekly,
    Monthly,
    Quarterly,
}

impl From<RecheckFrequencyArg> for RecheckFrequency {
    fn from(f: RecheckFrequencyArg) -> Self {
        match f {
            RecheckFrequencyArg::Once => RecheckFrequency::Once,
            RecheckFrequencyArg::Daily => RecheckFrequency::Daily,
            RecheckFrequencyArg::Weekly => RecheckFrequency::Weekly,
            RecheckFrequencyArg::Monthly => RecheckFrequency::Monthly,
            RecheckFrequencyArg::Quarterly => RecheckFrequency::Quarterly,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RecheckOutputFormat {
    Json,
    Table,
}

#[derive(Debug, Deserialize, Serialize)]
struct RecheckResponse {
    recheck_id: RecheckId,
    finding_id: FindingId,
    scan_id: ScanId,
    status: RemediationStatusType,
    verification_result: Option<VerificationResultResponse>,
    risk_score_before: Option<u8>,
    risk_score_after: Option<u8>,
    verified_at: chrono::DateTime<chrono::Utc>,
    verified_by: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct VerificationResultResponse {
    status: String,
    confidence: f32,
    notes: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ScheduledRecheckResponse {
    rechecks: Vec<ScheduledRecheckInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ScheduledRecheckInfo {
    recheck_id: RecheckId,
    finding_id: FindingId,
    scan_id: ScanId,
    scheduled_at: chrono::DateTime<chrono::Utc>,
    frequency: RecheckFrequency,
    max_retries: u32,
    current_retries: u32,
    status: RecheckStatus,
    last_run: Option<chrono::DateTime<chrono::Utc>>,
    next_run: Option<chrono::DateTime<chrono::Utc>>,
    created_by: String,
}

impl RecheckCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let scan_id = ScanId::from_str(&self.scan_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid scan ID: {}", self.scan_id)))?;
        let finding_id = FindingId::from_str(&self.finding_id).map_err(|_| {
            CliError::InvalidInput(format!("Invalid finding ID: {}", self.finding_id))
        })?;

        // Handle list subcommand
        if self.list {
            return self.list_rechecks(&mut ctx, scan_id).await;
        }

        // Handle cancel subcommand
        if let Some(ref recheck_id_str) = self.cancel {
            let recheck_id = RecheckId::from_str(recheck_id_str).map_err(|_| {
                CliError::InvalidInput(format!("Invalid recheck ID: {}", recheck_id_str))
            })?;
            return self.cancel_recheck(&mut ctx, recheck_id).await;
        }

        // Trigger immediate recheck
        let payload = serde_json::json!({
            "finding_id": finding_id.to_string(),
            "schedule": self.schedule,
            "frequency": format!("{:?}", self.frequency).to_lowercase(),
            "max_retries": self.max_retries,
        });

        let response = ctx.post(&format!("/api/scans/{}/recheck", scan_id), &payload).await?;
        let data: RecheckResponse = response.json().await?;

        match self.output {
            RecheckOutputFormat::Table => self.print_table(&data),
            RecheckOutputFormat::Json => print_output(&data, &OutputFormat::Json)?,
        }

        Ok(())
    }

    async fn list_rechecks(&self, ctx: &mut Context, scan_id: ScanId) -> Result<(), CliError> {
        let response = ctx.get(&format!("/api/scans/{}/rechecks", scan_id)).await?;
        let data: ScheduledRecheckResponse = response.json().await?;

        println!(
            "\n{}",
            format!("Scheduled Rechecks for Scan {} ({})", scan_id, data.rechecks.len())
                .bold()
                .underline()
        );

        if data.rechecks.is_empty() {
            println!("No scheduled rechecks found.");
            return Ok(());
        }

        let mut builder = tabled::builder::Builder::default();
        builder.push_record(vec![
            "Recheck ID".to_string(),
            "Finding ID".to_string(),
            "Frequency".to_string(),
            "Status".to_string(),
            "Retries".to_string(),
            "Last Run".to_string(),
            "Next Run".to_string(),
        ]);

        for recheck in &data.rechecks {
            let status_str = format_recheck_status(&recheck.status);
            let last_run = recheck
                .last_run
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Never".to_string());
            let next_run = recheck
                .next_run
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "N/A".to_string());

            builder.push_record(vec![
                recheck.recheck_id.to_string(),
                recheck.finding_id.to_string(),
                format!("{:?}", recheck.frequency),
                status_str,
                format!("{}/{}", recheck.current_retries, recheck.max_retries),
                last_run,
                next_run,
            ]);
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);

        Ok(())
    }

    async fn cancel_recheck(
        &self,
        ctx: &mut Context,
        recheck_id: RecheckId,
    ) -> Result<(), CliError> {
        let response = ctx.delete(&format!("/api/rechecks/{}", recheck_id)).await?;

        if response.status().is_success() {
            println!("{} Recheck {} cancelled successfully", "✓".green(), recheck_id);
        } else {
            return Err(CliError::ApiError("Failed to cancel recheck".to_string()));
        }

        Ok(())
    }

    fn print_table(&self, data: &RecheckResponse) {
        println!(
            "\n{}",
            format!("Recheck Result for Finding {}", data.finding_id).bold().underline()
        );

        let status_str = format_remediation_status(&data.status);
        println!("  Recheck ID: {}", data.recheck_id);
        println!("  Finding ID: {}", data.finding_id);
        println!("  Scan ID: {}", data.scan_id);
        println!("  Status: {}", status_str);
        println!(
            "  Risk before: {}",
            data.risk_score_before.map_or("N/A".to_string(), |s| s.to_string())
        );
        println!(
            "  Risk after: {}",
            data.risk_score_after.map_or("N/A".to_string(), |s| s.to_string())
        );
        println!("  Verified at: {}", data.verified_at.format("%Y-%m-%d %H:%M:%S"));
        println!("  Verified by: {}", data.verified_by);

        if let Some(verification) = &data.verification_result {
            println!("\n  Verification:");
            println!("    Status: {}", verification.status);
            println!("    Confidence: {:.2}", verification.confidence);
            println!("    Notes: {}", verification.notes);
        }
    }
}

fn format_remediation_status(status: &RemediationStatusType) -> String {
    match status {
        RemediationStatusType::Fixed => format!("{} Fixed", "✓".green()),
        RemediationStatusType::PartiallyFixed => format!("{} Partially Fixed", "~".yellow()),
        RemediationStatusType::NotFixed => format!("{} Not Fixed", "✗".red()),
        RemediationStatusType::Regressed => format!("{} Regressed", "⚠".red().bold()),
        RemediationStatusType::CannotVerify => format!("{} Cannot Verify", "?".blue()),
        RemediationStatusType::InProgress => format!("{} In Progress", "⟳".yellow()),
        RemediationStatusType::PendingVerification => {
            format!("{} Pending Verification", "⏳".blue())
        }
    }
}

fn format_recheck_status(status: &RecheckStatus) -> String {
    match status {
        RecheckStatus::Scheduled => format!("{} Scheduled", "⏰".blue()),
        RecheckStatus::Running => format!("{} Running", "⟳".yellow()),
        RecheckStatus::Completed => format!("{} Completed", "✓".green()),
        RecheckStatus::Failed => format!("{} Failed", "✗".red()),
        RecheckStatus::Cancelled => format!("{} Cancelled", "⊘".bright_black()),
        RecheckStatus::Skipped => format!("{} Skipped", "⏭".bright_black()),
    }
}

/// Type alias for compatibility with main.rs imports
pub type RecheckCommands = RecheckCommand;

