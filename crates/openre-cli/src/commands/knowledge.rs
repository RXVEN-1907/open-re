//! Security Knowledge command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::FindingId;
use openre_core::risk_knowledge::{
    CapecEntry, CveEntry, CweEntry, MitreAttackEntry, OwaspEntry, SecurityKnowledgeBase,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct KnowledgeCommand {
    /// Finding ID to look up knowledge for
    #[arg(value_name = "FINDING_ID")]
    finding_id: String,

    /// Include CWE information
    #[arg(long)]
    cwe: bool,

    /// Include OWASP information
    #[arg(long)]
    owasp: bool,

    /// Include CAPEC information
    #[arg(long)]
    capec: bool,

    /// Include MITRE ATT&CK information
    #[arg(long)]
    mitre: bool,

    /// Include CVE information
    #[arg(long)]
    cve: bool,

    /// Include all knowledge sources
    #[arg(long)]
    all: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    output: KnowledgeOutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum KnowledgeOutputFormat {
    Json,
    Table,
}

#[derive(Debug, Deserialize, Serialize)]
struct KnowledgeResponse {
    finding_id: FindingId,
    cwe_entries: Vec<CweEntry>,
    owasp_entries: Vec<OwaspEntry>,
    capec_entries: Vec<CapecEntry>,
    mitre_attack_entries: Vec<MitreAttackEntry>,
    cve_entries: Vec<CveEntry>,
    secure_coding_guidelines: Vec<SecureCodingGuideline>,
    standards_references: Vec<StandardReference>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SecureCodingGuideline {
    title: String,
    description: String,
    examples: std::collections::HashMap<String, String>,
    references: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct StandardReference {
    standard: String,
    controls: Vec<String>,
    url: Option<String>,
}

impl KnowledgeCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let finding_id = FindingId::from_str(&self.finding_id).map_err(|_| {
            CliError::InvalidInput(format!("Invalid finding ID: {}", self.finding_id))
        })?;

        // Determine which knowledge sources to fetch
        let mut sources = Vec::new();
        if self.all || self.cwe {
            sources.push("cwe");
        }
        if self.all || self.owasp {
            sources.push("owasp");
        }
        if self.all || self.capec {
            sources.push("capec");
        }
        if self.all || self.mitre {
            sources.push("mitre");
        }
        if self.all || self.cve {
            sources.push("cve");
        }

        if sources.is_empty() {
            // Default to all if none specified
            sources = vec!["cwe", "owasp", "capec", "mitre", "cve"];
        }

        // Fetch knowledge from API
        let mut url = format!("/api/findings/{}/knowledge", finding_id);
        if !sources.is_empty() {
            url.push_str(&format!("?sources={}", sources.join(",")));
        }

        let response = ctx.get(&url).await?;
        let data: KnowledgeResponse = response.json().await?;

        match self.output {
            KnowledgeOutputFormat::Table => self.print_table(&data),
            KnowledgeOutputFormat::Json => print_output(&data, &OutputFormat::Json)?,
        }

        Ok(())
    }

    fn print_table(&self, data: &KnowledgeResponse) {
        println!(
            "\n{}",
            format!("Security Knowledge for Finding {}", data.finding_id).bold().underline()
        );

        // CWE
        if !data.cwe_entries.is_empty() {
            println!("\n{}", "CWE (Common Weakness Enumeration):".bold());
            for entry in &data.cwe_entries {
                println!("  {} - {}", entry.cwe_id.bold(), entry.name);
                println!("    {}", entry.description);
                if !entry.mitigations.is_empty() {
                    println!("    Mitigations: {}", entry.mitigations.join(", "));
                }
            }
        }

        // OWASP
        if !data.owasp_entries.is_empty() {
            println!("\n{}", "OWASP Top 10:".bold());
            for entry in &data.owasp_entries {
                println!("  {} ({}) - {}", entry.category.bold(), entry.year, entry.name);
                println!("    {}", entry.description);
                if !entry.prevention.is_empty() {
                    println!("    Prevention: {}", entry.prevention.join("; "));
                }
            }
        }

        // CAPEC
        if !data.capec_entries.is_empty() {
            println!("\n{}", "CAPEC (Common Attack Pattern Enumeration):".bold());
            for entry in &data.capec_entries {
                println!("  {} - {}", entry.capec_id.bold(), entry.name);
                println!("    Likelihood: {:?}, Severity: {:?}", entry.likelihood, entry.severity);
                println!("    {}", entry.description);
                if !entry.mitigations.is_empty() {
                    println!("    Mitigations: {}", entry.mitigations.join(", "));
                }
            }
        }

        // MITRE ATT&CK
        if !data.mitre_attack_entries.is_empty() {
            println!("\n{}", "MITRE ATT&CK:".bold());
            for entry in &data.mitre_attack_entries {
                println!(
                    "  {} - {} ({})",
                    entry.technique_id.bold(),
                    entry.technique_name,
                    entry.tactic
                );
                if let Some(sub) = &entry.sub_technique {
                    println!("    Sub-technique: {}", sub);
                }
                println!("    {}", entry.description);
                if !entry.detection.is_empty() {
                    println!("    Detection: {}", entry.detection.join("; "));
                }
                if !entry.mitigation.is_empty() {
                    println!("    Mitigation: {}", entry.mitigation.join("; "));
                }
            }
        }

        // CVE
        if !data.cve_entries.is_empty() {
            println!("\n{}", "CVE (Common Vulnerabilities and Exposures):".bold());
            for entry in &data.cve_entries {
                println!(
                    "  {} - {} (CVSS: {:?})",
                    entry.cve_id.bold(),
                    entry.description,
                    entry.cvss_v3_score
                );
                println!("    Severity: {:?}", entry.severity);
                if entry.exploit_available {
                    println!("    {} Exploit available", "⚠".yellow());
                }
                if entry.patch_available {
                    println!("    {} Patch available", "✓".green());
                }
            }
        }

        // Secure Coding Guidelines
        if !data.secure_coding_guidelines.is_empty() {
            println!("\n{}", "Secure Coding Guidelines:".bold());
            for guideline in &data.secure_coding_guidelines {
                println!("  {}", guideline.title.bold());
                println!("    {}", guideline.description);
                for (lang, example) in &guideline.examples {
                    println!("    {} example: {}", lang, example);
                }
            }
        }

        // Standards References
        if !data.standards_references.is_empty() {
            println!("\n{}", "Standards References:".bold());
            for reference in &data.standards_references {
                println!("  {}: {}", reference.standard.bold(), reference.controls.join(", "));
                if let Some(url) = &reference.url {
                    println!("    URL: {}", url);
                }
            }
        }
    }
}

/// Type alias for compatibility with main.rs imports
pub type KnowledgeCommands = KnowledgeCommand;

