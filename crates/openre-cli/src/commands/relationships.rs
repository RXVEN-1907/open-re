//! Finding Relationships command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::ids::{FindingId, RelationshipId, ScanId};
use openre_core::relationships::{
    EvidenceSource, EvidenceType, FindingRelationship, FindingRelationshipGraph,
    FindingRelationshipType, RelationshipEvidence, RiskFactor, RiskImpact, RiskLevelChange,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tabled::{settings::Style, Table};

#[derive(Parser)]
pub struct RelationshipsCommand {
    /// Scan ID to analyze relationships for
    #[arg(value_name = "SCAN_ID")]
    scan_id: String,

    /// Filter by specific finding ID
    #[arg(short, long)]
    finding_id: Option<String>,

    /// Filter by relationship type
    #[arg(short, long, value_enum)]
    r#type: Option<RelationshipTypeFilter>,

    /// Minimum confidence threshold (0.0-1.0)
    #[arg(long, default_value = "0.3")]
    min_confidence: f32,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    output: RelationshipOutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RelationshipTypeFilter {
    Enables,
    Amplifies,
    Requires,
    Chain,
    SameRootCause,
    ChainedExploit,
    Mitigates,
    Duplicate,
    SharedComponent,
    SharedAttackSurface,
    InformationLeakage,
    PrivilegeEscalation,
    LateralMovement,
    DataExfiltration,
    Prerequisite,
    MutuallyExclusive,
    Temporal,
    Spatial,
    Custom,
}

impl From<RelationshipTypeFilter> for FindingRelationshipType {
    fn from(f: RelationshipTypeFilter) -> Self {
        match f {
            RelationshipTypeFilter::Enables => FindingRelationshipType::Enables,
            RelationshipTypeFilter::Amplifies => FindingRelationshipType::Amplifies,
            RelationshipTypeFilter::Requires => FindingRelationshipType::Requires,
            RelationshipTypeFilter::Chain => FindingRelationshipType::ChainedExploit,
            RelationshipTypeFilter::SameRootCause => FindingRelationshipType::SameRootCause,
            RelationshipTypeFilter::ChainedExploit => FindingRelationshipType::ChainedExploit,
            RelationshipTypeFilter::Mitigates => FindingRelationshipType::Mitigates,
            RelationshipTypeFilter::Duplicate => FindingRelationshipType::Duplicate,
            RelationshipTypeFilter::SharedComponent => FindingRelationshipType::SharedComponent,
            RelationshipTypeFilter::SharedAttackSurface => {
                FindingRelationshipType::SharedAttackSurface
            }
            RelationshipTypeFilter::InformationLeakage => {
                FindingRelationshipType::InformationLeakage
            }
            RelationshipTypeFilter::PrivilegeEscalation => {
                FindingRelationshipType::PrivilegeEscalation
            }
            RelationshipTypeFilter::LateralMovement => FindingRelationshipType::LateralMovement,
            RelationshipTypeFilter::DataExfiltration => FindingRelationshipType::DataExfiltration,
            RelationshipTypeFilter::Prerequisite => FindingRelationshipType::Prerequisite,
            RelationshipTypeFilter::MutuallyExclusive => FindingRelationshipType::MutuallyExclusive,
            RelationshipTypeFilter::Temporal => FindingRelationshipType::Temporal,
            RelationshipTypeFilter::Spatial => FindingRelationshipType::Spatial,
            RelationshipTypeFilter::Custom => FindingRelationshipType::Custom,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RelationshipOutputFormat {
    Json,
    Table,
    Graph,
    Dot,
    Mermaid,
}

#[derive(Debug, Deserialize, Serialize)]
struct ScanRelationshipResponse {
    scan_id: ScanId,
    relationships: Vec<FindingRelationship>,
    metadata: RelationshipGraphMetadata,
}

#[derive(Debug, Deserialize, Serialize)]
struct RelationshipGraphMetadata {
    total_relationships: usize,
    by_type: HashMap<String, usize>,
    average_confidence: f32,
    max_confidence: f32,
    min_confidence: f32,
    generated_at: chrono::DateTime<chrono::Utc>,
    engine_version: String,
}

impl RelationshipsCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        let scan_id = ScanId::from_str(&self.scan_id)
            .map_err(|_| CliError::InvalidInput(format!("Invalid scan ID: {}", self.scan_id)))?;

        // Fetch relationships from API
        let mut url = format!("/api/scans/{}/relationships", scan_id);
        let mut params = Vec::new();

        if let Some(finding_id) = &self.finding_id {
            params.push(format!("finding_id={}", finding_id));
        }
        if let Some(rel_type) = self.r#type {
            params.push(format!("type={:?}", rel_type));
        }
        params.push(format!("min_confidence={}", self.min_confidence));

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        let response = ctx.get(&url).await?;
        let data: ScanRelationshipResponse = response.json().await?;

        // Filter relationships by confidence
        let relationships: Vec<_> = data
            .relationships
            .into_iter()
            .filter(|r| r.confidence >= self.min_confidence)
            .collect();

        match self.output {
            RelationshipOutputFormat::Table => self.print_table(&relationships, &data.metadata),
            RelationshipOutputFormat::Json => print_output(&relationships, &OutputFormat::Json)?,
            RelationshipOutputFormat::Graph => self.print_graph(&relationships),
            RelationshipOutputFormat::Dot => self.print_dot(&relationships),
            RelationshipOutputFormat::Mermaid => self.print_mermaid(&relationships),
        }

        Ok(())
    }

    fn print_table(
        &self,
        relationships: &[FindingRelationship],
        metadata: &RelationshipGraphMetadata,
    ) {
        println!(
            "\n{}",
            format!("Finding Relationships for Scan (Total: {})", relationships.len())
                .bold()
                .underline()
        );

        if relationships.is_empty() {
            println!("No relationships found matching criteria.");
            return;
        }

        // Build table
        let mut builder = tabled::builder::Builder::default();
        builder.push_record(vec![
            "ID".to_string(),
            "Source Finding".to_string(),
            "Target Finding".to_string(),
            "Type".to_string(),
            "Confidence".to_string(),
            "Risk Impact".to_string(),
            "Explanation".to_string(),
        ]);

        for rel in relationships {
            let risk_impact =
                format!("{:?} ({:+})", rel.risk_impact.level_change, rel.risk_impact.score_delta);

            let explanation = if rel.explanation.len() > 60 {
                format!("{}...", &rel.explanation[..57])
            } else {
                rel.explanation.clone()
            };

            builder.push_record(vec![
                rel.id.to_string(),
                rel.source_finding.to_string(),
                rel.target_finding.to_string(),
                format!("{:?}", rel.relationship_type),
                format!("{:.2}", rel.confidence),
                risk_impact,
                explanation,
            ]);
        }

        let table = builder.build().with(Style::modern()).to_string();
        println!("{}", table);

        // Print summary
        println!("\n{}", "Summary:".bold());
        println!("  Total relationships: {}", metadata.total_relationships);
        println!("  Average confidence: {:.2}", metadata.average_confidence);
        println!("  By type:");
        for (rel_type, count) in &metadata.by_type {
            println!("    {}: {}", rel_type, count);
        }
    }

    fn print_graph(&self, relationships: &[FindingRelationship]) {
        println!("\n{}", "Relationship Graph (DOT format):".bold());
        let dot = self.build_dot(relationships);
        println!("{}", dot);
    }

    fn print_dot(&self, relationships: &[FindingRelationship]) {
        let dot = self.build_dot(relationships);
        println!("{}", dot);
    }

    fn print_mermaid(&self, relationships: &[FindingRelationship]) {
        let mermaid = self.build_mermaid(relationships);
        println!("{}", mermaid);
    }

    fn build_dot(&self, relationships: &[FindingRelationship]) -> String {
        let mut dot = String::new();
        dot.push_str("digraph FindingRelationships {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled, fillcolor=lightgray];\n");

        // Collect unique findings
        let mut finding_ids = std::collections::HashSet::new();
        for rel in relationships {
            finding_ids.insert(&rel.source_finding);
            finding_ids.insert(&rel.target_finding);
        }

        // Add nodes
        for finding_id in finding_ids {
            dot.push_str(&format!("  finding_{} [label=\"{}\"];\n", finding_id.0, finding_id.0));
        }

        // Add edges with colors
        let type_colors = [
            (FindingRelationshipType::Enables, "green"),
            (FindingRelationshipType::Amplifies, "red"),
            (FindingRelationshipType::Requires, "blue"),
            (FindingRelationshipType::SameRootCause, "purple"),
            (FindingRelationshipType::ChainedExploit, "orange"),
            (FindingRelationshipType::Mitigates, "lightgreen"),
            (FindingRelationshipType::Duplicate, "gray"),
            (FindingRelationshipType::SharedComponent, "lightblue"),
            (FindingRelationshipType::SharedAttackSurface, "yellow"),
            (FindingRelationshipType::InformationLeakage, "lightyellow"),
            (FindingRelationshipType::PrivilegeEscalation, "darkred"),
            (FindingRelationshipType::LateralMovement, "darkblue"),
            (FindingRelationshipType::DataExfiltration, "darkgreen"),
            (FindingRelationshipType::Prerequisite, "cyan"),
            (FindingRelationshipType::MutuallyExclusive, "pink"),
            (FindingRelationshipType::Temporal, "lightgray"),
            (FindingRelationshipType::Spatial, "lightcyan"),
            (FindingRelationshipType::Custom, "black"),
        ];

        for rel in relationships {
            let color = type_colors
                .iter()
                .find(|(t, _)| *t == rel.relationship_type)
                .map(|(_, c)| *c)
                .unwrap_or("black");

            let label = format!("{:?}", rel.relationship_type);
            dot.push_str(&format!(
                "  finding_{} -> finding_{} [label=\"{}\", color={}, penwidth={}];\n",
                rel.source_finding.0,
                rel.target_finding.0,
                label,
                color,
                (rel.confidence * 3.0).max(1.0) as u32
            ));
        }

        dot.push_str("}\n");
        dot
    }

    fn build_mermaid(&self, relationships: &[FindingRelationship]) -> String {
        let mut mermaid = String::new();
        mermaid.push_str("graph LR\n");

        // Collect unique findings
        let mut finding_ids = std::collections::HashSet::new();
        for rel in relationships {
            finding_ids.insert(&rel.source_finding);
            finding_ids.insert(&rel.target_finding);
        }

        // Add nodes
        for finding_id in finding_ids {
            mermaid.push_str(&format!("  finding_{}[\"{}\"]\n", finding_id.0, finding_id.0));
        }

        // Add edges
        for rel in relationships {
            let label = format!("{:?}", rel.relationship_type);
            mermaid.push_str(&format!(
                "  finding_{} -->|{}| finding_{}\n",
                rel.source_finding.0, label, rel.target_finding.0
            ));
        }

        mermaid
    }
}

/// Type alias for compatibility with main.rs imports
pub type RelationshipsCommands = RelationshipsCommand;

