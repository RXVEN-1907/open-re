//! Security Analyst CLI commands
//!
//! CLI interface for the AI-powered security analyst that interprets,
//! correlates, explains, prioritizes, and assists with security scan findings.

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};

#[derive(Subcommand)]
pub enum AnalystCommands {
    /// Explain a security finding
    Explain {
        /// Scan ID containing the finding
        #[arg(short, long)]
        scan_id: String,

        /// Finding ID to explain
        #[arg(short, long)]
        finding_id: String,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },

    /// Generate remediation plan for a finding
    Remediate {
        /// Scan ID containing the finding
        #[arg(short, long)]
        scan_id: String,

        /// Finding ID to remediate
        #[arg(short, long)]
        finding_id: String,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },

    /// Correlate findings to identify relationships
    Correlate {
        /// Scan ID to analyze
        #[arg(short, long)]
        scan_id: String,

        /// Filter by severity (comma-separated)
        #[arg(long, value_delimiter = ',')]
        severity: Option<Vec<String>>,

        /// Filter by category (comma-separated)
        #[arg(long, value_delimiter = ',')]
        category: Option<Vec<String>>,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },

    /// Prioritize findings for remediation
    Prioritize {
        /// Scan ID to prioritize
        #[arg(short, long)]
        scan_id: String,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },

    /// Generate executive summary for different audiences
    Summarize {
        /// Scan ID to summarize
        #[arg(short, long)]
        scan_id: String,

        /// Target audience for the summary
        #[arg(short, long, value_enum)]
        audience: SummaryAudience,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },

    /// Query findings with natural language
    Query {
        /// Scan ID to query
        #[arg(short, long)]
        scan_id: String,

        /// Natural language question
        #[arg(short, long)]
        question: String,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },

    /// Compare two scans for changes
    Compare {
        /// Base scan ID for comparison
        #[arg(long)]
        base_scan_id: String,

        /// Target scan ID for comparison
        #[arg(long)]
        target_scan_id: String,

        /// Stream the response
        #[arg(long)]
        stream: bool,
    },
}

/// Target audience for summaries
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum SummaryAudience {
    Developer,
    SecurityEngineer,
    Manager,
    Executive,
}

impl AnalystCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            AnalystCommands::Explain {
                scan_id,
                finding_id,
                stream,
            } => {
                if stream {
                    if ctx.is_offline() {
                        return Err(CliError::InvalidInput("Streaming not supported in offline mode. Use --no-stream flag.".to_string()));
                    }
                    let client = ctx.client()?;
                    let response = client
                        .get(&format!("{}/api/analyst/explain/stream", ctx.server_url()))
                        .query(&[("scan_id", &scan_id), ("finding_id", &finding_id)])
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(content) = json.as_str() {
                                print!("{}", content);
                                use std::io::{self, Write};
                                io::stdout().flush()?;
                            }
                        }
                    }
                    println!();
                } else {
                    let payload = serde_json::json!({
                        "scan_id": scan_id,
                        "finding_id": finding_id,
                    });

                    let response = ctx.post("/api/analyst/explain", &payload).await?;
                    let result: FindingExplanationResponse = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }

            AnalystCommands::Remediate {
                scan_id,
                finding_id,
                stream,
            } => {
                let payload = serde_json::json!({
                    "scan_id": scan_id,
                    "finding_id": finding_id,
                });

                if stream {
                    // For remediation, streaming might not be as useful, but we'll implement it
                    let client = ctx.client()?;
                    let response = client
                        .post(&format!("{}/api/analyst/remediate/stream", ctx.server_url()))
                        .json(&payload)
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                            if let Some(content) = json.as_str() {
                                print!("{}", content);
                                use std::io::{self, Write};
                                io::stdout().flush()?;
                            }
                        }
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/analyst/remediate", &payload).await?;
                    let result: RemediationPlanResponse = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }

            AnalystCommands::Correlate {
                scan_id,
                severity,
                category,
                stream,
            } => {
                let mut filter = serde_json::Map::new();
                if let Some(sev) = severity {
                    filter.insert(
                        "severity".to_string(),
                        serde_json::Value::Array(
                            sev.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                }
                if let Some(cat) = category {
                    filter.insert(
                        "category".to_string(),
                        serde_json::Value::Array(
                            cat.into_iter().map(serde_json::Value::String).collect(),
                        ),
                    );
                }

                let payload = serde_json::json!({
                    "scan_id": scan_id,
                    "filter": if filter.is_empty() { None } else { Some(filter) },
                });

                if stream {
                    if ctx.is_offline() {
                        return Err(CliError::InvalidInput("Streaming not supported in offline mode. Use --no-stream flag.".to_string()));
                    }
                    let client = ctx.client()?;
                    let response = client
                        .get(&format!("{}/api/analyst/correlate/stream", ctx.server_url()))
                        .query(&[("scan_id", &scan_id)])
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        print!("{}", text);
                        use std::io::{self, Write};
                        io::stdout().flush()?;
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/analyst/correlate", &payload).await?;
                    let result: CorrelationReportResponse = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }

            AnalystCommands::Prioritize { scan_id, stream } => {
                let payload = serde_json::json!({
                    "scan_id": scan_id,
                });

                if stream {
                    if ctx.is_offline() {
                        return Err(CliError::InvalidInput("Streaming not supported in offline mode. Use --no-stream flag.".to_string()));
                    }
                    let client = ctx.client()?;
                    let response = client
                        .get(&format!("{}/api/analyst/prioritize/stream", ctx.server_url()))
                        .query(&[("scan_id", &scan_id)])
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        print!("{}", text);
                        use std::io::{self, Write};
                        io::stdout().flush()?;
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/analyst/prioritize", &payload).await?;
                    let result: PrioritizedFindingsResponse = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }

            AnalystCommands::Summarize {
                scan_id,
                audience,
                stream,
            } => {
                let payload = serde_json::json!({
                    "scan_id": scan_id,
                    "audience": format!("{:?}", audience).to_lowercase(),
                });

                if stream {
                    if ctx.is_offline() {
                        return Err(CliError::InvalidInput("Streaming not supported in offline mode. Use --no-stream flag.".to_string()));
                    }
                    let client = ctx.client()?;
                    let response = client
                        .get(&format!("{}/api/analyst/summarize/stream", ctx.server_url()))
                        .query(&[
                            ("scan_id", &scan_id),
                            ("audience", &format!("{:?}", audience).to_lowercase()),
                        ])
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        print!("{}", text);
                        use std::io::{self, Write};
                        io::stdout().flush()?;
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/analyst/summarize", &payload).await?;
                    let result: ExecutiveSummaryResponse = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }

            AnalystCommands::Query {
                scan_id,
                question,
                stream,
            } => {
                let payload = serde_json::json!({
                    "scan_id": scan_id,
                    "question": question,
                });

                if stream {
                    if ctx.is_offline() {
                        return Err(CliError::InvalidInput("Streaming not supported in offline mode. Use --no-stream flag.".to_string()));
                    }
                    let client = ctx.client()?;
                    let response = client
                        .get(&format!("{}/api/analyst/query/stream", ctx.server_url()))
                        .query(&[("scan_id", &scan_id), ("question", &question)])
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        print!("{}", text);
                        use std::io::{self, Write};
                        io::stdout().flush()?;
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/analyst/query", &payload).await?;
                    let result: QueryResponseResult = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }

            AnalystCommands::Compare {
                base_scan_id,
                target_scan_id,
                stream,
            } => {
                let payload = serde_json::json!({
                    "base_scan_id": base_scan_id,
                    "target_scan_id": target_scan_id,
                });

                if stream {
                    if ctx.is_offline() {
                        return Err(CliError::InvalidInput("Streaming not supported in offline mode. Use --no-stream flag.".to_string()));
                    }
                    let client = ctx.client()?;
                    let response = client
                        .get(&format!("{}/api/analyst/compare/stream", ctx.server_url()))
                        .query(&[
                            ("base_scan_id", &base_scan_id),
                            ("target_scan_id", &target_scan_id),
                        ])
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        print!("{}", text);
                        use std::io::{self, Write};
                        io::stdout().flush()?;
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/analyst/compare", &payload).await?;
                    let result: ScanComparisonResponse = response.json().await?;
                    print_output(&result, &ctx.output_format)?;
                }
            }
        }

        Ok(())
    }
}

// Response types for CLI output

#[derive(Debug, Deserialize, Serialize)]
pub struct FindingExplanationResponse {
    pub finding_id: String,
    pub root_cause: String,
    pub security_impact: String,
    pub attack_scenarios: String, // Simplified for CLI display
    pub confidence: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RemediationPlanResponse {
    pub finding_id: String,
    pub summary: String,
    pub steps_count: usize,
    pub effort: String,
    pub priority: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CorrelationReportResponse {
    pub scan_id: String,
    pub correlations_count: usize,
    pub risk_assessment: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrioritizedFindingsResponse {
    pub scan_id: String,
    pub findings_count: usize,
    pub rationale: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ExecutiveSummaryResponse {
    pub scan_id: String,
    pub audience: String,
    pub key_findings_count: usize,
    pub risk_assessment: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct QueryResponseResult {
    pub question: String,
    pub answer: String,
    pub supporting_findings_count: usize,
    pub confidence: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScanComparisonResponse {
    pub base_scan_id: String,
    pub target_scan_id: String,
    pub new_findings_count: usize,
    pub fixed_findings_count: usize,
    pub summary: String,
}
