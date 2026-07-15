//! Analysis commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use openre_core::ids::JobId;
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

#[derive(Subcommand)]
pub enum AnalysisCommands {
    /// Start analysis
    Start {
        #[arg(short, long)]
        file_id: String,
        
        #[arg(short, long, num_args = 1..)]
        stages: Vec<String>,
        
        #[arg(long)]
        priority: Option<String>,
    },
    
    /// Get analysis status
    Status {
        #[arg(short, long)]
        id: String,
    },
    
    /// Get analysis results
    Results {
        #[arg(short, long)]
        id: String,
    },
    
    /// Cancel analysis
    Cancel {
        #[arg(short, long)]
        id: String,
    },
    
    /// Retry analysis
    Retry {
        #[arg(short, long)]
        id: String,
    },
    
    /// List analyses
    List {
        #[arg(short, long, default_value = "1")]
        page: u32,
        
        #[arg(short, long, default_value = "50")]
        per_page: u32,
        
        #[arg(long)]
        status: Option<String>,
    },
}

impl AnalysisCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            AnalysisCommands::Start { file_id, stages, priority } => {
                let response = ctx.post("/api/analysis", &serde_json::json!({
                    "file_id": file_id,
                    "stages": stages,
                    "priority": priority,
                })).await?;
                
                let analysis: AnalysisResponse = response.json().await?;
                print_output(&analysis, &ctx.output_format)?;
                println!("Analysis started!");
            }
            
            AnalysisCommands::Status { id } => {
                let response = ctx.get(&format!("/api/analysis/{}", id)).await?;
                let status: AnalysisStatusResponse = response.json().await?;
                print_output(&status, &ctx.output_format)?;
            }
            
            AnalysisCommands::Results { id } => {
                let response = ctx.get(&format!("/api/analysis/{}/results", id)).await?;
                let results: AnalysisResultsResponse = response.json().await?;
                print_output(&results, &ctx.output_format)?;
            }
            
            AnalysisCommands::Cancel { id } => {
                let response = ctx.post(&format!("/api/analysis/{}/cancel", id), &serde_json::json!({})).await?;
                let cancel: CancelResponse = response.json().await?;
                if cancel.cancelled {
                    println!("Analysis cancelled successfully!");
                } else {
                    println!("Analysis was not running or already completed.");
                }
            }
            
            AnalysisCommands::Retry { id } => {
                let response = ctx.post(&format!("/api/analysis/{}/retry", id), &serde_json::json!({})).await?;
                let analysis: AnalysisResponse = response.json().await?;
                print_output(&analysis, &ctx.output_format)?;
                println!("Analysis retried!");
            }
            
            AnalysisCommands::List { page, per_page, status } => {
                let mut url = format!("/api/analysis?page={}&per_page={}", page, per_page);
                if let Some(status) = status {
                    url.push_str(&format!("&status={}", status));
                }
                
                let response = ctx.get(&url).await?;
                let list: AnalysisListResponse = response.json().await?;
                print_output(&list.analyses, &ctx.output_format)?;
                println!("Page {} of {} (total: {})", list.page, (list.total + list.per_page - 1) / list.per_page, list.total);
            }
        }
        
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnalysisResponse {
    pub job_id: JobId,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnalysisStatusResponse {
    pub job_id: JobId,
    pub job_type: String,
    pub status: String,
    pub progress: Option<f32>,
    pub current_stage: Option<String>,
    pub stages_completed: u32,
    pub total_stages: u32,
    pub error: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnalysisResultsResponse {
    pub job_id: JobId,
    pub result: serde_json::Value,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct CancelResponse {
    pub job_id: JobId,
    pub cancelled: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnalysisListResponse {
    pub analyses: Vec<AnalysisSummary>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnalysisSummary {
    pub job_id: JobId,
    pub job_type: String,
    pub status: String,
    pub progress: Option<f32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}