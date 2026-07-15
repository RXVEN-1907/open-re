//! File commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use openre_core::ids::FileId;
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Subcommand)]
pub enum FileCommands {
    /// List files
    List {
        #[arg(short, long, default_value = "1")]
        page: u32,
        
        #[arg(short, long, default_value = "50")]
        per_page: u32,
        
        #[arg(long)]
        project_id: Option<String>,
        
        #[arg(long)]
        status: Option<String>,
    },
    
    /// Upload a file
    Upload {
        #[arg(short, long)]
        path: PathBuf,
        
        #[arg(short, long)]
        project_id: Option<String>,
    },
    
    /// Get file details
    Get {
        #[arg(short, long)]
        id: String,
    },
    
    /// Delete file
    Delete {
        #[arg(short, long)]
        id: String,
        
        #[arg(long)]
        force: bool,
    },
    
    /// Download file
    Download {
        #[arg(short, long)]
        id: String,
        
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    
    /// Start analysis
    Analyze {
        #[arg(short, long)]
        id: String,
        
        #[arg(short, long, num_args = 1..)]
        stages: Vec<String>,
        
        #[arg(long)]
        priority: Option<String>,
    },
}

impl FileCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            FileCommands::List { page, per_page, project_id, status } => {
                let mut url = format!("/api/files?page={}&per_page={}", page, per_page);
                if let Some(project_id) = project_id {
                    url.push_str(&format!("&project_id={}", project_id));
                }
                if let Some(status) = status {
                    url.push_str(&format!("&status={}", status));
                }
                
                let response = ctx.get(&url).await?;
                let list: FileListResponse = response.json().await?;
                print_output(&list.files, &ctx.output_format)?;
                println!("Page {} of {} (total: {})", list.page, (list.total + list.per_page - 1) / list.per_page, list.total);
            }
            
            FileCommands::Upload { path, project_id } => {
                if !path.exists() {
                    return Err(CliError::FileNotFound(path.display().to_string()));
                }
                
                let mut file = File::open(&path).await?;
                let mut buffer = Vec::new();
                file.read_to_end(&mut buffer).await?;
                
                let filename = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                
                // Create multipart form
                let form = reqwest::multipart::Form::new()
                    .part("file", reqwest::multipart::Part::bytes(buffer)
                        .file_name(filename.clone())
                        .mime_str("application/octet-stream")?)
                    .part("project_id", reqwest::multipart::Part::text(
                        project_id.unwrap_or_default()
                    ));
                
                let response = ctx.client
                    .post(&format!("{}/api/files", ctx.server_url))
                    .multipart(form)
                    .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                    .send()
                    .await?;
                
                if !response.status().is_success() {
                    let error = response.text().await?;
                    return Err(CliError::ApiError(error));
                }
                
                let file_response: FileResponse = response.json().await?;
                print_output(&file_response, &ctx.output_format)?;
                println!("File uploaded successfully!");
            }
            
            FileCommands::Get { id } => {
                let response = ctx.get(&format!("/api/files/{}", id)).await?;
                let file: FileResponse = response.json().await?;
                print_output(&file, &ctx.output_format)?;
            }
            
            FileCommands::Delete { id, force } => {
                if !force {
                    print!("Are you sure you want to delete file {}? (y/N): ", id);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }
                
                ctx.delete(&format!("/api/files/{}", id)).await?;
                println!("File deleted successfully!");
            }
            
            FileCommands::Download { id, output } => {
                let response = ctx.get(&format!("/api/files/{}/download", id)).await?;
                
                let output_path = output.unwrap_or_else(|| {
                    // Get filename from response headers or use ID
                    PathBuf::from(format!("{}.bin", id))
                });
                
                let bytes = response.bytes().await?;
                tokio::fs::write(&output_path, bytes).await?;
                
                println!("File downloaded to: {}", output_path.display());
            }
            
            FileCommands::Analyze { id, stages, priority } => {
                let response = ctx.post(&format!("/api/files/{}/analysis", id), &serde_json::json!({
                    "stages": stages,
                    "priority": priority,
                })).await?;
                
                let analysis: AnalysisResponse = response.json().await?;
                print_output(&analysis, &ctx.output_format)?;
                println!("Analysis started!");
            }
        }
        
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct FileResponse {
    pub id: FileId,
    pub user_id: String,
    pub project_id: Option<String>,
    pub filename: String,
    pub content_type: String,
    pub size: u64,
    pub object_id: String,
    pub status: String,
    pub hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FileListResponse {
    pub files: Vec<FileResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnalysisResponse {
    pub job_id: String,
    pub status: String,
}