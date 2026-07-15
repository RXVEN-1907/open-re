//! Function commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use openre_core::ids::FunctionId;
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

#[derive(Subcommand)]
pub enum FunctionCommands {
    /// List functions
    List {
        #[arg(short, long, default_value = "1")]
        page: u32,
        
        #[arg(short, long, default_value = "50")]
        per_page: u32,
        
        #[arg(long)]
        project_id: Option<String>,
        
        #[arg(long)]
        file_id: Option<String>,
        
        #[arg(long)]
        name: Option<String>,
    },
    
    /// Get function details
    Get {
        #[arg(short, long)]
        id: String,
    },
    
    /// Get pseudocode
    Pseudocode {
        #[arg(short, long)]
        id: String,
    },
    
    /// Get CFG
    Cfg {
        #[arg(short, long)]
        id: String,
    },
    
    /// Get xrefs
    Xrefs {
        #[arg(short, long)]
        id: String,
        
        #[arg(long)]
        direction: Option<String>,
    },
    
    /// Get annotations
    Annotations {
        #[arg(short, long)]
        id: String,
    },
}

impl FunctionCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            FunctionCommands::List { page, per_page, project_id, file_id, name } => {
                let mut url = format!("/api/functions?page={}&per_page={}", page, per_page);
                if let Some(project_id) = project_id {
                    url.push_str(&format!("&project_id={}", project_id));
                }
                if let Some(file_id) = file_id {
                    url.push_str(&format!("&file_id={}", file_id));
                }
                if let Some(name) = name {
                    url.push_str(&format!("&name={}", urlencoding::encode(&name)));
                }
                
                let response = ctx.get(&url).await?;
                let list: FunctionListResponse = response.json().await?;
                print_output(&list.functions, &ctx.output_format)?;
                println!("Page {} of {} (total: {})", list.page, (list.total + list.per_page - 1) / list.per_page, list.total);
            }
            
            FunctionCommands::Get { id } => {
                let response = ctx.get(&format!("/api/functions/{}", id)).await?;
                let function: FunctionResponse = response.json().await?;
                print_output(&function, &ctx.output_format)?;
            }
            
            FunctionCommands::Pseudocode { id } => {
                let response = ctx.get(&format!("/api/functions/{}/pseudocode", id)).await?;
                let pseudocode: PseudocodeResponse = response.json().await?;
                println!("{}", pseudocode.pseudocode);
            }
            
            FunctionCommands::Cfg { id } => {
                let response = ctx.get(&format!("/api/functions/{}/cfg", id)).await?;
                let cfg: CfgResponse = response.json().await?;
                print_output(&cfg, &ctx.output_format)?;
            }
            
            FunctionCommands::Xrefs { id, direction } => {
                let mut url = format!("/api/functions/{}/xrefs", id);
                if let Some(direction) = direction {
                    url.push_str(&format!("?direction={}", direction));
                }
                
                let response = ctx.get(&url).await?;
                let xrefs: XrefResponse = response.json().await?;
                print_output(&xrefs.xrefs, &ctx.output_format)?;
            }
            
            FunctionCommands::Annotations { id } => {
                let response = ctx.get(&format!("/api/functions/{}/annotations", id)).await?;
                let annotations: AnnotationsResponse = response.json().await?;
                print_output(&annotations.annotations, &ctx.output_format)?;
            }
        }
        
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctionListResponse {
    pub functions: Vec<FunctionResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct FunctionResponse {
    pub id: FunctionId,
    pub file_id: String,
    pub name: String,
    pub address: u64,
    pub size: u32,
    pub is_entry: bool,
    pub is_thunk: bool,
    pub calling_convention: Option<String>,
    pub return_type: Option<String>,
    pub parameters: Vec<ParameterInfo>,
    pub stack_frame_size: Option<u32>,
    pub cyclomatic_complexity: Option<u32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ParameterInfo {
    pub name: String,
    pub type_: String,
    pub location: String,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct PseudocodeResponse {
    pub function_id: FunctionId,
    pub pseudocode: String,
    pub language: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct CfgResponse {
    pub function_id: FunctionId,
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct CfgNode {
    pub id: String,
    pub address: u64,
    pub instructions: Vec<String>,
    pub is_entry: bool,
    pub is_exit: bool,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct CfgEdge {
    pub from: String,
    pub to: String,
    pub type_: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct XrefResponse {
    pub function_id: FunctionId,
    pub xrefs: Vec<XrefInfo>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct XrefInfo {
    pub from_address: u64,
    pub to_address: u64,
    pub type_: String,
    pub from_function: Option<FunctionId>,
    pub to_function: Option<FunctionId>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnnotationsResponse {
    pub function_id: FunctionId,
    pub annotations: Vec<AnnotationInfo>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnnotationInfo {
    pub id: String,
    pub type_: String,
    pub content: String,
    pub address: Option<u64>,
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}