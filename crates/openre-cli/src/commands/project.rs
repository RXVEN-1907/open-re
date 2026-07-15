//! Project commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use openre_core::ids::ProjectId;
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

#[derive(Subcommand)]
pub enum ProjectCommands {
    /// List projects
    List {
        #[arg(short, long, default_value = "1")]
        page: u32,
        
        #[arg(short, long, default_value = "50")]
        per_page: u32,
        
        #[arg(long)]
        search: Option<String>,
    },
    
    /// Create a new project
    Create {
        #[arg(short, long)]
        name: String,
        
        #[arg(short, long)]
        description: Option<String>,
        
        #[arg(long)]
        public: bool,
    },
    
    /// Get project details
    Get {
        #[arg(short, long)]
        id: String,
    },
    
    /// Update project
    Update {
        #[arg(short, long)]
        id: String,
        
        #[arg(short, long)]
        name: Option<String>,
        
        #[arg(short, long)]
        description: Option<String>,
        
        #[arg(long)]
        public: Option<bool>,
    },
    
    /// Delete project
    Delete {
        #[arg(short, long)]
        id: String,
        
        #[arg(long)]
        force: bool,
    },
    
    /// Collaborator management
    #[command(subcommand)]
    Collaborator(CollaboratorCommands),
    
    /// Invite management
    #[command(subcommand)]
    Invite(InviteCommands),
    
    /// Share link management
    #[command(subcommand)]
    Share(ShareCommands),
    
    /// Export project
    Export {
        #[arg(short, long)]
        id: String,
        
        #[arg(short, long)]
        format: String,
        
        #[arg(long)]
        include_files: bool,
        
        #[arg(long)]
        include_analysis: bool,
    },
}

#[derive(Subcommand)]
pub enum CollaboratorCommands {
    /// List collaborators
    List {
        #[arg(short, long)]
        project_id: String,
    },
    
    /// Add collaborator
    Add {
        #[arg(short, long)]
        project_id: String,
        
        #[arg(short, long)]
        user_id: String,
        
        #[arg(short, long)]
        role: String,
    },
    
    /// Remove collaborator
    Remove {
        #[arg(short, long)]
        project_id: String,
        
        #[arg(short, long)]
        user_id: String,
    },
}

#[derive(Subcommand)]
pub enum InviteCommands {
    /// List invites
    List {
        #[arg(short, long)]
        project_id: String,
    },
    
    /// Create invite
    Create {
        #[arg(short, long)]
        project_id: String,
        
        #[arg(short, long)]
        email: String,
        
        #[arg(short, long)]
        role: String,
        
        #[arg(long)]
        expires_at: Option<String>,
    },
    
    /// Revoke invite
    Revoke {
        #[arg(short, long)]
        project_id: String,
        
        #[arg(short, long)]
        invite_id: String,
    },
}

#[derive(Subcommand)]
pub enum ShareCommands {
    /// Create share link
    Create {
        #[arg(short, long)]
        project_id: String,
        
        #[arg(short, long)]
        permission: String,
        
        #[arg(long)]
        expires_at: Option<String>,
        
        #[arg(long)]
        max_uses: Option<u32>,
    },
}

impl ProjectCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ProjectCommands::List { page, per_page, search } => {
                let mut url = format!("/api/projects?page={}&per_page={}", page, per_page);
                if let Some(search) = search {
                    url.push_str(&format!("&search={}", urlencoding::encode(&search)));
                }
                
                let response = ctx.get(&url).await?;
                let list: ProjectListResponse = response.json().await?;
                print_output(&list.projects, &ctx.output_format)?;
                println!("Page {} of {} (total: {})", list.page, (list.total + list.per_page - 1) / list.per_page, list.total);
            }
            
            ProjectCommands::Create { name, description, public } => {
                let response = ctx.post("/api/projects", &serde_json::json!({
                    "name": name,
                    "description": description,
                    "is_public": public,
                })).await?;
                
                let project: ProjectResponse = response.json().await?;
                print_output(&project, &ctx.output_format)?;
                println!("Project created successfully!");
            }
            
            ProjectCommands::Get { id } => {
                let response = ctx.get(&format!("/api/projects/{}", id)).await?;
                let project: ProjectResponse = response.json().await?;
                print_output(&project, &ctx.output_format)?;
            }
            
            ProjectCommands::Update { id, name, description, public } => {
                let mut payload = serde_json::json!({});
                if let Some(name) = name { payload["name"] = serde_json::json!(name); }
                if let Some(description) = description { payload["description"] = serde_json::json!(description); }
                if let Some(public) = public { payload["is_public"] = serde_json::json!(public); }
                
                let response = ctx.put(&format!("/api/projects/{}", id), &payload).await?;
                let project: ProjectResponse = response.json().await?;
                print_output(&project, &ctx.output_format)?;
                println!("Project updated successfully!");
            }
            
            ProjectCommands::Delete { id, force } => {
                if !force {
                    print!("Are you sure you want to delete project {}? (y/N): ", id);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }
                
                ctx.delete(&format!("/api/projects/{}", id)).await?;
                println!("Project deleted successfully!");
            }
            
            ProjectCommands::Collaborator(cmd) => cmd.execute(ctx).await?,
            ProjectCommands::Invite(cmd) => cmd.execute(ctx).await?,
            ProjectCommands::Share(cmd) => cmd.execute(ctx).await?,
            
            ProjectCommands::Export { id, format, include_files, include_analysis } => {
                let response = ctx.post(&format!("/api/projects/{}/export", id), &serde_json::json!({
                    "format": format,
                    "include_files": include_files,
                    "include_analysis": include_analysis,
                })).await?;
                
                let export: ExportResponse = response.json().await?;
                print_output(&export, &ctx.output_format)?;
                println!("Export started!");
            }
        }
        
        Ok(())
    }
}

impl CollaboratorCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            CollaboratorCommands::List { project_id } => {
                let response = ctx.get(&format!("/api/projects/{}/collaborators", project_id)).await?;
                let collaborators: Vec<CollaboratorResponse> = response.json().await?;
                print_output(&collaborators, &ctx.output_format)?;
            }
            
            CollaboratorCommands::Add { project_id, user_id, role } => {
                let response = ctx.post(&format!("/api/projects/{}/collaborators", project_id), &serde_json::json!({
                    "user_id": user_id,
                    "role": role,
                })).await?;
                
                let collaborator: CollaboratorResponse = response.json().await?;
                print_output(&collaborator, &ctx.output_format)?;
                println!("Collaborator added successfully!");
            }
            
            CollaboratorCommands::Remove { project_id, user_id } => {
                ctx.delete(&format!("/api/projects/{}/collaborators/{}", project_id, user_id)).await?;
                println!("Collaborator removed successfully!");
            }
        }
        Ok(())
    }
}

impl InviteCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            InviteCommands::List { project_id } => {
                let response = ctx.get(&format!("/api/projects/{}/invites", project_id)).await?;
                let invites: Vec<InviteResponse> = response.json().await?;
                print_output(&invites, &ctx.output_format)?;
            }
            
            InviteCommands::Create { project_id, email, role, expires_at } => {
                let response = ctx.post(&format!("/api/projects/{}/invites", project_id), &serde_json::json!({
                    "email": email,
                    "role": role,
                    "expires_at": expires_at,
                })).await?;
                
                let invite: InviteResponse = response.json().await?;
                print_output(&invite, &ctx.output_format)?;
                println!("Invite created successfully!");
            }
            
            InviteCommands::Revoke { project_id, invite_id } => {
                ctx.delete(&format!("/api/projects/{}/invites/{}", project_id, invite_id)).await?;
                println!("Invite revoked successfully!");
            }
        }
        Ok(())
    }
}

impl ShareCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ShareCommands::Create { project_id, permission, expires_at, max_uses } => {
                let response = ctx.post(&format!("/api/projects/{}/share", project_id), &serde_json::json!({
                    "permission": permission,
                    "expires_at": expires_at,
                    "max_uses": max_uses,
                })).await?;
                
                let link: ShareLinkResponse = response.json().await?;
                print_output(&link, &ctx.output_format)?;
                println!("Share link created!");
            }
        }
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ProjectResponse {
    pub id: ProjectId,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub is_public: bool,
    pub settings: Option<serde_json::Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct CollaboratorResponse {
    pub user_id: String,
    pub project_id: ProjectId,
    pub role: String,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub user: Option<UserSummary>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct InviteResponse {
    pub id: String,
    pub project_id: ProjectId,
    pub email: String,
    pub role: String,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub accepted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ShareLinkResponse {
    pub id: String,
    pub project_id: ProjectId,
    pub token: String,
    pub permission: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ExportResponse {
    pub id: String,
    pub project_id: ProjectId,
    pub format: String,
    pub status: String,
    pub download_url: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: Option<String>,
}