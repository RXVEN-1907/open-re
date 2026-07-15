//! Auth commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use openre_core::ids::UserId;
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

#[derive(Subcommand)]
pub enum AuthCommands {
    /// Login to the server
    Login {
        #[arg(short, long)]
        email: String,
        
        #[arg(short, long)]
        password: String,
    },
    
    /// Register a new account
    Register {
        #[arg(short, long)]
        email: String,
        
        #[arg(short, long)]
        username: String,
        
        #[arg(short, long)]
        password: String,
        
        #[arg(long)]
        full_name: Option<String>,
    },
    
    /// Refresh access token
    Refresh {
        #[arg(short, long)]
        refresh_token: String,
    },
    
    /// Logout
    Logout,
    
    /// Show current user info
    Me,
    
    /// Change password
    ChangePassword {
        #[arg(short, long)]
        current: String,
        
        #[arg(short, long)]
        new: String,
    },
    
    /// API key management
    #[command(subcommand)]
    ApiKey(ApiKeyCommands),
}

#[derive(Subcommand)]
pub enum ApiKeyCommands {
    /// List API keys
    List,
    
    /// Create API key
    Create {
        #[arg(short, long)]
        name: String,
        
        #[arg(short, long, num_args = 1..)]
        scopes: Vec<String>,
        
        #[arg(long)]
        expires_at: Option<String>,
    },
    
    /// Revoke API key
    Revoke {
        #[arg(short, long)]
        id: String,
    },
}

impl AuthCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            AuthCommands::Login { email, password } => {
                let response = ctx.post("/api/auth/login", &serde_json::json!({
                    "email": email,
                    "password": password,
                })).await?;
                
                let login_response: LoginResponse = response.json().await?;
                
                // Save tokens to config
                ctx.config.save_tokens(&login_response.access_token, &login_response.refresh_token)?;
                
                print_output(&login_response.user, &ctx.output_format)?;
                println!("Login successful! Token saved to config.");
            }
            
            AuthCommands::Register { email, username, password, full_name } => {
                let response = ctx.post("/api/auth/register", &serde_json::json!({
                    "email": email,
                    "username": username,
                    "password": password,
                    "full_name": full_name,
                })).await?;
                
                let login_response: LoginResponse = response.json().await?;
                
                ctx.config.save_tokens(&login_response.access_token, &login_response.refresh_token)?;
                
                print_output(&login_response.user, &ctx.output_format)?;
                println!("Registration successful! Token saved to config.");
            }
            
            AuthCommands::Refresh { refresh_token } => {
                let response = ctx.post("/api/auth/refresh", &serde_json::json!({
                    "refresh_token": refresh_token,
                })).await?;
                
                let login_response: LoginResponse = response.json().await?;
                
                ctx.config.save_tokens(&login_response.access_token, &login_response.refresh_token)?;
                
                println!("Token refreshed successfully!");
            }
            
            AuthCommands::Logout => {
                let _ = ctx.post("/api/auth/logout", &serde_json::json!({})).await;
                ctx.config.clear_tokens()?;
                println!("Logged out successfully!");
            }
            
            AuthCommands::Me => {
                let response = ctx.get("/api/auth/me").await?;
                let user: UserResponse = response.json().await?;
                print_output(&user, &ctx.output_format)?;
            }
            
            AuthCommands::ChangePassword { current, new } => {
                let response = ctx.put("/api/auth/password", &serde_json::json!({
                    "current_password": current,
                    "new_password": new,
                })).await?;
                
                println!("Password changed successfully!");
            }
            
            AuthCommands::ApiKey(cmd) => cmd.execute(ctx).await?,
        }
        
        Ok(())
    }
}

impl ApiKeyCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            ApiKeyCommands::List => {
                let response = ctx.get("/api/auth/api-keys").await?;
                let keys: Vec<ApiKeyResponse> = response.json().await?;
                print_output(&keys, &ctx.output_format)?;
            }
            
            ApiKeyCommands::Create { name, scopes, expires_at } => {
                let response = ctx.post("/api/auth/api-keys", &serde_json::json!({
                    "name": name,
                    "scopes": scopes,
                    "expires_at": expires_at,
                })).await?;
                
                let create_response: ApiKeyCreateResponse = response.json().await?;
                
                println!("API Key created (save this - it won't be shown again):");
                println!("{}", create_response.api_key);
                println!();
                print_output(&create_response.key, &ctx.output_format)?;
            }
            
            ApiKeyCommands::Revoke { id } => {
                ctx.delete(&format("/api/auth/api-keys/{}", id)).await?;
                println!("API key revoked successfully!");
            }
        }
        
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: UserResponse,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct UserResponse {
    pub id: UserId,
    pub email: String,
    pub username: String,
    pub full_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ApiKeyCreateResponse {
    pub api_key: String,
    pub key: ApiKeyResponse,
}