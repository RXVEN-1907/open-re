//! Plugin commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use openre_core::ids::PluginId;
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

#[derive(Subcommand)]
pub enum PluginCommands {
    /// List plugins
    List {
        #[arg(short, long, default_value = "1")]
        page: u32,
        
        #[arg(short, long, default_value = "50")]
        per_page: u32,
        
        #[arg(long)]
        plugin_type: Option<String>,
        
        #[arg(long)]
        enabled: Option<bool>,
    },
    
    /// Get plugin details
    Get {
        #[arg(short, long)]
        id: String,
    },
    
    /// Install plugin
    Install {
        #[arg(short, long)]
        source: String, // registry:name, local:path, git:url
        
        #[arg(short, long)]
        version: Option<String>,
    },
    
    /// Uninstall plugin
    Uninstall {
        #[arg(short, long)]
        id: String,
        
        #[arg(long)]
        force: bool,
    },
    
    /// Enable plugin
    Enable {
        #[arg(short, long)]
        id: String,
    },
    
    /// Disable plugin
    Disable {
        #[arg(short, long)]
        id: String,
    },
    
    /// Configure plugin
    Configure {
        #[arg(short, long)]
        id: String,
        
        #[arg(short, long)]
        config: String, // JSON string or file path
    },
}

impl PluginCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            PluginCommands::List { page, per_page, plugin_type, enabled } => {
                let mut url = format!("/api/plugins?page={}&per_page={}", page, per_page);
                if let Some(plugin_type) = plugin_type {
                    url.push_str(&format!("&plugin_type={}", plugin_type));
                }
                if let Some(enabled) = enabled {
                    url.push_str(&format!("&enabled={}", enabled));
                }
                
                let response = ctx.get(&url).await?;
                let list: PluginListResponse = response.json().await?;
                print_output(&list.plugins, &ctx.output_format)?;
                println!("Page {} of {} (total: {})", list.page, (list.total + list.per_page - 1) / list.per_page, list.total);
            }
            
            PluginCommands::Get { id } => {
                let response = ctx.get(&format!("/api/plugins/{}", id)).await?;
                let plugin: PluginResponse = response.json().await?;
                print_output(&plugin, &ctx.output_format)?;
            }
            
            PluginCommands::Install { source, version } => {
                let (source_type, source_value) = source.split_once(':')
                    .ok_or_else(|| CliError::InvalidInput("Source must be in format 'type:value' (e.g., 'registry:plugin-name', 'local:/path', 'git:https://...')".into()))?;
                
                let source_json = match source_type {
                    "registry" => serde_json::json!({ "type": "registry", "name": source_value }),
                    "local" => serde_json::json!({ "type": "local", "path": source_value }),
                    "git" => serde_json::json!({ "type": "git", "url": source_value }),
                    _ => return Err(CliError::InvalidInput("Unknown source type. Use: registry, local, or git".into())),
                };
                
                let mut payload = serde_json::json!({ "source": source_json });
                if let Some(version) = version {
                    payload["version"] = serde_json::json!(version);
                }
                
                let response = ctx.post("/api/plugins", &payload).await?;
                let plugin: PluginResponse = response.json().await?;
                print_output(&plugin, &ctx.output_format)?;
                println!("Plugin installed successfully!");
            }
            
            PluginCommands::Uninstall { id, force } => {
                if !force {
                    print!("Are you sure you want to uninstall plugin {}? (y/N): ", id);
                    use std::io::{self, Write};
                    io::stdout().flush()?;
                    let mut input = String::new();
                    io::stdin().read_line(&mut input)?;
                    if !input.trim().eq_ignore_ascii_case("y") {
                        println!("Cancelled.");
                        return Ok(());
                    }
                }
                
                ctx.delete(&format!("/api/plugins/{}", id)).await?;
                println!("Plugin uninstalled successfully!");
            }
            
            PluginCommands::Enable { id } => {
                let response = ctx.post(&format!("/api/plugins/{}/enable", id), &serde_json::json!({})).await?;
                let plugin: PluginResponse = response.json().await?;
                print_output(&plugin, &ctx.output_format)?;
                println!("Plugin enabled successfully!");
            }
            
            PluginCommands::Disable { id } => {
                let response = ctx.post(&format!("/api/plugins/{}/disable", id), &serde_json::json!({})).await?;
                let plugin: PluginResponse = response.json().await?;
                print_output(&plugin, &ctx.output_format)?;
                println!("Plugin disabled successfully!");
            }
            
            PluginCommands::Configure { id, config } => {
                let config_value: serde_json::Value = if config.starts_with('@') {
                    // Read from file
                    let path = &config[1..];
                    let content = tokio::fs::read_to_string(path).await?;
                    serde_json::from_str(&content)?
                } else {
                    // Parse as JSON
                    serde_json::from_str(&config)?
                };
                
                let response = ctx.put(&format!("/api/plugins/{}/configure", id), &serde_json::json!({
                    "config": config_value
                })).await?;
                
                let plugin: PluginResponse = response.json().await?;
                print_output(&plugin, &ctx.output_format)?;
                println!("Plugin configured successfully!");
            }
        }
        
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize)]
pub struct PluginListResponse {
    pub plugins: Vec<PluginResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct PluginResponse {
    pub id: PluginId,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub plugin_type: String,
    pub capabilities: Vec<String>,
    pub enabled: bool,
    pub config: Option<serde_json::Value>,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}