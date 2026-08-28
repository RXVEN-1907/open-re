//! AI commands

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tabled::{settings::Style, Table};

#[derive(Subcommand)]
pub enum AiCommands {
    /// Chat with AI
    Chat {
        #[arg(short, long)]
        message: String,

        #[arg(short, long)]
        model: Option<String>,

        #[arg(long)]
        temperature: Option<f32>,

        #[arg(long)]
        max_tokens: Option<u32>,

        #[arg(long)]
        stream: bool,
    },

    /// Analyze a finding with AI
    Analyze {
        #[arg(short, long)]
        finding_id: String,

        #[arg(long)]
        provider: Option<String>,

        #[arg(long)]
        model: Option<String>,

        #[arg(long)]
        stream: bool,
    },

    /// Explain a finding in detail
    Explain {
        #[arg(short, long)]
        finding_id: String,

        #[arg(long)]
        provider: Option<String>,

        #[arg(long)]
        model: Option<String>,
    },

    /// Generate remediation for a finding
    Remediate {
        #[arg(short, long)]
        finding_id: String,

        #[arg(long)]
        provider: Option<String>,

        #[arg(long)]
        model: Option<String>,
    },

    /// Correlate findings across a project
    Correlate {
        /// Project name or ID
        #[arg(short, long)]
        project: String,

        #[arg(long)]
        provider: Option<String>,

        #[arg(long)]
        model: Option<String>,
    },

    /// List prompt templates
    Templates,

    /// Get template details
    Template {
        #[arg(short, long)]
        name: String,
    },

    /// List available AI providers
    Providers,
}

impl AiCommands {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        match self {
            AiCommands::Chat {
                message,
                model,
                temperature,
                max_tokens,
                stream,
            } => {
                let mut payload = serde_json::json!({
                    "messages": [{ "role": "user", "content": message }],
                });

                if let Some(model) = model {
                    payload["model"] = serde_json::json!(model);
                }
                if let Some(temp) = temperature {
                    payload["temperature"] = serde_json::json!(temp);
                }
                if let Some(tokens) = max_tokens {
                    payload["max_tokens"] = serde_json::json!(tokens);
                }
                if stream {
                    payload["stream"] = serde_json::json!(true);
                }

                if stream {
                    // Streaming response
                    let response = ctx
                        .client
                        .post(&format!("{}/api/ai/chat/stream", ctx.server_url))
                        .json(&payload)
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        for line in text.lines() {
                            if line.starts_with("data: ") {
                                let data = &line[6..];
                                if data == "[DONE]" {
                                    break;
                                }
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                                    if let Some(content) =
                                        json.get("content").and_then(|v| v.as_str())
                                    {
                                        print!("{}", content);
                                        use std::io::{self, Write};
                                        io::stdout().flush()?;
                                    }
                                }
                            }
                        }
                    }
                    println!();
                } else {
                    let response = ctx.post("/api/ai/chat", &payload).await?;
                    let result: ChatCompletionResponse = response.json().await?;

                    if let Some(choice) = result.choices.first() {
                        if let Some(content) = &choice.message.content {
                            println!("{}", content);
                        }
                    }

                    println!("\n---");
                    println!("Model: {}", result.model);
                    println!(
                        "Tokens: {} prompt + {} completion = {} total",
                        result.usage.prompt_tokens,
                        result.usage.completion_tokens,
                        result.usage.total_tokens
                    );
                }
            }

            AiCommands::Analyze {
                finding_id,
                provider,
                model,
                stream,
            } => {
                let mut payload = serde_json::json!({
                    "finding_id": finding_id,
                    "action": "analyze",
                });

                if let Some(provider) = provider {
                    payload["provider"] = serde_json::json!(provider);
                }
                if let Some(model) = model {
                    payload["model"] = serde_json::json!(model);
                }

                let url = if stream {
                    "/api/ai/finding/analyze/stream"
                } else {
                    "/api/ai/finding/analyze"
                };

                if stream {
                    let response = ctx
                        .client
                        .post(&format!("{}{}", ctx.server_url, url))
                        .json(&payload)
                        .header("Authorization", format!("Bearer {}", ctx.get_token()?))
                        .send()
                        .await?;

                    let mut stream = response.bytes_stream();
                    use futures::StreamExt;
                    while let Some(chunk) = stream.next().await {
                        let chunk = chunk?;
                        let text = String::from_utf8_lossy(&chunk);
                        for line in text.lines() {
                            if line.starts_with("data: ") {
                                let data = &line[6..];
                                if data == "[DONE]" {
                                    break;
                                }
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                                    if let Some(content) =
                                        json.get("content").and_then(|v| v.as_str())
                                    {
                                        print!("{}", content);
                                        use std::io::{self, Write};
                                        io::stdout().flush()?;
                                    }
                                }
                            }
                        }
                    }
                    println!();
                } else {
                    let response = ctx.post(url, &payload).await?;
                    let result: AiFindingResponse = response.json().await?;
                    println!("{}", result.result);
                    println!("\n---");
                    println!("Model: {}", result.model);
                    println!(
                        "Tokens: {} prompt + {} completion = {} total",
                        result.usage.prompt_tokens,
                        result.usage.completion_tokens,
                        result.usage.total_tokens
                    );
                }
            }

            AiCommands::Explain {
                finding_id,
                provider,
                model,
            } => {
                let mut payload = serde_json::json!({
                    "finding_id": finding_id,
                    "action": "explain",
                });

                if let Some(provider) = provider {
                    payload["provider"] = serde_json::json!(provider);
                }
                if let Some(model) = model {
                    payload["model"] = serde_json::json!(model);
                }

                let response = ctx.post("/api/ai/finding/explain", &payload).await?;
                let result: AiFindingResponse = response.json().await?;
                println!("{}", result.result);
                println!("\n---");
                println!("Model: {}", result.model);
                println!(
                    "Tokens: {} prompt + {} completion = {} total",
                    result.usage.prompt_tokens,
                    result.usage.completion_tokens,
                    result.usage.total_tokens
                );
            }

            AiCommands::Remediate {
                finding_id,
                provider,
                model,
            } => {
                let mut payload = serde_json::json!({
                    "finding_id": finding_id,
                    "action": "remediate",
                });

                if let Some(provider) = provider {
                    payload["provider"] = serde_json::json!(provider);
                }
                if let Some(model) = model {
                    payload["model"] = serde_json::json!(model);
                }

                let response = ctx.post("/api/ai/finding/remediate", &payload).await?;
                let result: AiFindingResponse = response.json().await?;
                println!("{}", result.result);
                println!("\n---");
                println!("Model: {}", result.model);
                println!(
                    "Tokens: {} prompt + {} completion = {} total",
                    result.usage.prompt_tokens,
                    result.usage.completion_tokens,
                    result.usage.total_tokens
                );
            }

            AiCommands::Correlate {
                project,
                provider,
                model,
            } => {
                // Resolve project ID
                let project_id = resolve_project_id(&mut ctx, &project).await?;

                let mut payload = serde_json::json!({
                    "project_id": project_id,
                    "action": "correlate",
                });

                if let Some(provider) = provider {
                    payload["provider"] = serde_json::json!(provider);
                }
                if let Some(model) = model {
                    payload["model"] = serde_json::json!(model);
                }

                println!("Correlating findings across project...");
                let response = ctx.post("/api/ai/correlate", &payload).await?;
                let result: AiCorrelateResponse = response.json().await?;

                println!("{}", result.correlations);
                if let Some(risk_summary) = result.risk_summary {
                    println!("\n{}", "Risk Summary:".bold());
                    println!("{}", risk_summary);
                }
                println!("\n---");
                println!("Model: {}", result.model);
                println!(
                    "Tokens: {} prompt + {} completion = {} total",
                    result.usage.prompt_tokens,
                    result.usage.completion_tokens,
                    result.usage.total_tokens
                );
            }

            AiCommands::Templates => {
                let response = ctx.get("/api/ai/templates").await?;
                let templates: TemplateListResponse = response.json().await?;
                print_output(&templates.templates, &ctx.output_format)?;
            }

            AiCommands::Template { name } => {
                let response = ctx.get(&format!("/api/ai/templates/{}", name)).await?;
                let template: TemplateInfo = response.json().await?;
                print_output(&template, &ctx.output_format)?;
            }

            AiCommands::Providers => {
                let response = ctx.get("/api/ai/providers").await?;
                let providers: ProviderListResponse = response.json().await?;
                print_output(&providers.providers, &ctx.output_format)?;
            }
        }

        Ok(())
    }
}

// Helper to resolve project name to ID
async fn resolve_project_id(ctx: &mut Context, project: &str) -> Result<String, CliError> {
    if uuid::Uuid::parse_str(project).is_ok() {
        return Ok(project.to_string());
    }

    let response = ctx.get(&format!("/api/projects?search={}", urlencoding::encode(project))).await?;
    let list: ProjectListResponse = response.json().await?;

    if let Some(project) = list.projects.first() {
        Ok(project.id.to_string())
    } else {
        Err(CliError::InvalidInput(format!("Project not found: {}", project)))
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
    pub created: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessageResponse,
    pub finish_reason: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChatMessageResponse {
    pub role: String,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCallResponse>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ToolCallResponse {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnalyzeFunctionResponse {
    pub analysis: String,
    pub model: String,
    pub usage: Usage,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateInfo {
    pub name: String,
    pub description: String,
    pub variables: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AiFindingResponse {
    pub result: String,
    pub model: String,
    pub usage: Usage,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AiCorrelateResponse {
    pub correlations: String,
    pub risk_summary: Option<String>,
    pub model: String,
    pub usage: Usage,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProviderListResponse {
    pub providers: Vec<ProviderInfo>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub models: Vec<String>,
    pub description: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProjectResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: String,
    pub is_public: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}
