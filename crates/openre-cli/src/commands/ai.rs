//! AI commands

use clap::{Parser, Subcommand};
use crate::{Context, CliError, print_output};
use serde::{Deserialize, Serialize};
use tabled::{Table, settings::Style};

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
    
    /// Analyze function with AI
    Analyze {
        #[arg(short, long)]
        function_id: String,
        
        #[arg(short, long)]
        project_id: String,
        
        #[arg(long)]
        stream: bool,
    },
    
    /// List prompt templates
    Templates,
    
    /// Get template details
    Template {
        #[arg(short, long)]
        name: String,
    },
}

impl AiCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            AiCommands::Chat { message, model, temperature, max_tokens, stream } => {
                let mut payload = serde_json::json!({
                    "messages": [{ "role": "user", "content": message }],
                });
                
                if let Some(model) = model { payload["model"] = serde_json::json!(model); }
                if let Some(temp) = temperature { payload["temperature"] = serde_json::json!(temp); }
                if let Some(tokens) = max_tokens { payload["max_tokens"] = serde_json::json!(tokens); }
                if stream { payload["stream"] = serde_json::json!(true); }
                
                if stream {
                    // Streaming response
                    let response = ctx.client
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
                                if data == "[DONE]" { break; }
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                                    if let Some(content) = json.get("content").and_then(|v| v.as_str()) {
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
                    println!("Tokens: {} prompt + {} completion = {} total", 
                        result.usage.prompt_tokens, result.usage.completion_tokens, result.usage.total_tokens);
                }
            }
            
            AiCommands::Analyze { function_id, project_id, stream } => {
                let payload = serde_json::json!({
                    "function_id": function_id,
                    "project_id": project_id,
                });
                
                let url = if stream {
                    "/api/ai/analyze/stream"
                } else {
                    "/api/ai/analyze"
                };
                
                if stream {
                    let response = ctx.client
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
                                if data == "[DONE]" { break; }
                                if let Ok(json) = serde_json::from_str::<serde_json::Value>(data) {
                                    if let Some(content) = json.get("content").and_then(|v| v.as_str()) {
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
                    let result: AnalyzeFunctionResponse = response.json().await?;
                    println!("{}", result.analysis);
                    println!("\n---");
                    println!("Model: {}", result.model);
                    println!("Tokens: {} prompt + {} completion = {} total", 
                        result.usage.prompt_tokens, result.usage.completion_tokens, result.usage.total_tokens);
                }
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
        }
        
        Ok(())
    }
}

// Response types

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: Usage,
    pub created: u64,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessageResponse,
    pub finish_reason: String,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ChatMessageResponse {
    pub role: String,
    pub content: Option<String>,
    pub tool_calls: Option<Vec<ToolCallResponse>>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct ToolCallResponse {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct AnalyzeFunctionResponse {
    pub analysis: String,
    pub model: String,
    pub usage: Usage,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateInfo>,
}

#[derive(Debug, Deserialize, Serialize, tabled::Tabled)]
pub struct TemplateInfo {
    pub name: String,
    pub description: String,
    pub variables: Vec<String>,
}