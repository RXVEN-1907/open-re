//! Application Map command

use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use openre_core::app_map::{AppMapOutputFormat, ApplicationMap, TargetInfo};
use openre_core::ids::{ScanId, TargetId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser)]
pub struct MapCommand {
    /// Target URL or scan ID
    #[arg(value_name = "TARGET")]
    target: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    output: MapOutputFormat,

    /// Maximum depth to traverse
    #[arg(short, long, default_value = "5")]
    depth: usize,

    /// Include authentication endpoints
    #[arg(long)]
    include_auth: bool,

    /// Include parameters
    #[arg(long)]
    include_params: bool,

    /// Include attack paths
    #[arg(long)]
    attack_paths: bool,

    /// Output file path
    #[arg(short, long)]
    output_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MapOutputFormat {
    Json,
    Yaml,
    Dot,
    Mermaid,
    Html,
    Table,
}

impl From<MapOutputFormat> for AppMapOutputFormat {
    fn from(f: MapOutputFormat) -> Self {
        match f {
            MapOutputFormat::Json => AppMapOutputFormat::Json,
            MapOutputFormat::Yaml => AppMapOutputFormat::Yaml,
            MapOutputFormat::Dot => AppMapOutputFormat::Dot,
            MapOutputFormat::Mermaid => AppMapOutputFormat::Mermaid,
            MapOutputFormat::Html => AppMapOutputFormat::Html,
            MapOutputFormat::Table => AppMapOutputFormat::Json, // Fallback for table
        }
    }
}

impl MapCommand {
    pub async fn execute(self, mut ctx: Context) -> Result<(), CliError> {
        // First, try to resolve the target as a scan ID
        let scan_id = if uuid::Uuid::parse_str(&self.target).is_ok() {
            Some(
                ScanId::from_str(&self.target)
                    .map_err(|_| CliError::InvalidInput("Invalid scan ID".to_string()))?,
            )
        } else {
            None
        };

        let app_map = if let Some(scan_id) = scan_id {
            // Fetch application map from scan
            self.fetch_app_map_from_scan(&mut ctx, scan_id).await?
        } else {
            // Generate application map from target URL
            self.generate_app_map_from_target(&mut ctx).await?
        };

        // Filter based on options
        let filtered_map = self.filter_app_map(app_map);

        // Handle output
        match self.output {
            MapOutputFormat::Table => self.print_table(&filtered_map),
            MapOutputFormat::Json => print_output(&filtered_map, &OutputFormat::Json)?,
            MapOutputFormat::Yaml => print_output(&filtered_map, &OutputFormat::Yaml)?,
            MapOutputFormat::Dot => self.print_dot(&filtered_map),
            MapOutputFormat::Mermaid => self.print_mermaid(&filtered_map),
            MapOutputFormat::Html => self.print_html(&filtered_map),
        }

        // Write to file if specified
        if let Some(output_path) = self.output_file {
            let content = match self.output {
                MapOutputFormat::Dot => filtered_map.to_dot(),
                MapOutputFormat::Mermaid => filtered_map.to_mermaid(),
                MapOutputFormat::Json => serde_json::to_string_pretty(&filtered_map)?,
                MapOutputFormat::Yaml => serde_yaml::to_string(&filtered_map)?,
                _ => serde_json::to_string_pretty(&filtered_map)?,
            };
            tokio::fs::write(&output_path, content).await?;
            println!("{} Output saved to {}", "✓".green(), output_path.display());
        }

        Ok(())
    }

    async fn fetch_app_map_from_scan(
        &self,
        ctx: &mut Context,
        scan_id: ScanId,
    ) -> Result<ApplicationMap, CliError> {
        let response = ctx.get(&format!("/api/scans/{}/app-map", scan_id)).await?;
        let app_map: ApplicationMap = response.json().await?;
        Ok(app_map)
    }

    async fn generate_app_map_from_target(
        &self,
        ctx: &mut Context,
    ) -> Result<ApplicationMap, CliError> {
        // Create a new scan or use existing to generate app map
        let payload = serde_json::json!({
            "target": self.target,
            "depth": self.depth,
            "include_auth": self.include_auth,
            "include_params": self.include_params,
        });

        let response = ctx.post("/api/app-map/generate", &payload).await?;
        let app_map: ApplicationMap = response.json().await?;
        Ok(app_map)
    }

    fn filter_app_map(&self, mut app_map: ApplicationMap) -> ApplicationMap {
        if !self.include_auth {
            app_map.auth_endpoints.clear();
        }
        if !self.include_params {
            app_map.parameters.clear();
            for endpoint in &mut app_map.endpoints {
                endpoint.parameters.clear();
            }
            for url in &mut app_map.urls {
                url.parameters.clear();
            }
        }
        // Filter URLs by depth
        app_map.urls.retain(|u| u.depth <= self.depth);
        app_map.metadata.total_urls = app_map.urls.len();
        app_map
    }

    fn print_table(&self, app_map: &ApplicationMap) {
        println!("\n{}", "Application Map Summary".bold().underline());
        println!("Target: {}", app_map.target.base_url);
        println!("Type: {}", app_map.target.target_type);
        println!("Scan ID: {}", app_map.target.scan_id);
        println!("Created: {}", app_map.target.created_at);
        println!();
        println!("URLs: {}", app_map.metadata.total_urls);
        println!("Endpoints: {}", app_map.metadata.total_endpoints);
        println!("Parameters: {}", app_map.metadata.total_parameters);
        println!("Forms: {}", app_map.metadata.total_forms);
        println!("Technologies: {}", app_map.metadata.total_technologies);
        println!("Auth Endpoints: {}", app_map.metadata.total_auth_endpoints);
        println!("Resources: {}", app_map.metadata.total_resources);
        println!();

        // Print top URLs by depth
        println!("{}", "Top URLs by Depth:".bold());
        for depth in 0..=self.depth.min(3) {
            let urls = app_map.get_urls_at_depth(depth);
            if !urls.is_empty() {
                println!("  Depth {}: {} URLs", depth, urls.len());
                for url in urls.iter().take(5) {
                    println!("    - {} [{}]", url.url, url.method);
                }
                if urls.len() > 5 {
                    println!("    ... and {} more", urls.len() - 5);
                }
            }
        }
    }

    fn print_dot(&self, app_map: &ApplicationMap) {
        println!("{}", app_map.to_dot());
    }

    fn print_mermaid(&self, app_map: &ApplicationMap) {
        println!("{}", app_map.to_mermaid());
    }

    fn print_html(&self, app_map: &ApplicationMap) {
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Application Map - {}</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <script>mermaid.initialize({{startOnLoad:true}});</script>
</head>
<body>
    <h1>Application Map for {}</h1>
    <div class="mermaid">
{}
    </div>
</body>
</html>"#,
            app_map.target.base_url,
            app_map.target.base_url,
            app_map.to_mermaid()
        );
        println!("{}", html);
    }
}

/// Type alias for compatibility with main.rs imports
pub type MapCommands = MapCommand;

