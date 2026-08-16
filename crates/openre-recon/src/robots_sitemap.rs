//! Robots & Sitemap Discovery Plugin
//!
//! Locates and parses robots.txt and sitemap.xml to extract paths and useful endpoints.

use crate::{ReconMetadata, ReconPlugin, ReconPluginConfig, ReconType};
use openre_core::error::OpenreResult as Result;
use openre_plugins::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin,
};
use openre_scanner::{
    context::ScanContext,
    result::{
        Category, Confidence, Evidence, EvidenceType, Finding, Reference, ReferenceType, Severity,
    },
    target::TargetType,
};
use reqwest::Client;
use select::document::Document;
use select::predicate::Name;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Robots & Sitemap Discovery Plugin
pub struct RobotsSitemapPlugin {
    config: ReconPluginConfig,
    client: Client,
}

impl RobotsSitemapPlugin {
    pub fn new(config: ReconPluginConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()?;

        Ok(Self { config, client })
    }

    /// Discover and parse robots.txt
    async fn discover_robots(&self, base_url: &str) -> Result<RobotsResult> {
        let mut result = RobotsResult::default();
        let robots_url = format!("{}/robots.txt", base_url.trim_end_matches('/'));

        match self.client.get(&robots_url).send().await {
            Ok(response) if response.status().is_success() => {
                let content = response.text().await?;
                result.found = true;
                result.content = Some(content.clone());
                result.parsed = self.parse_robots(&content);
            }
            Ok(_) => {
                result.found = false;
            }
            Err(e) => {
                warn!("Failed to fetch robots.txt: {}", e);
                result.found = false;
            }
        }

        Ok(result)
    }

    /// Parse robots.txt content
    fn parse_robots(&self, content: &str) -> ParsedRobots {
        let mut parsed = ParsedRobots::default();
        let mut current_user_agent = String::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();

                match key.as_str() {
                    "user-agent" => {
                        current_user_agent = value.to_string();
                    }
                    "disallow" => {
                        if !value.is_empty() {
                            parsed.disallowed_paths.push(value.to_string());
                        }
                    }
                    "allow" => {
                        if !value.is_empty() {
                            parsed.allowed_paths.push(value.to_string());
                        }
                    }
                    "sitemap" => {
                        parsed.sitemaps.push(value.to_string());
                    }
                    "crawl-delay" => {
                        if let Ok(delay) = value.parse::<f64>() {
                            parsed.crawl_delay = Some(delay);
                        }
                    }
                    _ => {}
                }
            }
        }

        parsed
    }

    /// Discover and parse sitemap.xml
    async fn discover_sitemap(
        &self,
        base_url: &str,
        robots_sitemaps: &[String],
    ) -> Result<SitemapResult> {
        let mut result = SitemapResult::default();
        let mut sitemap_urls = vec![format!("{}/sitemap.xml", base_url.trim_end_matches('/'))];
        sitemap_urls.extend(robots_sitemaps.iter().cloned());

        for sitemap_url in sitemap_urls {
            match self.client.get(&sitemap_url).send().await {
                Ok(response) if response.status().is_success() => {
                    let content = response.text().await?;
                    result.found = true;
                    result.sitemap_url = Some(sitemap_url.clone());
                    result.content = Some(content.clone());
                    result.parsed = self.parse_sitemap(&content);
                    break;
                }
                Ok(_) => continue,
                Err(e) => {
                    warn!("Failed to fetch sitemap {}: {}", sitemap_url, e);
                    continue;
                }
            }
        }

        Ok(result)
    }

    /// Parse sitemap.xml content
    fn parse_sitemap(&self, content: &str) -> ParsedSitemap {
        let mut parsed = ParsedSitemap::default();

        let doc = Document::from(content.as_bytes());

        // Parse URL entries
        for url_node in doc.find(Name("url")) {
            let mut entry = SitemapEntry::default();

            if let Some(loc) = url_node.find(Name("loc")).next() {
                entry.url = loc.text();
            }
            if let Some(lastmod) = url_node.find(Name("lastmod")).next() {
                entry.lastmod = Some(lastmod.text());
            }
            if let Some(changefreq) = url_node.find(Name("changefreq")).next() {
                entry.changefreq = Some(changefreq.text());
            }
            if let Some(priority) = url_node.find(Name("priority")).next() {
                entry.priority = priority.text().parse().ok();
            }

            parsed.urls.push(entry);
        }

        // Parse sitemap index entries
        for sitemap_node in doc.find(Name("sitemap")) {
            let mut entry = SitemapIndexEntry::default();

            if let Some(loc) = sitemap_node.find(Name("loc")).next() {
                entry.url = loc.text();
            }
            if let Some(lastmod) = sitemap_node.find(Name("lastmod")).next() {
                entry.lastmod = Some(lastmod.text());
            }

            parsed.sitemaps.push(entry);
        }

        parsed
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct RobotsResult {
    found: bool,
    content: Option<String>,
    parsed: ParsedRobots,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ParsedRobots {
    disallowed_paths: Vec<String>,
    allowed_paths: Vec<String>,
    sitemaps: Vec<String>,
    crawl_delay: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SitemapResult {
    found: bool,
    sitemap_url: Option<String>,
    content: Option<String>,
    parsed: ParsedSitemap,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ParsedSitemap {
    urls: Vec<SitemapEntry>,
    sitemaps: Vec<SitemapIndexEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SitemapEntry {
    url: String,
    lastmod: Option<String>,
    changefreq: Option<String>,
    priority: Option<f64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SitemapIndexEntry {
    url: String,
    lastmod: Option<String>,
}

#[async_trait::async_trait]
impl Plugin for RobotsSitemapPlugin {
    type Config = ReconPluginConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create RobotsSitemapPlugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&mut self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let findings = self.recon(&context).await?;

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "recon_type": ReconType::RobotsSitemap,
        })))
    }
}

#[async_trait::async_trait]
impl ReconPlugin for RobotsSitemapPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::RobotsSitemap
    }

    fn supported_target_types(&self) -> Vec<TargetType> {
        vec![
            TargetType::LocalWebApp,
            TargetType::RemoteWebApp,
            TargetType::RestApi,
            TargetType::GraphQLApi,
        ]
    }

    async fn recon(&mut self, context: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let target_url = context.target.to_string();

        info!(
            "Starting robots.txt & sitemap discovery for: {}",
            target_url
        );

        // Discover robots.txt
        let robots = self.discover_robots(&target_url).await?;

        if robots.found {
            findings.push(
                Finding::new(
                    "robots.txt Found".to_string(),
                    "robots.txt file is accessible".to_string(),
                    Severity::Info,
                    Confidence::High,
                    Category::InformationDisclosure,
                    target_url.clone(),
                    "web_application".to_string(),
                    "robots_sitemap".to_string(),
                    "0.1.0".to_string(),
                    context.scan_id,
                )
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "robots.txt found".to_string(),
                    data: Some(serde_json::json!({
                        "disallowed_paths": robots.parsed.disallowed_paths,
                        "allowed_paths": robots.parsed.allowed_paths,
                        "sitemaps": robots.parsed.sitemaps,
                        "crawl_delay": robots.parsed.crawl_delay,
                    })),
                    location: Some(format!("{}/robots.txt", target_url.trim_end_matches('/'))),
                    metadata: HashMap::new(),
                }),
            );

            // Interesting disallowed paths
            for path in &robots.parsed.disallowed_paths {
                if path.contains("admin")
                    || path.contains("login")
                    || path.contains("private")
                    || path.contains("secret")
                {
                    findings.push(
                        Finding::new(
                            "Sensitive Path in robots.txt".to_string(),
                            format!("Disallowed path may indicate sensitive area: {}", path),
                            Severity::Low,
                            Confidence::Medium,
                            Category::InformationDisclosure,
                            target_url.clone(),
                            "web_application".to_string(),
                            "robots_sitemap".to_string(),
                            "0.1.0".to_string(),
                            context.scan_id,
                        )
                        .with_evidence(Evidence {
                            evidence_type: EvidenceType::HttpResponse,
                            description: "Potentially sensitive path in robots.txt".to_string(),
                            data: Some(serde_json::json!({"path": path})),
                            location: Some(format!(
                                "{}/robots.txt",
                                target_url.trim_end_matches('/')
                            )),
                            metadata: HashMap::new(),
                        }),
                    );
                }
            }
        }

        // Discover sitemap.xml
        let sitemap = self
            .discover_sitemap(&target_url, &robots.parsed.sitemaps)
            .await?;

        if sitemap.found {
            findings.push(
                Finding::new(
                    "Sitemap Found".to_string(),
                    format!(
                        "Sitemap discovered at: {}",
                        sitemap.sitemap_url.as_deref().unwrap_or("unknown")
                    ),
                    Severity::Info,
                    Confidence::High,
                    Category::InformationDisclosure,
                    target_url.clone(),
                    "web_application".to_string(),
                    "robots_sitemap".to_string(),
                    "0.1.0".to_string(),
                    context.scan_id,
                )
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Sitemap.xml found".to_string(),
                    data: Some(serde_json::json!({
                        "url_count": sitemap.parsed.urls.len(),
                        "sitemap_index_count": sitemap.parsed.sitemaps.len(),
                    })),
                    location: sitemap.sitemap_url,
                    metadata: HashMap::new(),
                }),
            );

            // List discovered URLs (limit to first 50)
            for entry in sitemap.parsed.urls.iter().take(50) {
                findings.push(
                    Finding::new(
                        "Endpoint Discovered via Sitemap".to_string(),
                        format!("URL found in sitemap: {}", entry.url),
                        Severity::Info,
                        Confidence::High,
                        Category::InformationDisclosure,
                        target_url.clone(),
                        "web_application".to_string(),
                        "robots_sitemap".to_string(),
                        "0.1.0".to_string(),
                        context.scan_id,
                    )
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: "Endpoint from sitemap".to_string(),
                        data: Some(serde_json::json!({
                            "url": entry.url,
                            "lastmod": entry.lastmod,
                            "changefreq": entry.changefreq,
                            "priority": entry.priority,
                        })),
                        location: Some(entry.url.clone()),
                        metadata: HashMap::new(),
                    }),
                );
            }
        }

        info!(
            "Robots & sitemap discovery completed for: {} - {} findings",
            target_url,
            findings.len()
        );
        Ok(findings)
    }
}

/// Plugin entry point
#[no_mangle]
pub extern "C" fn plugin_init(config_ptr: *const u8, config_len: usize) -> i32 {
    if config_ptr.is_null() || config_len == 0 {
        return -1;
    }
    let config_slice = unsafe { std::slice::from_raw_parts(config_ptr, config_len) };
    let config: ReconPluginConfig = match serde_json::from_slice(config_slice) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let plugin = RobotsSitemapPlugin::new(config);
    0
}

#[no_mangle]
pub extern "C" fn plugin_execute(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_len: *mut usize,
) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn plugin_shutdown() -> i32 {
    0
}
