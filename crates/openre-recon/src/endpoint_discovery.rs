//! Endpoint Discovery Plugin
//!
//! Discovers routes and endpoints from common files, public metadata,
//! HTML parsing, and basic JavaScript analysis.

use crate::{ReconPlugin, ReconPluginConfig, ReconType, ReconMetadata};
use openre_plugins::sdk::{Plugin, CapabilityRequest, CapabilityResponse, Capability, AnalysisContext};
use openre_core::error::OpenreResult as Result;
use openre_scanner::{target::TargetType, context::ScanContext, result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType}};
use reqwest::Client;
use select::document::Document;
use select::predicate::{Name, Attr};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Endpoint Discovery Plugin
pub struct EndpointDiscoveryPlugin {
    config: ReconPluginConfig,
    client: Client,
    common_paths: Vec<String>,
}

impl EndpointDiscoveryPlugin {
    pub fn new(config: ReconPluginConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()?;

        let common_paths = vec![
            // Admin panels
            "/admin", "/administrator", "/admin/login", "/admin/dashboard",
            "/wp-admin", "/wp-login.php", "/phpmyadmin", "/pma",
            // API endpoints
            "/api", "/api/v1", "/api/v2", "/graphql", "/graphiql",
            "/swagger", "/swagger-ui", "/redoc", "/openapi.json",
            // Config files
            "/.env", "/.env.local", "/.env.production", "/config.json",
            "/config.yaml", "/config.yml", "/settings.json",
            // Version control
            "/.git", "/.git/config", "/.svn", "/.hg",
            // Backup files
            "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
            // Documentation
            "/docs", "/doc", "/readme", "/README.md", "/CHANGELOG.md",
            // Debug endpoints
            "/debug", "/actuator", "/health", "/metrics", "/status",
            // Server status
            "/server-status", "/server-info", "/nginx_status",
            // Common CMS paths
            "/wp-json", "/drupal", "/joomla", "/magento",
        ];

        Ok(Self { config, client, common_paths })
    }

    /// Discover endpoints
    async fn discover_endpoints(&self, base_url: &str) -> Result<EndpointDiscoveryResult> {
        let mut result = EndpointDiscoveryResult::default();
        let mut discovered = HashSet::new();
        
        // Check common paths
        for path in &self.common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            match self.client.head(&url).send().await {
                Ok(response) if response.status().is_success() || response.status().is_redirection() => {
                    discovered.insert(DiscoveredEndpoint {
                        url: url.clone(),
                        method: "HEAD".to_string(),
                        status_code: response.status().as_u16(),
                        content_type: response.headers().get("content-type")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                        source: "common_paths".to_string(),
                    });
                }
                Ok(response) if response.status().as_u16() == 403 => {
                    discovered.insert(DiscoveredEndpoint {
                        url: url.clone(),
                        method: "HEAD".to_string(),
                        status_code: 403,
                        content_type: None,
                        source: "common_paths".to_string(),
                    });
                }
                _ => {}
            }
        }
        
        // Parse HTML for links
        if let Ok(response) = self.client.get(base_url).send().await {
            if let Ok(body) = response.text().await {
                let html_endpoints = self.extract_endpoints_from_html(&body, base_url);
                discovered.extend(html_endpoints);
            }
        }
        
        // Parse JavaScript for endpoints
        if let Ok(response) = self.client.get(base_url).send().await {
            if let Ok(body) = response.text().await {
                let js_endpoints = self.extract_endpoints_from_js(&body, base_url);
                discovered.extend(js_endpoints);
            }
        }
        
        result.endpoints = discovered.into_iter().collect();
        Ok(result)
    }

    fn extract_endpoints_from_html(&self, html: &str, base_url: &str) -> HashSet<DiscoveredEndpoint> {
        let mut endpoints = HashSet::new();
        let doc = Document::from(html.as_bytes());
        
        // Extract links
        for link in doc.find(Name("a")) {
            if let Some(href) = link.attr("href") {
                let url = self.resolve_url(base_url, href);
                if self.is_same_origin(base_url, &url) {
                    endpoints.insert(DiscoveredEndpoint {
                        url,
                        method: "GET".to_string(),
                        status_code: 0,
                        content_type: None,
                        source: "html_link".to_string(),
                    });
                }
            }
        }
        
        // Extract forms
        for form in doc.find(Name("form")) {
            let action = form.attr("action").unwrap_or("");
            let method = form.attr("method").unwrap_or("GET").to_uppercase();
            let url = self.resolve_url(base_url, action);
            if self.is_same_origin(base_url, &url) {
                endpoints.insert(DiscoveredEndpoint {
                    url,
                    method,
                    status_code: 0,
                    content_type: None,
                    source: "html_form".to_string(),
                });
            }
        }
        
        // Extract script sources
        for script in doc.find(Name("script")) {
            if let Some(src) = script.attr("src") {
                let url = self.resolve_url(base_url, src);
                if self.is_same_origin(base_url, &url) {
                    endpoints.insert(DiscoveredEndpoint {
                        url,
                        method: "GET".to_string(),
                        status_code: 0,
                        content_type: Some("application/javascript".to_string()),
                        source: "html_script".to_string(),
                    });
                }
            }
        }
        
        endpoints
    }

    fn extract_endpoints_from_js(&self, html: &str, base_url: &str) -> HashSet<DiscoveredEndpoint> {
        let mut endpoints = HashSet::new();
        
        // Simple regex patterns for API endpoints in JavaScript
        let patterns = [
            r#"["'](/api/[^"']+)["']"#,
            r#"["'](/v\d+/[^"']+)["']"#,
            r#"fetch\(["']([^"']+)["']"#,
            r#"axios\.(get|post|put|delete|patch)\(["']([^"']+)["']"#,
            r#"\.ajax\(["']([^"']+)["']"#,
        ];
        
        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(html) {
                    if let Some(endpoint) = cap.get(1).or_else(|| cap.get(2)) {
                        let url = self.resolve_url(base_url, endpoint.as_str());
                        if self.is_same_origin(base_url, &url) {
                            endpoints.insert(DiscoveredEndpoint {
                                url,
                                method: "GET".to_string(),
                                status_code: 0,
                                content_type: None,
                                source: "javascript".to_string(),
                            });
                        }
                    }
                }
            }
        }
        
        endpoints
    }

    fn resolve_url(&self, base: &str, path: &str) -> String {
        if path.starts_with("http://") || path.starts_with("https://") {
            path.to_string()
        } else if path.starts_with('/') {
            format!("{}{}", base.trim_end_matches('/'), path)
        } else {
            format!("{}/{}", base.trim_end_matches('/'), path)
        }
    }

    fn is_same_origin(&self, base: &str, url: &str) -> bool {
        let base_parsed = url::Url::parse(base).ok();
        let url_parsed = url::Url::parse(url).ok();
        
        match (base_parsed, url_parsed) {
            (Some(b), Some(u)) => b.origin() == u.origin(),
            _ => false,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EndpointDiscoveryResult {
    endpoints: Vec<DiscoveredEndpoint>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
struct DiscoveredEndpoint {
    url: String,
    method: String,
    status_code: u16,
    content_type: Option<String>,
    source: String,
}

#[async_trait::async_trait]
impl Plugin for EndpointDiscoveryPlugin {
    type Config = ReconPluginConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create EndpointDiscoveryPlugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAccess,
            Capability::ReadConfig,
        ]
    }

    async fn execute(&mut self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let findings = self.recon(&context).await?;
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "recon_type": ReconType::EndpointDiscovery,
        })))
    }
}

#[async_trait::async_trait]
impl ReconPlugin for EndpointDiscoveryPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::EndpointDiscovery
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
        
        info!("Starting endpoint discovery for: {}", target_url);
        
        let discovery = self.discover_endpoints(&target_url).await?;
        
        // Create findings for discovered endpoints
        for endpoint in discovery.endpoints {
            let severity = if endpoint.status_code == 403 {
                Severity::Low
            } else if endpoint.status_code >= 200 && endpoint.status_code < 400 {
                Severity::Info
            } else {
                Severity::Info
            };
            
            findings.push(Finding::new(
                format!("Endpoint Discovered: {}", endpoint.url),
                format!("Discovered via {} (status: {})", endpoint.source, endpoint.status_code),
                severity,
                Confidence::Medium,
                Category::InformationDisclosure,
                target_url.clone(),
                "web_application".to_string(),
                "endpoint_discovery".to_string(),
                "0.1.0".to_string(),
                context.scan_id,
            ).with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Discovered endpoint".to_string(),
                data: Some(serde_json::json!({
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "status_code": endpoint.status_code,
                    "content_type": endpoint.content_type,
                    "source": endpoint.source,
                })),
                location: Some(endpoint.url.clone()),
                metadata: HashMap::new(),
            }));
        }
        
        info!("Endpoint discovery completed for: {} - {} endpoints found", target_url, findings.len());
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
    let plugin = EndpointDiscoveryPlugin::new(config);
    0
}

#[no_mangle]
pub extern "C" fn plugin_execute(request_ptr: *const u8, request_len: usize, response_ptr: *mut u8, response_len: *mut usize) -> i32 {
    0
}

#[no_mangle]
pub extern "C" fn plugin_shutdown() -> i32 {
    0
}