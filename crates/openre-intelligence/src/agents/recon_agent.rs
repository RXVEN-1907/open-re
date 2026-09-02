//! Recon agent implementation

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, AgentInput, AgentOutput, SecurityAgent};
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use crate::error::IntelligenceError;
use async_trait::async_trait;
use openre_core::ids::ScanId;
use openre_core::result::Finding;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

/// Recon agent for discovering URLs, endpoints, technologies
pub struct ReconAgent {
    base: crate::agents::agent_trait::BaseAgent,
    http_client: Arc<Client>,
}

impl ReconAgent {
    /// Create a new recon agent
    pub fn new(http_client: Arc<Client>) -> Self {
        let base = crate::agents::agent_trait::BaseAgent::new(
            "recon-agent".to_string(),
            AgentType::Recon,
        );
        Self { base, http_client }
    }

    /// Create a new recon agent with custom ID
    pub fn with_id(id: AgentId, http_client: Arc<Client>) -> Self {
        let base = crate::agents::agent_trait::BaseAgent::with_id(
            id,
            "recon-agent".to_string(),
            AgentType::Recon,
        );
        Self { base, http_client }
    }

    /// Discover URLs from a target
    async fn discover_urls(&self, target: &str, max_depth: usize, ctx: &AgentContext) -> anyhow::Result<Vec<DiscoveredUrl>> {
        let mut urls = Vec::new();
        let mut visited = HashMap::new();
        let mut to_visit = VecDeque::new();
        to_visit.push_back((target.to_string(), 0));

        let timeout = Duration::from_secs(10);

        while let Some((url, depth)) = to_visit.pop_front() {
            if depth > max_depth {
                continue;
            }

            if visited.contains_key(&url) {
                continue;
            }

            if ctx.is_cancelled() {
                break;
            }

            visited.insert(url.clone(), true);

            debug!("Discovering: {}", url);

            match self.fetch_url(&url, timeout).await {
                Ok(response) => {
                    let discovered = DiscoveredUrl {
                        url: url.clone(),
                        method: "GET".to_string(),
                        status_code: Some(response.status().as_u16()),
                        discovered_via: if depth == 0 { "initial".to_string() } else { "crawl".to_string() },
                        response_headers: response.headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect(),
                        technologies: Vec::new(),
                        parameters: Vec::new(),
                        forms: Vec::new(),
                        auth_info: None,
                    };

                    // Extract links for further crawling
                    if depth < max_depth {
                        if let Ok(body) = response.text().await {
                            let links = self.extract_links(&url, &body);
                            for link in links {
                                if !visited.contains_key(&link) {
                                    to_visit.push_back((link, depth + 1));
                                }
                            }
                        }
                    }

                    urls.push(discovered);
                }
                Err(e) => {
                    warn!("Failed to fetch {}: {}", url, e);
                }
            }
        }

        Ok(urls)
    }

    /// Fetch a URL
    async fn fetch_url(&self, url: &str, timeout: Duration) -> anyhow::Result<reqwest::Response> {
        let response = self.http_client
            .get(url)
            .timeout(timeout)
            .send()
            .await?;
        Ok(response)
    }

    /// Extract links from HTML
    fn extract_links(&self, base_url: &str, html: &str) -> Vec<String> {
        let mut links = Vec::new();
        let base = Url::parse(base_url).ok();

        // Simple regex-based link extraction
        let re = regex::Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in re.captures_iter(html) {
            if let Some(link) = cap.get(1) {
                let link_str = link.as_str();
                if let Ok(parsed) = Url::parse(link_str) {
                    links.push(parsed.to_string());
                } else if let Some(base) = &base {
                    if let Ok(joined) = base.join(link_str) {
                        links.push(joined.to_string());
                    }
                }
            }
        }

        // Also check for src attributes
        let re_src = regex::Regex::new(r#"src\s*=\s*["']([^"']+)["']"#).unwrap();
        for cap in re_src.captures_iter(html) {
            if let Some(link) = cap.get(1) {
                let link_str = link.as_str();
                if let Ok(parsed) = Url::parse(link_str) {
                    links.push(parsed.to_string());
                } else if let Some(base) = &base {
                    if let Ok(joined) = base.join(link_str) {
                        links.push(joined.to_string());
                    }
                }
            }
        }

        links
    }

    /// Detect technologies from response
    async fn detect_technologies(&self, urls: &[DiscoveredUrl]) -> Vec<DetectedTechnology> {
        let mut technologies = HashMap::new();

        for url in urls {
            // Check headers for technology indicators
            for (header, value) in &url.response_headers {
                let header_lower = header.to_lowercase();
                let value_lower = value.to_lowercase();

                // Server header
                if header_lower == "server" {
                    self.add_technology(&mut technologies, "Web Server", &value_lower, 0.8, vec!["server header"]);
                }

                // X-Powered-By
                if header_lower == "x-powered-by" {
                    self.add_technology(&mut technologies, "Framework", &value_lower, 0.9, vec!["x-powered-by header"]);
                }

                // Cookies
                if header_lower == "set-cookie" {
                    if value_lower.contains("php") {
                        self.add_technology(&mut technologies, "PHP", "detected via cookie", 0.7, vec!["cookie"]);
                    }
                    if value_lower.contains("laravel") {
                        self.add_technology(&mut technologies, "Laravel", "detected via cookie", 0.8, vec!["cookie"]);
                    }
                    if value_lower.contains("django") {
                        self.add_technology(&mut technologies, "Django", "detected via cookie", 0.8, vec!["cookie"]);
                    }
                    if value_lower.contains("express") || value_lower.contains("connect.sid") {
                        self.add_technology(&mut technologies, "Express.js", "detected via cookie", 0.7, vec!["cookie"]);
                    }
                }

                // Security headers
                if header_lower == "x-frame-options" {
                    self.add_technology(&mut technologies, "Security Headers", "X-Frame-Options present", 0.5, vec!["security header"]);
                }
                if header_lower == "content-security-policy" {
                    self.add_technology(&mut technologies, "Security Headers", "CSP present", 0.5, vec!["security header"]);
                }
            }

            // Check URL path for technology indicators
            let url_lower = url.url.to_lowercase();
            if url_lower.contains(".php") {
                self.add_technology(&mut technologies, "PHP", "detected via URL", 0.6, vec!["url path"]);
            }
            if url_lower.contains(".asp") || url_lower.contains(".aspx") {
                self.add_technology(&mut technologies, "ASP.NET", "detected via URL", 0.7, vec!["url path"]);
            }
            if url_lower.contains(".jsp") {
                self.add_technology(&mut technologies, "JSP", "detected via URL", 0.7, vec!["url path"]);
            }
            if url_lower.contains("wp-admin") || url_lower.contains("wp-content") {
                self.add_technology(&mut technologies, "WordPress", "detected via URL", 0.9, vec!["url path"]);
            }
            if url_lower.contains("/api/") {
                self.add_technology(&mut technologies, "REST API", "detected via URL", 0.6, vec!["url path"]);
            }
            if url_lower.contains("/graphql") {
                self.add_technology(&mut technologies, "GraphQL", "detected via URL", 0.8, vec!["url path"]);
            }
        }

        technologies.into_values().collect()
    }

    fn add_technology(
        &self,
        technologies: &mut HashMap<String, DetectedTechnology>,
        name: &str,
        version: &str,
        confidence: f32,
        evidence: Vec<&str>,
    ) {
        let key = name.to_lowercase();
        technologies.entry(key.clone()).and_modify(|t| {
            t.confidence = t.confidence.max(confidence);
            t.evidence.extend(evidence.iter().map(|s| s.to_string()));
        }).or_insert_with(|| DetectedTechnology {
            name: name.to_string(),
            version: Some(version.to_string()),
            confidence,
            categories: vec![],
            evidence: evidence.iter().map(|s| s.to_string()).collect(),
        });
    }

    /// Discover endpoints from URLs
    fn discover_endpoints(&self, urls: &[DiscoveredUrl]) -> Vec<DiscoveredEndpoint> {
        let mut endpoints = HashMap::new();

        for url in urls {
            let parsed = Url::parse(&url.url).ok();
            if let Some(parsed) = parsed {
                let path = parsed.path().to_string();
                let entry = endpoints.entry(path.clone()).or_insert_with(|| DiscoveredEndpoint {
                    path: path.clone(),
                    methods: Vec::new(),
                    parameters: Vec::new(),
                    authentication: None,
                    sensitivity: "public".to_string(),
                    technology_stack: Vec::new(),
                });

                entry.methods.push(url.method.clone());
                // Add query parameters
                for (key, _value) in parsed.query_pairs() {
                    if !entry.parameters.iter().any(|p: &EndpointParameter| p.name == key) {
                        entry.parameters.push(EndpointParameter {
                            name: key.to_string(),
                            param_type: "string".to_string(),
                            location: "query".to_string(),
                            required: false,
                            description: None,
                        });
                    }
                }
            }
        }

        endpoints.into_values().collect()
    }

    /// Discover authentication endpoints
    fn discover_auth_endpoints(&self, urls: &[DiscoveredUrl]) -> Vec<AuthEndpoint> {
        let mut auth_endpoints = Vec::new();

        for url in urls {
            let url_lower = url.url.to_lowercase();
            if url_lower.contains("login") || url_lower.contains("signin") || url_lower.contains("auth") {
                auth_endpoints.push(AuthEndpoint {
                    url: url.url.clone(),
                    auth_type: "form".to_string(),
                    login_form: None,
                    password_reset: None,
                    registration: None,
                });
            }
            if url_lower.contains("register") || url_lower.contains("signup") {
                auth_endpoints.push(AuthEndpoint {
                    url: url.url.clone(),
                    auth_type: "registration".to_string(),
                    login_form: None,
                    password_reset: None,
                    registration: Some(url.url.clone()),
                });
            }
            if url_lower.contains("password") && (url_lower.contains("reset") || url_lower.contains("forgot")) {
                auth_endpoints.push(AuthEndpoint {
                    url: url.url.clone(),
                    auth_type: "password_reset".to_string(),
                    login_form: None,
                    password_reset: Some(url.url.clone()),
                    registration: None,
                });
            }
        }

        auth_endpoints
    }

    /// Discover forms from URLs (simplified)
    fn discover_forms(&self, urls: &[DiscoveredUrl]) -> Vec<DiscoveredForm> {
        // In a real implementation, this would parse HTML for forms
        // For now, return empty
        Vec::new()
    }
}

#[async_trait]
impl SecurityAgent for ReconAgent {
    type Input = ReconInput;
    type Output = ReconOutput;

    fn agent_id(&self) -> AgentId {
        self.base.agent_id()
    }

    fn agent_type(&self) -> AgentType {
        self.base.agent_type()
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities()
    }

    fn name(&self) -> &str {
        self.base.name()
    }

    async fn execute(&self, input: Self::Input, ctx: AgentContext) -> anyhow::Result<AgentResult<Self::Output>> {
        let started_at = std::time::Instant::now();
        info!("Recon agent starting for target: {}", input.target);

        // Discover URLs
        let urls = self.discover_urls(&input.target, input.max_depth.unwrap_or(3), &ctx).await?;

        // Detect technologies
        let technologies = self.detect_technologies(&urls).await;

        // Discover endpoints
        let endpoints = self.discover_endpoints(&urls);

        // Discover auth endpoints
        let auth_endpoints = self.discover_auth_endpoints(&urls);

        // Discover forms
        let forms = self.discover_forms(&urls);

        let duration_ms = started_at.elapsed().as_millis() as u64;

        let output = ReconOutput {
            urls,
            endpoints,
            technologies,
            auth_endpoints,
            forms,
        };

        Ok(AgentResult::success(output, duration_ms))
    }

    async fn health_check(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}

use std::collections::VecDeque;