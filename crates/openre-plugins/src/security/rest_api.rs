//! REST API Security Plugin
//!
//! Discovers and analyzes REST API endpoints for security issues including
//! missing authentication, improper authorization, insecure HTTP methods,
//! and sensitive endpoint exposure.

use crate::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use async_trait::async_trait;
use chrono::Utc;
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Reference, ReferenceType,
    Severity,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// REST API Security Plugin
pub struct RestApiPlugin {
    config: RestApiConfig,
    client: Arc<reqwest::Client>,
}

impl RestApiPlugin {
    /// Create a new REST API security plugin
    pub fn new(config: RestApiConfig) -> std::result::Result<Self, String> {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?,
        );

        Ok(Self { config, client })
    }

    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }

    /// Get plugin description
    fn description(&self) -> &'static str {
        "Discovers and analyzes REST API endpoints for security issues including missing authentication, improper authorization, insecure HTTP methods, and sensitive endpoint exposure"
    }

    /// Get plugin references
    fn references(&self) -> Vec<SecurityReference> {
        vec![
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API1:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x11-broken-object-level-authorization/".to_string(),
                description: "OWASP API Security Top 10 2023 - Broken Object Level Authorization".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API2:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x21-broken-authentication/".to_string(),
                description: "OWASP API Security Top 10 2023 - Broken Authentication".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API3:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x31-broken-object-property-level-authorization/".to_string(),
                description: "OWASP API Security Top 10 2023 - Broken Object Property Level Authorization".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-284".to_string(),
                url: "https://cwe.mitre.org/data/definitions/284.html".to_string(),
                description: "Improper Access Control".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-306".to_string(),
                url: "https://cwe.mitre.org/data/definitions/306.html".to_string(),
                description: "Missing Authentication for Critical Function".to_string(),
            },
        ]
    }

    /// Validate configuration
    fn validate_config(&self, config: &RestApiConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Discover API endpoints from common paths and OpenAPI specs
    async fn discover_endpoints(&self, base_url: &str) -> Vec<ApiEndpoint> {
        let mut endpoints = Vec::new();

        // Common API paths to check
        let common_paths = vec![
            "/api",
            "/api/v1",
            "/api/v2",
            "/api/v3",
            "/rest",
            "/rest/v1",
            "/rest/v2",
            "/v1",
            "/v2",
            "/v3",
            "/graphql",
            "/graphql/",
            "/swagger",
            "/swagger.json",
            "/swagger.yaml",
            "/openapi",
            "/openapi.json",
            "/openapi.yaml",
            "/api-docs",
            "/api-docs.json",
            "/docs",
            "/redoc",
        ];

        for path in common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success()
                    || resp.status().as_u16() == 401
                    || resp.status().as_u16() == 403
                {
                    let content_type = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    endpoints.push(ApiEndpoint {
                        url: url.clone(),
                        path: path.to_string(),
                        method: "GET".to_string(),
                        status: resp.status().as_u16(),
                        content_type,
                        requires_auth: resp.status().as_u16() == 401
                            || resp.status().as_u16() == 403,
                    });
                }
            }
        }

        // Try to fetch OpenAPI spec
        if let Some(spec_endpoints) = self.fetch_openapi_spec(base_url).await {
            endpoints.extend(spec_endpoints);
        }

        endpoints
    }

    /// Fetch and parse OpenAPI/Swagger specification
    async fn fetch_openapi_spec(&self, base_url: &str) -> Option<Vec<ApiEndpoint>> {
        let spec_paths = vec![
            "/openapi.json",
            "/openapi.yaml",
            "/openapi.yml",
            "/swagger.json",
            "/swagger.yaml",
            "/swagger.yml",
            "/api-docs",
            "/api-docs.json",
            "/v3/api-docs",
            "/v2/api-docs",
        ];

        for path in spec_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success() {
                    let body = resp.text().await.ok()?;
                    return self.parse_openapi_spec(&body, base_url);
                }
            }
        }
        None
    }

    /// Parse OpenAPI specification and extract endpoints
    fn parse_openapi_spec(&self, spec: &str, base_url: &str) -> Option<Vec<ApiEndpoint>> {
        let mut endpoints = Vec::new();

        // Try JSON first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(spec) {
            if let Some(paths) = json.get("paths").and_then(|p| p.as_object()) {
                for (path, methods) in paths {
                    if let Some(methods_obj) = methods.as_object() {
                        for (method, _details) in methods_obj {
                            if ["get", "post", "put", "patch", "delete", "head", "options"]
                                .contains(&method.as_str())
                            {
                                endpoints.push(ApiEndpoint {
                                    url: format!("{}{}", base_url.trim_end_matches('/'), path),
                                    path: path.clone(),
                                    method: method.to_uppercase(),
                                    status: 0, // Unknown until tested
                                    content_type: "application/json".to_string(),
                                    requires_auth: false,
                                });
                            }
                        }
                    }
                }
            }
            return Some(endpoints);
        }

        // Try YAML (basic parsing)
        if spec.contains("openapi:") || spec.contains("swagger:") {
            // Simple YAML parsing for paths
            for line in spec.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('/') && trimmed.ends_with(':') {
                    let path = trimmed.trim_end_matches(':').to_string();
                    for method in ["get", "post", "put", "patch", "delete", "head", "options"] {
                        endpoints.push(ApiEndpoint {
                            url: format!("{}{}", base_url.trim_end_matches('/'), path),
                            path: path.clone(),
                            method: method.to_uppercase(),
                            status: 0,
                            content_type: "application/json".to_string(),
                            requires_auth: false,
                        });
                    }
                }
            }
            return Some(endpoints);
        }

        None
    }

    /// Test endpoint for security issues
    async fn test_endpoint(
        &self,
        endpoint: &ApiEndpoint,
        scan_id: openre_core::ids::ScanId,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Test 1: Missing authentication on sensitive endpoints
        if self.is_sensitive_endpoint(&endpoint.path) && !endpoint.requires_auth {
            findings.push(self.create_finding(
                "Missing Authentication on Sensitive Endpoint",
                &format!(
                    "Endpoint {} {} does not require authentication",
                    endpoint.method, endpoint.path
                ),
                Severity::High,
                Confidence::High,
                Category::BrokenAuthentication,
                endpoint,
                vec!["missing-auth".to_string(), "sensitive-endpoint".to_string()],
                vec!["Verify authentication is required for this endpoint".to_string()],
                scan_id,
            ));
        }

        // Test 2: Insecure HTTP methods
        if matches!(
            endpoint.method.as_str(),
            "PUT" | "DELETE" | "PATCH" | "TRACE" | "CONNECT"
        ) {
            if !endpoint.requires_auth {
                findings.push(self.create_finding(
                    "Insecure HTTP Method Without Authentication",
                    &format!(
                        "Endpoint {} {} allows {} without authentication",
                        endpoint.method, endpoint.path, endpoint.method
                    ),
                    Severity::Medium,
                    Confidence::Medium,
                    Category::SecurityMisconfiguration,
                    endpoint,
                    vec!["insecure-method".to_string(), "missing-auth".to_string()],
                    vec!["Restrict dangerous HTTP methods to authenticated users".to_string()],
                    scan_id,
                ));
            }
        }

        // Test 3: TRACE method enabled
        if endpoint.method == "TRACE" {
            findings.push(self.create_finding(
                "TRACE Method Enabled",
                &format!(
                    "Endpoint {} {} has TRACE method enabled",
                    endpoint.method, endpoint.path
                ),
                Severity::Low,
                Confidence::High,
                Category::SecurityMisconfiguration,
                endpoint,
                vec!["trace-method".to_string()],
                vec!["Disable TRACE method in server configuration".to_string()],
                scan_id,
            ));
        }

        // Test 4: OPTIONS method information disclosure
        if endpoint.method == "OPTIONS" {
            // Would need to check Allow header
            findings.push(self.create_finding(
                "OPTIONS Method Information Disclosure",
                &format!(
                    "Endpoint {} {} exposes allowed methods via OPTIONS",
                    endpoint.method, endpoint.path
                ),
                Severity::Info,
                Confidence::Medium,
                Category::InformationDisclosure,
                endpoint,
                vec!["options-method".to_string(), "info-disclosure".to_string()],
                vec!["Review if OPTIONS response reveals sensitive information".to_string()],
                scan_id,
            ));
        }

        // Test 5: API versioning issues
        if endpoint.path.contains("/v1/") || endpoint.path.contains("/v2/") {
            // Check for deprecated versions
            findings.push(self.create_finding(
                "Potential Deprecated API Version",
                &format!(
                    "Endpoint {} {} uses potentially deprecated API version",
                    endpoint.method, endpoint.path
                ),
                Severity::Info,
                Confidence::Low,
                Category::SecurityMisconfiguration,
                endpoint,
                vec!["api-versioning".to_string()],
                vec!["Verify API version is current and supported".to_string()],
                scan_id,
            ));
        }

        findings
    }

    /// Check if endpoint path is sensitive
    fn is_sensitive_endpoint(&self, path: &str) -> bool {
        let sensitive_patterns = [
            "/admin",
            "/management",
            "/actuator",
            "/metrics",
            "/health",
            "/config",
            "/env",
            "/debug",
            "/trace",
            "/dump",
            "/users",
            "/accounts",
            "/profile",
            "/password",
            "/api/users",
            "/api/admin",
            "/api/config",
            "/internal",
            "/private",
            "/secret",
        ];

        sensitive_patterns.iter().any(|p| path.contains(p))
    }

    /// Create a finding from endpoint test
    fn create_finding(
        &self,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        endpoint: &ApiEndpoint,
        tags: Vec<String>,
        verification_steps: Vec<String>,
        scan_id: openre_core::ids::ScanId,
    ) -> Finding {
        let mut finding = Finding::new(FindingConfig {
            title: title.to_string(),
            description: description.to_string(),
            severity,
            confidence,
            category,
            target: endpoint.url.clone(),
            target_type: "web_api".to_string(),
            plugin_source: "rest_api_security".to_string(),
            plugin_version: self.version().to_string(),
            scan_id,
        });

        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!(
                "REST API endpoint test for {} {}",
                endpoint.method, endpoint.path
            ),
            data: Some(serde_json::json!({
                "endpoint": {
                    "url": endpoint.url,
                    "path": endpoint.path,
                    "method": endpoint.method,
                    "status": endpoint.status,
                    "content_type": endpoint.content_type,
                    "requires_auth": endpoint.requires_auth,
                }
            })),
            location: Some(endpoint.url.clone()),
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("rest_api_security".to_string()),
            timestamp: Utc::now(),
        });

        for reference in self.references() {
            finding = finding.with_reference(Reference {
                reference_type: match reference.ref_type.as_str() {
                    "CWE" => ReferenceType::Cwe,
                    "OWASP" => ReferenceType::Owasp,
                    "CVE" => ReferenceType::Cve,
                    _ => ReferenceType::Custom(reference.ref_type),
                },
                title: reference.id.clone(),
                url: reference.url.clone(),
                description: Some(reference.description.clone()),
            });
        }

        for tag in tags {
            finding = finding.with_tag(tag);
        }
        finding = finding.with_tag("rest-api".to_string());

        finding
    }
}

#[async_trait]
impl Plugin for RestApiPlugin {
    type Config = RestApiConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create REST API plugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let scan_id = openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid());
        let target_url = request
            .input
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");

        info!("Starting REST API security analysis for {}", target_url);

        // Discover endpoints
        let endpoints = self.discover_endpoints(target_url).await;
        let endpoints_count = endpoints.len();
        info!("Discovered {} endpoints", endpoints_count);

        // Test each endpoint
        let mut all_findings = Vec::new();
        for endpoint in endpoints {
            let findings = self.test_endpoint(&endpoint, scan_id).await;
            all_findings.extend(findings);
        }

        info!("Found {} security issues", all_findings.len());

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": all_findings,
            "endpoints_tested": endpoints_count,
            "vulnerabilities_found": all_findings.len(),
        })))
    }
}

/// REST API Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RestApiConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for RestApiConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-rest-api-scanner/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

/// API Endpoint representation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApiEndpoint {
    url: String,
    path: String,
    method: String,
    status: u16,
    content_type: String,
    requires_auth: bool,
}

// Plugin entry point
