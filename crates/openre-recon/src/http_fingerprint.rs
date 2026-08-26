//! HTTP Fingerprinting Plugin
//!
//! Collects HTTP methods, response headers, server banner, security headers,
//! content types, compression, and redirect chains.

use crate::{ReconMetadata, ReconPlugin, ReconPluginConfig, ReconType};
use openre_core::error::OpenreResult as Result;
use openre_core::result::FindingConfig;
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
use reqwest::{redirect::Policy, Client, Method};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// HTTP Fingerprinting Plugin
pub struct HttpFingerprintPlugin {
    config: ReconPluginConfig,
    client: Client,
}

impl HttpFingerprintPlugin {
    pub fn new(config: ReconPluginConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(Policy::limited(config.max_redirects))
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(crate::internal_err)?;

        Ok(Self { config, client })
    }

    /// Perform HTTP fingerprinting on a target
    async fn fingerprint_target(&self, url: &str) -> Result<HttpFingerprintResult> {
        let mut result = HttpFingerprintResult::default();
        let mut current_url = url.to_string();
        let mut redirect_chain = Vec::new();

        for _ in 0..self.config.max_redirects {
            let response = self
                .client
                .get(&current_url)
                .send()
                .await
                .map_err(crate::internal_err)?;

            // Collect headers
            let headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            result.headers = headers.clone();

            // Server banner
            if let Some(server) = headers.get("server") {
                result.server_banner = Some(server.clone());
            }

            // Security headers
            result.security_headers = self.extract_security_headers(&headers);

            // Content type
            if let Some(content_type) = headers.get("content-type") {
                result.content_type = Some(content_type.clone());
            }

            // Compression
            if let Some(encoding) = headers.get("content-encoding") {
                result.compression = Some(encoding.clone());
            }

            // HTTP methods (via OPTIONS)
            if result.allowed_methods.is_empty() {
                if let Ok(options_resp) = self
                    .client
                    .request(Method::OPTIONS, &current_url)
                    .send()
                    .await
                {
                    if let Some(allow) = options_resp.headers().get("allow") {
                        result.allowed_methods = allow
                            .to_str()
                            .unwrap_or("")
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                    }
                }
            }

            // Track redirect
            if response.status().is_redirection() {
                redirect_chain.push(current_url.clone());
                if let Some(location) = response.headers().get("location") {
                    current_url = location.to_str().unwrap_or(&current_url).to_string();
                    result.redirect_chain = redirect_chain.clone();
                    continue;
                }
            }

            result.status_code = response.status().as_u16();
            result.final_url = current_url;
            break;
        }

        Ok(result)
    }

    fn extract_security_headers(&self, headers: &HashMap<String, String>) -> SecurityHeaders {
        SecurityHeaders {
            csp: headers.get("content-security-policy").cloned(),
            hsts: headers.get("strict-transport-security").cloned(),
            x_frame_options: headers.get("x-frame-options").cloned(),
            referrer_policy: headers.get("referrer-policy").cloned(),
            permissions_policy: headers.get("permissions-policy").cloned(),
            x_content_type_options: headers.get("x-content-type-options").cloned(),
            x_xss_protection: headers.get("x-xss-protection").cloned(),
            cross_origin_embedder_policy: headers.get("cross-origin-embedder-policy").cloned(),
            cross_origin_opener_policy: headers.get("cross-origin-opener-policy").cloned(),
            cross_origin_resource_policy: headers.get("cross-origin-resource-policy").cloned(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HttpFingerprintResult {
    status_code: u16,
    final_url: String,
    headers: HashMap<String, String>,
    server_banner: Option<String>,
    security_headers: SecurityHeaders,
    content_type: Option<String>,
    compression: Option<String>,
    allowed_methods: Vec<String>,
    redirect_chain: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SecurityHeaders {
    csp: Option<String>,
    hsts: Option<String>,
    x_frame_options: Option<String>,
    referrer_policy: Option<String>,
    permissions_policy: Option<String>,
    x_content_type_options: Option<String>,
    x_xss_protection: Option<String>,
    cross_origin_embedder_policy: Option<String>,
    cross_origin_opener_policy: Option<String>,
    cross_origin_resource_policy: Option<String>,
}

#[async_trait::async_trait]
impl Plugin for HttpFingerprintPlugin {
    type Config = ReconPluginConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create HttpFingerprintPlugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let _ = request;

        // Recon plugins perform their work through the scan pipeline, which
        // supplies a full ScanContext. Capability execution has no scan context,
        // so report an empty result set instead.
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": [],
            "recon_type": ReconType::HttpFingerprint,
        })))
    }
}

#[async_trait::async_trait]
impl ReconPlugin for HttpFingerprintPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::HttpFingerprint
    }

    fn supported_target_types(&self) -> Vec<TargetType> {
        vec![
            TargetType::LocalWebApp,
            TargetType::RemoteWebApp,
            TargetType::RestApi,
            TargetType::GraphQLApi,
        ]
    }

    async fn recon(&self, context: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Get target URL from context
        let target_url = context.target.metadata.base_url.as_str().to_string();

        info!("Starting HTTP fingerprinting for: {}", target_url);

        let fingerprint = self.fingerprint_target(&target_url).await?;

        // Create findings based on fingerprint results

        // Server banner finding
        if let Some(server) = &fingerprint.server_banner {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Server Banner Disclosure".to_string(),
                    description: format!("Server header reveals: {}", server),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "http_fingerprint".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: format!("Server header: {}", server),
                    data: Some(serde_json::json!({"server": server})),
                    location: Some(target_url.clone()),
                    metadata: HashMap::new(),
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: None,
                    timestamp: chrono::Utc::now(),
                }),
            );
        }

        // Missing security headers
        let security = &fingerprint.security_headers;
        let missing_headers = vec![
            (
                "Content-Security-Policy",
                &security.csp,
                "CSP header missing",
            ),
            (
                "Strict-Transport-Security",
                &security.hsts,
                "HSTS header missing",
            ),
            (
                "X-Frame-Options",
                &security.x_frame_options,
                "X-Frame-Options header missing",
            ),
            (
                "Referrer-Policy",
                &security.referrer_policy,
                "Referrer-Policy header missing",
            ),
            (
                "Permissions-Policy",
                &security.permissions_policy,
                "Permissions-Policy header missing",
            ),
            (
                "X-Content-Type-Options",
                &security.x_content_type_options,
                "X-Content-Type-Options header missing",
            ),
        ];

        for (header_name, header_value, description) in missing_headers {
            if header_value.is_none() {
                findings.push(
                    Finding::new(FindingConfig {
                        title: format!("Missing Security Header: {}", header_name),
                        description: description.to_string(),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: Category::SecurityMisconfiguration,
                        target: target_url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "http_fingerprint".to_string(),
                        plugin_version: "0.1.0".to_string(),
                        scan_id: context.scan_id,
                    })
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: format!("Missing {} header", header_name),
                        data: Some(serde_json::json!({"missing_header": header_name})),
                        location: Some(target_url.clone()),
                        metadata: HashMap::new(),
                        http_request: None,
                        http_response: None,
                        timing: None,
                        payload: None,
                        reproduction_steps: None,
                        plugin_source: None,
                        timestamp: chrono::Utc::now(),
                    }),
                );
            }
        }

        // Redirect chain finding
        if !fingerprint.redirect_chain.is_empty() {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Redirect Chain Detected".to_string(),
                    description: format!(
                        "Request redirected through {} hops",
                        fingerprint.redirect_chain.len()
                    ),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "http_fingerprint".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Redirect chain detected".to_string(),
                    data: Some(serde_json::json!({"redirect_chain": fingerprint.redirect_chain})),
                    location: Some(target_url.clone()),
                    metadata: HashMap::new(),
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: None,
                    timestamp: chrono::Utc::now(),
                }),
            );
        }

        // Allowed methods
        if !fingerprint.allowed_methods.is_empty() {
            findings.push(
                Finding::new(FindingConfig {
                    title: "HTTP Methods Enumerated".to_string(),
                    description: format!(
                        "Allowed methods: {}",
                        fingerprint.allowed_methods.join(", ")
                    ),
                    severity: Severity::Info,
                    confidence: Confidence::Medium,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "http_fingerprint".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Allowed HTTP methods".to_string(),
                    data: Some(serde_json::json!({"methods": fingerprint.allowed_methods})),
                    location: Some(target_url.clone()),
                    metadata: HashMap::new(),
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: None,
                    timestamp: chrono::Utc::now(),
                }),
            );
        }

        info!(
            "HTTP fingerprinting completed for: {} - {} findings",
            target_url,
            findings.len()
        );
        Ok(findings)
    }
}

/// Plugin entry point
#[cfg(feature = "wasm-plugin")]
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
    let plugin = HttpFingerprintPlugin::new(config);
    // Store plugin in global state (simplified)
    0
}

#[cfg(feature = "wasm-plugin")]
#[no_mangle]
pub extern "C" fn plugin_execute(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_len: *mut usize,
) -> i32 {
    // Implementation would go here
    0
}

#[cfg(feature = "wasm-plugin")]
#[no_mangle]
pub extern "C" fn plugin_shutdown() -> i32 {
    0
}
