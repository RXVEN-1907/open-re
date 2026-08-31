//! Cookie Analysis Plugin
//!
//! Inspects cookies for Secure flag, HttpOnly, SameSite, Expiration, and Scope.

use crate::{
    Capability, CapabilityRequest, CapabilityResponse, PluginMetadata, ReconPlugin,
    ReconPluginConfig, ReconType,
};
use cookie::Cookie;
use openre_core::error::OpenreResult as Result;
use openre_core::plugin::{CommandContext, CommandRegistration, CommandResult, Plugin};
use openre_core::result::FindingConfig;
use openre_scanner::{
    context::ScanContext,
    result::{
        Category, Confidence, Evidence, EvidenceType, Finding, Reference, ReferenceType, Severity,
    },
    target::TargetType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Cookie Analysis Plugin
pub struct CookieAnalysisPlugin {
    config: ReconPluginConfig,
    client: Client,
}

impl CookieAnalysisPlugin {
    pub fn new(config: ReconPluginConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(crate::internal_err)?;

        Ok(Self { config, client })
    }

    /// Analyze cookies from response
    async fn analyze_cookies(&self, url: &str) -> Result<CookieAnalysisResult> {
        let mut result = CookieAnalysisResult::default();

        let response = self.client.get(url).send().await.map_err(crate::internal_err)?;

        // Extract cookies from Set-Cookie headers
        for header in response.headers().get_all("set-cookie") {
            if let Ok(header_str) = header.to_str() {
                if let Ok(cookie) = Cookie::parse(header_str) {
                    let analysis = self.analyze_cookie(&cookie);
                    result.cookies.push(analysis);
                }
            }
        }

        // Also check for cookies in response body (JavaScript-set cookies)
        let body = response.text().await.unwrap_or_default();
        let js_cookies = self.extract_js_cookies(&body);
        result.js_cookies = js_cookies;

        Ok(result)
    }

    fn analyze_cookie(&self, cookie: &Cookie) -> CookieAnalysis {
        let mut analysis = CookieAnalysis {
            name: cookie.name().to_string(),
            value: cookie.value().to_string(),
            domain: cookie.domain().map(|d| d.to_string()),
            path: cookie.path().map(|p| p.to_string()),
            secure: cookie.secure().unwrap_or(false),
            http_only: cookie.http_only().unwrap_or(false),
            same_site: cookie.same_site().map(|s| format!("{:?}", s)),
            expires: cookie.expires().map(|e| format!("{:?}", e)),
            max_age: cookie.max_age().map(|m| m.to_string()),
            issues: Vec::new(),
        };

        // Check for security issues
        if !analysis.secure {
            analysis.issues.push("Missing Secure flag - cookie transmitted over HTTP".to_string());
        }

        if !analysis.http_only {
            analysis.issues.push("Missing HttpOnly flag - accessible via JavaScript".to_string());
        }

        if analysis.same_site.is_none() || analysis.same_site.as_ref().map_or(true, |s| s == "None")
        {
            analysis.issues.push("Missing or weak SameSite attribute".to_string());
        }

        if analysis.expires.is_none() && analysis.max_age.is_none() {
            analysis.issues.push("Session cookie - no expiration set".to_string());
        }

        // Check for overly broad domain
        if let Some(domain) = &analysis.domain {
            if domain.starts_with('.') && domain.matches('.').count() <= 1 {
                analysis.issues.push("Overly broad domain scope".to_string());
            }
        }

        // Check for overly broad path
        if let Some(path) = &analysis.path {
            if path == "/" {
                analysis
                    .issues
                    .push("Cookie path is root - accessible to entire domain".to_string());
            }
        }

        analysis
    }

    fn extract_js_cookies(&self, body: &str) -> Vec<JsCookie> {
        let mut cookies = Vec::new();

        // Look for document.cookie assignments
        let patterns =
            [r#"document\.cookie\s*=\s*["']([^"']+)["']"#, r#"cookie\s*=\s*["']([^"']+)["']"#];

        for pattern in patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                for cap in re.captures_iter(body) {
                    if let Some(cookie_str) = cap.get(1) {
                        cookies.push(JsCookie {
                            raw: cookie_str.as_str().to_string(),
                            source: "javascript".to_string(),
                        });
                    }
                }
            }
        }

        cookies
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CookieAnalysisResult {
    cookies: Vec<CookieAnalysis>,
    js_cookies: Vec<JsCookie>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CookieAnalysis {
    name: String,
    value: String,
    domain: Option<String>,
    path: Option<String>,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    expires: Option<String>,
    max_age: Option<String>,
    issues: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsCookie {
    raw: String,
    source: String,
}

#[async_trait::async_trait]
impl Plugin for CookieAnalysisPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "cookie_analysis".to_string(),
            version: "0.1.0".to_string(),
            description: "Cookie security analysis plugin".to_string(),
            author: "open-re team".to_string(),
            license: "MIT".to_string(),
            repository: "https://github.com/RXVEN-1907/open-re".to_string(),
            homepage: None,
            categories: vec!["reconnaissance".to_string()],
            keywords: vec!["cookie".to_string(), "security".to_string()],
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    fn commands(&self) -> Vec<CommandRegistration> {
        vec![]
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> anyhow::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl ReconPlugin for CookieAnalysisPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::CookieAnalysis
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
        let target_url = context.target.metadata.base_url.as_str().to_string();

        info!("Starting cookie analysis for: {}", target_url);

        let analysis = self.analyze_cookies(&target_url).await?;

        // Create findings for each cookie
        for cookie in analysis.cookies {
            for issue in &cookie.issues {
                let severity = match issue.as_str() {
                    "Missing Secure flag - cookie transmitted over HTTP" => Severity::Medium,
                    "Missing HttpOnly flag - accessible via JavaScript" => Severity::Medium,
                    "Missing or weak SameSite attribute" => Severity::Low,
                    "Session cookie - no expiration set" => Severity::Info,
                    "Overly broad domain scope" => Severity::Low,
                    "Cookie path is root - accessible to entire domain" => Severity::Info,
                    _ => Severity::Info,
                };

                findings.push(
                    Finding::new(FindingConfig {
                        title: format!("Cookie Issue: {}", cookie.name),
                        description: format!("{}: {}", cookie.name, issue),
                        severity: severity,
                        confidence: Confidence::High,
                        category: Category::SecurityMisconfiguration,
                        target: target_url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "cookie_analysis".to_string(),
                        plugin_version: "0.1.0".to_string(),
                        scan_id: context.scan_id,
                    })
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: format!("Cookie security issue: {}", issue),
                        data: Some(serde_json::json!({
                            "cookie_name": cookie.name,
                            "domain": cookie.domain,
                            "path": cookie.path,
                            "secure": cookie.secure,
                            "http_only": cookie.http_only,
                            "same_site": cookie.same_site,
                            "expires": cookie.expires,
                            "max_age": cookie.max_age,
                            "issue": issue,
                        })),
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

            // Also create a general finding for the cookie
            if cookie.issues.is_empty() {
                findings.push(
                    Finding::new(FindingConfig {
                        title: format!("Cookie Analyzed: {}", cookie.name),
                        description: format!(
                            "Cookie {} appears to have proper security attributes",
                            cookie.name
                        ),
                        severity: Severity::Info,
                        confidence: Confidence::Medium,
                        category: Category::Configuration,
                        target: target_url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "cookie_analysis".to_string(),
                        plugin_version: "0.1.0".to_string(),
                        scan_id: context.scan_id,
                    })
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: "Cookie security analysis".to_string(),
                        data: Some(serde_json::json!({
                            "cookie_name": cookie.name,
                            "secure": cookie.secure,
                            "http_only": cookie.http_only,
                            "same_site": cookie.same_site,
                        })),
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

        // JavaScript-set cookies
        for js_cookie in analysis.js_cookies {
            findings.push(
                Finding::new(FindingConfig {
                    title: "JavaScript-Set Cookie Detected".to_string(),
                    description: "Cookie set via JavaScript (document.cookie)".to_string(),
                    severity: Severity::Info,
                    confidence: Confidence::Medium,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "cookie_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "JavaScript-set cookie".to_string(),
                    data: Some(serde_json::json!({
                        "raw": js_cookie.raw,
                    })),
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

        info!("Cookie analysis completed for: {} - {} findings", target_url, findings.len());
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
    let plugin = CookieAnalysisPlugin::new(config);
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
    0
}

#[cfg(feature = "wasm-plugin")]
#[no_mangle]
pub extern "C" fn plugin_shutdown() -> i32 {
    0
}
