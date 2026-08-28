//! Header Analysis Plugin
//!
//! Evaluates CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy,
//! and other security-related headers.

use crate::{
    Capability, CapabilityRequest, CapabilityResponse, PluginMetadata, ReconPlugin,
    ReconPluginConfig, ReconType,
};
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

/// Header Analysis Plugin
pub struct HeaderAnalysisPlugin {
    config: ReconPluginConfig,
    client: Client,
}

impl HeaderAnalysisPlugin {
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

    /// Analyze security headers
    async fn analyze_headers(&self, url: &str) -> Result<HeaderAnalysisResult> {
        let mut result = HeaderAnalysisResult::default();

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(crate::internal_err)?;

        // Extract all headers
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        result.all_headers = headers.clone();

        // Analyze security headers
        result.csp = self.analyze_csp(&headers);
        result.hsts = self.analyze_hsts(&headers);
        result.x_frame_options = self.analyze_x_frame_options(&headers);
        result.referrer_policy = self.analyze_referrer_policy(&headers);
        result.permissions_policy = self.analyze_permissions_policy(&headers);
        result.x_content_type_options = self.analyze_x_content_type_options(&headers);
        result.x_xss_protection = self.analyze_x_xss_protection(&headers);
        result.cross_origin_policies = self.analyze_cross_origin_policies(&headers);
        result.cache_control = self.analyze_cache_control(&headers);
        result.server_info = self.analyze_server_info(&headers);

        Ok(result)
    }

    fn analyze_csp(&self, headers: &HashMap<String, String>) -> CspAnalysis {
        let mut analysis = CspAnalysis::default();

        if let Some(csp) = headers.get("content-security-policy") {
            analysis.present = true;
            analysis.value = Some(csp.clone());
            analysis.directives = self.parse_csp_directives(csp);
            analysis.issues = self.check_csp_issues(&analysis.directives);
        } else if let Some(csp_report) = headers.get("content-security-policy-report-only") {
            analysis.present = true;
            analysis.report_only = true;
            analysis.value = Some(csp_report.clone());
            analysis.directives = self.parse_csp_directives(csp_report);
            analysis.issues = self.check_csp_issues(&analysis.directives);
        }

        analysis
    }

    fn parse_csp_directives(&self, csp: &str) -> HashMap<String, Vec<String>> {
        let mut directives = HashMap::new();

        for directive in csp.split(';') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }

            let parts: Vec<&str> = directive.split_whitespace().collect();
            if !parts.is_empty() {
                let name = parts[0].to_string();
                let values = parts[1..].iter().map(|s| s.to_string()).collect();
                directives.insert(name, values);
            }
        }

        directives
    }

    fn check_csp_issues(&self, directives: &HashMap<String, Vec<String>>) -> Vec<String> {
        let mut issues = Vec::new();

        // Check for unsafe-inline
        if let Some(script_src) = directives.get("script-src") {
            if script_src
                .iter()
                .any(|v| v == "'unsafe-inline'" || v == "'unsafe-eval'")
            {
                issues.push("CSP allows unsafe-inline or unsafe-eval in script-src".to_string());
            }
        }

        // Check for missing default-src
        if !directives.contains_key("default-src") {
            issues.push("CSP missing default-src directive".to_string());
        }

        // Check for wildcard
        for (_, values) in directives {
            if values.iter().any(|v| v == "*") {
                issues.push("CSP contains wildcard (*) directive".to_string());
                break;
            }
        }

        // Check for frame-ancestors (clickjacking protection)
        if !directives.contains_key("frame-ancestors") {
            issues.push(
                "CSP missing frame-ancestors directive (clickjacking protection)".to_string(),
            );
        }

        issues
    }

    fn analyze_hsts(&self, headers: &HashMap<String, String>) -> HstsAnalysis {
        let mut analysis = HstsAnalysis::default();

        if let Some(hsts) = headers.get("strict-transport-security") {
            analysis.present = true;
            analysis.value = Some(hsts.clone());

            // Parse HSTS directives
            for part in hsts.split(';') {
                let part = part.trim();
                if part.starts_with("max-age=") {
                    if let Ok(age) = part[8..].parse::<u64>() {
                        analysis.max_age = Some(age);
                        if age < 31536000 {
                            // Less than 1 year
                            analysis.issues.push(
                                "HSTS max-age less than 1 year (31536000 seconds)".to_string(),
                            );
                        }
                    }
                } else if part == "includeSubDomains" {
                    analysis.include_subdomains = true;
                } else if part == "preload" {
                    analysis.preload = true;
                }
            }

            if !analysis.include_subdomains {
                analysis
                    .issues
                    .push("HSTS missing includeSubDomains directive".to_string());
            }
        }

        analysis
    }

    fn analyze_x_frame_options(&self, headers: &HashMap<String, String>) -> XFrameOptionsAnalysis {
        let mut analysis = XFrameOptionsAnalysis::default();

        if let Some(xfo) = headers.get("x-frame-options") {
            analysis.present = true;
            analysis.value = Some(xfo.clone());

            let xfo_upper = xfo.to_uppercase();
            if xfo_upper == "DENY" {
                analysis.policy = XFramePolicy::Deny;
            } else if xfo_upper == "SAMEORIGIN" {
                analysis.policy = XFramePolicy::SameOrigin;
            } else if xfo_upper.starts_with("ALLOW-FROM") {
                analysis.policy = XFramePolicy::AllowFrom;
                analysis.allow_from = xfo[10..].trim().to_string();
            }
        }

        analysis
    }

    fn analyze_referrer_policy(&self, headers: &HashMap<String, String>) -> ReferrerPolicyAnalysis {
        let mut analysis = ReferrerPolicyAnalysis::default();

        if let Some(rp) = headers.get("referrer-policy") {
            analysis.present = true;
            analysis.value = Some(rp.clone());
            analysis.policy = rp.clone();
        }

        analysis
    }

    fn analyze_permissions_policy(
        &self,
        headers: &HashMap<String, String>,
    ) -> PermissionsPolicyAnalysis {
        let mut analysis = PermissionsPolicyAnalysis::default();

        if let Some(pp) = headers.get("permissions-policy") {
            analysis.present = true;
            analysis.value = Some(pp.clone());
            analysis.directives = self.parse_permissions_policy(pp);
        } else if let Some(fp) = headers.get("feature-policy") {
            analysis.present = true;
            analysis.value = Some(fp.clone());
            analysis.directives = self.parse_permissions_policy(fp);
            analysis.deprecated = true;
        }

        analysis
    }

    fn parse_permissions_policy(&self, policy: &str) -> HashMap<String, Vec<String>> {
        let mut directives = HashMap::new();

        for directive in policy.split(',') {
            let directive = directive.trim();
            if directive.is_empty() {
                continue;
            }

            let parts: Vec<&str> = directive.split_whitespace().collect();
            if !parts.is_empty() {
                let name = parts[0].to_string();
                let values = parts[1..].iter().map(|s| s.to_string()).collect();
                directives.insert(name, values);
            }
        }

        directives
    }

    fn analyze_x_content_type_options(
        &self,
        headers: &HashMap<String, String>,
    ) -> XContentTypeOptionsAnalysis {
        let mut analysis = XContentTypeOptionsAnalysis::default();

        if let Some(xcto) = headers.get("x-content-type-options") {
            analysis.present = true;
            analysis.value = Some(xcto.clone());
            analysis.nosniff = xcto.to_lowercase() == "nosniff";
        }

        analysis
    }

    fn analyze_x_xss_protection(
        &self,
        headers: &HashMap<String, String>,
    ) -> XXssProtectionAnalysis {
        let mut analysis = XXssProtectionAnalysis::default();

        if let Some(xxp) = headers.get("x-xss-protection") {
            analysis.present = true;
            analysis.value = Some(xxp.clone());
            analysis.enabled = xxp.contains("1");
            analysis.mode_block = xxp.contains("mode=block");
        }

        analysis
    }

    fn analyze_cross_origin_policies(
        &self,
        headers: &HashMap<String, String>,
    ) -> CrossOriginPoliciesAnalysis {
        let mut analysis = CrossOriginPoliciesAnalysis::default();

        if let Some(coep) = headers.get("cross-origin-embedder-policy") {
            analysis.embedder_policy = Some(coep.clone());
        }

        if let Some(coop) = headers.get("cross-origin-opener-policy") {
            analysis.opener_policy = Some(coop.clone());
        }

        if let Some(corp) = headers.get("cross-origin-resource-policy") {
            analysis.resource_policy = Some(corp.clone());
        }

        analysis
    }

    fn analyze_cache_control(&self, headers: &HashMap<String, String>) -> CacheControlAnalysis {
        let mut analysis = CacheControlAnalysis::default();

        if let Some(cc) = headers.get("cache-control") {
            analysis.present = true;
            analysis.value = Some(cc.clone());
            analysis.no_store = cc.contains("no-store");
            analysis.no_cache = cc.contains("no-cache");
            analysis.must_revalidate = cc.contains("must-revalidate");
            analysis.private = cc.contains("private");
            analysis.public = cc.contains("public");

            // Extract max-age
            for part in cc.split(',') {
                let part = part.trim();
                if part.starts_with("max-age=") {
                    if let Ok(age) = part[8..].parse::<u64>() {
                        analysis.max_age = Some(age);
                    }
                } else if part.starts_with("s-maxage=") {
                    if let Ok(age) = part[9..].parse::<u64>() {
                        analysis.s_maxage = Some(age);
                    }
                }
            }
        }

        if let Some(pragma) = headers.get("pragma") {
            analysis.pragma = Some(pragma.clone());
            if pragma.contains("no-cache") {
                analysis.no_cache = true;
            }
        }

        if let Some(expires) = headers.get("expires") {
            analysis.expires = Some(expires.clone());
        }

        analysis
    }

    fn analyze_server_info(&self, headers: &HashMap<String, String>) -> ServerInfoAnalysis {
        let mut analysis = ServerInfoAnalysis::default();

        if let Some(server) = headers.get("server") {
            analysis.server = Some(server.clone());
        }

        if let Some(powered) = headers.get("x-powered-by") {
            analysis.powered_by = Some(powered.clone());
        }

        if let Some(aspnet) = headers.get("x-aspnet-version") {
            analysis.aspnet_version = Some(aspnet.clone());
        }

        if let Some(runtime) = headers.get("x-runtime") {
            analysis.runtime = Some(runtime.clone());
        }

        analysis
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HeaderAnalysisResult {
    all_headers: HashMap<String, String>,
    csp: CspAnalysis,
    hsts: HstsAnalysis,
    x_frame_options: XFrameOptionsAnalysis,
    referrer_policy: ReferrerPolicyAnalysis,
    permissions_policy: PermissionsPolicyAnalysis,
    x_content_type_options: XContentTypeOptionsAnalysis,
    x_xss_protection: XXssProtectionAnalysis,
    cross_origin_policies: CrossOriginPoliciesAnalysis,
    cache_control: CacheControlAnalysis,
    server_info: ServerInfoAnalysis,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CspAnalysis {
    present: bool,
    report_only: bool,
    value: Option<String>,
    directives: HashMap<String, Vec<String>>,
    issues: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct HstsAnalysis {
    present: bool,
    value: Option<String>,
    max_age: Option<u64>,
    include_subdomains: bool,
    preload: bool,
    issues: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct XFrameOptionsAnalysis {
    present: bool,
    value: Option<String>,
    policy: XFramePolicy,
    allow_from: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum XFramePolicy {
    Deny,
    SameOrigin,
    AllowFrom,
    None,
}

impl Default for XFramePolicy {
    fn default() -> Self {
        XFramePolicy::None
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ReferrerPolicyAnalysis {
    present: bool,
    value: Option<String>,
    policy: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PermissionsPolicyAnalysis {
    present: bool,
    deprecated: bool,
    value: Option<String>,
    directives: HashMap<String, Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct XContentTypeOptionsAnalysis {
    present: bool,
    value: Option<String>,
    nosniff: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct XXssProtectionAnalysis {
    present: bool,
    value: Option<String>,
    enabled: bool,
    mode_block: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CrossOriginPoliciesAnalysis {
    embedder_policy: Option<String>,
    opener_policy: Option<String>,
    resource_policy: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheControlAnalysis {
    present: bool,
    value: Option<String>,
    no_store: bool,
    no_cache: bool,
    must_revalidate: bool,
    private: bool,
    public: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
    pragma: Option<String>,
    expires: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ServerInfoAnalysis {
    server: Option<String>,
    powered_by: Option<String>,
    aspnet_version: Option<String>,
    runtime: Option<String>,
}

#[async_trait::async_trait]
impl Plugin for HeaderAnalysisPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "header_analysis".to_string(),
            version: "0.1.0".to_string(),
            description: "Security header analysis plugin".to_string(),
            author: "open-re team".to_string(),
            license: "MIT".to_string(),
            repository: "https://github.com/RXVEN-1907/open-re".to_string(),
            homepage: None,
            categories: vec!["reconnaissance".to_string()],
            keywords: vec!["header".to_string(), "security".to_string()],
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
impl ReconPlugin for HeaderAnalysisPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::HeaderAnalysis
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

        info!("Starting header analysis for: {}", target_url);

        let analysis = self.analyze_headers(&target_url).await?;

        // CSP findings
        if !analysis.csp.present {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing Content-Security-Policy Header".to_string(),
                    description: "Content-Security-Policy header is not present".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Missing CSP header".to_string(),
                    data: None,
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
        } else {
            for issue in &analysis.csp.issues {
                findings.push(
                    Finding::new(FindingConfig {
                        title: "CSP Configuration Issue".to_string(),
                        description: issue.clone(),
                        severity: Severity::Low,
                        confidence: Confidence::Medium,
                        category: Category::SecurityMisconfiguration,
                        target: target_url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "header_analysis".to_string(),
                        plugin_version: "0.1.0".to_string(),
                        scan_id: context.scan_id,
                    })
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: "CSP issue".to_string(),
                        data: Some(serde_json::json!({"issue": issue, "csp": analysis.csp.value})),
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

        // HSTS findings
        if !analysis.hsts.present {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing HSTS Header".to_string(),
                    description: "Strict-Transport-Security header is not present".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Missing HSTS header".to_string(),
                    data: None,
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
        } else {
            for issue in &analysis.hsts.issues {
                findings.push(
                    Finding::new(FindingConfig {
                        title: "HSTS Configuration Issue".to_string(),
                        description: issue.clone(),
                        severity: Severity::Low,
                        confidence: Confidence::Medium,
                        category: Category::SecurityMisconfiguration,
                        target: target_url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "header_analysis".to_string(),
                        plugin_version: "0.1.0".to_string(),
                        scan_id: context.scan_id,
                    })
                    .with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: "HSTS issue".to_string(),
                        data: Some(
                            serde_json::json!({"issue": issue, "hsts": analysis.hsts.value}),
                        ),
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

        // X-Frame-Options findings
        if !analysis.x_frame_options.present {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing X-Frame-Options Header".to_string(),
                    description: "X-Frame-Options header is not present (clickjacking protection)"
                        .to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Missing X-Frame-Options header".to_string(),
                    data: None,
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

        // Referrer-Policy findings
        if !analysis.referrer_policy.present {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing Referrer-Policy Header".to_string(),
                    description: "Referrer-Policy header is not present".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Missing Referrer-Policy header".to_string(),
                    data: None,
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

        // Permissions-Policy findings
        if !analysis.permissions_policy.present {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing Permissions-Policy Header".to_string(),
                    description: "Permissions-Policy header is not present".to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Missing Permissions-Policy header".to_string(),
                    data: None,
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

        // X-Content-Type-Options findings
        if !analysis.x_content_type_options.present || !analysis.x_content_type_options.nosniff {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing or Weak X-Content-Type-Options Header".to_string(),
                    description: "X-Content-Type-Options header is missing or not set to 'nosniff'"
                        .to_string(),
                    severity: Severity::Low,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Missing X-Content-Type-Options: nosniff".to_string(),
                data: Some(serde_json::json!({"present": analysis.x_content_type_options.present, "nosniff": analysis.x_content_type_options.nosniff})),
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

        // X-XSS-Protection findings
        if !analysis.x_xss_protection.present {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Missing X-XSS-Protection Header".to_string(),
                    description: "X-XSS-Protection header is not present (legacy XSS protection)"
                        .to_string(),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Missing X-XSS-Protection header".to_string(),
                    data: None,
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

        // Server information disclosure
        if let Some(server) = &analysis.server_info.server {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Server Header Information Disclosure".to_string(),
                    description: format!("Server header reveals: {}", server),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Server header disclosure".to_string(),
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

        if let Some(powered) = &analysis.server_info.powered_by {
            findings.push(
                Finding::new(FindingConfig {
                    title: "X-Powered-By Header Information Disclosure".to_string(),
                    description: format!("X-Powered-By header reveals: {}", powered),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "header_analysis".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "X-Powered-By header disclosure".to_string(),
                    data: Some(serde_json::json!({"powered_by": powered})),
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
            "Header analysis completed for: {} - {} findings",
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
    let plugin = HeaderAnalysisPlugin::new(config);
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
