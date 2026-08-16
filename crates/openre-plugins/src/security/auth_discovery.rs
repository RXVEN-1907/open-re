//! Authentication Discovery Plugin
//!
//! Detects login forms, registration endpoints, password reset flows,
//! MFA indicators, SSO providers, and OAuth/OpenID Connect indicators.

use crate::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{
    detect_mfa_indicators, detect_sso_providers, is_auth_page, standard_references, HttpResponse,
    SecurityPlugin, SecurityPluginConfig, SecurityReference,
};
use async_trait::async_trait;
use chrono::Utc;
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Reference, ReferenceType,
    Severity,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Authentication Discovery Plugin
pub struct AuthDiscoveryPlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl AuthDiscoveryPlugin {
    pub fn new(config: SecurityPluginConfig) -> Self {
        let http_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .user_agent(&config.user_agent)
                .build()
                .expect("Failed to create HTTP client"),
        );

        Self {
            config,
            http_client,
        }
    }

    /// Discover authentication endpoints by crawling
    async fn discover_auth_endpoints(&self, base_url: &str) -> Vec<String> {
        let mut endpoints = Vec::new();

        // Common authentication paths to check
        let auth_paths = [
            "/login",
            "/signin",
            "/sign-in",
            "/logon",
            "/auth/login",
            "/register",
            "/signup",
            "/sign-up",
            "/registration",
            "/auth/register",
            "/password/reset",
            "/password/forgot",
            "/forgot-password",
            "/reset-password",
            "/auth/password",
            "/account/recovery",
            "/mfa",
            "/2fa",
            "/two-factor",
            "/totp",
            "/sso",
            "/saml",
            "/oidc",
            "/oauth",
            "/auth",
            "/account/login",
            "/user/login",
        ];

        for path in &auth_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            endpoints.push(url);
        }

        endpoints
    }

    /// Check a single endpoint for authentication features
    async fn check_endpoint(&self, url: &str) -> Option<AuthEndpointInfo> {
        let response = match self.http_client.get(url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Failed to fetch {}: {}", url, e);
                return None;
            }
        };

        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => String::new(),
        };

        // Only analyze successful responses or redirects
        if status >= 400 && status != 401 && status != 403 {
            return None;
        }

        let mut info = AuthEndpointInfo {
            url: url.to_string(),
            status,
            is_auth_page: is_auth_page(url, &body),
            login_form: false,
            registration_form: false,
            password_reset_form: false,
            mfa_indicators: Vec::new(),
            sso_providers: Vec::new(),
            oauth_indicators: Vec::new(),
            csrf_tokens: Vec::new(),
            form_fields: Vec::new(),
        };

        if info.is_auth_page {
            // Detect specific form types
            info.login_form = self.detect_login_form(&body);
            info.registration_form = self.detect_registration_form(&body);
            info.password_reset_form = self.detect_password_reset_form(&body);

            // Detect MFA
            info.mfa_indicators = detect_mfa_indicators(&body);

            // Detect SSO
            info.sso_providers = detect_sso_providers(&body);

            // Detect OAuth/OIDC
            info.oauth_indicators = self.detect_oauth_indicators(&body);

            // Detect CSRF tokens
            info.csrf_tokens = self.detect_csrf_tokens(&body);

            // Extract form fields
            info.form_fields = self.extract_form_fields(&body);
        }

        Some(info)
    }

    fn detect_login_form(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();
        let patterns = [
            r#"type=["']password["']"#,
            r#"name=["']password["']"#,
            r#"id=["']password["']"#,
            r#"name=["']username["']"#,
            r#"name=["']email["']"#,
            r#"name=["']login["']"#,
            r#"name=["']signin["']"#,
            "login",
            "sign in",
            "log in",
        ];

        let password_field = patterns.iter().any(|p| body_lower.contains(p));
        let submit_indicators = [
            "type=\"submit\"",
            "type='submit'",
            "button",
            "input type=\"button\"",
        ];
        let has_submit = submit_indicators.iter().any(|p| body_lower.contains(p));

        password_field && has_submit
    }

    fn detect_registration_form(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();
        let patterns = [
            r#"name=["']confirm_password["']"#,
            r#"name=["']password_confirm["']"#,
            r#"name=["']repassword["']"#,
            r#"name=["']email["']"#,
            r#"name=["']username["']"#,
            "register",
            "sign up",
            "create account",
            "join",
        ];

        let has_confirm = patterns[0..3].iter().any(|p| body_lower.contains(p));
        let has_fields = patterns[3..5].iter().any(|p| body_lower.contains(p));
        let has_submit = patterns[5..].iter().any(|p| body_lower.contains(p));

        (has_confirm || has_fields) && has_submit
    }

    fn detect_password_reset_form(&self, body: &str) -> bool {
        let body_lower = body.to_lowercase();
        let patterns = [
            "forgot password",
            "reset password",
            "password recovery",
            "forgot your password",
            "lost password",
        ];

        patterns.iter().any(|p| body_lower.contains(p))
    }

    fn detect_oauth_indicators(&self, body: &str) -> Vec<String> {
        let mut indicators = Vec::new();
        let body_lower = body.to_lowercase();

        let oauth_patterns = [
            ("oauth", "OAuth"),
            ("openid", "OpenID Connect"),
            ("client_id", "OAuth Client ID"),
            ("redirect_uri", "OAuth Redirect URI"),
            ("response_type=code", "Authorization Code Flow"),
            ("response_type=token", "Implicit Flow"),
            ("scope=", "OAuth Scopes"),
            ("state=", "OAuth State Parameter"),
            ("pkce", "PKCE"),
            ("code_challenge", "PKCE Code Challenge"),
        ];

        for (pattern, name) in &oauth_patterns {
            if body_lower.contains(pattern) {
                indicators.push(name.to_string());
            }
        }

        indicators
    }

    fn detect_csrf_tokens(&self, body: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let body_lower = body.to_lowercase();

        let csrf_patterns = [
            "csrf_token",
            "authenticity_token",
            "_token",
            "csrfmiddlewaretoken",
            "xsrf_token",
            "_csrf",
            "antiforgerytoken",
        ];

        for pattern in &csrf_patterns {
            if body_lower.contains(pattern) {
                tokens.push(pattern.to_string());
            }
        }

        tokens
    }

    fn extract_form_fields(&self, body: &str) -> Vec<FormField> {
        let mut fields = Vec::new();
        // Simple regex-based extraction (in production, use a proper HTML parser)
        let input_regex =
            regex::Regex::new(r#"<input[^>]*name=["']([^"']+)["'][^>]*type=["']([^"']+)["']"#)
                .unwrap();

        for cap in input_regex.captures_iter(body) {
            if let (Some(name), Some(field_type)) = (cap.get(1), cap.get(2)) {
                fields.push(FormField {
                    name: name.as_str().to_string(),
                    field_type: field_type.as_str().to_string(),
                });
            }
        }

        fields
    }
}

/// Information about an authentication endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthEndpointInfo {
    url: String,
    status: u16,
    is_auth_page: bool,
    login_form: bool,
    registration_form: bool,
    password_reset_form: bool,
    mfa_indicators: Vec<String>,
    sso_providers: Vec<String>,
    oauth_indicators: Vec<String>,
    csrf_tokens: Vec<String>,
    form_fields: Vec<FormField>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FormField {
    name: String,
    field_type: String,
}

#[async_trait]
impl Plugin for AuthDiscoveryPlugin {
    type Config = SecurityPluginConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config)
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> crate::sdk::Result<CapabilityResponse> {
        let context = request.context;
        let target_url = request
            .input
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");

        info!("Starting authentication discovery for {}", target_url);

        let mut findings = Vec::new();
        let endpoints = self.discover_auth_endpoints(target_url).await;
        let endpoints_count = endpoints.len();

        for endpoint in endpoints {
            if let Some(info) = self.check_endpoint(&endpoint).await {
                if info.is_auth_page {
                    // Create finding for discovered auth endpoint
                    let mut finding = Finding::new(FindingConfig {
                        title: format!("Authentication Endpoint Discovered: {}", endpoint),
                        description: format!(
                            "Discovered authentication endpoint at {} with status {}. \
                            Login form: {}, Registration form: {}, Password reset: {}. \
                            MFA indicators: {:?}, SSO providers: {:?}, OAuth indicators: {:?}",
                            info.url,
                            info.status,
                            info.login_form,
                            info.registration_form,
                            info.password_reset_form,
                            info.mfa_indicators,
                            info.sso_providers,
                            info.oauth_indicators
                        ),
                        severity: Severity::Info,
                        confidence: Confidence::High,
                        category: Category::BrokenAuthentication,
                        target: info.url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "auth_discovery".to_string(),
                        plugin_version: env!("CARGO_PKG_VERSION").to_string(),
                        scan_id: openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
                    });

                    // Add evidence
                    finding = finding.with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: format!(
                            "Authentication endpoint response (status: {})",
                            info.status
                        ),
                        data: Some(serde_json::json!({
                            "url": info.url,
                            "status": info.status,
                            "login_form": info.login_form,
                            "registration_form": info.registration_form,
                            "password_reset_form": info.password_reset_form,
                            "mfa_indicators": info.mfa_indicators,
                            "sso_providers": info.sso_providers,
                            "oauth_indicators": info.oauth_indicators,
                            "csrf_tokens": info.csrf_tokens,
                            "form_fields": info.form_fields,
                        })),
                        location: Some(info.url.clone()),
                        metadata: HashMap::new(),
                        timestamp: Utc::now(),
                        http_request: None,
                        http_response: None,
                        timing: None,
                        payload: None,
                        reproduction_steps: None,
                        plugin_source: Some("auth_discovery".to_string()),
                    });

                    // Add references
                    for reference in self.references() {
                        finding = finding.with_reference(Reference {
                            reference_type: match reference.ref_type.as_str() {
                                "CWE" => ReferenceType::Cwe,
                                "OWASP" => ReferenceType::Owasp,
                                _ => ReferenceType::Custom(reference.ref_type),
                            },
                            title: reference.id.clone(),
                            url: reference.url,
                            description: Some(reference.description),
                        });
                    }

                    // Add tags
                    if info.login_form {
                        finding = finding.with_tag("login_form".to_string());
                    }
                    if info.registration_form {
                        finding = finding.with_tag("registration_form".to_string());
                    }
                    if info.password_reset_form {
                        finding = finding.with_tag("password_reset".to_string());
                    }
                    for mfa in &info.mfa_indicators {
                        finding = finding
                            .with_tag(format!("mfa:{}", mfa.to_lowercase().replace(' ', "_")));
                    }
                    for sso in &info.sso_providers {
                        finding = finding
                            .with_tag(format!("sso:{}", sso.to_lowercase().replace(' ', "_")));
                    }

                    findings.push(finding);
                }
            }
        }

        // Also check for SSO/OAuth endpoints that might not be traditional auth pages
        let sso_endpoints = [
            "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server",
            "/oauth/authorize",
            "/oauth/token",
            "/saml/metadata",
            "/sso/login",
            "/auth/realms",
        ];

        for endpoint in &sso_endpoints {
            let url = format!("{}{}", target_url.trim_end_matches('/'), endpoint);
            if let Some(info) = self.check_endpoint(&url).await {
                if info.status == 200 || info.status == 302 {
                    let mut finding = Finding::new(FindingConfig {
                        title: format!("SSO/OAuth Endpoint Discovered: {}", endpoint),
                        description: format!(
                            "Discovered SSO/OAuth endpoint at {} with status {}",
                            info.url, info.status
                        ),
                        severity: Severity::Info,
                        confidence: Confidence::Medium,
                        category: Category::BrokenAuthentication,
                        target: info.url.clone(),
                        target_type: "web_application".to_string(),
                        plugin_source: "auth_discovery".to_string(),
                        plugin_version: env!("CARGO_PKG_VERSION").to_string(),
                        scan_id: openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
                    });

                    finding = finding.with_evidence(Evidence {
                        evidence_type: EvidenceType::HttpResponse,
                        description: "SSO/OAuth endpoint response".to_string(),
                        data: Some(serde_json::json!({
                            "url": info.url,
                            "status": info.status,
                        })),
                        location: Some(info.url.clone()),
                        metadata: HashMap::new(),
                        timestamp: Utc::now(),
                        http_request: None,
                        http_response: None,
                        timing: None,
                        payload: None,
                        reproduction_steps: None,
                        plugin_source: Some("auth_discovery".to_string()),
                    });

                    for reference in self.references() {
                        finding = finding.with_reference(Reference {
                            reference_type: match reference.ref_type.as_str() {
                                "CWE" => ReferenceType::Cwe,
                                "OWASP" => ReferenceType::Owasp,
                                _ => ReferenceType::Custom(reference.ref_type),
                            },
                            title: reference.id.clone(),
                            url: reference.url,
                            description: Some(reference.description),
                        });
                    }

                    finding = finding.with_tag("sso_endpoint".to_string());
                    findings.push(finding);
                }
            }
        }

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "endpoints_checked": endpoints_count,
            "auth_endpoints_found": findings.len(),
        })))
    }
}

impl SecurityPlugin for AuthDiscoveryPlugin {
    fn security_category(&self) -> &'static str {
        "authentication"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> &'static str {
        "Discovers authentication endpoints including login forms, registration pages, password reset flows, MFA indicators, SSO providers, and OAuth/OpenID Connect endpoints"
    }

    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-306".to_string(),
                url: "https://cwe.mitre.org/data/definitions/306.html".to_string(),
                description: "Missing Authentication for Critical Function".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-287".to_string(),
                url: "https://cwe.mitre.org/data/definitions/287.html".to_string(),
                description: "Improper Authentication".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A07:2021".to_string(),
                url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                    .to_string(),
                description: "OWASP Top 10 2021 - Identification and Authentication Failures"
                    .to_string(),
            },
        ]);
        refs
    }

    fn validate_config(&self, config: &SecurityPluginConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }
}

// Plugin entry point
