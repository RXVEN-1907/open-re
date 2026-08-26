//! Basic Authentication Discovery Plugin
//!
//! Identifies authentication mechanisms such as login forms, Basic Authentication,
//! Bearer token usage, OAuth indicators, and session cookie patterns.

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
use reqwest::Client;
use select::document::Document;
use select::predicate::{Attr, Name};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Authentication Discovery Plugin
pub struct AuthDiscoveryPlugin {
    config: ReconPluginConfig,
    client: Client,
}

impl AuthDiscoveryPlugin {
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

    /// Discover authentication mechanisms
    async fn discover_auth(&self, url: &str) -> Result<AuthDiscoveryResult> {
        let mut result = AuthDiscoveryResult::default();

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(crate::internal_err)?;
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response.text().await.unwrap_or_default();

        // Check for Basic Auth challenge
        if let Some(www_auth) = headers.get("www-authenticate") {
            result.basic_auth = Some(BasicAuthInfo {
                challenge: www_auth.clone(),
                realm: self.extract_realm(www_auth),
            });
        }

        // Check for Bearer token usage
        if let Some(www_auth) = headers.get("www-authenticate") {
            if www_auth.to_lowercase().contains("bearer") {
                result.bearer_auth = Some(BearerAuthInfo {
                    challenge: www_auth.clone(),
                });
            }
        }

        // Check for OAuth indicators
        self.detect_oauth(&headers, &body, &mut result);

        // Check for login forms
        self.detect_login_forms(&body, &mut result)?;

        // Check for session cookies
        self.detect_session_cookies(&headers, &mut result);

        // Check for authentication-related headers
        self.detect_auth_headers(&headers, &mut result);

        Ok(result)
    }

    fn extract_realm(&self, www_auth: &str) -> Option<String> {
        if let Some(start) = www_auth.find("realm=\"") {
            let start = start + 7;
            if let Some(end) = www_auth[start..].find('"') {
                return Some(www_auth[start..start + end].to_string());
            }
        }
        None
    }

    fn detect_oauth(
        &self,
        headers: &HashMap<String, String>,
        body: &str,
        result: &mut AuthDiscoveryResult,
    ) {
        let body_lower = body.to_lowercase();

        // Check for OAuth endpoints in headers
        if let Some(link) = headers.get("link") {
            if link.contains("rel=\"oauth") || link.contains("rel=\"authorization") {
                result.oauth_indicators.push(OAuthIndicator {
                    type_: "header_link".to_string(),
                    detail: link.clone(),
                });
            }
        }

        // Check for OAuth in body
        let oauth_patterns = [
            ("oauth2", "OAuth 2.0"),
            ("oauth", "OAuth 1.0/2.0"),
            ("openid", "OpenID Connect"),
            ("authorization_code", "Authorization Code Flow"),
            ("implicit", "Implicit Flow"),
            ("client_id", "Client ID"),
            ("redirect_uri", "Redirect URI"),
            ("scope=", "Scope Parameter"),
            ("state=", "State Parameter"),
            ("response_type", "Response Type"),
            ("grant_type", "Grant Type"),
            ("access_token", "Access Token"),
            ("refresh_token", "Refresh Token"),
            ("id_token", "ID Token"),
        ];

        for (pattern, name) in oauth_patterns {
            if body_lower.contains(pattern) {
                result.oauth_indicators.push(OAuthIndicator {
                    type_: "body_pattern".to_string(),
                    detail: format!("Found {} indicator: {}", name, pattern),
                });
            }
        }

        // Check for well-known OAuth endpoints
        let oauth_endpoints = [
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/userinfo",
            "/auth/realms",
            "/auth/token",
            "/connect/authorize",
            "/connect/token",
            "/connect/userinfo",
        ];

        for endpoint in oauth_endpoints {
            if body_lower.contains(endpoint) {
                result.oauth_indicators.push(OAuthIndicator {
                    type_: "endpoint_reference".to_string(),
                    detail: format!("Referenced OAuth endpoint: {}", endpoint),
                });
            }
        }
    }

    fn detect_login_forms(&self, body: &str, result: &mut AuthDiscoveryResult) -> Result<()> {
        let doc = crate::parse_html(body)?;

        for form in doc.find(Name("form")) {
            let mut login_form = LoginFormInfo::default();
            login_form.action = form.attr("action").unwrap_or("").to_string();
            login_form.method = form.attr("method").unwrap_or("GET").to_uppercase();

            // Check for password field
            let has_password = form.find(Name("input")).any(|input| {
                input
                    .attr("type")
                    .map_or(false, |t| t.to_lowercase() == "password")
            });

            if has_password {
                login_form.has_password_field = true;

                // Check for username/email field
                let has_username = form.find(Name("input")).any(|input| {
                    let t = input.attr("type").unwrap_or("").to_lowercase();
                    let name = input.attr("name").unwrap_or("").to_lowercase();
                    t == "text"
                        || t == "email"
                        || name.contains("user")
                        || name.contains("email")
                        || name.contains("login")
                });

                if has_username {
                    login_form.has_username_field = true;
                }

                // Check for CSRF token
                let has_csrf = form.find(Name("input")).any(|input| {
                    let name = input.attr("name").unwrap_or("").to_lowercase();
                    name.contains("csrf") || name.contains("token") || name.contains("_token")
                });

                if has_csrf {
                    login_form.has_csrf_token = true;
                }

                // Check for remember me
                let has_remember = form.find(Name("input")).any(|input| {
                    let name = input.attr("name").unwrap_or("").to_lowercase();
                    name.contains("remember") || name.contains("persist")
                });

                if has_remember {
                    login_form.has_remember_me = true;
                }

                // Check for MFA indicators
                let has_mfa = form.find(Name("input")).any(|input| {
                    let name = input.attr("name").unwrap_or("").to_lowercase();
                    name.contains("totp")
                        || name.contains("mfa")
                        || name.contains("2fa")
                        || name.contains("code")
                });

                if has_mfa {
                    login_form.has_mfa = true;
                }

                result.login_forms.push(login_form);
            }
        }

        Ok(())
    }

    fn detect_session_cookies(
        &self,
        headers: &HashMap<String, String>,
        result: &mut AuthDiscoveryResult,
    ) {
        if let Some(set_cookie) = headers.get("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();

            let session_patterns = [
                ("jsessionid", "Java/JSP Session"),
                ("phpsessid", "PHP Session"),
                ("asp.net_sessionid", "ASP.NET Session"),
                ("sessionid", "Generic Session"),
                ("sid", "Session ID"),
                ("_session", "Rails/Framework Session"),
                ("connect.sid", "Express/Connect Session"),
                ("laravel_session", "Laravel Session"),
                ("ci_session", "CodeIgniter Session"),
            ];

            for (pattern, name) in session_patterns {
                if cookie_lower.contains(pattern) {
                    result.session_cookies.push(SessionCookieInfo {
                        name: name.to_string(),
                        pattern: pattern.to_string(),
                    });
                }
            }
        }
    }

    fn detect_auth_headers(
        &self,
        headers: &HashMap<String, String>,
        result: &mut AuthDiscoveryResult,
    ) {
        // Check for authentication-related headers
        let auth_headers = [
            ("authorization", "Authorization Header"),
            ("proxy-authorization", "Proxy Authorization"),
            ("x-api-key", "API Key Header"),
            ("x-auth-token", "Auth Token Header"),
            ("x-access-token", "Access Token Header"),
            ("x-csrf-token", "CSRF Token Header"),
            ("x-xsrf-token", "XSRF Token Header"),
        ];

        for (header, name) in auth_headers {
            if headers.contains_key(header) {
                result.auth_headers.push(AuthHeaderInfo {
                    name: name.to_string(),
                    header: header.to_string(),
                });
            }
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AuthDiscoveryResult {
    basic_auth: Option<BasicAuthInfo>,
    bearer_auth: Option<BearerAuthInfo>,
    oauth_indicators: Vec<OAuthIndicator>,
    login_forms: Vec<LoginFormInfo>,
    session_cookies: Vec<SessionCookieInfo>,
    auth_headers: Vec<AuthHeaderInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BasicAuthInfo {
    challenge: String,
    realm: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BearerAuthInfo {
    challenge: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OAuthIndicator {
    type_: String,
    detail: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LoginFormInfo {
    action: String,
    method: String,
    has_password_field: bool,
    has_username_field: bool,
    has_csrf_token: bool,
    has_remember_me: bool,
    has_mfa: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionCookieInfo {
    name: String,
    pattern: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthHeaderInfo {
    name: String,
    header: String,
}

#[async_trait::async_trait]
impl Plugin for AuthDiscoveryPlugin {
    type Config = ReconPluginConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create AuthDiscoveryPlugin")
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
            "recon_type": ReconType::AuthDiscovery,
        })))
    }
}

#[async_trait::async_trait]
impl ReconPlugin for AuthDiscoveryPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::AuthDiscovery
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

        info!("Starting authentication discovery for: {}", target_url);

        let discovery = self.discover_auth(&target_url).await?;

        // Basic Auth findings
        if let Some(basic) = &discovery.basic_auth {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Basic Authentication Detected".to_string(),
                    description: format!("WWW-Authenticate header present: {}", basic.challenge),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::BrokenAuthentication,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "auth_discovery".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Basic Auth challenge".to_string(),
                    data: Some(serde_json::json!({
                        "challenge": basic.challenge,
                        "realm": basic.realm,
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

        // Bearer Auth findings
        if let Some(bearer) = &discovery.bearer_auth {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Bearer Token Authentication Detected".to_string(),
                    description: format!(
                        "WWW-Authenticate header indicates Bearer token: {}",
                        bearer.challenge
                    ),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::BrokenAuthentication,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "auth_discovery".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Bearer token challenge".to_string(),
                    data: Some(serde_json::json!({
                        "challenge": bearer.challenge,
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

        // OAuth findings
        for oauth in &discovery.oauth_indicators {
            findings.push(
                Finding::new(FindingConfig {
                    title: "OAuth Indicator Detected".to_string(),
                    description: oauth.detail.clone(),
                    severity: Severity::Info,
                    confidence: Confidence::Medium,
                    category: Category::BrokenAuthentication,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "auth_discovery".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "OAuth indicator".to_string(),
                    data: Some(serde_json::json!({
                        "type": oauth.type_,
                        "detail": oauth.detail,
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

        // Login form findings
        for form in &discovery.login_forms {
            let mut details = vec![
                format!("Action: {}", form.action),
                format!("Method: {}", form.method),
            ];

            if form.has_password_field {
                details.push("Password field: Yes".to_string());
            }
            if form.has_username_field {
                details.push("Username field: Yes".to_string());
            }
            if form.has_csrf_token {
                details.push("CSRF token: Yes".to_string());
            }
            if form.has_remember_me {
                details.push("Remember me: Yes".to_string());
            }
            if form.has_mfa {
                details.push("MFA field: Yes".to_string());
            }

            findings.push(
                Finding::new(FindingConfig {
                    title: "Login Form Detected".to_string(),
                    description: details.join(", "),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::BrokenAuthentication,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "auth_discovery".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Login form found".to_string(),
                    data: Some(serde_json::json!({
                        "action": form.action,
                        "method": form.method,
                        "has_password_field": form.has_password_field,
                        "has_username_field": form.has_username_field,
                        "has_csrf_token": form.has_csrf_token,
                        "has_remember_me": form.has_remember_me,
                        "has_mfa": form.has_mfa,
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

        // Session cookie findings
        for cookie in &discovery.session_cookies {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Session Cookie Detected".to_string(),
                    description: format!(
                        "Session cookie pattern found: {} ({})",
                        cookie.name, cookie.pattern
                    ),
                    severity: Severity::Info,
                    confidence: Confidence::Medium,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "auth_discovery".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Session cookie pattern".to_string(),
                    data: Some(serde_json::json!({
                        "name": cookie.name,
                        "pattern": cookie.pattern,
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

        // Auth header findings
        for header in &discovery.auth_headers {
            findings.push(
                Finding::new(FindingConfig {
                    title: "Authentication Header Detected".to_string(),
                    description: format!("{} header present", header.name),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "auth_discovery".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Auth header found".to_string(),
                    data: Some(serde_json::json!({
                        "name": header.name,
                        "header": header.header,
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

        info!(
            "Authentication discovery completed for: {} - {} findings",
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
    let plugin = AuthDiscoveryPlugin::new(config);
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
