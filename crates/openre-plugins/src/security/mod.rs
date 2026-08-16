//! Security Plugins Module
//!
//! This module contains all security assessment plugins for authentication,
//! session management, and common web security misconfigurations.

pub mod access_control;
pub mod api_rate_limiting;
pub mod auth_discovery;
pub mod cookie_security;
pub mod cors_analysis;
pub mod file_upload;
pub mod graphql;
pub mod information_disclosure;
pub mod path_traversal;
pub mod rate_limiting;
pub mod rest_api;
pub mod security_headers;
pub mod sensitive_info;
pub mod session_management;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base configuration for all security plugins
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityPluginConfig {
    /// Plugin-specific settings
    pub settings: HashMap<String, serde_json::Value>,
    /// Enable/disable specific checks
    pub enabled_checks: Vec<String>,
    /// Request timeout in seconds
    pub request_timeout: u64,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    /// User agent string
    pub user_agent: String,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirect depth
    pub max_redirects: usize,
}

impl Default for SecurityPluginConfig {
    fn default() -> Self {
        let mut settings = HashMap::new();
        settings.insert("aggressive_mode".to_string(), serde_json::json!(false));
        settings.insert("verify_ssl".to_string(), serde_json::json!(true));

        Self {
            settings,
            enabled_checks: vec![],
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-security-scanner/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
        }
    }
}

/// Common trait for all security plugins
#[async_trait::async_trait]
pub trait SecurityPlugin: crate::sdk::Plugin {
    /// Get the plugin's security category
    fn security_category(&self) -> &'static str;

    /// Get the plugin's version
    fn version(&self) -> &'static str;

    /// Get the plugin's description
    fn description(&self) -> &'static str;

    /// Get the plugin's references (CWE, OWASP, etc.)
    fn references(&self) -> Vec<SecurityReference>;

    /// Validate the plugin configuration
    fn validate_config(&self, config: &SecurityPluginConfig) -> std::result::Result<(), String>;
}

/// Security reference for findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReference {
    /// Reference type (CWE, OWASP, CVE, etc.)
    pub ref_type: String,
    /// Reference ID
    pub id: String,
    /// Reference URL
    pub url: String,
    /// Description
    pub description: String,
}

/// Helper to create standard security references
pub fn standard_references() -> Vec<SecurityReference> {
    vec![
        SecurityReference {
            ref_type: "OWASP".to_string(),
            id: "A07:2021".to_string(),
            url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
                .to_string(),
            description: "OWASP Top 10 2021 - Identification and Authentication Failures"
                .to_string(),
        },
        SecurityReference {
            ref_type: "OWASP".to_string(),
            id: "A05:2021".to_string(),
            url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
            description: "OWASP Top 10 2021 - Security Misconfiguration".to_string(),
        },
        SecurityReference {
            ref_type: "CWE".to_string(),
            id: "CWE-384".to_string(),
            url: "https://cwe.mitre.org/data/definitions/384.html".to_string(),
            description: "Session Fixation".to_string(),
        },
        SecurityReference {
            ref_type: "CWE".to_string(),
            id: "CWE-614".to_string(),
            url: "https://cwe.mitre.org/data/definitions/614.html".to_string(),
            description: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute".to_string(),
        },
        SecurityReference {
            ref_type: "CWE".to_string(),
            id: "CWE-1004".to_string(),
            url: "https://cwe.mitre.org/data/definitions/1004.html".to_string(),
            description: "Sensitive Cookie Without 'HttpOnly' Flag".to_string(),
        },
    ]
}

/// HTTP response wrapper for analysis
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub url: String,
    pub cookies: Vec<CookieInfo>,
}

/// Cookie information extracted from response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieInfo {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub expires: Option<String>,
    pub max_age: Option<i64>,
}

/// Extract cookies from Set-Cookie headers
pub fn extract_cookies(headers: &HashMap<String, String>, url: &str) -> Vec<CookieInfo> {
    let mut cookies = Vec::new();

    for (key, value) in headers {
        if key.to_lowercase() == "set-cookie" {
            cookies.extend(parse_cookie_header(value, url));
        }
    }

    cookies
}

/// Parse a single Set-Cookie header
fn parse_cookie_header(header: &str, url: &str) -> Vec<CookieInfo> {
    let mut cookies = Vec::new();
    let parts: Vec<&str> = header.split(';').collect();

    if parts.is_empty() {
        return cookies;
    }

    // Parse name=value
    let name_value = parts[0].trim();
    let eq_pos = name_value.find('=');
    if eq_pos.is_none() {
        return cookies;
    }

    let name = name_value[..eq_pos.unwrap()].trim().to_string();
    let value = name_value[eq_pos.unwrap() + 1..].trim().to_string();

    let mut cookie = CookieInfo {
        name,
        value,
        domain: None,
        path: None,
        secure: false,
        http_only: false,
        same_site: None,
        expires: None,
        max_age: None,
    };

    // Parse attributes
    for part in &parts[1..] {
        let part = part.trim().to_lowercase();
        if part == "secure" {
            cookie.secure = true;
        } else if part == "httponly" {
            cookie.http_only = true;
        } else if part.starts_with("domain=") {
            cookie.domain = Some(part[7..].trim().to_string());
        } else if part.starts_with("path=") {
            cookie.path = Some(part[5..].trim().to_string());
        } else if part.starts_with("samesite=") {
            cookie.same_site = Some(part[9..].trim().to_string());
        } else if part.starts_with("expires=") {
            cookie.expires = Some(part[8..].trim().to_string());
        } else if part.starts_with("max-age=") {
            cookie.max_age = part[8..].trim().parse().ok();
        }
    }

    cookies.push(cookie);
    cookies
}

/// Check if a URL is a login/registration/password reset page
pub fn is_auth_page(url: &str, body: &str) -> bool {
    let url_lower = url.to_lowercase();
    let body_lower = body.to_lowercase();

    // Check URL patterns
    let auth_url_patterns = [
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
    ];

    for pattern in &auth_url_patterns {
        if url_lower.contains(pattern) {
            return true;
        }
    }

    // Check body for auth form indicators
    let auth_body_patterns = [
        r#"type=["']password["']"#,
        r#"name=["']password["']"#,
        r#"id=["']password["']"#,
        r#"name=["']username["']"#,
        r#"name=["']email["']"#,
        r#"name=["']login["']"#,
        r#"name=["']signin["']"#,
        "csrf_token",
        "authenticity_token",
        "_token",
    ];

    for pattern in &auth_body_patterns {
        if body_lower.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check for SSO/OAuth indicators
pub fn detect_sso_providers(body: &str) -> Vec<String> {
    let mut providers = Vec::new();
    let body_lower = body.to_lowercase();

    let sso_patterns = [
        ("google", "Google OAuth"),
        ("github", "GitHub OAuth"),
        ("gitlab", "GitLab OAuth"),
        ("microsoft", "Microsoft OAuth"),
        ("azure", "Azure AD"),
        ("okta", "Okta"),
        ("auth0", "Auth0"),
        ("keycloak", "Keycloak"),
        ("ping", "Ping Identity"),
        ("onelogin", "OneLogin"),
        ("saml", "SAML"),
        ("oidc", "OpenID Connect"),
        ("openid", "OpenID"),
    ];

    for (pattern, name) in &sso_patterns {
        if body_lower.contains(pattern) {
            providers.push(name.to_string());
        }
    }

    providers
}

/// Check for MFA indicators
pub fn detect_mfa_indicators(body: &str) -> Vec<String> {
    let mut indicators = Vec::new();
    let body_lower = body.to_lowercase();

    let mfa_patterns = [
        ("totp", "TOTP (Time-based One-Time Password)"),
        ("authenticator", "Authenticator App"),
        ("google authenticator", "Google Authenticator"),
        ("microsoft authenticator", "Microsoft Authenticator"),
        ("authy", "Authy"),
        ("duo", "Duo Security"),
        ("yubikey", "YubiKey"),
        ("webauthn", "WebAuthn/FIDO2"),
        ("passkey", "Passkey"),
        ("sms", "SMS-based 2FA"),
        ("email code", "Email-based 2FA"),
        ("backup code", "Backup Codes"),
        ("recovery code", "Recovery Codes"),
    ];

    for (pattern, name) in &mfa_patterns {
        if body_lower.contains(pattern) {
            indicators.push(name.to_string());
        }
    }

    indicators
}
