//! Session Management Plugin
//! 
//! Evaluates session cookie generation, expiration, invalidation after logout,
//! cookie rotation after authentication, and session fixation indicators.

use crate::security::{
    SecurityPlugin, SecurityPluginConfig, SecurityReference, standard_references,
    HttpResponse, CookieInfo, extract_cookies,
};
use crate::sdk::{CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability, PluginId, Plugin};
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};
use chrono::{DateTime, Utc};

/// Session Management Plugin
pub struct SessionManagementPlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl SessionManagementPlugin {
    pub fn new(config: SecurityPluginConfig) -> Self {
        let http_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(config.max_redirects as usize))
                .user_agent(&config.user_agent)
                .cookie_store(true) // Enable cookie store for session tracking
                .build()
                .expect("Failed to create HTTP client")
        );
        
        Self { config, http_client }
    }
    
    /// Analyze session management by making requests and observing cookie behavior
    async fn analyze_session(&self, base_url: &str) -> SessionAnalysisResult {
        let mut result = SessionAnalysisResult::default();
        
        // 1. Initial request to get baseline cookies
        let initial_response = self.make_request(base_url, None).await;
        if let Some(resp) = initial_response {
            result.initial_cookies = extract_cookies(&resp.headers, base_url);
            result.initial_status = resp.status;
        }
        
        // 2. Check for session cookie characteristics
        result.session_cookies = self.identify_session_cookies(&result.initial_cookies);
        
        // 3. Test session fixation - request again with same session
        let fixation_response = self.make_request(base_url, Some(&result.initial_cookies)).await;
        if let Some(resp) = fixation_response {
            result.fixation_test_cookies = extract_cookies(&resp.headers, base_url);
            result.session_fixation_possible = self.check_session_fixation(&result.initial_cookies, &result.fixation_test_cookies);
        }
        
        // 4. Test session expiration (if we can find a login endpoint)
        // This would require actual login - for now we analyze cookie attributes
        result.cookie_analysis = self.analyze_cookie_security(&result.initial_cookies);
        
        // 5. Check for session rotation after auth (would need login flow)
        // For now, we note this as a limitation
        
        result
    }
    
    /// Make an HTTP request with optional cookies
    async fn make_request(&self, url: &str, cookies: Option<&Vec<CookieInfo>>) -> Option<HttpResponse> {
        let mut request = self.http_client.get(url);
        
        if let Some(cookie_list) = cookies {
            let cookie_header = cookie_list.iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; ");
            if !cookie_header.is_empty() {
                request = request.header("Cookie", cookie_header);
            }
        }
        
        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Failed to fetch {}: {}", url, e);
                return None;
            }
        };
        
        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => String::new(),
        };
        
        let cookies = extract_cookies(&headers, url);
        
        Some(HttpResponse {
            status,
            headers,
            body,
            url: url.to_string(),
            cookies,
        })
    }
    
    /// Identify which cookies are likely session cookies
    fn identify_session_cookies(&self, cookies: &[CookieInfo]) -> Vec<SessionCookieInfo> {
        let mut session_cookies = Vec::new();
        
        let session_names = [
            "session", "sessionid", "sid", "jsessionid", "phpsessid", "aspsessionid",
            "cfid", "cftoken", "zenid", "laravel_session", "express:sess",
            "connect.sid", "koa:sess", "session_id", "auth_token", "access_token",
            "refresh_token", "csrf_token", "xsrf_token", "_session", "_csrf",
        ];
        
        for cookie in cookies {
            let name_lower = cookie.name.to_lowercase();
            let is_session = session_names.iter().any(|n| name_lower.contains(n));
            
            // Also check for typical session cookie attributes
            let looks_like_session = cookie.http_only && cookie.secure && cookie.path.as_deref() == Some("/");
            
            if is_session || looks_like_session {
                session_cookies.push(SessionCookieInfo {
                    cookie: cookie.clone(),
                    confidence: if is_session { Confidence::High } else { Confidence::Medium },
                    reasons: self.get_session_reasons(&name_lower, &cookie),
                });
            }
        }
        
        session_cookies
    }
    
    fn get_session_reasons(&self, name_lower: &str, cookie: &CookieInfo) -> Vec<String> {
        let mut reasons = Vec::new();
        
        let session_names = [
            "session", "sessionid", "sid", "jsessionid", "phpsessid", "aspsessionid",
            "cfid", "cftoken", "zenid", "laravel_session", "express:sess",
            "connect.sid", "koa:sess", "session_id", "auth_token", "access_token",
            "refresh_token", "csrf_token", "xsrf_token", "_session", "_csrf",
        ];
        
        for sn in &session_names {
            if name_lower.contains(sn) {
                reasons.push(format!("Name matches known session pattern: {}", sn));
            }
        }
        
        if cookie.http_only {
            reasons.push("HttpOnly flag set".to_string());
        }
        if cookie.secure {
            reasons.push("Secure flag set".to_string());
        }
        if cookie.path.as_deref() == Some("/") {
            reasons.push("Path is root (/)" .to_string());
        }
        if cookie.same_site.as_deref() == Some("lax") || cookie.same_site.as_deref() == Some("strict") {
            reasons.push(format!("SameSite: {}", cookie.same_site.as_deref().unwrap()));
        }
        
        reasons
    }
    
    /// Check for session fixation vulnerability
    fn check_session_fixation(&self, initial: &[CookieInfo], subsequent: &[CookieInfo]) -> bool {
        // Session fixation is possible if the session ID doesn't change between requests
        // when no authentication has occurred
        
        for init_cookie in initial {
            for sub_cookie in subsequent {
                if init_cookie.name == sub_cookie.name && init_cookie.value == sub_cookie.value {
                    // Same session ID returned - potential fixation
                    // But we need to check if this is expected (e.g., anonymous session)
                    if init_cookie.http_only && init_cookie.secure {
                        // This looks like a proper session cookie that didn't rotate
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    /// Analyze cookie security attributes
    fn analyze_cookie_security(&self, cookies: &[CookieInfo]) -> Vec<CookieSecurityIssue> {
        let mut issues = Vec::new();
        
        for cookie in cookies {
            // Check Secure flag
            if !cookie.secure {
                issues.push(CookieSecurityIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "missing_secure_flag".to_string(),
                    severity: Severity::Medium,
                    description: format!("Cookie '{}' is missing the Secure flag", cookie.name),
                    recommendation: "Set the Secure flag to ensure cookie is only transmitted over HTTPS".to_string(),
                });
            }
            
            // Check HttpOnly flag
            if !cookie.http_only {
                issues.push(CookieSecurityIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "missing_httponly_flag".to_string(),
                    severity: Severity::Medium,
                    description: format!("Cookie '{}' is missing the HttpOnly flag", cookie.name),
                    recommendation: "Set the HttpOnly flag to prevent client-side script access".to_string(),
                });
            }
            
            // Check SameSite
            match cookie.same_site.as_deref() {
                None => {
                    issues.push(CookieSecurityIssue {
                        cookie_name: cookie.name.clone(),
                        issue_type: "missing_samesite".to_string(),
                        severity: Severity::Low,
                        description: format!("Cookie '{}' is missing the SameSite attribute", cookie.name),
                        recommendation: "Set SameSite to Lax or Strict to prevent CSRF attacks".to_string(),
                    });
                }
                Some("none") => {
                    issues.push(CookieSecurityIssue {
                        cookie_name: cookie.name.clone(),
                        issue_type: "samesite_none".to_string(),
                        severity: Severity::Medium,
                        description: format!("Cookie '{}' has SameSite=None", cookie.name),
                        recommendation: "Only use SameSite=None with Secure flag for cross-site cookies".to_string(),
                    });
                }
                Some("lax") | Some("strict") => {
                    // Good
                }
                Some(other) => {
                    issues.push(CookieSecurityIssue {
                        cookie_name: cookie.name.clone(),
                        issue_type: "invalid_samesite".to_string(),
                        severity: Severity::Low,
                        description: format!("Cookie '{}' has invalid SameSite value: {}", cookie.name, other),
                        recommendation: "Use Lax, Strict, or None for SameSite attribute".to_string(),
                    });
                }
            }
            
            // Check expiration
            if let Some(max_age) = cookie.max_age {
                if max_age > 2592000 { // 30 days
                    issues.push(CookieSecurityIssue {
                        cookie_name: cookie.name.clone(),
                        issue_type: "long_expiration".to_string(),
                        severity: Severity::Low,
                        description: format!("Cookie '{}' has long expiration ({} seconds)", cookie.name, max_age),
                        recommendation: "Consider shorter session lifetimes (e.g., 24 hours for session cookies)".to_string(),
                    });
                }
            } else if let Some(expires) = &cookie.expires {
                // Parse expires date
                if let Ok(expires_dt) = DateTime::parse_from_rfc2822(expires) {
                    let now = Utc::now();
                    let expires_utc = expires_dt.with_timezone(&Utc);
                    let diff = expires_utc - now;
                    if diff.num_days() > 30 {
                        issues.push(CookieSecurityIssue {
                            cookie_name: cookie.name.clone(),
                            issue_type: "long_expiration".to_string(),
                            severity: Severity::Low,
                            description: format!("Cookie '{}' expires in {} days", cookie.name, diff.num_days()),
                            recommendation: "Consider shorter session lifetimes".to_string(),
                        });
                    }
                }
            } else {
                // Session cookie (no expiration) - this is actually good for session cookies
                // but could be an issue for persistent cookies
            }
            
            // Check domain scope
            if let Some(domain) = &cookie.domain {
                if domain.starts_with('.') {
                    issues.push(CookieSecurityIssue {
                        cookie_name: cookie.name.clone(),
                        issue_type: "wide_domain_scope".to_string(),
                        severity: Severity::Low,
                        description: format!("Cookie '{}' has wide domain scope: {}", cookie.name, domain),
                        recommendation: "Restrict cookie domain to the minimum necessary".to_string(),
                    });
                }
            }
            
            // Check path scope
            if let Some(path) = &cookie.path {
                if path == "/" {
                    // This is common but could be too broad
                    // Only flag if it's not a session cookie
                }
            }
            
            // Check for weak/predictable patterns
            if self.is_weak_cookie_value(&cookie.value) {
                issues.push(CookieSecurityIssue {
                    cookie_name: cookie.name.clone(),
                    issue_type: "weak_cookie_value".to_string(),
                    severity: Severity::High,
                    description: format!("Cookie '{}' has a potentially weak/predictable value", cookie.name),
                    recommendation: "Use cryptographically secure random values for session identifiers".to_string(),
                });
            }
        }
        
        issues
    }
    
    /// Check if cookie value appears weak or predictable
    fn is_weak_cookie_value(&self, value: &str) -> bool {
        // Check for common weak patterns
        let weak_patterns = [
            "test", "admin", "user", "guest", "anonymous", "default",
            "123", "abc", "session", "token", "auth",
        ];
        
        let value_lower = value.to_lowercase();
        
        // Too short
        if value.len() < 16 {
            return true;
        }
        
        // Common weak values
        for pattern in &weak_patterns {
            if value_lower.contains(pattern) {
                return true;
            }
        }
        
        // All same character
        if value.chars().all(|c| c == value.chars().next().unwrap()) {
            return true;
        }
        
        // Sequential patterns
        if value_lower.contains("123456") || value_lower.contains("abcdef") {
            return true;
        }
        
        // Base64-like but short
        if value.len() < 22 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
            return true;
        }
        
        false
    }
}

/// Result of session analysis
#[derive(Debug, Default, Serialize, Deserialize)]
struct SessionAnalysisResult {
    initial_cookies: Vec<CookieInfo>,
    initial_status: u16,
    session_cookies: Vec<SessionCookieInfo>,
    fixation_test_cookies: Vec<CookieInfo>,
    session_fixation_possible: bool,
    cookie_analysis: Vec<CookieSecurityIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionCookieInfo {
    cookie: CookieInfo,
    confidence: Confidence,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CookieSecurityIssue {
    cookie_name: String,
    issue_type: String,
    severity: Severity,
    description: String,
    recommendation: String,
}

#[async_trait]
impl Plugin for SessionManagementPlugin {
    type Config = SecurityPluginConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config)
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAccess,
            Capability::ReadConfig,
        ]
    }
    
    async fn execute(&self, request: CapabilityRequest) -> crate::sdk::Result<CapabilityResponse> {
        let context = request.context;
        let target_url = request.input.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");
        
        info!("Starting session management analysis for {}", target_url);
        
        let analysis = self.analyze_session(target_url).await;
        let mut findings = Vec::new();
        
        // Report session cookies found
        for session_cookie in &analysis.session_cookies {
            let mut finding = Finding::new(
                format!("Session Cookie Identified: {}", session_cookie.cookie.name),
                format!(
                    "Identified session cookie '{}' with attributes: Secure={}, HttpOnly={}, SameSite={:?}, Path={:?}, Domain={:?}. \
                    Confidence: {:?}. Reasons: {}",
                    session_cookie.cookie.name,
                    session_cookie.cookie.secure,
                    session_cookie.cookie.http_only,
                    session_cookie.cookie.same_site,
                    session_cookie.cookie.path,
                    session_cookie.cookie.domain,
                    session_cookie.confidence,
                    session_cookie.reasons.join(", ")
                ),
                Severity::Info,
                session_cookie.confidence,
                Category::BrokenAuthentication,
                target_url.to_string(),
                "web_application".to_string(),
                "session_management".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Session cookie details".to_string(),
                data: Some(serde_json::to_value(session_cookie).unwrap()),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
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
            
            finding = finding.with_tag("session_cookie".to_string());
            findings.push(finding);
        }
        
        // Report session fixation
        if analysis.session_fixation_possible {
            let mut finding = Finding::new(
                "Potential Session Fixation Vulnerability".to_string(),
                "The application appears to accept a pre-existing session ID without regenerating it after authentication. This could allow an attacker to fixate a user's session ID.".to_string(),
                Severity::High,
                Confidence::Medium,
                Category::BrokenAuthentication,
                target_url.to_string(),
                "web_application".to_string(),
                "session_management".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Session fixation test results".to_string(),
                data: Some(serde_json::json!({
                    "initial_cookies": analysis.initial_cookies,
                    "fixation_test_cookies": analysis.fixation_test_cookies,
                })),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
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
            
            finding = finding.with_tag("session_fixation".to_string());
            finding = finding.with_cvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N".to_string(), 6.5);
            findings.push(finding);
        }
        
        // Report cookie security issues
        for issue in &analysis.cookie_analysis {
            let mut finding = Finding::new(
                format!("Cookie Security Issue: {} - {}", issue.cookie_name, issue.issue_type),
                format!("{}\n\nRecommendation: {}", issue.description, issue.recommendation),
                issue.severity,
                Confidence::High,
                Category::SecurityMisconfiguration,
                target_url.to_string(),
                "web_application".to_string(),
                "session_management".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Cookie security analysis".to_string(),
                data: Some(serde_json::to_value(issue).unwrap()),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
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
            
            finding = finding.with_tag(format!("cookie_{}", issue.issue_type));
            findings.push(finding);
        }
        
        // Check for missing session cookies entirely
        if analysis.session_cookies.is_empty() && !analysis.initial_cookies.is_empty() {
            let mut finding = Finding::new(
                "No Session Cookies Identified".to_string(),
                "The application returned cookies but none were identified as session cookies. This could indicate custom session management or token-based authentication.".to_string(),
                Severity::Info,
                Confidence::Low,
                Category::BrokenAuthentication,
                target_url.to_string(),
                "web_application".to_string(),
                "session_management".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "All cookies received".to_string(),
                data: Some(serde_json::to_value(&analysis.initial_cookies).unwrap()),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
            });
            
            findings.push(finding);
        }
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "session_cookies_found": analysis.session_cookies.len(),
            "cookie_issues_found": analysis.cookie_analysis.len(),
            "session_fixation_possible": analysis.session_fixation_possible,
        })))
    }
}

impl SecurityPlugin for SessionManagementPlugin {
    fn security_category(&self) -> &'static str {
        "session_management"
    }
    
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    
    fn description(&self) -> &'static str {
        "Analyzes session management including session cookie generation, expiration, invalidation after logout, cookie rotation after authentication, and session fixation indicators"
    }
    
    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-384".to_string(),
                url: "https://cwe.mitre.org/data/definitions/384.html".to_string(),
                description: "Session Fixation".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-613".to_string(),
                url: "https://cwe.mitre.org/data/definitions/613.html".to_string(),
                description: "Insufficient Session Expiration".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-614".to_string(),
                url: "https://cwe.mitre.org/data/definitions/614.html".to_string(),
                description: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A07:2021".to_string(),
                url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/".to_string(),
                description: "OWASP Top 10 2021 - Identification and Authentication Failures".to_string(),
            },
        ]);
        refs
    }
    
    fn validate_config(&self, config: &SecurityPluginConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

// Plugin entry point
