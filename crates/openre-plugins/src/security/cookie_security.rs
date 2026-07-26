//! Cookie Security Plugin
//! 
//! Validates Secure flag, HttpOnly flag, SameSite policy, Domain scope,
//! Path scope, Expiration, and Weak or predictable cookie patterns.

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

/// Cookie Security Plugin
pub struct CookieSecurityPlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl CookieSecurityPlugin {
    pub fn new(config: SecurityPluginConfig) -> Self {
        let http_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(config.max_redirects as usize))
                .user_agent(&config.user_agent)
                .build()
                .expect("Failed to create HTTP client")
        );
        
        Self { config, http_client }
    }
    
    /// Analyze all cookies from a target
    async fn analyze_cookies(&self, base_url: &str) -> CookieAnalysisResult {
        let mut result = CookieAnalysisResult::default();
        
        // Make initial request to get cookies
        let response = self.make_request(base_url).await;
        if let Some(resp) = response {
            result.cookies = extract_cookies(&resp.headers, base_url);
            result.status = resp.status;
        }
        
        // Analyze each cookie
        for cookie in &result.cookies {
            let analysis = self.analyze_single_cookie(cookie, base_url);
            result.analyses.push(analysis);
        }
        
        result
    }
    
    async fn make_request(&self, url: &str) -> Option<HttpResponse> {
        let response = match self.http_client.get(url).send().await {
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
    
    fn analyze_single_cookie(&self, cookie: &CookieInfo, base_url: &str) -> CookieAnalysis {
        let mut analysis = CookieAnalysis {
            cookie: cookie.clone(),
            issues: Vec::new(),
            score: 100, // Start with perfect score, deduct for issues
        };
        
        // 1. Check Secure flag
        if !cookie.secure {
            analysis.issues.push(CookieIssue {
                issue_type: "missing_secure".to_string(),
                severity: Severity::Medium,
                title: "Missing Secure Flag".to_string(),
                description: format!("Cookie '{}' is missing the Secure flag", cookie.name),
                impact: "Cookie may be transmitted over unencrypted HTTP connections".to_string(),
                recommendation: "Set the Secure flag to ensure cookie is only transmitted over HTTPS".to_string(),
                references: vec![
                    SecurityReference {
                        ref_type: "CWE".to_string(),
                        id: "CWE-614".to_string(),
                        url: "https://cwe.mitre.org/data/definitions/614.html".to_string(),
                        description: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute".to_string(),
                    },
                ],
            });
            analysis.score -= 20;
        }
        
        // 2. Check HttpOnly flag
        if !cookie.http_only {
            analysis.issues.push(CookieIssue {
                issue_type: "missing_httponly".to_string(),
                severity: Severity::Medium,
                title: "Missing HttpOnly Flag".to_string(),
                description: format!("Cookie '{}' is missing the HttpOnly flag", cookie.name),
                impact: "Cookie accessible to client-side JavaScript, increasing XSS risk".to_string(),
                recommendation: "Set the HttpOnly flag to prevent client-side script access".to_string(),
                references: vec![
                    SecurityReference {
                        ref_type: "CWE".to_string(),
                        id: "CWE-1004".to_string(),
                        url: "https://cwe.mitre.org/data/definitions/1004.html".to_string(),
                        description: "Sensitive Cookie Without 'HttpOnly' Flag".to_string(),
                    },
                ],
            });
            analysis.score -= 20;
        }
        
        // 3. Check SameSite attribute
        match cookie.same_site.as_deref() {
            None => {
                analysis.issues.push(CookieIssue {
                    issue_type: "missing_samesite".to_string(),
                    severity: Severity::Low,
                    title: "Missing SameSite Attribute".to_string(),
                    description: format!("Cookie '{}' is missing the SameSite attribute", cookie.name),
                    impact: "Cookie sent with cross-site requests, enabling CSRF attacks".to_string(),
                    recommendation: "Set SameSite to Lax or Strict to prevent CSRF attacks".to_string(),
                    references: vec![
                        SecurityReference {
                            ref_type: "CWE".to_string(),
                            id: "CWE-1275".to_string(),
                            url: "https://cwe.mitre.org/data/definitions/1275.html".to_string(),
                            description: "Sensitive Cookie with Improper SameSite Attribute".to_string(),
                        },
                    ],
                });
                analysis.score -= 10;
            }
            Some("none") => {
                if !cookie.secure {
                    analysis.issues.push(CookieIssue {
                        issue_type: "samesite_none_without_secure".to_string(),
                        severity: Severity::High,
                        title: "SameSite=None Without Secure Flag".to_string(),
                        description: format!("Cookie '{}' has SameSite=None but is missing Secure flag", cookie.name),
                        impact: "Cookie will be rejected by modern browsers".to_string(),
                        recommendation: "Either add Secure flag or change SameSite to Lax/Strict".to_string(),
                        references: vec![],
                    });
                    analysis.score -= 30;
                } else {
                    analysis.issues.push(CookieIssue {
                        issue_type: "samesite_none".to_string(),
                        severity: Severity::Low,
                        title: "SameSite=None (Cross-Site Cookie)".to_string(),
                        description: format!("Cookie '{}' has SameSite=None, allowing cross-site requests", cookie.name),
                        impact: "Cookie sent with all cross-site requests".to_string(),
                        recommendation: "Only use SameSite=None with Secure for legitimate cross-site cookies".to_string(),
                        references: vec![],
                    });
                    analysis.score -= 5;
                }
            }
            Some("lax") => {
                // Good - Lax is reasonable default
            }
            Some("strict") => {
                // Good - Strict is most secure
            }
            Some(other) => {
                analysis.issues.push(CookieIssue {
                    issue_type: "invalid_samesite".to_string(),
                    severity: Severity::Low,
                    title: "Invalid SameSite Value".to_string(),
                    description: format!("Cookie '{}' has invalid SameSite value: {}", cookie.name, other),
                    impact: "Browser may ignore the SameSite attribute".to_string(),
                    recommendation: "Use Lax, Strict, or None for SameSite attribute".to_string(),
                    references: vec![],
                });
                analysis.score -= 5;
            }
        }
        
        // 4. Check Domain scope
        if let Some(domain) = &cookie.domain {
            if domain.starts_with('.') {
                analysis.issues.push(CookieIssue {
                    issue_type: "wide_domain".to_string(),
                    severity: Severity::Low,
                    title: "Wide Domain Scope".to_string(),
                    description: format!("Cookie '{}' has wide domain scope: {}", cookie.name, domain),
                    impact: "Cookie accessible to all subdomains".to_string(),
                    recommendation: "Restrict cookie domain to the minimum necessary".to_string(),
                    references: vec![],
                });
                analysis.score -= 5;
            }
            
            // Check if domain matches target
            let target_domain = url::Url::parse(base_url).ok().and_then(|u| u.host_str().map(|s| s.to_string()));
            if let Some(target) = target_domain {
                if !domain.contains(&target) && !target.contains(domain.trim_start_matches('.')) {
                    analysis.issues.push(CookieIssue {
                        issue_type: "domain_mismatch".to_string(),
                        severity: Severity::Medium,
                        title: "Domain Mismatch".to_string(),
                        description: format!("Cookie '{}' domain '{}' doesn't match target domain '{}'", cookie.name, domain, target),
                        impact: "Cookie may be set by a different domain (potential cookie tossing)".to_string(),
                        recommendation: "Ensure cookies are only set for the intended domain".to_string(),
                        references: vec![],
                    });
                    analysis.score -= 15;
                }
            }
        }
        
        // 5. Check Path scope
        if let Some(path) = &cookie.path {
            if path == "/" {
                analysis.issues.push(CookieIssue {
                    issue_type: "wide_path".to_string(),
                    severity: Severity::Info,
                    title: "Root Path Scope".to_string(),
                    description: format!("Cookie '{}' has path '/', accessible to entire application", cookie.name),
                    impact: "Cookie sent to all paths on the domain".to_string(),
                    recommendation: "Restrict cookie path to the minimum necessary application path".to_string(),
                    references: vec![],
                });
                analysis.score -= 2;
            }
        }
        
        // 6. Check Expiration
        let has_expiration = cookie.expires.is_some() || cookie.max_age.is_some();
        if has_expiration {
            if let Some(max_age) = cookie.max_age {
                if max_age > 31536000 { // 1 year
                    analysis.issues.push(CookieIssue {
                        issue_type: "long_expiration".to_string(),
                        severity: Severity::Low,
                        title: "Long Cookie Expiration".to_string(),
                        description: format!("Cookie '{}' expires in {} seconds ({} days)", cookie.name, max_age, max_age / 86400),
                        impact: "Long-lived cookies increase risk if compromised".to_string(),
                        recommendation: "Use shorter expiration times for session cookies (e.g., 24 hours)".to_string(),
                        references: vec![
                            SecurityReference {
                                ref_type: "CWE".to_string(),
                                id: "CWE-613".to_string(),
                                url: "https://cwe.mitre.org/data/definitions/613.html".to_string(),
                                description: "Insufficient Session Expiration".to_string(),
                            },
                        ],
                    });
                    analysis.score -= 10;
                } else if max_age > 2592000 { // 30 days
                    analysis.issues.push(CookieIssue {
                        issue_type: "moderate_expiration".to_string(),
                        severity: Severity::Info,
                        title: "Moderate Cookie Expiration".to_string(),
                        description: format!("Cookie '{}' expires in {} days", cookie.name, max_age / 86400),
                        impact: "Moderately long-lived cookie".to_string(),
                        recommendation: "Consider shorter expiration for sensitive cookies".to_string(),
                        references: vec![],
                    });
                    analysis.score -= 5;
                }
            } else if let Some(expires) = &cookie.expires {
                if let Ok(expires_dt) = DateTime::parse_from_rfc2822(expires) {
                    let now = Utc::now();
                    let expires_utc = expires_dt.with_timezone(&Utc);
                    let diff = expires_utc - now;
                    if diff.num_days() > 365 {
                        analysis.issues.push(CookieIssue {
                            issue_type: "long_expiration".to_string(),
                            severity: Severity::Low,
                            title: "Long Cookie Expiration".to_string(),
                            description: format!("Cookie '{}' expires in {} days", cookie.name, diff.num_days()),
                            impact: "Long-lived cookies increase risk if compromised".to_string(),
                            recommendation: "Use shorter expiration times for session cookies".to_string(),
                            references: vec![],
                        });
                        analysis.score -= 10;
                    }
                }
            }
        } else {
            // Session cookie (no expiration) - this is good for session cookies
            analysis.issues.push(CookieIssue {
                issue_type: "session_cookie".to_string(),
                severity: Severity::Info,
                title: "Session Cookie (No Expiration)".to_string(),
                description: format!("Cookie '{}' is a session cookie (expires when browser closes)", cookie.name),
                impact: "Session cookies are cleared when browser closes - good for security".to_string(),
                recommendation: "This is the recommended behavior for session cookies".to_string(),
                references: vec![],
            });
            // No score deduction - this is good
        }
        
        // 7. Check for weak/predictable cookie values
        if self.is_weak_cookie_value(&cookie.value) {
            analysis.issues.push(CookieIssue {
                issue_type: "weak_value".to_string(),
                severity: Severity::High,
                title: "Weak/Predictable Cookie Value".to_string(),
                description: format!("Cookie '{}' has a potentially weak or predictable value", cookie.name),
                impact: "Session ID could be guessed or brute-forced".to_string(),
                recommendation: "Use cryptographically secure random values (at least 128 bits of entropy)".to_string(),
                references: vec![
                    SecurityReference {
                        ref_type: "CWE".to_string(),
                        id: "CWE-330".to_string(),
                        url: "https://cwe.mitre.org/data/definitions/330.html".to_string(),
                        description: "Use of Insufficiently Random Values".to_string(),
                    },
                ],
            });
            analysis.score -= 30;
        }
        
        // 8. Check for cookie prefixes (__Secure-, __Host-)
        if cookie.name.starts_with("__Secure-") && !cookie.secure {
            analysis.issues.push(CookieIssue {
                issue_type: "secure_prefix_violation".to_string(),
                severity: Severity::High,
                title: "__Secure- Prefix Violation".to_string(),
                description: format!("Cookie '{}' has __Secure- prefix but is missing Secure flag", cookie.name),
                impact: "Browser will reject this cookie".to_string(),
                recommendation: "Add Secure flag to cookies with __Secure- prefix".to_string(),
                references: vec![],
            });
            analysis.score -= 25;
        }
        
        if cookie.name.starts_with("__Host-") {
            if !cookie.secure {
                analysis.issues.push(CookieIssue {
                    issue_type: "host_prefix_violation".to_string(),
                    severity: Severity::High,
                    title: "__Host- Prefix Violation (Missing Secure)".to_string(),
                    description: format!("Cookie '{}' has __Host- prefix but is missing Secure flag", cookie.name),
                    impact: "Browser will reject this cookie".to_string(),
                    recommendation: "Add Secure flag to cookies with __Host- prefix".to_string(),
                    references: vec![],
                });
                analysis.score -= 25;
            }
            if cookie.domain.is_some() {
                analysis.issues.push(CookieIssue {
                    issue_type: "host_prefix_violation".to_string(),
                    severity: Severity::High,
                    title: "__Host- Prefix Violation (Has Domain)".to_string(),
                    description: format!("Cookie '{}' has __Host- prefix but has a Domain attribute", cookie.name),
                    impact: "Browser will reject this cookie".to_string(),
                    recommendation: "Remove Domain attribute from cookies with __Host- prefix".to_string(),
                    references: vec![],
                });
                analysis.score -= 25;
            }
            if cookie.path.as_deref() != Some("/") {
                analysis.issues.push(CookieIssue {
                    issue_type: "host_prefix_violation".to_string(),
                    severity: Severity::High,
                    title: "__Host- Prefix Violation (Path Not Root)".to_string(),
                    description: format!("Cookie '{}' has __Host- prefix but path is not '/'", cookie.name),
                    impact: "Browser will reject this cookie".to_string(),
                    recommendation: "Set path to '/' for cookies with __Host- prefix".to_string(),
                    references: vec![],
                });
                analysis.score -= 25;
            }
        }
        
        // Ensure score doesn't go below 0
        analysis.score = analysis.score.max(0);
        
        analysis
    }
    
    fn is_weak_cookie_value(&self, value: &str) -> bool {
        // Check for common weak patterns
        let weak_patterns = [
            "test", "admin", "user", "guest", "anonymous", "default",
            "123", "abc", "session", "token", "auth", "demo",
        ];
        
        let value_lower = value.to_lowercase();
        
        // Too short (less than 16 chars = 128 bits if base64)
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
        if value_lower.contains("123456") || value_lower.contains("abcdef") || value_lower.contains("qwerty") {
            return true;
        }
        
        // Only alphanumeric (no special chars) and short - might be base64 but too short
        if value.len() < 22 && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
            return true;
        }
        
        // Check entropy (simplified)
        let unique_chars: std::collections::HashSet<char> = value.chars().collect();
        if unique_chars.len() < 8 && value.len() > 20 {
            // Low character diversity for a long string
            return true;
        }
        
        false
    }
}

/// Result of cookie analysis
#[derive(Debug, Default, Serialize, Deserialize)]
struct CookieAnalysisResult {
    cookies: Vec<CookieInfo>,
    status: u16,
    analyses: Vec<CookieAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CookieAnalysis {
    cookie: CookieInfo,
    issues: Vec<CookieIssue>,
    score: u8, // 0-100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CookieIssue {
    issue_type: String,
    severity: Severity,
    title: String,
    description: String,
    impact: String,
    recommendation: String,
    references: Vec<SecurityReference>,
}

#[async_trait]
impl Plugin for CookieSecurityPlugin {
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
        
        info!("Starting cookie security analysis for {}", target_url);
        
        let analysis = self.analyze_cookies(target_url).await;
        let mut findings = Vec::new();
        
        // Report overall cookie summary
        let total_cookies = analysis.cookies.len();
        let cookies_with_issues = analysis.analyses.iter().filter(|a| !a.issues.is_empty()).count();
        let high_severity_issues = analysis.analyses.iter()
            .flat_map(|a| &a.issues)
            .filter(|i| matches!(i.severity, Severity::High | Severity::Critical))
            .count();
        
        if total_cookies > 0 {
            let mut finding = Finding::new(
                "Cookie Security Analysis Summary".to_string(),
                format!(
                    "Analyzed {} cookies from {}. {} cookies have security issues. {} high/critical severity issues found.",
                    total_cookies, target_url, cookies_with_issues, high_severity_issues
                ),
                if high_severity_issues > 0 { Severity::High } else if cookies_with_issues > 0 { Severity::Medium } else { Severity::Info },
                Confidence::High,
                Category::SecurityMisconfiguration,
                target_url.to_string(),
                "web_application".to_string(),
                "cookie_security".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Cookie security analysis summary".to_string(),
                data: Some(serde_json::json!({
                    "total_cookies": total_cookies,
                    "cookies_with_issues": cookies_with_issues,
                    "high_severity_issues": high_severity_issues,
                    "analyses": analysis.analyses,
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
            
            finding = finding.with_tag("cookie_analysis".to_string());
            findings.push(finding);
        }
        
        // Report individual cookie issues
        for cookie_analysis in &analysis.analyses {
            for issue in &cookie_analysis.issues {
                let mut finding = Finding::new(
                    format!("Cookie Issue: {} - {}", cookie_analysis.cookie.name, issue.title),
                    format!("{}\n\nImpact: {}\n\nRecommendation: {}", issue.description, issue.impact, issue.recommendation),
                    issue.severity,
                    Confidence::High,
                    Category::SecurityMisconfiguration,
                    target_url.to_string(),
                    "web_application".to_string(),
                    "cookie_security".to_string(),
                    env!("CARGO_PKG_VERSION").to_string(),
                    openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
                );
                
                finding = finding.with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Cookie security issue details".to_string(),
                    data: Some(serde_json::json!({
                        "cookie": cookie_analysis.cookie,
                        "issue": issue,
                        "cookie_score": cookie_analysis.score,
                    })),
                    location: Some(target_url.to_string()),
                    metadata: HashMap::new(),
                });
                
                for reference in &issue.references {
                    finding = finding.with_reference(Reference {
                        reference_type: match reference.ref_type.as_str() {
                            "CWE" => ReferenceType::Cwe,
                            "OWASP" => ReferenceType::Owasp,
                            _ => ReferenceType::Custom(reference.ref_type.clone()),
                        },
                        title: reference.id.clone(),
                        url: reference.url.clone(),
                        description: Some(reference.description.clone()),
                    });
                }
                
                // Add standard references too
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
        }
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "total_cookies": total_cookies,
            "cookies_with_issues": cookies_with_issues,
            "high_severity_issues": high_severity_issues,
        })))
    }
}

impl SecurityPlugin for CookieSecurityPlugin {
    fn security_category(&self) -> &'static str {
        "cookie_security"
    }
    
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    
    fn description(&self) -> &'static str {
        "Validates cookie security attributes including Secure flag, HttpOnly flag, SameSite policy, Domain scope, Path scope, Expiration, and Weak or predictable cookie patterns"
    }
    
    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
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
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-1275".to_string(),
                url: "https://cwe.mitre.org/data/definitions/1275.html".to_string(),
                description: "Sensitive Cookie with Improper SameSite Attribute".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-613".to_string(),
                url: "https://cwe.mitre.org/data/definitions/613.html".to_string(),
                description: "Insufficient Session Expiration".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-330".to_string(),
                url: "https://cwe.mitre.org/data/definitions/330.html".to_string(),
                description: "Use of Insufficiently Random Values".to_string(),
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
