//! Security Headers Plugin
//!
//! Checks for Content-Security-Policy, Strict-Transport-Security,
//! X-Frame-Options, Referrer-Policy, Permissions-Policy,
//! X-Content-Type-Options, Cache-Control and reports missing or weak configurations.

use crate::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{
    standard_references, HttpResponse, SecurityPlugin, SecurityPluginConfig, SecurityReference,
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

/// Security Headers Plugin
pub struct SecurityHeadersPlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl SecurityHeadersPlugin {
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

    /// Analyze security headers from a target
    async fn analyze_headers(&self, base_url: &str) -> HeaderAnalysisResult {
        let mut result = HeaderAnalysisResult::default();

        // Make request to get headers
        let response = self.make_request(base_url).await;
        if let Some(resp) = response {
            result.headers = resp.headers;
            result.status = resp.status;
            result.url = resp.url;
        }

        // Analyze each security header
        result.csp_analysis = self.analyze_csp(&result.headers);
        result.hsts_analysis = self.analyze_hsts(&result.headers, &result.url);
        result.xfo_analysis = self.analyze_xfo(&result.headers);
        result.referrer_analysis = self.analyze_referrer_policy(&result.headers);
        result.permissions_analysis = self.analyze_permissions_policy(&result.headers);
        result.xcto_analysis = self.analyze_x_content_type_options(&result.headers);
        result.cache_control_analysis = self.analyze_cache_control(&result.headers);
        result.x_xss_protection_analysis = self.analyze_x_xss_protection(&result.headers);
        result.x_permitted_cross_domain_analysis =
            self.analyze_x_permitted_cross_domain(&result.headers);
        result.cross_origin_analysis = self.analyze_cross_origin_headers(&result.headers);

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
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => String::new(),
        };

        Some(HttpResponse {
            status,
            headers,
            body,
            url: url.to_string(),
            cookies: Vec::new(),
        })
    }

    /// Analyze Content-Security-Policy header
    fn analyze_csp(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "Content-Security-Policy".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        // Check for CSP header (including report-only)
        let csp_value = headers
            .get("content-security-policy")
            .or_else(|| headers.get("content-security-policy-report-only"))
            .cloned();

        if let Some(value) = csp_value {
            analysis.present = true;
            analysis.value = Some(value.clone());
            analysis.score = 50; // Base score for having CSP

            // Parse CSP directives
            let directives = self.parse_csp(&value);

            // Check for dangerous directives
            if directives.get("default-src").map_or(false, |v| {
                v.contains("'unsafe-inline'") || v.contains("'unsafe-eval'") || v.contains("*")
            }) {
                analysis.issues.push(HeaderIssue {
                    issue_type: "csp_unsafe_default_src".to_string(),
                    severity: Severity::High,
                    title: "CSP default-src Allows Unsafe Inline/Eval or Wildcard".to_string(),
                    description: "The default-src directive allows 'unsafe-inline', 'unsafe-eval', or '*' which significantly weakens CSP protection".to_string(),
                    recommendation: "Remove 'unsafe-inline', 'unsafe-eval', and '*' from default-src. Use nonces or hashes for inline scripts/styles".to_string(),
                });
                analysis.score -= 30;
            }

            if directives.get("script-src").map_or(false, |v| {
                v.contains("'unsafe-inline'") || v.contains("'unsafe-eval'") || v.contains("*")
            }) {
                analysis.issues.push(HeaderIssue {
                    issue_type: "csp_unsafe_script_src".to_string(),
                    severity: Severity::High,
                    title: "CSP script-src Allows Unsafe Inline/Eval or Wildcard".to_string(),
                    description: "The script-src directive allows 'unsafe-inline', 'unsafe-eval', or '*' which allows arbitrary script execution".to_string(),
                    recommendation: "Remove 'unsafe-inline', 'unsafe-eval', and '*' from script-src. Use nonces or hashes for inline scripts".to_string(),
                });
                analysis.score -= 30;
            }

            if directives
                .get("style-src")
                .map_or(false, |v| v.contains("'unsafe-inline'") || v.contains("*"))
            {
                analysis.issues.push(HeaderIssue {
                    issue_type: "csp_unsafe_style_src".to_string(),
                    severity: Severity::Medium,
                    title: "CSP style-src Allows Unsafe Inline or Wildcard".to_string(),
                    description: "The style-src directive allows 'unsafe-inline' or '*' which allows arbitrary style injection".to_string(),
                    recommendation: "Remove 'unsafe-inline' and '*' from style-src. Use nonces or hashes for inline styles".to_string(),
                });
                analysis.score -= 20;
            }

            // Check for missing important directives
            let important_directives = [
                "default-src",
                "script-src",
                "style-src",
                "img-src",
                "connect-src",
                "font-src",
                "object-src",
                "frame-src",
                "base-uri",
                "form-action",
            ];
            for directive in &important_directives {
                if !directives.contains_key(*directive) {
                    analysis.issues.push(HeaderIssue {
                        issue_type: format!("csp_missing_{}", directive.replace("-", "_")),
                        severity: Severity::Low,
                        title: format!("CSP Missing {} Directive", directive),
                        description: format!(
                            "The CSP policy is missing the {} directive",
                            directive
                        ),
                        recommendation: format!(
                            "Add {} directive to restrict {} resources",
                            directive,
                            directive.replace("-src", "")
                        ),
                    });
                    analysis.score -= 5;
                }
            }

            // Check for frame-ancestors (clickjacking protection)
            if !directives.contains_key("frame-ancestors") {
                analysis.issues.push(HeaderIssue {
                    issue_type: "csp_missing_frame_ancestors".to_string(),
                    severity: Severity::Medium,
                    title: "CSP Missing frame-ancestors Directive".to_string(),
                    description: "The CSP policy is missing frame-ancestors directive for clickjacking protection".to_string(),
                    recommendation: "Add frame-ancestors 'none' or frame-ancestors 'self' to prevent framing".to_string(),
                });
                analysis.score -= 10;
            }

            // Check for report-uri or report-to
            if !directives.contains_key("report-uri") && !directives.contains_key("report-to") {
                analysis.issues.push(HeaderIssue {
                    issue_type: "csp_missing_reporting".to_string(),
                    severity: Severity::Info,
                    title: "CSP Missing Violation Reporting".to_string(),
                    description: "The CSP policy has no violation reporting endpoint (report-uri or report-to)".to_string(),
                    recommendation: "Add report-uri or report-to directive to collect CSP violation reports".to_string(),
                });
                analysis.score -= 5;
            }

            // Bonus for strict CSP
            if !analysis
                .issues
                .iter()
                .any(|i| matches!(i.severity, Severity::High | Severity::Critical))
            {
                analysis.score += 20;
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "csp_missing".to_string(),
                severity: Severity::High,
                title: "Missing Content-Security-Policy Header".to_string(),
                description: "The Content-Security-Policy header is not present, leaving the application vulnerable to XSS and data injection attacks".to_string(),
                recommendation: "Implement a Content-Security-Policy header with appropriate directives for your application".to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    fn parse_csp(&self, csp: &str) -> HashMap<String, String> {
        let mut directives = HashMap::new();
        let parts: Vec<&str> = csp.split(';').collect();

        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let space_pos = part.find(' ');
            if let Some(pos) = space_pos {
                let directive = part[..pos].trim().to_lowercase();
                let value = part[pos + 1..].trim().to_string();
                directives.insert(directive, value);
            } else {
                directives.insert(part.to_lowercase(), String::new());
            }
        }

        directives
    }

    /// Analyze Strict-Transport-Security header
    fn analyze_hsts(&self, headers: &HashMap<String, String>, url: &str) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "Strict-Transport-Security".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let hsts_value = headers.get("strict-transport-security").cloned();

        if let Some(value) = hsts_value {
            analysis.present = true;
            analysis.value = Some(value.clone());
            analysis.score = 50;

            // Parse HSTS directives
            let directives = self.parse_hsts(&value);

            // Check max-age
            if let Some(max_age_str) = directives.get("max-age") {
                if let Ok(max_age) = max_age_str.parse::<i64>() {
                    if max_age < 31536000 {
                        // Less than 1 year
                        analysis.issues.push(HeaderIssue {
                            issue_type: "hsts_short_max_age".to_string(),
                            severity: Severity::Medium,
                            title: "HSTS max-age Too Short".to_string(),
                            description: format!("HSTS max-age is {} seconds ({} days), recommended minimum is 1 year (31536000 seconds)", max_age, max_age / 86400),
                            recommendation: "Set max-age to at least 31536000 (1 year)".to_string(),
                        });
                        analysis.score -= 20;
                    } else {
                        analysis.score += 10;
                    }
                }
            } else {
                analysis.issues.push(HeaderIssue {
                    issue_type: "hsts_missing_max_age".to_string(),
                    severity: Severity::High,
                    title: "HSTS Missing max-age Directive".to_string(),
                    description: "HSTS header is missing the required max-age directive"
                        .to_string(),
                    recommendation: "Add max-age directive with value of at least 31536000"
                        .to_string(),
                });
                analysis.score -= 30;
            }

            // Check includeSubDomains
            if directives.contains_key("includesubdomains") {
                analysis.score += 10;
            } else {
                analysis.issues.push(HeaderIssue {
                    issue_type: "hsts_missing_include_subdomains".to_string(),
                    severity: Severity::Low,
                    title: "HSTS Missing includeSubDomains".to_string(),
                    description: "HSTS header does not include includeSubDomains directive"
                        .to_string(),
                    recommendation: "Add includeSubDomains to protect all subdomains".to_string(),
                });
                analysis.score -= 5;
            }

            // Check preload
            if directives.contains_key("preload") {
                analysis.score += 10;
            } else {
                analysis.issues.push(HeaderIssue {
                    issue_type: "hsts_missing_preload".to_string(),
                    severity: Severity::Info,
                    title: "HSTS Missing preload Directive".to_string(),
                    description:
                        "HSTS header does not include preload directive for HSTS preload list"
                            .to_string(),
                    recommendation:
                        "Consider adding preload directive and submitting to HSTS preload list"
                            .to_string(),
                });
                analysis.score -= 2;
            }
        } else {
            // Only flag as issue if using HTTPS
            if url.starts_with("https://") {
                analysis.issues.push(HeaderIssue {
                    issue_type: "hsts_missing".to_string(),
                    severity: Severity::High,
                    title: "Missing Strict-Transport-Security Header".to_string(),
                    description: "The Strict-Transport-Security header is not present on an HTTPS site, leaving users vulnerable to SSL stripping attacks".to_string(),
                    recommendation: "Implement HSTS header with max-age of at least 31536000, includeSubDomains, and preload".to_string(),
                });
                analysis.score = 0;
            } else {
                analysis.issues.push(HeaderIssue {
                    issue_type: "hsts_not_applicable".to_string(),
                    severity: Severity::Info,
                    title: "HSTS Not Applicable (HTTP Site)".to_string(),
                    description: "HSTS is only applicable to HTTPS sites".to_string(),
                    recommendation: "Migrate to HTTPS and then implement HSTS".to_string(),
                });
                analysis.score = 0;
            }
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    fn parse_hsts(&self, hsts: &str) -> HashMap<String, String> {
        let mut directives = HashMap::new();
        let parts: Vec<&str> = hsts.split(';').collect();

        for part in parts {
            let part = part.trim().to_lowercase();
            if part.is_empty() {
                continue;
            }
            let eq_pos = part.find('=');
            if let Some(pos) = eq_pos {
                let directive = part[..pos].trim().to_string();
                let value = part[pos + 1..].trim().to_string();
                directives.insert(directive, value);
            } else {
                directives.insert(part, String::new());
            }
        }

        directives
    }

    /// Analyze X-Frame-Options header
    fn analyze_xfo(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "X-Frame-Options".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let xfo_value = headers.get("x-frame-options").cloned();

        if let Some(value) = xfo_value {
            analysis.present = true;
            analysis.value = Some(value.clone());

            let value_upper = value.to_uppercase();
            if value_upper == "DENY" {
                analysis.score = 100;
            } else if value_upper == "SAMEORIGIN" {
                analysis.score = 80;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xfo_sameorigin".to_string(),
                    severity: Severity::Low,
                    title: "X-Frame-Options Set to SAMEORIGIN".to_string(),
                    description: "X-Frame-Options is set to SAMEORIGIN which allows framing from same origin".to_string(),
                    recommendation: "Consider using DENY for stronger clickjacking protection, or use CSP frame-ancestors".to_string(),
                });
            } else if value_upper.starts_with("ALLOW-FROM") {
                analysis.score = 40;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xfo_allow_from".to_string(),
                    severity: Severity::Medium,
                    title: "X-Frame-Options Uses Deprecated ALLOW-FROM".to_string(),
                    description: "ALLOW-FROM is deprecated and not supported by all browsers"
                        .to_string(),
                    recommendation: "Use CSP frame-ancestors directive instead".to_string(),
                });
            } else {
                analysis.score = 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xfo_invalid".to_string(),
                    severity: Severity::High,
                    title: "Invalid X-Frame-Options Value".to_string(),
                    description: format!("X-Frame-Options has invalid value: {}", value),
                    recommendation: "Use DENY, SAMEORIGIN, or CSP frame-ancestors".to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "xfo_missing".to_string(),
                severity: Severity::Medium,
                title: "Missing X-Frame-Options Header".to_string(),
                description: "The X-Frame-Options header is not present, leaving the application vulnerable to clickjacking attacks".to_string(),
                recommendation: "Add X-Frame-Options: DENY or use CSP frame-ancestors directive".to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze Referrer-Policy header
    fn analyze_referrer_policy(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "Referrer-Policy".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let referrer_value = headers.get("referrer-policy").cloned();

        if let Some(value) = referrer_value {
            analysis.present = true;
            analysis.value = Some(value.clone());

            let policies: Vec<String> = value.split(',').map(|s| s.trim().to_lowercase()).collect();

            let secure_policies = [
                "no-referrer",
                "no-referrer-when-downgrade",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "same-origin",
            ];
            let insecure_policies = ["unsafe-url", "origin", "origin-when-cross-origin"];

            let has_secure = policies
                .iter()
                .any(|p| secure_policies.contains(&p.as_str()));
            let has_insecure = policies
                .iter()
                .any(|p| insecure_policies.contains(&p.as_str()));

            if has_secure && !has_insecure {
                analysis.score = 100;
            } else if has_secure && has_insecure {
                analysis.score = 60;
                analysis.issues.push(HeaderIssue {
                    issue_type: "referrer_mixed_policies".to_string(),
                    severity: Severity::Low,
                    title: "Referrer-Policy Contains Mixed Secure/Insecure Policies".to_string(),
                    description: format!("Referrer-Policy contains both secure and insecure policies: {}", value),
                    recommendation: "Use only secure policies: no-referrer, strict-origin-when-cross-origin, etc.".to_string(),
                });
            } else if has_insecure {
                analysis.score = 20;
                analysis.issues.push(HeaderIssue {
                    issue_type: "referrer_insecure_policy".to_string(),
                    severity: Severity::Medium,
                    title: "Referrer-Policy Uses Insecure Policy".to_string(),
                    description: format!("Referrer-Policy uses insecure policy: {}", value),
                    recommendation:
                        "Use secure policies like strict-origin-when-cross-origin or no-referrer"
                            .to_string(),
                });
            } else {
                analysis.score = 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "referrer_unknown_policy".to_string(),
                    severity: Severity::Low,
                    title: "Referrer-Policy Uses Unknown Policy".to_string(),
                    description: format!(
                        "Referrer-Policy contains unknown policy values: {}",
                        value
                    ),
                    recommendation: "Use standard referrer policy values".to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "referrer_missing".to_string(),
                severity: Severity::Low,
                title: "Missing Referrer-Policy Header".to_string(),
                description:
                    "The Referrer-Policy header is not present, which may leak referrer information"
                        .to_string(),
                recommendation: "Add Referrer-Policy: strict-origin-when-cross-origin or stricter"
                    .to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze Permissions-Policy header
    fn analyze_permissions_policy(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "Permissions-Policy".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let permissions_value = headers
            .get("permissions-policy")
            .or_else(|| headers.get("feature-policy")) // Legacy name
            .cloned();

        if let Some(value) = permissions_value {
            analysis.present = true;
            analysis.value = Some(value.clone());
            analysis.score = 50;

            // Check for dangerous permissions
            let dangerous_permissions = [
                "geolocation",
                "camera",
                "microphone",
                "payment",
                "usb",
                "magnetometer",
                "gyroscope",
                "accelerometer",
                "ambient-light-sensor",
                "autoplay",
                "encrypted-media",
                "fullscreen",
                "picture-in-picture",
            ];

            for perm in &dangerous_permissions {
                if value.to_lowercase().contains(&perm.to_lowercase())
                    && !value.contains(&format!("{} 'none'", perm))
                    && !value.contains(&format!("{} ()", perm))
                {
                    analysis.issues.push(HeaderIssue {
                        issue_type: format!("permissions_{}_enabled", perm.replace("-", "_")),
                        severity: Severity::Low,
                        title: format!("Permissions-Policy Allows {}", perm),
                        description: format!(
                            "Permissions-Policy allows access to {} feature",
                            perm
                        ),
                        recommendation: format!(
                            "Restrict {} permission to 'none' or specific origins if not needed",
                            perm
                        ),
                    });
                    analysis.score -= 5;
                }
            }

            // Check for '*' (allow all origins)
            if value.contains("*") {
                analysis.issues.push(HeaderIssue {
                    issue_type: "permissions_wildcard".to_string(),
                    severity: Severity::Medium,
                    title: "Permissions-Policy Uses Wildcard (*)".to_string(),
                    description: "Permissions-Policy allows features for all origins".to_string(),
                    recommendation: "Restrict permissions to specific origins or 'none'"
                        .to_string(),
                });
                analysis.score -= 20;
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "permissions_missing".to_string(),
                severity: Severity::Info,
                title: "Missing Permissions-Policy Header".to_string(),
                description: "The Permissions-Policy header is not present, allowing all browser features by default".to_string(),
                recommendation: "Add Permissions-Policy header to restrict unnecessary browser features".to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze X-Content-Type-Options header
    fn analyze_x_content_type_options(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "X-Content-Type-Options".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let xcto_value = headers.get("x-content-type-options").cloned();

        if let Some(value) = xcto_value {
            analysis.present = true;
            analysis.value = Some(value.clone());

            if value.to_lowercase() == "nosniff" {
                analysis.score = 100;
            } else {
                analysis.score = 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xcto_invalid".to_string(),
                    severity: Severity::Medium,
                    title: "Invalid X-Content-Type-Options Value".to_string(),
                    description: format!("X-Content-Type-Options has invalid value: {}", value),
                    recommendation: "Set X-Content-Type-Options: nosniff".to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "xcto_missing".to_string(),
                severity: Severity::Medium,
                title: "Missing X-Content-Type-Options Header".to_string(),
                description:
                    "The X-Content-Type-Options header is not present, allowing MIME type sniffing"
                        .to_string(),
                recommendation: "Add X-Content-Type-Options: nosniff".to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze Cache-Control header
    fn analyze_cache_control(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "Cache-Control".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let cache_value = headers.get("cache-control").cloned();

        if let Some(value) = cache_value {
            analysis.present = true;
            analysis.value = Some(value.clone());
            analysis.score = 50;

            let directives: Vec<String> =
                value.split(',').map(|s| s.trim().to_lowercase()).collect();

            // Check for no-store on sensitive pages
            if directives.iter().any(|d| d == "no-store") {
                analysis.score += 30;
            }

            // Check for no-cache
            if directives.iter().any(|d| d == "no-cache") {
                analysis.score += 20;
            }

            // Check for must-revalidate
            if directives.iter().any(|d| d == "must-revalidate") {
                analysis.score += 10;
            }

            // Check for public on potentially sensitive content
            if directives.iter().any(|d| d == "public") {
                analysis.issues.push(HeaderIssue {
                    issue_type: "cache_public".to_string(),
                    severity: Severity::Low,
                    title: "Cache-Control Allows Public Caching".to_string(),
                    description: "Cache-Control includes 'public' directive which allows caching by shared caches".to_string(),
                    recommendation: "Use 'private' for user-specific content, 'no-store' for sensitive content".to_string(),
                });
                analysis.score -= 10;
            }

            // Check for long max-age
            for directive in &directives {
                if directive.starts_with("max-age=") {
                    if let Ok(max_age) = directive[8..].parse::<i64>() {
                        if max_age > 31536000 {
                            // 1 year
                            analysis.issues.push(HeaderIssue {
                                issue_type: "cache_long_max_age".to_string(),
                                severity: Severity::Info,
                                title: "Cache-Control Has Long max-age".to_string(),
                                description: format!(
                                    "Cache-Control max-age is {} seconds ({} days)",
                                    max_age,
                                    max_age / 86400
                                ),
                                recommendation: "Consider shorter max-age for dynamic content"
                                    .to_string(),
                            });
                            analysis.score -= 5;
                        }
                    }
                }
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "cache_missing".to_string(),
                severity: Severity::Info,
                title: "Missing Cache-Control Header".to_string(),
                description: "The Cache-Control header is not present, allowing default browser caching behavior".to_string(),
                recommendation: "Add appropriate Cache-Control header based on content sensitivity".to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze X-XSS-Protection header (legacy)
    fn analyze_x_xss_protection(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "X-XSS-Protection".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let xss_value = headers.get("x-xss-protection").cloned();

        if let Some(value) = xss_value {
            analysis.present = true;
            analysis.value = Some(value.clone());

            if value == "1; mode=block" {
                analysis.score = 80;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xss_protection_legacy".to_string(),
                    severity: Severity::Info,
                    title: "X-XSS-Protection Header Present (Legacy)".to_string(),
                    description:
                        "X-XSS-Protection is a legacy header, modern browsers rely on CSP instead"
                            .to_string(),
                    recommendation:
                        "Implement Content-Security-Policy instead of relying on X-XSS-Protection"
                            .to_string(),
                });
            } else if value == "0" {
                analysis.score = 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xss_protection_disabled".to_string(),
                    severity: Severity::Medium,
                    title: "X-XSS-Protection Disabled".to_string(),
                    description: "X-XSS-Protection is explicitly disabled (value: 0)".to_string(),
                    recommendation:
                        "Enable X-XSS-Protection: 1; mode=block or better, implement CSP"
                            .to_string(),
                });
            } else {
                analysis.score = 40;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xss_protection_weak".to_string(),
                    severity: Severity::Low,
                    title: "Weak X-XSS-Protection Configuration".to_string(),
                    description: format!("X-XSS-Protection has suboptimal value: {}", value),
                    recommendation: "Use X-XSS-Protection: 1; mode=block or implement CSP"
                        .to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "xss_protection_missing".to_string(),
                severity: Severity::Info,
                title: "Missing X-XSS-Protection Header (Legacy)".to_string(),
                description:
                    "X-XSS-Protection header is not present (legacy header, CSP is preferred)"
                        .to_string(),
                recommendation: "Implement Content-Security-Policy for modern XSS protection"
                    .to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze X-Permitted-Cross-Domain-Policies header
    fn analyze_x_permitted_cross_domain(
        &self,
        headers: &HashMap<String, String>,
    ) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "X-Permitted-Cross-Domain-Policies".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let xpcd_value = headers.get("x-permitted-cross-domain-policies").cloned();

        if let Some(value) = xpcd_value {
            analysis.present = true;
            analysis.value = Some(value.clone());

            let value_lower = value.to_lowercase();
            if value_lower == "none" {
                analysis.score = 100;
            } else if value_lower == "master-only" {
                analysis.score = 60;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xpcd_master_only".to_string(),
                    severity: Severity::Low,
                    title: "X-Permitted-Cross-Domain-Policies Set to master-only".to_string(),
                    description: "Allows only master policy file".to_string(),
                    recommendation:
                        "Use 'none' for maximum security unless cross-domain policies are needed"
                            .to_string(),
                });
            } else if value_lower == "by-content-type"
                || value_lower == "by-ftp-filename"
                || value_lower == "all"
            {
                analysis.score = 20;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xpcd_permissive".to_string(),
                    severity: Severity::Medium,
                    title: "Permissive X-Permitted-Cross-Domain-Policies".to_string(),
                    description: format!(
                        "X-Permitted-Cross-Domain-Policies allows cross-domain access: {}",
                        value
                    ),
                    recommendation:
                        "Set to 'none' unless Flash/legacy cross-domain access is required"
                            .to_string(),
                });
            } else {
                analysis.score = 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "xpcd_invalid".to_string(),
                    severity: Severity::Low,
                    title: "Invalid X-Permitted-Cross-Domain-Policies Value".to_string(),
                    description: format!(
                        "X-Permitted-Cross-Domain-Policies has unknown value: {}",
                        value
                    ),
                    recommendation:
                        "Use 'none', 'master-only', 'by-content-type', 'by-ftp-filename', or 'all'"
                            .to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "xpcd_missing".to_string(),
                severity: Severity::Info,
                title: "Missing X-Permitted-Cross-Domain-Policies Header".to_string(),
                description: "Header not present (mainly relevant for legacy Flash content)"
                    .to_string(),
                recommendation: "Add X-Permitted-Cross-Domain-Policies: none for defense in depth"
                    .to_string(),
            });
            analysis.score = 0;
        }

        analysis.score = analysis.score.max(0).min(100);
        analysis
    }

    /// Analyze Cross-Origin headers (COOP, COEP, CORP)
    fn analyze_cross_origin_headers(&self, headers: &HashMap<String, String>) -> HeaderAnalysis {
        let mut analysis = HeaderAnalysis {
            header_name: "Cross-Origin Headers (COOP/COEP/CORP)".to_string(),
            present: false,
            value: None,
            issues: Vec::new(),
            score: 0,
        };

        let coop = headers.get("cross-origin-opener-policy").cloned();
        let coep = headers.get("cross-origin-embedder-policy").cloned();
        let corp = headers.get("cross-origin-resource-policy").cloned();

        let mut present_count = 0;
        let mut score = 0;

        let coop_value = coop.clone();
        if let Some(value) = coop {
            present_count += 1;
            if value == "same-origin" {
                score += 30;
            } else if value == "same-origin-allow-popups" {
                score += 20;
            } else if value == "unsafe-none" {
                score += 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "coop_unsafe_none".to_string(),
                    severity: Severity::Low,
                    title: "COOP Set to unsafe-none".to_string(),
                    description: "Cross-Origin-Opener-Policy is set to unsafe-none, disabling cross-origin isolation".to_string(),
                    recommendation: "Use same-origin or same-origin-allow-popups for cross-origin isolation".to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "coop_missing".to_string(),
                severity: Severity::Info,
                title: "Missing Cross-Origin-Opener-Policy".to_string(),
                description: "COOP header not present, cross-origin isolation not enabled"
                    .to_string(),
                recommendation:
                    "Add Cross-Origin-Opener-Policy: same-origin for cross-origin isolation"
                        .to_string(),
            });
        }

        let coep_value = coep.clone();
        if let Some(value) = coep {
            present_count += 1;
            if value == "require-corp" {
                score += 30;
            } else if value == "credentialless" {
                score += 20;
            } else if value == "unsafe-none" {
                score += 0;
                analysis.issues.push(HeaderIssue {
                    issue_type: "coep_unsafe_none".to_string(),
                    severity: Severity::Low,
                    title: "COEP Set to unsafe-none".to_string(),
                    description: "Cross-Origin-Embedder-Policy is set to unsafe-none".to_string(),
                    recommendation: "Use require-corp or credentialless for cross-origin isolation"
                        .to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "coep_missing".to_string(),
                severity: Severity::Info,
                title: "Missing Cross-Origin-Embedder-Policy".to_string(),
                description: "COEP header not present, cross-origin isolation not enabled"
                    .to_string(),
                recommendation:
                    "Add Cross-Origin-Embedder-Policy: require-corp for cross-origin isolation"
                        .to_string(),
            });
        }

        let corp_value = corp.clone();
        if let Some(value) = corp {
            present_count += 1;
            if value == "same-origin" {
                score += 20;
            } else if value == "same-site" {
                score += 15;
            } else if value == "cross-origin" {
                score += 5;
                analysis.issues.push(HeaderIssue {
                    issue_type: "corp_cross_origin".to_string(),
                    severity: Severity::Low,
                    title: "CORP Set to cross-origin".to_string(),
                    description:
                        "Cross-Origin-Resource-Policy allows any origin to load this resource"
                            .to_string(),
                    recommendation:
                        "Use same-origin or same-site unless cross-origin loading is required"
                            .to_string(),
                });
            }
        } else {
            analysis.issues.push(HeaderIssue {
                issue_type: "corp_missing".to_string(),
                severity: Severity::Info,
                title: "Missing Cross-Origin-Resource-Policy".to_string(),
                description: "CORP header not present".to_string(),
                recommendation: "Add Cross-Origin-Resource-Policy: same-origin for defense in depth".to_string(),
            });
        }

        analysis.present = present_count > 0;
        analysis.value = Some(format!(
            "COOP: {:?}, COEP: {:?}, CORP: {:?}",
            coop_value, coep_value, corp_value
        ));
        analysis.score = score.max(0).min(100);

        if present_count == 3 && score >= 80 {
            analysis.issues.push(HeaderIssue {
                issue_type: "cross_origin_isolation_enabled".to_string(),
                severity: Severity::Info,
                title: "Cross-Origin Isolation Enabled".to_string(),
                description: "All three cross-origin headers are properly configured for cross-origin isolation".to_string(),
                recommendation: "This enables powerful features like SharedArrayBuffer".to_string(),
            });
        }

        analysis
    }
}

/// Result of header analysis
#[derive(Debug, Default, Serialize, Deserialize)]
struct HeaderAnalysisResult {
    headers: HashMap<String, String>,
    status: u16,
    url: String,
    csp_analysis: HeaderAnalysis,
    hsts_analysis: HeaderAnalysis,
    xfo_analysis: HeaderAnalysis,
    referrer_analysis: HeaderAnalysis,
    permissions_analysis: HeaderAnalysis,
    xcto_analysis: HeaderAnalysis,
    cache_control_analysis: HeaderAnalysis,
    x_xss_protection_analysis: HeaderAnalysis,
    x_permitted_cross_domain_analysis: HeaderAnalysis,
    cross_origin_analysis: HeaderAnalysis,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HeaderAnalysis {
    header_name: String,
    present: bool,
    value: Option<String>,
    issues: Vec<HeaderIssue>,
    score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeaderIssue {
    issue_type: String,
    severity: Severity,
    title: String,
    description: String,
    recommendation: String,
}

#[async_trait]
impl Plugin for SecurityHeadersPlugin {
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

        info!("Starting security headers analysis for {}", target_url);

        let analysis = self.analyze_headers(target_url).await;
        let mut findings = Vec::new();

        // Collect all analyses
        let all_analyses = vec![
            analysis.csp_analysis,
            analysis.hsts_analysis,
            analysis.xfo_analysis,
            analysis.referrer_analysis,
            analysis.permissions_analysis,
            analysis.xcto_analysis,
            analysis.cache_control_analysis,
            analysis.x_xss_protection_analysis,
            analysis.x_permitted_cross_domain_analysis,
            analysis.cross_origin_analysis,
        ];

        // Report overall summary
        let total_headers = all_analyses.len();
        let present_headers = all_analyses.iter().filter(|a| a.present).count();
        let total_issues = all_analyses.iter().map(|a| a.issues.len()).sum::<usize>();
        let high_severity_issues = all_analyses
            .iter()
            .flat_map(|a| &a.issues)
            .filter(|i| matches!(i.severity, Severity::High | Severity::Critical))
            .count();

        let avg_score = if total_headers > 0 {
            all_analyses.iter().map(|a| a.score as u32).sum::<u32>() / total_headers as u32
        } else {
            0
        };

        let severity = if high_severity_issues > 0 {
            Severity::High
        } else if total_issues > 0 {
            Severity::Medium
        } else {
            Severity::Info
        };
        let mut summary_finding = Finding::new(FindingConfig {
            title: "Security Headers Analysis Summary".to_string(),
            description: format!(
                "Analyzed {} security headers for {}. {} headers present. {} total issues found ({} high/critical). Average score: {}/100",
                total_headers, target_url, present_headers, total_issues, high_severity_issues, avg_score
            ),
            severity,
            confidence: Confidence::High,
            category: Category::SecurityMisconfiguration,
            target: target_url.to_string(),
            target_type: "web_application".to_string(),
            plugin_source: "security_headers".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_id: openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
        });

        summary_finding = summary_finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: "Security headers analysis summary".to_string(),
            data: Some(serde_json::json!({
                "total_headers": total_headers,
                "present_headers": present_headers,
                "total_issues": total_issues,
                "high_severity_issues": high_severity_issues,
                "average_score": avg_score,
                "analyses": all_analyses,
            })),
            location: Some(target_url.to_string()),
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("security_headers".to_string()),
            timestamp: Utc::now(),
        });

        for reference in self.references() {
            summary_finding = summary_finding.with_reference(Reference {
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

        summary_finding = summary_finding.with_tag("headers_analysis".to_string());
        findings.push(summary_finding);

        // Report individual header issues
        for header_analysis in all_analyses {
            for issue in &header_analysis.issues {
                let mut finding = Finding::new(FindingConfig {
                    title: format!(
                        "Header Issue: {} - {}",
                        header_analysis.header_name, issue.title
                    ),
                    description: format!(
                        "{}\n\nRecommendation: {}",
                        issue.description, issue.recommendation
                    ),
                    severity: issue.severity,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target_url.to_string(),
                    target_type: "web_application".to_string(),
                    plugin_source: "security_headers".to_string(),
                    plugin_version: env!("CARGO_PKG_VERSION").to_string(),
                    scan_id: openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
                });

                finding = finding.with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Security header issue details".to_string(),
                    data: Some(serde_json::json!({
                        "header": header_analysis.header_name,
                        "header_value": header_analysis.value,
                        "issue": issue,
                        "header_score": header_analysis.score,
                    })),
                    location: Some(target_url.to_string()),
                    metadata: HashMap::new(),
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: Some("security_headers".to_string()),
                    timestamp: Utc::now(),
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

                finding = finding.with_tag(format!("header_{}", issue.issue_type));
                findings.push(finding);
            }
        }

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "total_headers": total_headers,
            "present_headers": present_headers,
            "total_issues": total_issues,
            "high_severity_issues": high_severity_issues,
            "average_score": avg_score,
        })))
    }
}

impl SecurityPlugin for SecurityHeadersPlugin {
    fn security_category(&self) -> &'static str {
        "security_headers"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> &'static str {
        "Checks for security headers including Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-Content-Type-Options, Cache-Control, and cross-origin isolation headers"
    }

    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-693".to_string(),
                url: "https://cwe.mitre.org/data/definitions/693.html".to_string(),
                description: "Protection Mechanism Failure".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-16".to_string(),
                url: "https://cwe.mitre.org/data/definitions/16.html".to_string(),
                description: "Configuration".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A05:2021".to_string(),
                url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
                description: "OWASP Top 10 2021 - Security Misconfiguration".to_string(),
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
