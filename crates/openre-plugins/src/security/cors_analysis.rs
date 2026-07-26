//! CORS Analysis Plugin
//! 
//! Evaluates wildcard origins, credential handling, origin reflection,
//! unsafe methods, and misconfigured headers.

use crate::security::{
    SecurityPlugin, SecurityPluginConfig, SecurityReference, standard_references,
    HttpResponse,
};
use crate::sdk::{CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability, PluginId, Plugin};
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};

/// CORS Analysis Plugin
pub struct CorsAnalysisPlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl CorsAnalysisPlugin {
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
    
    /// Analyze CORS configuration
    async fn analyze_cors(&self, base_url: &str) -> CorsAnalysisResult {
        let mut result = CorsAnalysisResult::default();
        
        // Test with various origins
        let test_origins = vec![
            "https://evil.com",           // External origin
            "https://sub.evil.com",       // Subdomain of external
            "null",                       // Null origin
            base_url,                     // Same origin
            "https://example.com",        // Another external
        ];
        
        for origin in test_origins {
            let test_result = self.test_origin(base_url, origin).await;
            result.origin_tests.push(test_result);
        }
        
        // Test preflight requests
        let preflight_result = self.test_preflight(base_url, "https://evil.com").await;
        result.preflight_test = Some(preflight_result);
        
        // Test with credentials
        let cred_result = self.test_with_credentials(base_url, "https://evil.com").await;
        result.credentials_test = Some(cred_result);
        
        // Test unsafe methods
        let unsafe_methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
        for method in &unsafe_methods {
            let method_result = self.test_method(base_url, method, "https://evil.com").await;
            result.method_tests.push(method_result);
        }
        
        result
    }
    
    /// Test CORS with a specific origin
    async fn test_origin(&self, url: &str, origin: &str) -> OriginTestResult {
        let mut result = OriginTestResult {
            origin: origin.to_string(),
            allowed: false,
            acao_header: None,
            acac_header: None,
            acam_header: None,
            acah_header: None,
            acma_header: None,
            issues: Vec::new(),
        };
        
        let response = self.make_request_with_origin(url, origin).await;
        if let Some(resp) = response {
            result.acao_header = resp.headers.get("access-control-allow-origin").cloned();
            result.acac_header = resp.headers.get("access-control-allow-credentials").cloned();
            result.acam_header = resp.headers.get("access-control-allow-methods").cloned();
            result.acah_header = resp.headers.get("access-control-allow-headers").cloned();
            result.acma_header = resp.headers.get("access-control-max-age").cloned();
            
            // Check if origin is allowed
            if let Some(acao) = &result.acao_header {
                if acao == "*" || acao == origin {
                    result.allowed = true;
                }
            }
            
            // Analyze issues
            self.analyze_origin_response(&mut result, origin);
        }
        
        result
    }
    
    /// Make a request with a specific Origin header
    async fn make_request_with_origin(&self, url: &str, origin: &str) -> Option<HttpResponse> {
        let response = match self.http_client
            .get(url)
            .header("Origin", origin)
            .send()
            .await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Failed to fetch {} with origin {}: {}", url, origin, e);
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
        
        Some(HttpResponse {
            status,
            headers,
            body,
            url: url.to_string(),
            cookies: Vec::new(),
        })
    }
    
    /// Analyze origin response for issues
    fn analyze_origin_response(&self, result: &mut OriginTestResult, test_origin: &str) {
        // Check for wildcard with credentials
        if result.acao_header.as_deref() == Some("*") {
            if result.acac_header.as_deref() == Some("true") {
                result.issues.push(CorsIssue {
                    issue_type: "wildcard_with_credentials".to_string(),
                    severity: Severity::Critical,
                    title: "Wildcard Origin with Credentials Allowed".to_string(),
                    description: "Access-Control-Allow-Origin is '*' but Access-Control-Allow-Credentials is 'true'. This is invalid per spec and browsers will reject it, but indicates misconfiguration.".to_string(),
                    recommendation: "Never use wildcard (*) with credentials. Specify exact origin when credentials are needed.".to_string(),
                });
            } else {
                result.issues.push(CorsIssue {
                    issue_type: "wildcard_origin".to_string(),
                    severity: Severity::Medium,
                    title: "Wildcard Origin Allowed".to_string(),
                    description: "Access-Control-Allow-Origin is set to '*', allowing any origin to access the resource".to_string(),
                    recommendation: "Restrict Access-Control-Allow-Origin to specific trusted origins".to_string(),
                });
            }
        }
        
        // Check for origin reflection
        if let Some(acao) = &result.acao_header {
            if acao == test_origin && test_origin != "null" && !test_origin.starts_with("http://localhost") && !test_origin.starts_with("https://localhost") {
                // Check if it's a dynamic reflection (echoing back the Origin header)
                result.issues.push(CorsIssue {
                    issue_type: "origin_reflection".to_string(),
                    severity: Severity::High,
                    title: "Origin Reflection Detected".to_string(),
                    description: format!("Server reflects the Origin header '{}' in Access-Control-Allow-Origin", test_origin),
                    recommendation: "Validate Origin header against a whitelist of allowed origins before reflecting".to_string(),
                });
            }
        }
        
        // Check for null origin allowed
        if test_origin == "null" && result.allowed {
            result.issues.push(CorsIssue {
                issue_type: "null_origin_allowed".to_string(),
                severity: Severity::High,
                title: "Null Origin Allowed".to_string(),
                description: "Server allows 'null' origin, which can be exploited via sandboxed iframes or redirects".to_string(),
                recommendation: "Do not allow 'null' origin. Validate Origin header against whitelist".to_string(),
            });
        }
        
        // Check for overly permissive methods
        if let Some(acam) = &result.acam_header {
            let methods: Vec<String> = acam.split(',').map(|s| s.trim().to_uppercase()).collect();
            let unsafe_methods = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
            for method in &unsafe_methods {
                if methods.iter().any(|m| m == method) {
                    result.issues.push(CorsIssue {
                        issue_type: format!("unsafe_method_{}", method.to_lowercase()),
                        severity: Severity::Medium,
                        title: format!("Unsafe HTTP Method Allowed: {}", method),
                        description: format!("Access-Control-Allow-Methods includes {}", method),
                        recommendation: format!("Only allow necessary methods. Consider removing {} unless required", method),
                    });
                }
            }
        }
        
        // Check for overly permissive headers
        if let Some(acah) = &result.acah_header {
            if acah == "*" {
                result.issues.push(CorsIssue {
                    issue_type: "wildcard_allow_headers".to_string(),
                    severity: Severity::Medium,
                    title: "Wildcard Access-Control-Allow-Headers".to_string(),
                    description: "Access-Control-Allow-Headers is set to '*', allowing any header in cross-origin requests".to_string(),
                    recommendation: "Specify only the headers that are actually needed".to_string(),
                });
            }
        }
        
        // Check for missing Vary header
        // This would require checking the response headers for Vary: Origin
        // For now, we note it as a potential issue
    }
    
    /// Test preflight (OPTIONS) request
    async fn test_preflight(&self, url: &str, origin: &str) -> PreflightTestResult {
        let mut result = PreflightTestResult {
            origin: origin.to_string(),
            success: false,
            acao_header: None,
            acam_header: None,
            acah_header: None,
            acma_header: None,
            issues: Vec::new(),
        };
        
        let response = match self.http_client
            .request(reqwest::Method::OPTIONS, url)
            .header("Origin", origin)
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type,Authorization")
            .send()
            .await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Preflight failed for {} with origin {}: {}", url, origin, e);
                return result;
            }
        };
        
        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        result.success = status == 200 || status == 204;
        result.acao_header = headers.get("access-control-allow-origin").cloned();
        result.acam_header = headers.get("access-control-allow-methods").cloned();
        result.acah_header = headers.get("access-control-allow-headers").cloned();
        result.acma_header = headers.get("access-control-max-age").cloned();
        
        // Analyze preflight response
        if result.success {
            if let Some(acao) = &result.acao_header {
                if acao == "*" {
                    result.issues.push(CorsIssue {
                        issue_type: "preflight_wildcard".to_string(),
                        severity: Severity::Medium,
                        title: "Preflight Allows Wildcard Origin".to_string(),
                        description: "Preflight response allows wildcard origin".to_string(),
                        recommendation: "Restrict preflight Access-Control-Allow-Origin to specific origins".to_string(),
                    });
                } else if acao == origin {
                    result.issues.push(CorsIssue {
                        issue_type: "preflight_origin_reflection".to_string(),
                        severity: Severity::High,
                        title: "Preflight Reflects Origin".to_string(),
                        description: "Preflight response reflects the Origin header".to_string(),
                        recommendation: "Validate Origin header against whitelist in preflight response".to_string(),
                    });
                }
            }
            
            if let Some(acam) = &result.acam_header {
                let methods: Vec<String> = acam.split(',').map(|s| s.trim().to_uppercase()).collect();
                if methods.contains(&"PUT".to_string()) || methods.contains(&"DELETE".to_string()) || methods.contains(&"PATCH".to_string()) {
                    result.issues.push(CorsIssue {
                        issue_type: "preflight_unsafe_methods".to_string(),
                        severity: Severity::Medium,
                        title: "Preflight Allows Unsafe Methods".to_string(),
                        description: format!("Preflight Access-Control-Allow-Methods includes unsafe methods: {}", acam),
                        recommendation: "Only allow necessary methods in preflight response".to_string(),
                    });
                }
            }
        }
        
        result
    }
    
    /// Test with credentials
    async fn test_with_credentials(&self, url: &str, origin: &str) -> CredentialsTestResult {
        let mut result = CredentialsTestResult {
            origin: origin.to_string(),
            acac_header: None,
            acao_header: None,
            credentials_supported: false,
            issues: Vec::new(),
        };
        
        let response = match self.http_client
            .get(url)
            .header("Origin", origin)
            .send()
            .await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Credentials test failed for {} with origin {}: {}", url, origin, e);
                return result;
            }
        };
        
        let headers: HashMap<String, String> = response.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        result.acac_header = headers.get("access-control-allow-credentials").cloned();
        result.acao_header = headers.get("access-control-allow-origin").cloned();
        
        if result.acac_header.as_deref() == Some("true") {
            result.credentials_supported = true;
            
            if result.acao_header.as_deref() == Some("*") {
                result.issues.push(CorsIssue {
                    issue_type: "credentials_with_wildcard".to_string(),
                    severity: Severity::Critical,
                    title: "Credentials Allowed with Wildcard Origin".to_string(),
                    description: "Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: * (invalid combination)".to_string(),
                    recommendation: "Specify exact origin when using credentials, never use wildcard".to_string(),
                });
            } else if result.acao_header.as_deref() == Some(origin) {
                result.issues.push(CorsIssue {
                    issue_type: "credentials_with_reflection".to_string(),
                    severity: Severity::High,
                    title: "Credentials Allowed with Reflected Origin".to_string(),
                    description: "Server allows credentials and reflects the Origin header".to_string(),
                    recommendation: "Validate Origin against whitelist before allowing credentials".to_string(),
                });
            }
        }
        
        result
    }
    
    /// Test specific HTTP method
    async fn test_method(&self, url: &str, method: &str, origin: &str) -> MethodTestResult {
        let mut result = MethodTestResult {
            method: method.to_string(),
            origin: origin.to_string(),
            allowed: false,
            acam_header: None,
            issues: Vec::new(),
        };
        
        let response = match self.http_client
            .request(method.parse().unwrap(), url)
            .header("Origin", origin)
            .send()
            .await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Method test failed for {} {} with origin {}: {}", method, url, origin, e);
                return result;
            }
        };
        
        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        
        result.allowed = status < 400 || status == 405; // 405 means method not allowed but CORS worked
        result.acam_header = headers.get("access-control-allow-methods").cloned();
        
        if result.allowed && (method == "PUT" || method == "DELETE" || method == "PATCH" || method == "TRACE" || method == "CONNECT") {
            result.issues.push(CorsIssue {
                issue_type: format!("method_{}_allowed", method.to_lowercase()),
                severity: Severity::Medium,
                title: format!("Unsafe Method {} Allowed via CORS", method),
                description: format!("The {} method is allowed for cross-origin requests from {}", method, origin),
                recommendation: format!("Restrict {} method to same-origin only unless absolutely necessary", method),
            });
        }
        
        result
    }
}

/// Result of CORS analysis
#[derive(Debug, Default, Serialize, Deserialize)]
struct CorsAnalysisResult {
    origin_tests: Vec<OriginTestResult>,
    preflight_test: Option<PreflightTestResult>,
    credentials_test: Option<CredentialsTestResult>,
    method_tests: Vec<MethodTestResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OriginTestResult {
    origin: String,
    allowed: bool,
    acao_header: Option<String>,
    acac_header: Option<String>,
    acam_header: Option<String>,
    acah_header: Option<String>,
    acma_header: Option<String>,
    issues: Vec<CorsIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PreflightTestResult {
    origin: String,
    success: bool,
    acao_header: Option<String>,
    acam_header: Option<String>,
    acah_header: Option<String>,
    acma_header: Option<String>,
    issues: Vec<CorsIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CredentialsTestResult {
    origin: String,
    acac_header: Option<String>,
    acao_header: Option<String>,
    credentials_supported: bool,
    issues: Vec<CorsIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MethodTestResult {
    method: String,
    origin: String,
    allowed: bool,
    acam_header: Option<String>,
    issues: Vec<CorsIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CorsIssue {
    issue_type: String,
    severity: Severity,
    title: String,
    description: String,
    recommendation: String,
}

#[async_trait]
impl Plugin for CorsAnalysisPlugin {
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
        
        info!("Starting CORS analysis for {}", target_url);
        
        let analysis = self.analyze_cors(target_url).await;
        let mut findings = Vec::new();
        
        // Collect all issues
        let mut all_issues = Vec::new();
        for test in &analysis.origin_tests {
            all_issues.extend(test.issues.clone());
        }
        if let Some(preflight) = &analysis.preflight_test {
            all_issues.extend(preflight.issues.clone());
        }
        if let Some(cred) = &analysis.credentials_test {
            all_issues.extend(cred.issues.clone());
        }
        for test in &analysis.method_tests {
            all_issues.extend(test.issues.clone());
        }
        
        let high_severity = all_issues.iter().filter(|i| matches!(i.severity, Severity::High | Severity::Critical)).count();
        let critical_severity = all_issues.iter().filter(|i| matches!(i.severity, Severity::Critical)).count();
        
        // Summary finding
        let mut summary_finding = Finding::new(
            "CORS Configuration Analysis Summary".to_string(),
            format!(
                "Analyzed CORS configuration for {}. Tested {} origins, preflight, credentials, and {} methods. Found {} total issues ({} high/critical, {} critical).",
                target_url,
                analysis.origin_tests.len(),
                analysis.method_tests.len(),
                all_issues.len(),
                high_severity,
                critical_severity
            ),
            if critical_severity > 0 { Severity::Critical } else if high_severity > 0 { Severity::High } else if all_issues.len() > 0 { Severity::Medium } else { Severity::Info },
            Confidence::High,
            Category::SecurityMisconfiguration,
            target_url.to_string(),
            "web_application".to_string(),
            "cors_analysis".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
        );
        
        summary_finding = summary_finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: "CORS analysis summary".to_string(),
            data: Some(serde_json::json!({
                "origin_tests": analysis.origin_tests,
                "preflight_test": analysis.preflight_test,
                "credentials_test": analysis.credentials_test,
                "method_tests": analysis.method_tests,
                "total_issues": all_issues.len(),
                "high_severity_issues": high_severity,
                "critical_severity_issues": critical_severity,
            })),
            location: Some(target_url.to_string()),
            metadata: HashMap::new(),
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
        
        summary_finding = summary_finding.with_tag("cors_analysis".to_string());
        findings.push(summary_finding);
        
        // Individual issue findings
        for issue in &all_issues {
            let mut finding = Finding::new(
                format!("CORS Issue: {}", issue.title),
                format!("{}\n\nRecommendation: {}", issue.description, issue.recommendation),
                issue.severity,
                Confidence::High,
                Category::SecurityMisconfiguration,
                target_url.to_string(),
                "web_application".to_string(),
                "cors_analysis".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "CORS issue details".to_string(),
                data: Some(serde_json::json!({
                    "issue": issue,
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
            
            finding = finding.with_tag(format!("cors_{}", issue.issue_type));
            findings.push(finding);
        }
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "total_issues": all_issues.len(),
            "high_severity_issues": high_severity,
            "critical_severity_issues": critical_severity,
        })))
    }
}

impl SecurityPlugin for CorsAnalysisPlugin {
    fn security_category(&self) -> &'static str {
        "cors"
    }
    
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    
    fn description(&self) -> &'static str {
        "Evaluates CORS configuration including wildcard origins, credential handling, origin reflection, unsafe methods, and misconfigured headers"
    }
    
    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-942".to_string(),
                url: "https://cwe.mitre.org/data/definitions/942.html".to_string(),
                description: "Permissive Cross-domain Policy with Untrusted Domains".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-346".to_string(),
                url: "https://cwe.mitre.org/data/definitions/346.html".to_string(),
                description: "Origin Validation Error".to_string(),
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
