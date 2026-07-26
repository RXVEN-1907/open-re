//! Access Control Security Plugin
//!
//! Detects indicators of Insecure Direct Object References (IDOR),
//! missing authorization checks, privilege boundary inconsistencies,
//! and excessive information disclosure.

use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use crate::sdk::{CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability, PluginId, Plugin};
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};
use reqwest::Client;

/// Access Control Security Plugin
pub struct AccessControlPlugin {
    config: AccessControlConfig,
    client: Arc<reqwest::Client>,
}

impl AccessControlPlugin {
    /// Create a new Access Control security plugin
    pub fn new(config: AccessControlConfig) -> std::result::Result<Self, String> {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(config.max_redirects as usize))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?
        );
        
        Ok(Self { config, client })
    }
    
    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    /// Get plugin description
    fn description(&self) -> &'static str {
        "Detects indicators of Insecure Direct Object References (IDOR), missing authorization checks, privilege boundary inconsistencies, and excessive information disclosure"
    }
    
    /// Get plugin references
    fn references(&self) -> Vec<SecurityReference> {
        vec![
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API1:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x11-broken-object-level-authorization/".to_string(),
                description: "OWASP API Security Top 10 2023 - Broken Object Level Authorization".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API3:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x31-broken-object-property-level-authorization/".to_string(),
                description: "OWASP API Security Top 10 2023 - Broken Object Property Level Authorization".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API5:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x51-broken-function-level-authorization/".to_string(),
                description: "OWASP API Security Top 10 2023 - Broken Function Level Authorization".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-639".to_string(),
                url: "https://cwe.mitre.org/data/definitions/639.html".to_string(),
                description: "Authorization Bypass Through User-Controlled Key".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-284".to_string(),
                url: "https://cwe.mitre.org/data/definitions/284.html".to_string(),
                description: "Improper Access Control".to_string(),
            },
        ]
    }
    
    /// Validate configuration
    fn validate_config(&self, config: &AccessControlConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }
    
    /// Test for IDOR vulnerabilities
    async fn test_idor(&self, base_url: &str, auth_tokens: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Common IDOR patterns to test
        let idor_patterns = vec![
            ("/api/users/{id}", "GET"),
            ("/api/users/{id}/profile", "GET"),
            ("/api/users/{id}/orders", "GET"),
            ("/api/users/{id}/settings", "GET"),
            ("/api/orders/{id}", "GET"),
            ("/api/orders/{id}/details", "GET"),
            ("/api/documents/{id}", "GET"),
            ("/api/documents/{id}/download", "GET"),
            ("/api/accounts/{id}", "GET"),
            ("/api/profiles/{id}", "GET"),
            ("/api/v1/users/{id}", "GET"),
            ("/api/v1/orders/{id}", "GET"),
        ];
        
        // Test with different user contexts
        for (pattern, method) in idor_patterns {
            // Test with valid IDs
            for test_id in &["1", "2", "100", "999", "1000"] {
                let url = format!("{}{}", base_url.trim_end_matches('/'), pattern.replace("{id}", test_id));
                
                // Test with first auth token (user 1)
                if let Some(token) = auth_tokens.first() {
                    if let Ok(resp) = self.client
                        .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
                        .bearer_auth(token)
                        .send()
                        .await 
                    {
                        if resp.status().is_success() {
                            // Now test with second auth token (user 2) accessing same resource
                            if auth_tokens.len() > 1 {
                                if let Ok(resp2) = self.client
                                    .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
                                    .bearer_auth(&auth_tokens[1])
                                    .send()
                                    .await 
                                {
                                    if resp2.status().is_success() {
                                        // Both users can access the same resource - potential IDOR
                                        findings.push(self.create_finding(
                                            "Potential IDOR - Cross-User Resource Access",
                                            &format!("User with token 2 can access resource {} belonging to user 1", url),
                                            Severity::High,
                                            Confidence::Medium,
                                            Category::BrokenAuthentication,
                                            &url,
                                            vec!["idor".to_string(), "cross-user-access".to_string()],
                                            vec![
                                                "Verify resource ownership checks are implemented".to_string(),
                                                "Implement proper authorization for object-level access".to_string(),
                                            ],
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        findings
    }
    
    /// Test for missing authorization checks
    async fn test_missing_authorization(&self, base_url: &str, auth_tokens: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Endpoints that should require authorization
        let protected_endpoints = vec![
            ("/api/admin/users", "GET"),
            ("/api/admin/settings", "GET"),
            ("/api/admin/dashboard", "GET"),
            ("/api/users", "POST"),
            ("/api/users", "PUT"),
            ("/api/users", "DELETE"),
            ("/api/orders", "POST"),
            ("/api/orders", "PUT"),
            ("/api/orders", "DELETE"),
            ("/api/documents", "POST"),
            ("/api/documents", "PUT"),
            ("/api/documents", "DELETE"),
            ("/api/settings", "PUT"),
            ("/api/settings", "DELETE"),
            ("/api/profile", "PUT"),
            ("/api/profile", "DELETE"),
        ];
        
        for (path, method) in protected_endpoints {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            // Test without authentication
            if let Ok(resp) = self.client
                .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
                .send()
                .await 
            {
                if resp.status().is_success() || resp.status().as_u16() == 400 {
                    // Endpoint accessible without auth - potential missing authorization
                    findings.push(self.create_finding(
                        "Missing Authorization Check",
                        &format!("Endpoint {} {} accessible without authentication", method, path),
                        Severity::High,
                        Confidence::High,
                        Category::BrokenAuthentication,
                        &url,
                        vec!["missing-auth".to_string(), "authorization-bypass".to_string()],
                        vec![
                            "Implement authentication middleware for protected endpoints".to_string(),
                            "Verify all state-changing operations require authentication".to_string(),
                        ],
                    ));
                } else if resp.status().as_u16() == 403 {
                    // 403 is acceptable - endpoint exists but properly protected
                }
            }
            
            // Test with low-privilege user accessing admin endpoints
            if path.starts_with("/api/admin/") && auth_tokens.len() > 0 {
                if let Ok(resp) = self.client
                    .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
                    .bearer_auth(&auth_tokens[0])
                    .send()
                    .await 
                {
                    if resp.status().is_success() {
                        findings.push(self.create_finding(
                            "Privilege Escalation - Regular User Accessing Admin Endpoint",
                            &format!("Regular user can access admin endpoint {} {}", method, path),
                            Severity::Critical,
                            Confidence::High,
                            Category::BrokenAuthentication,
                            &url,
                            vec!["privilege-escalation".to_string(), "admin-access".to_string()],
                            vec![
                                "Implement role-based access control (RBAC)".to_string(),
                                "Verify admin endpoints require admin role".to_string(),
                            ],
                        ));
                    }
                }
            }
        }
        
        findings
    }
    
    /// Test for privilege boundary inconsistencies
    async fn test_privilege_boundaries(&self, base_url: &str, auth_tokens: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        if auth_tokens.len() < 2 {
            return findings; // Need at least 2 users to test boundaries
        }
        
        // Test user 1 accessing user 2's resources with different HTTP methods
        let user_resources = vec![
            ("/api/users/2", "GET"),
            ("/api/users/2", "PUT"),
            ("/api/users/2", "PATCH"),
            ("/api/users/2", "DELETE"),
            ("/api/users/2/profile", "GET"),
            ("/api/users/2/profile", "PUT"),
            ("/api/users/2/settings", "GET"),
            ("/api/users/2/settings", "PUT"),
        ];
        
        for (path, method) in user_resources {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            // User 1 trying to access User 2's resources
            if let Ok(resp) = self.client
                .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET), &url)
                .bearer_auth(&auth_tokens[0])
                .send()
                .await 
            {
                if resp.status().is_success() && method != "GET" {
                    // User 1 can modify User 2's data - privilege boundary issue
                    findings.push(self.create_finding(
                        "Privilege Boundary Violation - Cross-User Modification",
                        &format!("User 1 can {} user 2's resource at {}", method, url),
                        Severity::High,
                        Confidence::High,
                        Category::BrokenAuthentication,
                        &url,
                        vec!["privilege-boundary".to_string(), "cross-user-modification".to_string()],
                        vec![
                            "Implement ownership checks for all modification operations".to_string(),
                            "Verify users can only modify their own resources".to_string(),
                        ],
                    ));
                }
            }
        }
        
        findings
    }
    
    /// Test for excessive information disclosure
    async fn test_information_disclosure(&self, base_url: &str, auth_tokens: &[String]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Endpoints that might leak excessive information
        let info_endpoints = vec![
            "/api/users",
            "/api/users?limit=1000",
            "/api/users?include=all",
            "/api/users/1",
            "/api/users/1?include=profile,settings,orders",
            "/api/orders",
            "/api/orders?limit=1000",
            "/api/orders?include=user,items",
            "/api/debug",
            "/api/health",
            "/api/metrics",
            "/api/actuator",
            "/api/actuator/env",
            "/api/actuator/configprops",
            "/api/actuator/beans",
            "/api/actuator/mappings",
            "/api/swagger.json",
            "/api/openapi.json",
            "/api/docs",
        ];
        
        for path in info_endpoints {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            // Test without auth first
            if let Ok(resp) = self.client.get(&url).send().await {
                if resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    
                    // Check for sensitive data in response
                    let sensitive_patterns = [
                        ("password", "Password field in response"),
                        ("secret", "Secret field in response"),
                        ("token", "Token field in response"),
                        ("api_key", "API key in response"),
                        ("private_key", "Private key in response"),
                        ("ssn", "SSN in response"),
                        ("credit_card", "Credit card in response"),
                        ("access_token", "Access token in response"),
                        ("refresh_token", "Refresh token in response"),
                    ];
                    
                    for (pattern, desc) in &sensitive_patterns {
                        if body.to_lowercase().contains(pattern) {
                            findings.push(self.create_finding(
                                "Excessive Information Disclosure",
                                &format!("Endpoint {} exposes sensitive data: {}", url, desc),
                                Severity::High,
                                Confidence::Medium,
                                Category::InformationDisclosure,
                                &url,
                                vec!["info-disclosure".to_string(), "sensitive-data".to_string()],
                                vec![
                                    "Remove sensitive fields from API responses".to_string(),
                                    "Implement field-level authorization".to_string(),
                                ],
                            ));
                        }
                    }
                    
                    // Check for large data dumps
                    if body.len() > 100000 {
                        findings.push(self.create_finding(
                            "Large Data Exposure",
                            &format!("Endpoint {} returns large response ({} bytes) - potential data dump", url, body.len()),
                            Severity::Medium,
                            Confidence::Low,
                            Category::InformationDisclosure,
                            &url,
                            vec!["large-response".to_string(), "data-dump".to_string()],
                            vec![
                                "Implement pagination and limit response size".to_string(),
                                "Review if all returned data is necessary".to_string(),
                            ],
                        ));
                    }
                }
            }
        }
        
        findings
    }
    
    /// Create a finding
    fn create_finding(
        &self,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        url: &str,
        tags: Vec<String>,
        verification_steps: Vec<String>,
    ) -> Finding {
        let mut finding = Finding::new(
            title.to_string(),
            description.to_string(),
            severity,
            confidence,
            category,
            url.to_string(),
            "web_api".to_string(),
            "access_control".to_string(),
            self.version().to_string(),
            openre_core::ids::ScanId::new(),
        );
        
        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!("Access control test for {}", url),
            data: Some(serde_json::json!({
                "url": url,
            })),
            location: Some(url.to_string()),
            metadata: HashMap::new(),
        });
        
        for reference in self.references() {
            finding = finding.with_reference(Reference {
                reference_type: match reference.ref_type.as_str() {
                    "CWE" => ReferenceType::Cwe,
                    "OWASP" => ReferenceType::Owasp,
                    "CVE" => ReferenceType::Cve,
                    _ => ReferenceType::Custom(reference.ref_type),
                },
                title: reference.id.clone(),
                url: reference.url.clone(),
                description: Some(reference.description.clone()),
            });
        }
        
        for tag in tags {
            finding = finding.with_tag(tag);
        }
        finding = finding.with_tag("access-control".to_string());
        
        finding
    }
}

#[async_trait]
impl Plugin for AccessControlPlugin {
    type Config = AccessControlConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create Access Control plugin")
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAccess,
            Capability::ReadConfig,
        ]
    }
    
    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let target_url = request.input.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");
        
        // Get auth tokens from input (would be provided by scan configuration)
        let auth_tokens = request.input.get("auth_tokens")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
            .unwrap_or_default();
        
        info!("Starting access control analysis for {}", target_url);
        
        let mut all_findings = Vec::new();
        
        // Test IDOR
        let idor_findings = self.test_idor(target_url, &auth_tokens).await;
        all_findings.extend(idor_findings);
        
        // Test missing authorization
        let auth_findings = self.test_missing_authorization(target_url, &auth_tokens).await;
        all_findings.extend(auth_findings);
        
        // Test privilege boundaries
        let boundary_findings = self.test_privilege_boundaries(target_url, &auth_tokens).await;
        all_findings.extend(boundary_findings);
        
        // Test information disclosure
        let info_findings = self.test_information_disclosure(target_url, &auth_tokens).await;
        all_findings.extend(info_findings);
        
        info!("Found {} access control issues", all_findings.len());
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": all_findings,
            "vulnerabilities_found": all_findings.len(),
        })))
    }
}

/// Access Control Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessControlConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for AccessControlConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-access-control/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

// Plugin entry point
