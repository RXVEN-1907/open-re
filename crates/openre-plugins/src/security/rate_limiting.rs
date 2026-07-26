//! Rate Limiting Plugin
//! 
//! Safely determines whether basic request throttling exists,
//! authentication endpoints enforce limits, and APIs expose unrestricted request rates.

use crate::security::{
    SecurityPlugin, SecurityPluginConfig, SecurityReference, standard_references,
    HttpResponse,
};
use crate::sdk::{CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability, PluginId, Plugin};
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use async_trait::async_trait;
use tracing::{debug, info, warn};
use tokio::time::sleep;

/// Rate Limiting Plugin
pub struct RateLimitingPlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl RateLimitingPlugin {
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
    
    /// Analyze rate limiting on target
    async fn analyze_rate_limiting(&self, base_url: &str) -> RateLimitAnalysisResult {
        let mut result = RateLimitAnalysisResult::default();
        
        // Discover endpoints to test
        let endpoints = self.discover_test_endpoints(base_url).await;
        
        for endpoint in endpoints {
            let test_result = self.test_endpoint_rate_limit(base_url, &endpoint).await;
            result.endpoint_tests.push(test_result);
        }
        
        // Test authentication endpoints specifically
        let auth_endpoints = self.discover_auth_endpoints(base_url).await;
        for endpoint in auth_endpoints {
            let test_result = self.test_endpoint_rate_limit(base_url, &endpoint).await;
            result.auth_endpoint_tests.push(test_result);
        }
        
        // Test API endpoints
        let api_endpoints = self.discover_api_endpoints(base_url).await;
        for endpoint in api_endpoints {
            let test_result = self.test_endpoint_rate_limit(base_url, &endpoint).await;
            result.api_endpoint_tests.push(test_result);
        }
        
        result
    }
    
    /// Discover endpoints to test for rate limiting
    async fn discover_test_endpoints(&self, base_url: &str) -> Vec<TestEndpoint> {
        let mut endpoints = Vec::new();
        
        // Common endpoints to test
        let common_paths = [
            "/", "/home", "/index", "/api", "/api/v1", "/api/v2",
            "/health", "/status", "/ping", "/ready",
        ];
        
        for path in &common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            endpoints.push(TestEndpoint {
                url,
                path: path.to_string(),
                endpoint_type: "general".to_string(),
                method: "GET".to_string(),
            });
        }
        
        endpoints
    }
    
    /// Discover authentication endpoints
    async fn discover_auth_endpoints(&self, base_url: &str) -> Vec<TestEndpoint> {
        let mut endpoints = Vec::new();
        
        let auth_paths = [
            ("/login", "POST"),
            ("/signin", "POST"),
            ("/auth/login", "POST"),
            ("/register", "POST"),
            ("/signup", "POST"),
            ("/auth/register", "POST"),
            ("/password/reset", "POST"),
            ("/forgot-password", "POST"),
            ("/mfa", "POST"),
            ("/2fa", "POST"),
        ];
        
        for (path, method) in &auth_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            endpoints.push(TestEndpoint {
                url,
                path: path.to_string(),
                endpoint_type: "auth".to_string(),
                method: method.to_string(),
            });
        }
        
        endpoints
    }
    
    /// Discover API endpoints
    async fn discover_api_endpoints(&self, base_url: &str) -> Vec<TestEndpoint> {
        let mut endpoints = Vec::new();
        
        let api_paths = [
            ("/api/users", "GET"),
            ("/api/user", "GET"),
            ("/api/profile", "GET"),
            ("/api/data", "GET"),
            ("/api/search", "GET"),
            ("/api/items", "GET"),
            ("/graphql", "POST"),
            ("/api/graphql", "POST"),
        ];
        
        for (path, method) in &api_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            endpoints.push(TestEndpoint {
                url,
                path: path.to_string(),
                endpoint_type: "api".to_string(),
                method: method.to_string(),
            });
        }
        
        endpoints
    }
    
    /// Test rate limiting on a specific endpoint
    async fn test_endpoint_rate_limit(&self, base_url: &str, endpoint: &TestEndpoint) -> EndpointRateLimitTest {
        let mut test = EndpointRateLimitTest {
            endpoint: endpoint.clone(),
            requests_made: 0,
            requests_succeeded: 0,
            requests_rate_limited: 0,
            requests_errored: 0,
            rate_limit_detected: false,
            rate_limit_headers: HashMap::new(),
            estimated_limit: None,
            reset_time: None,
            issues: Vec::new(),
            response_times: Vec::new(),
        };
        
        // Conservative testing: start with a small burst
        let burst_size = 10;
        let mut consecutive_429 = 0;
        let mut first_429_time = None;
        
        for i in 0..burst_size {
            let start = Instant::now();
            let response = self.make_request(&endpoint.url, &endpoint.method).await;
            let elapsed = start.elapsed();
            test.response_times.push(elapsed);
            test.requests_made += 1;
            
            if let Some(resp) = response {
                if resp.status == 429 {
                    test.requests_rate_limited += 1;
                    test.rate_limit_detected = true;
                    consecutive_429 += 1;
                    
                    if first_429_time.is_none() {
                        first_429_time = Some(i);
                        // Capture rate limit headers
                        test.rate_limit_headers = self.extract_rate_limit_headers(&resp.headers);
                    }
                } else if resp.status < 400 {
                    test.requests_succeeded += 1;
                    consecutive_429 = 0;
                } else {
                    test.requests_errored += 1;
                }
            } else {
                test.requests_errored += 1;
            }
            
            // Small delay between requests to be conservative
            if i < burst_size - 1 {
                sleep(Duration::from_millis(100)).await;
            }
            
            // Stop early if we hit rate limit consistently
            if consecutive_429 >= 3 {
                break;
            }
        }
        
        // If rate limit detected, try to estimate the limit
        if test.rate_limit_detected {
            test.estimated_limit = self.estimate_rate_limit(&test);
            test.reset_time = self.estimate_reset_time(&test.rate_limit_headers);
        }
        
        // If no rate limit detected after burst, do a sustained test
        if !test.rate_limit_detected && test.requests_succeeded > 0 {
            test = self.sustained_rate_test(base_url, endpoint, test).await;
        }
        
        // Analyze results
        self.analyze_rate_limit_results(&mut test);
        
        test
    }
    
    /// Make an HTTP request
    async fn make_request(&self, url: &str, method: &str) -> Option<HttpResponse> {
        let request = match method.to_uppercase().as_str() {
            "GET" => self.http_client.get(url),
            "POST" => self.http_client.post(url),
            "PUT" => self.http_client.put(url),
            "DELETE" => self.http_client.delete(url),
            "PATCH" => self.http_client.patch(url),
            "HEAD" => self.http_client.head(url),
            "OPTIONS" => self.http_client.request(reqwest::Method::OPTIONS, url),
            _ => self.http_client.get(url),
        };
        
        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Request failed for {}: {}", url, e);
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
    
    /// Extract rate limit headers from response
    fn extract_rate_limit_headers(&self, headers: &HashMap<String, String>) -> HashMap<String, String> {
        let mut rate_headers = HashMap::new();
        
        let rate_limit_headers = [
            "x-ratelimit-limit",
            "x-ratelimit-remaining",
            "x-ratelimit-reset",
            "x-ratelimit-reset-after",
            "retry-after",
            "rate-limit",
            "rate-limit-limit",
            "rate-limit-remaining",
            "rate-limit-reset",
        ];
        
        for header in &rate_limit_headers {
            if let Some(value) = headers.get(&header.to_lowercase()) {
                rate_headers.insert(header.to_string(), value.clone());
            }
        }
        
        rate_headers
    }
    
    /// Estimate rate limit from test results
    fn estimate_rate_limit(&self, test: &EndpointRateLimitTest) -> Option<u32> {
        if let Some(first_429) = test.response_times.len().checked_sub(test.requests_rate_limited as usize) {
            // Rough estimate: the request that got 429 was the (limit + 1)th request
            Some(first_429 as u32)
        } else {
            None
        }
    }
    
    /// Estimate reset time from headers
    fn estimate_reset_time(&self, headers: &HashMap<String, String>) -> Option<String> {
        if let Some(reset) = headers.get("x-ratelimit-reset") {
            return Some(reset.clone());
        }
        if let Some(reset_after) = headers.get("x-ratelimit-reset-after") {
            return Some(format!("{} seconds", reset_after));
        }
        if let Some(retry_after) = headers.get("retry-after") {
            return Some(format!("{} seconds", retry_after));
        }
        None
    }
    
    /// Sustained rate test for endpoints without obvious rate limiting
    async fn sustained_rate_test(&self, base_url: &str, endpoint: &TestEndpoint, mut test: EndpointRateLimitTest) -> EndpointRateLimitTest {
        // Test with sustained requests over a longer period
        let sustained_requests = 20;
        let delay_ms = 500; // 2 requests per second
        
        for i in 0..sustained_requests {
            let start = Instant::now();
            let response = self.make_request(&endpoint.url, &endpoint.method).await;
            let elapsed = start.elapsed();
            test.response_times.push(elapsed);
            test.requests_made += 1;
            
            if let Some(resp) = response {
                if resp.status == 429 {
                    test.requests_rate_limited += 1;
                    test.rate_limit_detected = true;
                    
                    if test.rate_limit_headers.is_empty() {
                        test.rate_limit_headers = self.extract_rate_limit_headers(&resp.headers);
                    }
                } else if resp.status < 400 {
                    test.requests_succeeded += 1;
                } else {
                    test.requests_errored += 1;
                }
            } else {
                test.requests_errored += 1;
            }
            
            if i < sustained_requests - 1 {
                sleep(Duration::from_millis(delay_ms)).await;
            }
            
            // Stop if rate limited
            if test.requests_rate_limited > 0 {
                break;
            }
        }
        
        if test.rate_limit_detected {
            test.estimated_limit = self.estimate_rate_limit(&test);
            test.reset_time = self.estimate_reset_time(&test.rate_limit_headers);
        }
        
        test
    }
    
    /// Analyze rate limit test results
    fn analyze_rate_limit_results(&self, test: &mut EndpointRateLimitTest) {
        // No rate limiting detected at all
        if !test.rate_limit_detected && test.requests_made >= 10 {
            let severity = match test.endpoint.endpoint_type.as_str() {
                "auth" => Severity::High,
                "api" => Severity::Medium,
                _ => Severity::Low,
            };
            
            test.issues.push(RateLimitIssue {
                issue_type: "no_rate_limiting".to_string(),
                severity,
                title: format!("No Rate Limiting Detected on {} Endpoint", test.endpoint.endpoint_type),
                description: format!(
                    "Made {} requests to {} ({}) without encountering rate limiting. \
                    All {} requests succeeded.",
                    test.requests_made, test.endpoint.path, test.endpoint.method, test.requests_succeeded
                ),
                recommendation: "Implement rate limiting to prevent abuse and brute-force attacks".to_string(),
            });
        }
        
        // Rate limiting detected but very high limit
        if test.rate_limit_detected {
            if let Some(limit) = test.estimated_limit {
                if limit > 1000 {
                    test.issues.push(RateLimitIssue {
                        issue_type: "high_rate_limit".to_string(),
                        severity: Severity::Low,
                        title: "High Rate Limit Threshold".to_string(),
                        description: format!("Estimated rate limit is {} requests, which may be too high", limit),
                        recommendation: "Consider lowering rate limits, especially for authentication endpoints".to_string(),
                    });
                } else if limit < 10 && test.endpoint.endpoint_type == "auth" {
                    test.issues.push(RateLimitIssue {
                        issue_type: "low_auth_rate_limit".to_string(),
                        severity: Severity::Info,
                        title: "Low Rate Limit on Authentication Endpoint".to_string(),
                        description: format!("Authentication endpoint has low rate limit ({} requests)", limit),
                        recommendation: "This is good for security. Ensure legitimate users aren't blocked".to_string(),
                    });
                }
            }
            
            // Check for standard rate limit headers
            if test.rate_limit_headers.is_empty() {
                test.issues.push(RateLimitIssue {
                    issue_type: "missing_rate_limit_headers".to_string(),
                    severity: Severity::Info,
                    title: "Missing Standard Rate Limit Headers".to_string(),
                    description: "Rate limiting is enforced but standard headers (X-RateLimit-*) are not present".to_string(),
                    recommendation: "Add standard rate limit headers for better client integration".to_string(),
                });
            }
            
            // Check for Retry-After header on 429
            if !test.rate_limit_headers.contains_key("retry-after") && 
               !test.rate_limit_headers.contains_key("x-ratelimit-reset") &&
               !test.rate_limit_headers.contains_key("x-ratelimit-reset-after") {
                test.issues.push(RateLimitIssue {
                    issue_type: "missing_retry_after".to_string(),
                    severity: Severity::Low,
                    title: "Missing Retry-After Header on 429 Response".to_string(),
                    description: "Rate limited responses should include Retry-After or X-RateLimit-Reset header".to_string(),
                    recommendation: "Add Retry-After header to 429 responses indicating when client can retry".to_string(),
                });
            }
        }
        
        // Check for inconsistent rate limiting (some requests succeed, some fail randomly)
        if test.requests_rate_limited > 0 && test.requests_succeeded > test.requests_rate_limited * 2 {
            test.issues.push(RateLimitIssue {
                issue_type: "inconsistent_rate_limiting".to_string(),
                severity: Severity::Medium,
                title: "Inconsistent Rate Limiting Behavior".to_string(),
                description: "Rate limiting appears to be applied inconsistently".to_string(),
                recommendation: "Ensure rate limiting is consistently applied across all requests".to_string(),
            });
        }
    }
}

/// Result of rate limit analysis
#[derive(Debug, Default, Serialize, Deserialize)]
struct RateLimitAnalysisResult {
    endpoint_tests: Vec<EndpointRateLimitTest>,
    auth_endpoint_tests: Vec<EndpointRateLimitTest>,
    api_endpoint_tests: Vec<EndpointRateLimitTest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TestEndpoint {
    url: String,
    path: String,
    endpoint_type: String,
    method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EndpointRateLimitTest {
    endpoint: TestEndpoint,
    requests_made: u32,
    requests_succeeded: u32,
    requests_rate_limited: u32,
    requests_errored: u32,
    rate_limit_detected: bool,
    rate_limit_headers: HashMap<String, String>,
    estimated_limit: Option<u32>,
    reset_time: Option<String>,
    issues: Vec<RateLimitIssue>,
    response_times: Vec<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateLimitIssue {
    issue_type: String,
    severity: Severity,
    title: String,
    description: String,
    recommendation: String,
}

#[async_trait]
impl Plugin for RateLimitingPlugin {
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
        
        info!("Starting rate limiting analysis for {}", target_url);
        
        let analysis = self.analyze_rate_limiting(target_url).await;
        let mut findings = Vec::new();
        
        // Collect all issues
        let mut all_issues = Vec::new();
        for test in &analysis.endpoint_tests {
            all_issues.extend(test.issues.clone());
        }
        for test in &analysis.auth_endpoint_tests {
            all_issues.extend(test.issues.clone());
        }
        for test in &analysis.api_endpoint_tests {
            all_issues.extend(test.issues.clone());
        }
        
        let high_severity = all_issues.iter().filter(|i| matches!(i.severity, Severity::High | Severity::Critical)).count();
        let critical_severity = all_issues.iter().filter(|i| matches!(i.severity, Severity::Critical)).count();
        let no_rate_limit_count = all_issues.iter().filter(|i| i.issue_type == "no_rate_limiting").count();
        
        // Summary finding
        let mut summary_finding = Finding::new(
            "Rate Limiting Analysis Summary".to_string(),
            format!(
                "Analyzed rate limiting for {}. Tested {} general, {} auth, and {} API endpoints. \
                Found {} total issues ({} high/critical, {} critical). {} endpoints have no rate limiting.",
                target_url,
                analysis.endpoint_tests.len(),
                analysis.auth_endpoint_tests.len(),
                analysis.api_endpoint_tests.len(),
                all_issues.len(),
                high_severity,
                critical_severity,
                no_rate_limit_count
            ),
            if critical_severity > 0 { Severity::Critical } else if high_severity > 0 { Severity::High } else if no_rate_limit_count > 0 { Severity::Medium } else { Severity::Info },
            Confidence::Medium, // Rate limiting tests are inherently probabilistic
            Category::SecurityMisconfiguration,
            target_url.to_string(),
            "web_application".to_string(),
            "rate_limiting".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
        );
        
        summary_finding = summary_finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: "Rate limiting analysis summary".to_string(),
            data: Some(serde_json::json!({
                "endpoint_tests": analysis.endpoint_tests,
                "auth_endpoint_tests": analysis.auth_endpoint_tests,
                "api_endpoint_tests": analysis.api_endpoint_tests,
                "total_issues": all_issues.len(),
                "high_severity_issues": high_severity,
                "critical_severity_issues": critical_severity,
                "endpoints_without_rate_limiting": no_rate_limit_count,
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
        
        summary_finding = summary_finding.with_tag("rate_limiting_analysis".to_string());
        findings.push(summary_finding);
        
        // Individual issue findings
        for issue in &all_issues {
            let mut finding = Finding::new(
                format!("Rate Limiting Issue: {}", issue.title),
                format!("{}\n\nRecommendation: {}", issue.description, issue.recommendation),
                issue.severity,
                Confidence::Medium,
                Category::SecurityMisconfiguration,
                target_url.to_string(),
                "web_application".to_string(),
                "rate_limiting".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Rate limiting issue details".to_string(),
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
            
            finding = finding.with_tag(format!("rate_limit_{}", issue.issue_type));
            findings.push(finding);
        }
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "total_issues": all_issues.len(),
            "high_severity_issues": high_severity,
            "critical_severity_issues": critical_severity,
            "endpoints_without_rate_limiting": no_rate_limit_count,
        })))
    }
}

impl SecurityPlugin for RateLimitingPlugin {
    fn security_category(&self) -> &'static str {
        "rate_limiting"
    }
    
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    
    fn description(&self) -> &'static str {
        "Safely determines whether basic request throttling exists, authentication endpoints enforce limits, and APIs expose unrestricted request rates"
    }
    
    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-770".to_string(),
                url: "https://cwe.mitre.org/data/definitions/770.html".to_string(),
                description: "Allocation of Resources Without Limits or Throttling".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-307".to_string(),
                url: "https://cwe.mitre.org/data/definitions/307.html".to_string(),
                description: "Improper Restriction of Excessive Authentication Attempts".to_string(),
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
