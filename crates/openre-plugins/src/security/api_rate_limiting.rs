//! API Rate Limiting Security Plugin
//!
//! Evaluates API rate limiting implementation including request throttling,
//! burst handling, and authentication endpoint protection.

use crate::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use async_trait::async_trait;
use chrono::Utc;
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Reference, ReferenceType,
    Severity,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// API Rate Limiting Security Plugin
pub struct ApiRateLimitingPlugin {
    config: ApiRateLimitingConfig,
    client: Arc<reqwest::Client>,
}

impl ApiRateLimitingPlugin {
    /// Create a new API rate limiting plugin
    pub fn new(config: ApiRateLimitingConfig) -> std::result::Result<Self, String> {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?,
        );

        Ok(Self { config, client })
    }

    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }

    /// Get plugin description
    fn description(&self) -> &'static str {
        "Evaluates API rate limiting implementation including request throttling, burst handling, and authentication endpoint protection"
    }

    /// Get plugin references
    fn references(&self) -> Vec<SecurityReference> {
        vec![
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API4:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x41-unrestricted-resource-consumption/".to_string(),
                description: "OWASP API Security Top 10 2023 - Unrestricted Resource Consumption".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-770".to_string(),
                url: "https://cwe.mitre.org/data/definitions/770.html".to_string(),
                description: "Allocation of Resources Without Limits or Throttling".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-400".to_string(),
                url: "https://cwe.mitre.org/data/definitions/400.html".to_string(),
                description: "Uncontrolled Resource Consumption".to_string(),
            },
        ]
    }

    /// Validate configuration
    fn validate_config(&self, config: &ApiRateLimitingConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        if config.test_requests_per_endpoint == 0 {
            return Err("test_requests_per_endpoint must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Test rate limiting on an endpoint
    async fn test_endpoint_rate_limit(
        &self,
        url: &str,
        method: &str,
        is_auth_endpoint: bool,
    ) -> RateLimitTestResult {
        let mut results = Vec::new();
        let mut rate_limited = false;
        let mut rate_limit_headers = HashMap::new();
        let mut retry_after = None;

        // Test 1: Sustained request rate (conservative)
        let sustained_rate = self.config.sustained_requests_per_second.min(10); // Conservative max
        let sustained_duration = Duration::from_secs(self.config.sustained_test_duration_seconds);
        let start = Instant::now();
        let mut request_count = 0;

        while start.elapsed() < sustained_duration && request_count < self.config.max_test_requests
        {
            let req_start = Instant::now();
            let resp = self.send_request(url, method).await;
            let elapsed = req_start.elapsed();

            match resp {
                Ok(response) => {
                    let status = response.status().as_u16();
                    results.push(RequestResult {
                        status,
                        response_time_ms: elapsed.as_millis() as u64,
                        rate_limited: status == 429,
                    });

                    if status == 429 {
                        rate_limited = true;
                        // Extract rate limit headers
                        for (key, value) in response.headers() {
                            let key_str = key.as_str().to_lowercase();
                            if key_str.contains("rate")
                                || key_str.contains("limit")
                                || key_str.contains("retry")
                            {
                                rate_limit_headers
                                    .insert(key_str, value.to_str().unwrap_or("").to_string());
                            }
                        }
                        if let Some(retry) = response.headers().get("retry-after") {
                            retry_after = retry.to_str().ok().map(|s| s.to_string());
                        }
                        break;
                    }
                }
                Err(_) => {
                    results.push(RequestResult {
                        status: 0,
                        response_time_ms: elapsed.as_millis() as u64,
                        rate_limited: false,
                    });
                }
            }

            request_count += 1;

            // Respect rate limit delay
            let target_interval = Duration::from_millis(1000 / sustained_rate as u64);
            if req_start.elapsed() < target_interval {
                tokio::time::sleep(target_interval - req_start.elapsed()).await;
            }
        }

        // Test 2: Burst handling
        let mut burst_results = Vec::new();
        let burst_size = self.config.burst_test_size.min(20); // Conservative max

        for _ in 0..burst_size {
            let req_start = Instant::now();
            let resp = self.send_request(url, method).await;
            let elapsed = req_start.elapsed();

            match resp {
                Ok(response) => {
                    let status = response.status().as_u16();
                    burst_results.push(RequestResult {
                        status,
                        response_time_ms: elapsed.as_millis() as u64,
                        rate_limited: status == 429,
                    });

                    if status == 429 {
                        rate_limited = true;
                    }
                }
                Err(_) => {
                    burst_results.push(RequestResult {
                        status: 0,
                        response_time_ms: elapsed.as_millis() as u64,
                        rate_limited: false,
                    });
                }
            }
        }

        // Test 3: Authentication endpoint specific (if applicable)
        let mut auth_results = Vec::new();
        if is_auth_endpoint {
            for _ in 0..self.config.auth_endpoint_test_requests.min(10) {
                let req_start = Instant::now();
                let resp = self.send_request(url, method).await;
                let elapsed = req_start.elapsed();

                match resp {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        auth_results.push(RequestResult {
                            status,
                            response_time_ms: elapsed.as_millis() as u64,
                            rate_limited: status == 429,
                        });

                        if status == 429 {
                            rate_limited = true;
                        }
                    }
                    Err(_) => {
                        auth_results.push(RequestResult {
                            status: 0,
                            response_time_ms: elapsed.as_millis() as u64,
                            rate_limited: false,
                        });
                    }
                }

                // Small delay between auth requests
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        RateLimitTestResult {
            url: url.to_string(),
            method: method.to_string(),
            is_auth_endpoint,
            sustained_results: results,
            burst_results,
            auth_results,
            rate_limited,
            rate_limit_headers,
            retry_after,
        }
    }

    /// Send a single HTTP request
    async fn send_request(&self, url: &str, method: &str) -> reqwest::Result<reqwest::Response> {
        let req = match method.to_uppercase().as_str() {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "PATCH" => self.client.patch(url),
            "DELETE" => self.client.delete(url),
            "HEAD" => self.client.head(url),
            "OPTIONS" => self.client.request(reqwest::Method::OPTIONS, url),
            _ => self.client.get(url),
        };

        req.send().await
    }

    /// Analyze rate limit test results
    fn analyze_results(
        &self,
        result: &RateLimitTestResult,
        scan_id: openre_core::ids::ScanId,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check 1: No rate limiting detected
        if !result.rate_limited {
            let severity = if result.is_auth_endpoint {
                Severity::High
            } else {
                Severity::Medium
            };
            findings.push(self.create_finding(
                "Missing Rate Limiting",
                &format!(
                    "Endpoint {} {} does not appear to implement rate limiting",
                    result.method, result.url
                ),
                severity,
                Confidence::Medium,
                Category::SecurityMisconfiguration,
                result,
                vec!["missing-rate-limit".to_string()],
                vec![
                    "Implement rate limiting for this endpoint".to_string(),
                    "Consider stricter limits for authentication endpoints".to_string(),
                ],
                scan_id,
            ));
        }

        // Check 2: Rate limit headers missing
        if result.rate_limited && result.rate_limit_headers.is_empty() {
            findings.push(self.create_finding(
                "Rate Limiting Headers Missing",
                &format!("Endpoint {} {} returns 429 but lacks standard rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After)", result.method, result.url),
                Severity::Low,
                Confidence::High,
                Category::SecurityMisconfiguration,
                result,
                vec!["missing-headers".to_string()],
                vec!["Add standard rate limit headers to 429 responses".to_string()],
                scan_id,
            ));
        }

        // Check 3: Burst handling
        let burst_limited = result.burst_results.iter().any(|r| r.rate_limited);
        if !burst_limited && result.burst_results.len() > 5 {
            findings.push(self.create_finding(
                "Insufficient Burst Protection",
                &format!(
                    "Endpoint {} {} allows burst of {} requests without rate limiting",
                    result.method,
                    result.url,
                    result.burst_results.len()
                ),
                Severity::Medium,
                Confidence::Medium,
                Category::SecurityMisconfiguration,
                result,
                vec!["burst-protection".to_string()],
                vec!["Implement burst request limiting".to_string()],
                scan_id,
            ));
        }

        // Check 4: Authentication endpoint protection
        if result.is_auth_endpoint {
            let auth_limited = result.auth_results.iter().any(|r| r.rate_limited);
            if !auth_limited && result.auth_results.len() > 3 {
                findings.push(self.create_finding(
                    "Authentication Endpoint Missing Rate Limiting",
                    &format!(
                        "Authentication endpoint {} {} allows unlimited login attempts",
                        result.method, result.url
                    ),
                    Severity::High,
                    Confidence::High,
                    Category::BrokenAuthentication,
                    result,
                    vec!["auth-rate-limit".to_string(), "brute-force".to_string()],
                    vec![
                        "Implement strict rate limiting on authentication endpoints".to_string(),
                        "Consider account lockout after failed attempts".to_string(),
                        "Implement CAPTCHA or MFA for additional protection".to_string(),
                    ],
                    scan_id,
                ));
            }
        }

        // Check 5: Retry-After header
        if result.rate_limited && result.retry_after.is_none() {
            findings.push(self.create_finding(
                "Missing Retry-After Header",
                &format!(
                    "Endpoint {} {} returns 429 without Retry-After header",
                    result.method, result.url
                ),
                Severity::Low,
                Confidence::High,
                Category::SecurityMisconfiguration,
                result,
                vec!["missing-retry-after".to_string()],
                vec!["Add Retry-After header to rate limit responses".to_string()],
                scan_id,
            ));
        }

        findings
    }

    /// Create a finding from rate limit test
    fn create_finding(
        &self,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        result: &RateLimitTestResult,
        tags: Vec<String>,
        verification_steps: Vec<String>,
        scan_id: openre_core::ids::ScanId,
    ) -> Finding {
        let mut finding = Finding::new(FindingConfig {
            title: title.to_string(),
            description: description.to_string(),
            severity,
            confidence,
            category,
            target: result.url.clone(),
            target_type: "web_api".to_string(),
            plugin_source: "api_rate_limiting".to_string(),
            plugin_version: self.version().to_string(),
            scan_id,
        });

        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!("Rate limit test for {} {}", result.method, result.url),
            data: Some(serde_json::json!({
                "endpoint": {
                    "url": result.url,
                    "method": result.method,
                    "is_auth_endpoint": result.is_auth_endpoint,
                    "rate_limited": result.rate_limited,
                    "rate_limit_headers": result.rate_limit_headers,
                    "retry_after": result.retry_after,
                    "sustained_requests": result.sustained_results.len(),
                    "burst_requests": result.burst_results.len(),
                    "auth_requests": result.auth_results.len(),
                }
            })),
            location: Some(result.url.clone()),
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("api_rate_limiting".to_string()),
            timestamp: Utc::now(),
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
        finding = finding.with_tag("rate-limiting".to_string());
        finding = finding.with_tag("api".to_string());

        finding
    }
}

#[async_trait]
impl Plugin for ApiRateLimitingPlugin {
    type Config = ApiRateLimitingConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create API Rate Limiting plugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let scan_id = openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid());
        let target_url = request
            .input
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");

        // Get endpoints to test from input or discover common ones
        let endpoints = request
            .input
            .get("endpoints")
            .and_then(|v| serde_json::from_value::<Vec<EndpointTestConfig>>(v.clone()).ok())
            .unwrap_or_else(|| {
                vec![
                    EndpointTestConfig {
                        url: format!("{}/api/login", target_url),
                        method: "POST".to_string(),
                        is_auth_endpoint: true,
                    },
                    EndpointTestConfig {
                        url: format!("{}/api/register", target_url),
                        method: "POST".to_string(),
                        is_auth_endpoint: true,
                    },
                    EndpointTestConfig {
                        url: format!("{}/api/users", target_url),
                        method: "GET".to_string(),
                        is_auth_endpoint: false,
                    },
                    EndpointTestConfig {
                        url: format!("{}/api/data", target_url),
                        method: "GET".to_string(),
                        is_auth_endpoint: false,
                    },
                ]
            });

        let endpoints_count = endpoints.len();
        info!(
            "Starting API rate limiting analysis for {} endpoints",
            endpoints_count
        );

        let mut all_findings = Vec::new();
        for endpoint in endpoints {
            let result = self
                .test_endpoint_rate_limit(
                    &endpoint.url,
                    &endpoint.method,
                    endpoint.is_auth_endpoint,
                )
                .await;
            let findings = self.analyze_results(&result, scan_id);
            all_findings.extend(findings);
        }

        info!("Found {} rate limiting issues", all_findings.len());

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": all_findings,
            "endpoints_tested": endpoints_count,
            "vulnerabilities_found": all_findings.len(),
        })))
    }
}

/// API Rate Limiting Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiRateLimitingConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
    pub sustained_requests_per_second: u32,
    pub sustained_test_duration_seconds: u64,
    pub burst_test_size: usize,
    pub auth_endpoint_test_requests: usize,
    pub max_test_requests: usize,
    pub test_requests_per_endpoint: usize,
}

impl Default for ApiRateLimitingConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            max_concurrent_requests: 5,
            user_agent: "open-re-api-rate-limiter/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
            sustained_requests_per_second: 5,
            sustained_test_duration_seconds: 10,
            burst_test_size: 10,
            auth_endpoint_test_requests: 5,
            max_test_requests: 50,
            test_requests_per_endpoint: 20,
        }
    }
}

/// Endpoint test configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
struct EndpointTestConfig {
    url: String,
    method: String,
    is_auth_endpoint: bool,
}

/// Rate limit test result
#[derive(Debug, Clone)]
struct RateLimitTestResult {
    url: String,
    method: String,
    is_auth_endpoint: bool,
    sustained_results: Vec<RequestResult>,
    burst_results: Vec<RequestResult>,
    auth_results: Vec<RequestResult>,
    rate_limited: bool,
    rate_limit_headers: HashMap<String, String>,
    retry_after: Option<String>,
}

/// Individual request result
#[derive(Debug, Clone)]
struct RequestResult {
    status: u16,
    response_time_ms: u64,
    rate_limited: bool,
}

// Plugin entry point
