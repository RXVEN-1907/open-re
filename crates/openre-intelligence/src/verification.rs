//! Finding Verification Framework
//!
//! This module provides safe, non-destructive verification of security findings
//! using various verification methods. NO destructive methods are included.

use crate::{error::IntelligenceError, IntelligenceResult};
use openre_core::evidence::{
    FindingEvidence, FindingVerifier, HttpInteraction, HttpRequestEvidence, HttpResponseEvidence,
    TimingEvidence, TriggerCondition, VerificationEvidence, VerificationMethod, VerificationResult,
    VerificationStatus,
};

/// Create an empty VerificationEvidence
fn empty_verification_evidence() -> VerificationEvidence {
    VerificationEvidence {
        http_interaction: None,
        response_analysis: None,
        configuration_extracted: None,
        differential_results: None,
        screenshots: Vec::new(),
        logs: Vec::new(),
    }
}
use openre_core::ids::{FindingId, VerificationId};
use openre_core::result::{Category, Finding, Severity};
use reqwest::Client;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Verification engine that coordinates multiple verifiers
pub struct VerificationEngine {
    verifiers: Vec<Box<dyn FindingVerifier>>,
    http_client: Client,
    config: VerificationConfig,
}

/// Configuration for verification engine
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Timeout for individual verification requests
    pub request_timeout: Duration,
    /// Maximum concurrent verifications
    pub max_concurrent: usize,
    /// Enable safe verification only (no destructive methods)
    pub safe_only: bool,
    /// Retry failed verifications
    pub retry_failed: bool,
    /// Number of retry attempts
    pub retry_attempts: u32,
    /// Delay between retries
    pub retry_delay: Duration,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            max_concurrent: 10,
            safe_only: true,
            retry_failed: true,
            retry_attempts: 3,
            retry_delay: Duration::from_secs(5),
        }
    }
}

impl VerificationEngine {
    /// Create a new verification engine with default configuration
    pub fn new() -> Self {
        let config = VerificationConfig::default();
        let http_client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .expect("Failed to create HTTP client");

        let mut engine = Self { verifiers: Vec::new(), http_client, config };

        // Register built-in verifiers
        engine.register_builtin_verifiers();
        engine
    }

    /// Create a new verification engine with custom configuration
    pub fn with_config(config: VerificationConfig) -> Self {
        let http_client = Client::builder()
            .timeout(config.request_timeout)
            .build()
            .expect("Failed to create HTTP client");

        let mut engine = Self { verifiers: Vec::new(), http_client, config };

        engine.register_builtin_verifiers();
        engine
    }

    /// Register built-in verifiers
    fn register_builtin_verifiers(&mut self) {
        self.verifiers.push(Box::new(SecurityHeaderVerifier::new()));
        self.verifiers.push(Box::new(InfoDisclosureVerifier::new()));
        self.verifiers.push(Box::new(TechnologyVerifier::new()));
        self.verifiers.push(Box::new(AuthVerifier::new()));
        self.verifiers.push(Box::new(RateLimitVerifier::new()));
        self.verifiers.push(Box::new(DirectoryListingVerifier::new()));
        self.verifiers.push(Box::new(CorsVerifier::new()));
        self.verifiers.push(Box::new(SslTlsVerifier::new()));
        self.verifiers.push(Box::new(CookieSecurityVerifier::new()));
    }

    /// Add a custom verifier
    pub fn add_verifier(&mut self, verifier: Box<dyn FindingVerifier>) {
        self.verifiers.push(verifier);
    }

    /// Get HTTP client for external use
    pub fn http_client(&self) -> &Client {
        &self.http_client
    }

    /// Verify a single finding using all applicable verifiers
    pub async fn verify_finding(
        &self,
        finding: &Finding,
    ) -> IntelligenceResult<VerificationResult> {
        let applicable_verifiers: Vec<&Box<dyn FindingVerifier>> =
            self.verifiers.iter().filter(|v| v.can_verify(finding)).collect();

        if applicable_verifiers.is_empty() {
            return Ok(VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status: VerificationStatus::Skipped,
                evidence: empty_verification_evidence(),
                confidence: 0.0,
                notes: "No applicable verifiers found".to_string(),
                verified_at: chrono::Utc::now(),
                verified_by: "VerificationEngine".to_string(),
                method_used: VerificationMethod::Custom {
                    description: "None".to_string(),
                    script: "".to_string(),
                },
                duration_ms: 0,
            });
        }

        // Run verifiers concurrently
        let mut results = Vec::new();
        for verifier in applicable_verifiers {
            match self.run_verifier(verifier, finding).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!(
                        "Verifier {} failed for finding {}: {}",
                        verifier.verification_method(),
                        finding.id,
                        e
                    );
                }
            }
        }

        self.combine_results(finding, results)
    }

    /// Verify multiple findings
    pub async fn verify_findings(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<VerificationResult>> {
        let mut results = Vec::new();

        for finding in findings {
            let result = self.verify_finding(finding).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Run a single verifier with retry logic
    async fn run_verifier(
        &self,
        verifier: &dyn FindingVerifier,
        finding: &Finding,
    ) -> IntelligenceResult<VerificationResult> {
        let mut last_error = None;

        for attempt in 0..=self.config.retry_attempts {
            let fut = verifier.verify(finding, &self.http_client);
            let result = fut.await;

            // Check if verification indicates an error state
            if result.status == VerificationStatus::Error {
                last_error = Some(IntelligenceError::VerificationError(result.notes.clone()));
                if attempt < self.config.retry_attempts && self.config.retry_failed {
                    warn!(
                        "Verification attempt {} failed for finding {}, retrying...",
                        attempt + 1,
                        finding.id
                    );
                    tokio::time::sleep(self.config.retry_delay).await;
                    continue;
                }
            }

            return Ok(result);
        }

        Err(last_error.unwrap_or_else(|| {
            IntelligenceError::VerificationError("Verification failed".to_string())
        }))
    }

    /// Combine results from multiple verifiers
    fn combine_results(
        &self,
        finding: &Finding,
        results: Vec<VerificationResult>,
    ) -> IntelligenceResult<VerificationResult> {
        if results.is_empty() {
            return Ok(VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status: VerificationStatus::Unconfirmed,
                evidence: empty_verification_evidence(),
                confidence: 0.0,
                notes: "No verification results".to_string(),
                verified_at: chrono::Utc::now(),
                verified_by: "VerificationEngine".to_string(),
                method_used: VerificationMethod::Custom {
                    description: "None".to_string(),
                    script: "".to_string(),
                },
                duration_ms: 0,
            });
        }

        // Determine overall status
        let statuses: Vec<_> = results.iter().map(|r| r.status).collect();
        let overall_status = if statuses.iter().any(|s| *s == VerificationStatus::Confirmed) {
            VerificationStatus::Confirmed
        } else if statuses.iter().any(|s| *s == VerificationStatus::Likely) {
            VerificationStatus::Likely
        } else if statuses.iter().any(|s| *s == VerificationStatus::Unconfirmed) {
            VerificationStatus::Unconfirmed
        } else if statuses.iter().any(|s| *s == VerificationStatus::NotReproducible) {
            VerificationStatus::NotReproducible
        } else {
            VerificationStatus::Error
        };

        // Average confidence
        let avg_confidence =
            results.iter().map(|r| r.confidence).sum::<f32>() / results.len() as f32;

        // Combine evidence
        let mut combined_evidence = empty_verification_evidence();
        let mut notes = Vec::new();
        let mut total_duration = 0;

        for result in &results {
            notes.push(format!("{}: {}", result.verified_by, result.notes));
            total_duration += result.duration_ms;

            if let Some(interaction) = &result.evidence.http_interaction {
                combined_evidence.http_interaction = Some(interaction.clone());
            }
            if let Some(analysis) = &result.evidence.response_analysis {
                combined_evidence.response_analysis = Some(analysis.clone());
            }
            if let Some(config) = &result.evidence.configuration_extracted {
                combined_evidence.configuration_extracted = Some(config.clone());
            }
            if let Some(diff) = &result.evidence.differential_results {
                combined_evidence.differential_results = Some(diff.clone());
            }
            combined_evidence.screenshots.extend(result.evidence.screenshots.clone());
            combined_evidence.logs.extend(result.evidence.logs.clone());
        }

        Ok(VerificationResult {
            verification_id: VerificationId::new(),
            finding_id: finding.id,
            status: overall_status,
            evidence: combined_evidence,
            confidence: avg_confidence,
            notes: notes.join("; "),
            verified_at: chrono::Utc::now(),
            verified_by: "VerificationEngine".to_string(),
            method_used: VerificationMethod::Custom {
                description: "Combined".to_string(),
                script: "".to_string(),
            },
            duration_ms: total_duration,
        })
    }
}

/// Security Header Verifier
pub struct SecurityHeaderVerifier {
    required_headers: Vec<&'static str>,
}

impl SecurityHeaderVerifier {
    pub fn new() -> Self {
        Self {
            required_headers: vec![
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            ],
        }
    }
}

impl FindingVerifier for SecurityHeaderVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(
            finding.category,
            Category::SecurityMisconfiguration | Category::InformationDisclosure
        ) && finding.title.to_lowercase().contains("header")
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::HeaderCheck {
            headers: self.required_headers.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.head(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "SecurityHeaderVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let status_code = response.status().as_u16();
            let headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let mut missing = Vec::new();
            let mut present = Vec::new();

            for header in &self.required_headers {
                if headers.contains_key(*header) {
                    present.push(header.to_string());
                } else {
                    missing.push(header.to_string());
                }
            }

            let status = if missing.is_empty() {
                VerificationStatus::NotReproducible
            } else if missing.len() >= 2 {
                VerificationStatus::Confirmed
            } else {
                VerificationStatus::Likely
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "HEAD".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code,
                            headers: headers.clone(),
                            body: None,
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: if missing.len() >= 2 { 0.9 } else { 0.7 },
                notes: format!("Missing headers: {:?}, Present: {:?}", missing, present),
                verified_at: chrono::Utc::now(),
                verified_by: "SecurityHeaderVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// Information Disclosure Verifier
pub struct InfoDisclosureVerifier {
    sensitive_patterns: Vec<String>,
}

impl InfoDisclosureVerifier {
    pub fn new() -> Self {
        Self {
            sensitive_patterns: vec![
                r#"(?i)api[_-]?key"#.to_string(),
                r#"(?i)secret"#.to_string(),
                r#"(?i)password"#.to_string(),
                r#"(?i)token"#.to_string(),
                r#"(?i)private[_-]?key"#.to_string(),
                r#"(?i)access[_-]?token"#.to_string(),
            ],
        }
    }
}

impl FindingVerifier for InfoDisclosureVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(
            finding.category,
            Category::InformationDisclosure | Category::SensitiveDataExposure
        )
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::BodyPatternCheck { patterns: self.sensitive_patterns.clone() }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "InfoDisclosureVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let status_code = response.status().as_u16();
            let body = match response.text().await {
                Ok(b) => b,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("Failed to read response: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "InfoDisclosureVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let mut matches = Vec::new();
            for pattern in &self.sensitive_patterns {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    for mat in regex.find_iter(&body) {
                        matches.push(mat.as_str().to_string());
                    }
                }
            }

            let status = if matches.is_empty() {
                VerificationStatus::NotReproducible
            } else {
                VerificationStatus::Confirmed
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code,
                            headers: HashMap::new(),
                            body: Some(body),
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: if matches.len() > 2 { 0.9 } else { 0.7 },
                notes: format!("Found {} sensitive patterns: {:?}", matches.len(), matches),
                verified_at: chrono::Utc::now(),
                verified_by: "InfoDisclosureVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// Technology Verifier
pub struct TechnologyVerifier {
    tech_patterns: HashMap<String, String>,
}

impl TechnologyVerifier {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        patterns.insert("nginx".to_string(), r#"nginx/([\d.]+)"#.to_string());
        patterns.insert("apache".to_string(), r#"Apache/([\d.]+)"#.to_string());
        patterns.insert("php".to_string(), r#"PHP/([\d.]+)"#.to_string());
        patterns.insert("express".to_string(), r#"express"#.to_string());
        patterns.insert("django".to_string(), r#"Django"#.to_string());
        patterns.insert("spring".to_string(), r#"Spring"#.to_string());
        patterns.insert("asp.net".to_string(), r#"ASP.NET"#.to_string());
        Self { tech_patterns: patterns }
    }
}

impl FindingVerifier for TechnologyVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(
            finding.category,
            Category::InformationDisclosure
                | Category::SecurityMisconfiguration
                | Category::Configuration
        )
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::BodyPatternCheck {
            patterns: self.tech_patterns.values().cloned().collect(),
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "TechnologyVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let status_code = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let combined = format!("{:?} {}", headers, body);

            let mut detected = Vec::new();
            for (tech, pattern) in &self.tech_patterns {
                if let Ok(regex) = regex::Regex::new(pattern) {
                    if regex.is_match(&combined) {
                        detected.push(tech.clone());
                    }
                }
            }

            let status = if detected.is_empty() {
                VerificationStatus::Unconfirmed
            } else {
                VerificationStatus::Confirmed
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code,
                            headers: headers.clone(),
                            body: Some(body),
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: if detected.len() > 1 { 0.8 } else { 0.6 },
                notes: format!("Detected technologies: {:?}", detected),
                verified_at: chrono::Utc::now(),
                verified_by: "TechnologyVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// Authentication Verifier
pub struct AuthVerifier;

impl AuthVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl FindingVerifier for AuthVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(
            finding.category,
            Category::BrokenAuthentication | Category::SecurityMisconfiguration
        ) && (finding.title.to_lowercase().contains("auth")
            || finding.title.to_lowercase().contains("login"))
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::Custom {
            description: "Authentication Check".to_string(),
            script: "".to_string(),
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "AuthVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let has_auth = response.status().is_client_error()
                && (response.status().as_u16() == 401 || response.status().as_u16() == 403);

            let status =
                if has_auth { VerificationStatus::Confirmed } else { VerificationStatus::Likely };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code: response.status().as_u16(),
                            headers: HashMap::new(),
                            body: None,
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: 0.6,
                notes: format!("Auth check: status={}", response.status().as_u16()),
                verified_at: chrono::Utc::now(),
                verified_by: "AuthVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// Rate Limit Verifier
pub struct RateLimitVerifier;

impl RateLimitVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl FindingVerifier for RateLimitVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(finding.category, Category::SecurityMisconfiguration | Category::DenialOfService)
            && finding.title.to_lowercase().contains("rate")
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::RateLimitCheck {
            endpoint: "/".to_string(),
            requests: 100,
            window_seconds: 60,
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let mut rate_limited = false;
            let mut status_codes = Vec::new();

            // Send rapid requests
            for _ in 0..20 {
                let resp = client.get(target).send().await;
                if let Ok(r) = resp {
                    status_codes.push(r.status().as_u16());
                    if r.status().as_u16() == 429 {
                        rate_limited = true;
                        break;
                    }
                }
            }

            let status = if rate_limited {
                VerificationStatus::NotReproducible // Rate limiting is working
            } else if status_codes.iter().any(|&s| s >= 500) {
                VerificationStatus::Likely // Server errors might indicate no rate limiting
            } else {
                VerificationStatus::Unconfirmed
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: None,
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: 0.5,
                notes: format!(
                    "Rate limit test: rate_limited={}, statuses={:?}",
                    rate_limited, status_codes
                ),
                verified_at: chrono::Utc::now(),
                verified_by: "RateLimitVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// Directory Listing Verifier
pub struct DirectoryListingVerifier;

impl DirectoryListingVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl FindingVerifier for DirectoryListingVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(finding.category, Category::InformationDisclosure | Category::Configuration)
            && finding.title.to_lowercase().contains("directory")
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::DirectoryListingCheck { path: "/".to_string() }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "DirectoryListingVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let status_code = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            let has_listing = body.to_lowercase().contains("index of")
                || body.to_lowercase().contains("directory listing")
                || body.to_lowercase().contains("parent directory");

            let status = if has_listing {
                VerificationStatus::Confirmed
            } else {
                VerificationStatus::NotReproducible
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code,
                            headers: HashMap::new(),
                            body: Some(body),
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: if has_listing { 0.9 } else { 0.7 },
                notes: format!(
                    "Directory listing check: {}",
                    if has_listing { "found" } else { "not found" }
                ),
                verified_at: chrono::Utc::now(),
                verified_by: "DirectoryListingVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// CORS Verifier
pub struct CorsVerifier;

impl CorsVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl FindingVerifier for CorsVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(finding.category, Category::SecurityMisconfiguration)
            && finding.title.to_lowercase().contains("cors")
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::CorsCheck {
            origins: vec!["*".to_string(), "null".to_string()],
            endpoint: "/".to_string(),
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "CorsVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let status_code = response.status().as_u16();
            let headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let has_cors = headers.contains_key("access-control-allow-origin");
            let allows_all = headers
                .get("access-control-allow-origin")
                .map(|v| v == "*" || v == "null")
                .unwrap_or(false);

            let status = if allows_all {
                VerificationStatus::Confirmed
            } else if has_cors {
                VerificationStatus::Likely
            } else {
                VerificationStatus::NotReproducible
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code,
                            headers: headers.clone(),
                            body: None,
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: if allows_all {
                    0.9
                } else if has_cors {
                    0.7
                } else {
                    0.5
                },
                notes: format!(
                    "CORS check: allows_all={}, headers={:?}",
                    allows_all,
                    headers.get("access-control-allow-origin")
                ),
                verified_at: chrono::Utc::now(),
                verified_by: "CorsVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// SSL/TLS Verifier
pub struct SslTlsVerifier;

impl SslTlsVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl FindingVerifier for SslTlsVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(finding.category, Category::SecurityMisconfiguration | Category::Cryptographic)
            && (finding.target.starts_with("https://")
                || finding.title.to_lowercase().contains("ssl")
                || finding.title.to_lowercase().contains("tls"))
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::Custom {
            description: "SSL/TLS Check".to_string(),
            script: "".to_string(),
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "SslTlsVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let has_tls = target.starts_with("https://");
            let tls_version = response.version();
            let is_secure = has_tls
                && (tls_version == reqwest::Version::HTTP_11
                    || tls_version == reqwest::Version::HTTP_2);

            let status = if is_secure {
                VerificationStatus::Confirmed
            } else if has_tls {
                VerificationStatus::Likely
            } else {
                VerificationStatus::NotReproducible
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code: response.status().as_u16(),
                            headers: HashMap::new(),
                            body: None,
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: 0.6,
                notes: format!("TLS check: https={}, version={:?}", has_tls, tls_version),
                verified_at: chrono::Utc::now(),
                verified_by: "SslTlsVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

/// Cookie Security Verifier
pub struct CookieSecurityVerifier;

impl CookieSecurityVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl FindingVerifier for CookieSecurityVerifier {
    fn can_verify(&self, finding: &Finding) -> bool {
        matches!(
            finding.category,
            Category::SecurityMisconfiguration | Category::InformationDisclosure
        ) && finding.title.to_lowercase().contains("cookie")
    }

    fn verification_method(&self) -> VerificationMethod {
        VerificationMethod::Custom {
            description: "Cookie Security Check".to_string(),
            script: "".to_string(),
        }
    }

    fn verify<'a>(
        &'a self,
        finding: &'a Finding,
        client: &'a Client,
    ) -> Pin<Box<dyn Future<Output = VerificationResult> + Send + 'a>> {
        Box::pin(async move {
            let start = Instant::now();
            let target = &finding.target;

            let response = match client.get(target).send().await {
                Ok(r) => r,
                Err(e) => {
                    return VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: empty_verification_evidence(),
                        confidence: 0.0,
                        notes: format!("HTTP error: {}", e),
                        verified_at: chrono::Utc::now(),
                        verified_by: "CookieSecurityVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

            let cookies: Vec<String> = response
                .headers()
                .get_all("set-cookie")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .collect();

            let mut issues = Vec::new();
            for cookie in &cookies {
                if !cookie.contains("HttpOnly") {
                    issues.push("Missing HttpOnly");
                }
                if !cookie.contains("Secure") && target.starts_with("https://") {
                    issues.push("Missing Secure");
                }
                if !cookie.contains("SameSite") {
                    issues.push("Missing SameSite");
                }
            }

            let status = if issues.is_empty() {
                VerificationStatus::NotReproducible
            } else {
                VerificationStatus::Confirmed
            };

            VerificationResult {
                verification_id: VerificationId::new(),
                finding_id: finding.id,
                status,
                evidence: VerificationEvidence {
                    http_interaction: Some(HttpInteraction {
                        request: HttpRequestEvidence {
                            method: "GET".to_string(),
                            url: target.clone(),
                            headers: HashMap::new(),
                            body: None,
                            query_params: HashMap::new(),
                            path_params: HashMap::new(),
                            cookies: HashMap::new(),
                            size_bytes: None,
                            curl_command: None,
                        },
                        response: HttpResponseEvidence {
                            status_code: response.status().as_u16(),
                            headers: HashMap::new(),
                            body: None,
                            size_bytes: None,
                            response_time_ms: Some(start.elapsed().as_millis() as u64),
                            tls_info: None,
                            redirected_from: None,
                            redirected_to: None,
                        },
                        timings: TimingEvidence {
                            total_ms: start.elapsed().as_millis() as u64,
                            dns_ms: None,
                            connect_ms: None,
                            tls_handshake_ms: None,
                            ttfb_ms: None,
                            download_ms: None,
                        },
                        tls_info: None,
                        sequence: None,
                    }),
                    response_analysis: None,
                    configuration_extracted: None,
                    differential_results: None,
                    screenshots: Vec::new(),
                    logs: Vec::new(),
                },
                confidence: 0.7,
                notes: format!("Cookie issues: {:?}", issues),
                verified_at: chrono::Utc::now(),
                verified_by: "CookieSecurityVerifier".to_string(),
                method_used: self.verification_method(),
                duration_ms: start.elapsed().as_millis() as u64,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use std::collections::HashMap;

    fn create_test_finding(title: &str, category: Category, severity: Severity) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity,
            confidence: Confidence::High,
            category,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(60),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some("test-fingerprint".to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[tokio::test]
    async fn test_verification_engine_creation() {
        let engine = VerificationEngine::new();
        assert!(!engine.verifiers.is_empty());
    }

    #[tokio::test]
    async fn test_security_header_verifier_can_verify() {
        let verifier = SecurityHeaderVerifier::new();
        let finding = create_test_finding(
            "Missing Security Headers",
            Category::SecurityMisconfiguration,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding2));
    }

    #[tokio::test]
    async fn test_info_disclosure_verifier_can_verify() {
        let verifier = InfoDisclosureVerifier::new();
        let finding = create_test_finding(
            "Sensitive Data Exposure",
            Category::SensitiveDataExposure,
            Severity::High,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding2));
    }

    #[tokio::test]
    async fn test_technology_verifier_can_verify() {
        let verifier = TechnologyVerifier::new();
        let finding = create_test_finding(
            "Technology Disclosure",
            Category::InformationDisclosure,
            Severity::Low,
        );
        assert!(verifier.can_verify(&finding));
    }

    #[tokio::test]
    async fn test_auth_verifier_can_verify() {
        let verifier = AuthVerifier::new();
        let finding = create_test_finding(
            "Weak Authentication",
            Category::BrokenAuthentication,
            Severity::High,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 = create_test_finding(
            "Login Bypass",
            Category::SecurityMisconfiguration,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding2));

        let finding3 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding3));
    }

    #[tokio::test]
    async fn test_rate_limit_verifier_can_verify() {
        let verifier = RateLimitVerifier::new();
        let finding = create_test_finding(
            "No Rate Limiting",
            Category::SecurityMisconfiguration,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("DoS via No Rate Limit", Category::DenialOfService, Severity::High);
        assert!(verifier.can_verify(&finding2));

        let finding3 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding3));
    }

    #[tokio::test]
    async fn test_directory_listing_verifier_can_verify() {
        let verifier = DirectoryListingVerifier::new();
        let finding = create_test_finding(
            "Directory Listing Enabled",
            Category::InformationDisclosure,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("Exposed Directory", Category::Configuration, Severity::Low);
        assert!(verifier.can_verify(&finding2));
    }

    #[tokio::test]
    async fn test_cors_verifier_can_verify() {
        let verifier = CorsVerifier::new();
        let finding = create_test_finding(
            "CORS Misconfiguration",
            Category::SecurityMisconfiguration,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding2));
    }

    #[tokio::test]
    async fn test_ssl_tls_verifier_can_verify() {
        let verifier = SslTlsVerifier::new();
        let finding = create_test_finding(
            "Weak SSL Configuration",
            Category::SecurityMisconfiguration,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("Weak Encryption", Category::Cryptographic, Severity::High);
        assert!(verifier.can_verify(&finding2));

        let finding3 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding3));
    }

    #[tokio::test]
    async fn test_cookie_security_verifier_can_verify() {
        let verifier = CookieSecurityVerifier::new();
        let finding = create_test_finding(
            "Insecure Cookies",
            Category::SecurityMisconfiguration,
            Severity::Medium,
        );
        assert!(verifier.can_verify(&finding));

        let finding2 =
            create_test_finding("Cookie Theft", Category::InformationDisclosure, Severity::Low);
        assert!(verifier.can_verify(&finding2));

        let finding3 =
            create_test_finding("SQL Injection", Category::Injection, Severity::Critical);
        assert!(!verifier.can_verify(&finding3));
    }
}
