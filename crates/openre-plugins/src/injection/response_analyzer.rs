//! Response Analyzer
//!
//! Implements comparison techniques for detecting injection vulnerabilities:
//! - Status code changes
//! - Response length changes
//! - Header changes
//! - Timing analysis
//! - Reflection detection
//! - Error message detection
//! - Pattern matching

use crate::injection::{
    DetectionMethod, InjectionCategory, InjectionEvidence, InjectionTestResult, 
    ParameterLocation, Payload, ResponseDiff, Severity, TimingInfo,
    HttpResponseSnapshot, HttpRequestSnapshot
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Response analyzer trait
pub trait ResponseAnalyzer: Send + Sync {
    /// Analyze a test result for injection indicators
    fn analyze(&self, result: &TestResult, baseline: Option<&HttpResponseSnapshot>) -> Vec<InjectionTestResult>;
    
    /// Get supported detection methods
    fn supported_methods(&self) -> Vec<DetectionMethod>;
    
    /// Get injection category this analyzer handles
    fn category(&self) -> InjectionCategory;
}

/// Test result with request/response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub parameter: String,
    pub location: ParameterLocation,
    pub payload: Option<Payload>,
    pub request: crate::injection::mod::HttpRequestSnapshot,
    pub response: crate::injection::mod::HttpResponseSnapshot,
    pub baseline_response: Option<crate::injection::mod::HttpResponseSnapshot>,
    pub category: InjectionCategory,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Built-in response analyzer
pub struct BuiltinResponseAnalyzer {
    category: InjectionCategory,
    error_patterns: Vec<ErrorPattern>,
    reflection_threshold: f64,
    timing_threshold_ms: u64,
    length_diff_threshold: f64,
}

impl BuiltinResponseAnalyzer {
    /// Create a new builtin response analyzer
    pub fn new(category: InjectionCategory) -> Self {
        Self {
            category,
            error_patterns: Self::load_error_patterns(category),
            reflection_threshold: 0.8,
            timing_threshold_ms: 3000,
            length_diff_threshold: 0.1,
        }
    }
    
    /// Load error patterns for a category
    fn load_error_patterns(category: InjectionCategory) -> Vec<ErrorPattern> {
        match category {
            InjectionCategory::SqlInjection => vec![
                ErrorPattern {
                    pattern: r"(?i)sql syntax".to_string(),
                    description: "SQL syntax error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)mysql.*error".to_string(),
                    description: "MySQL error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)postgresql.*error".to_string(),
                    description: "PostgreSQL error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)ora-\d{5}".to_string(),
                    description: "Oracle error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)sqlserver.*error".to_string(),
                    description: "SQL Server error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)syntax error".to_string(),
                    description: "Generic syntax error".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)unclosed quotation mark".to_string(),
                    description: "Unclosed quotation mark".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)unterminated string".to_string(),
                    description: "Unterminated string".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::NoSqlInjection => vec![
                ErrorPattern {
                    pattern: r"(?i)mongodb.*error".to_string(),
                    description: "MongoDB error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)bson.*error".to_string(),
                    description: "BSON error".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::Xss => vec![
                ErrorPattern {
                    pattern: r"(?i)script.*alert".to_string(),
                    description: "Script tag reflection".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::Reflection,
                },
                ErrorPattern {
                    pattern: r"(?i)onerror\s*=".to_string(),
                    description: "Event handler reflection".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::Reflection,
                },
                ErrorPattern {
                    pattern: r"(?i)onload\s*=".to_string(),
                    description: "Onload handler reflection".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::Reflection,
                },
                ErrorPattern {
                    pattern: r"(?i)javascript:".to_string(),
                    description: "JavaScript protocol reflection".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::Reflection,
                },
            ],
            InjectionCategory::Ssti => vec![
                ErrorPattern {
                    pattern: r"(?i)template.*error".to_string(),
                    description: "Template engine error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)jinja2.*error".to_string(),
                    description: "Jinja2 error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)twig.*error".to_string(),
                    description: "Twig error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)freemarker.*error".to_string(),
                    description: "Freemarker error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)velocity.*error".to_string(),
                    description: "Velocity error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::CommandInjection => vec![
                ErrorPattern {
                    pattern: r"(?i)command not found".to_string(),
                    description: "Command not found".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)sh: .*: not found".to_string(),
                    description: "Shell command not found".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)bash: .*: command not found".to_string(),
                    description: "Bash command not found".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)'.*' is not recognized".to_string(),
                    description: "Windows command not recognized".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::Xxe => vec![
                ErrorPattern {
                    pattern: r"(?i)xml.*error".to_string(),
                    description: "XML parsing error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)entity.*not.*declared".to_string(),
                    description: "Entity not declared".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)external entity".to_string(),
                    description: "External entity reference".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::LdapInjection => vec![
                ErrorPattern {
                    pattern: r"(?i)ldap.*error".to_string(),
                    description: "LDAP error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)invalid dn syntax".to_string(),
                    description: "Invalid DN syntax".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)naming violation".to_string(),
                    description: "Naming violation".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)unwilling to perform".to_string(),
                    description: "Unwilling to perform".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)constraint violation".to_string(),
                    description: "Constraint violation".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::XPathInjection => vec![
                ErrorPattern {
                    pattern: r"(?i)xpath.*error".to_string(),
                    description: "XPath error".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)invalid expression".to_string(),
                    description: "Invalid XPath expression".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)xml.*parse.*error".to_string(),
                    description: "XML parse error in XPath".to_string(),
                    severity: Severity::Medium,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            InjectionCategory::HeaderInjection => vec![
                ErrorPattern {
                    pattern: r"(?i)header.*injection".to_string(),
                    description: "Header injection detected".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)response splitting".to_string(),
                    description: "HTTP response splitting".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)crlf.*injection".to_string(),
                    description: "CRLF injection".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
                ErrorPattern {
                    pattern: r"(?i)cache.*poison".to_string(),
                    description: "Cache poisoning".to_string(),
                    severity: Severity::High,
                    detection_method: DetectionMethod::ErrorBased,
                },
            ],
            _ => vec![],
        }
    }
    
    /// Analyze response for injection indicators
    fn analyze_response(&self, result: &TestResult, baseline: Option<&HttpResponseSnapshot>) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        
        // 1. Error-based detection
        findings.extend(self.check_error_based(result));
        
        // 2. Reflection detection
        findings.extend(self.check_reflection(result));
        
        // 3. Timing analysis
        findings.extend(self.check_timing(result, baseline));
        
        // 4. Differential analysis
        findings.extend(self.check_differential(result, baseline));
        
        // 5. Pattern matching
        findings.extend(self.check_patterns(result));
        
        findings
    }
    
    /// Check for error-based indicators
    fn check_error_based(&self, result: &TestResult) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body = &result.response.body;
        let body_lower = body.to_lowercase();
        
        for pattern in &self.error_patterns {
            if regex::Regex::new(&pattern.pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let mut finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: pattern.detection_method,
                    confidence: 0.8,
                    severity: pattern.severity,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.pattern.clone()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the error is reproducible with the same payload".to_string(),
                        "Check if the error reveals database structure".to_string(),
                        "Attempt to extract data using UNION or boolean-based techniques".to_string(),
                    ],
                    tags: vec!["error-based".to_string(), format!("{:?}", self.category).to_lowercase()],
                };
                
                // Adjust confidence based on payload type
                if let Some(payload) = &result.payload {
                    if payload.tags.contains(&"time-based".to_string()) {
                        finding.detection_method = DetectionMethod::TimeBased;
                        finding.confidence = 0.9;
                    } else if payload.tags.contains(&"boolean-based".to_string()) {
                        finding.detection_method = DetectionMethod::BooleanBased;
                        finding.confidence = 0.85;
                    }
                }
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check for reflection-based indicators
    fn check_reflection(&self, result: &TestResult) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        
        if let Some(payload) = &result.payload {
            let payload_lower = payload.raw.to_lowercase();
            let body_lower = result.response.body.to_lowercase();
            
            // Check if payload is reflected in response
            if body_lower.contains(&payload_lower) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: payload.raw.clone(),
                    detection_method: DetectionMethod::Reflection,
                    confidence: 0.9,
                    severity: match self.category {
                        InjectionCategory::Xss => Severity::High,
                        InjectionCategory::Ssti => Severity::Critical,
                        _ => Severity::Medium,
                    },
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![payload.raw.clone()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: payload.raw.clone(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the payload is reflected without proper encoding".to_string(),
                        "Check if the reflection occurs in a dangerous context (HTML, JS, attribute)".to_string(),
                        "Test with a harmless payload like <test> to confirm reflection".to_string(),
                    ],
                    tags: vec!["reflection".to_string(), format!("{:?}", self.category).to_lowercase()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check for timing-based indicators
    fn check_timing(&self, result: &TestResult, baseline: Option<&HttpResponseSnapshot>) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        
        if let Some(payload) = &result.payload {
            if payload.tags.contains(&"time-based".to_string()) {
                let test_time = result.response.response_time_ms;
                let baseline_time = baseline.map(|b| b.response_time_ms).unwrap_or(0);
                let diff = test_time as i64 - baseline_time as i64;
                
                if diff >= self.timing_threshold_ms as i64 {
                    let finding = InjectionTestResult {
                        category: self.category,
                        parameter: result.parameter.clone(),
                        location: result.location,
                        payload: payload.raw.clone(),
                        detection_method: DetectionMethod::TimeBased,
                        confidence: 0.85,
                        severity: Severity::High,
                        evidence: InjectionEvidence {
                            original_request: Some(result.request.clone()),
                            triggering_response: result.response.clone(),
                            baseline_response: result.baseline_response.clone(),
                            diff: None,
                            matched_patterns: vec![],
                            timing_info: Some(TimingInfo {
                                baseline_ms: baseline_time,
                                test_ms: test_time,
                                diff_ms: diff,
                                threshold_ms: self.timing_threshold_ms,
                                is_significant: true,
                            }),
                        },
                        reproducible_request: ReproducibleRequest {
                            method: result.request.method.clone(),
                            url: result.request.url.clone(),
                            headers: result.request.headers.clone(),
                            body: result.request.body.clone(),
                            parameter: result.parameter.clone(),
                            payload: payload.raw.clone(),
                            location: result.location,
                        },
                        verification_steps: vec![
                            "Repeat the test multiple times to confirm consistent delay".to_string(),
                            "Test with different delay values (e.g., 3s, 10s) to confirm control".to_string(),
                            "Verify the delay is not due to network latency".to_string(),
                        ],
                        tags: vec!["time-based".to_string(), format!("{:?}", self.category).to_lowercase()],
                    };
                    
                    findings.push(finding);
                }
            }
        }
        
        findings
    }
    
    /// Check for differential indicators
    fn check_differential(&self, result: &TestResult, baseline: Option<&HttpResponseSnapshot>) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        
        if let Some(baseline) = baseline {
            let diff = self.compute_diff(baseline, &result.response);
            
            // Significant status code change
            if diff.status_changed && result.response.status >= 500 {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::Differential,
                    confidence: 0.7,
                    severity: Severity::Medium,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: Some(baseline.clone()),
                        diff: Some(diff.clone()),
                        matched_patterns: vec![],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the status code change is reproducible".to_string(),
                        "Check if the error reveals application internals".to_string(),
                    ],
                    tags: vec!["differential".to_string(), "status-change".to_string()],
                };
                
                findings.push(finding);
            }
            
            // Significant length change
            if diff.length_diff.abs() as f64 / baseline.body_length as f64 > self.length_diff_threshold {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::Differential,
                    confidence: 0.6,
                    severity: Severity::Low,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: Some(baseline.clone()),
                        diff: Some(diff.clone()),
                        matched_patterns: vec![],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the length change is reproducible".to_string(),
                        "Check if the response contains error messages or data leakage".to_string(),
                    ],
                    tags: vec!["differential".to_string(), "length-change".to_string()],
                };
                
                findings.push(finding);
            }
            
            // New patterns in response
            if !diff.new_patterns.is_empty() {
                for pattern in &diff.new_patterns {
                    if self.is_suspicious_pattern(pattern) {
                        let finding = InjectionTestResult {
                            category: self.category,
                            parameter: result.parameter.clone(),
                            location: result.location,
                            payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                            detection_method: DetectionMethod::Differential,
                            confidence: 0.75,
                            severity: Severity::Medium,
                            evidence: InjectionEvidence {
                                original_request: Some(result.request.clone()),
                                triggering_response: result.response.clone(),
                                baseline_response: Some(baseline.clone()),
                                diff: Some(diff.clone()),
                                matched_patterns: vec![pattern.clone()],
                                timing_info: None,
                            },
                            reproducible_request: ReproducibleRequest {
                                method: result.request.method.clone(),
                                url: result.request.url.clone(),
                                headers: result.request.headers.clone(),
                                body: result.request.body.clone(),
                                parameter: result.parameter.clone(),
                                payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                                location: result.location,
                            },
                            verification_steps: vec![
                                "Verify the new pattern is reproducible".to_string(),
                                "Analyze the pattern for sensitive data exposure".to_string(),
                            ],
                            tags: vec!["differential".to_string(), "new-pattern".to_string()],
                        };
                        
                        findings.push(finding);
                    }
                }
            }
        }
        
        findings
    }
    
    /// Check for pattern matches
    fn check_patterns(&self, result: &TestResult) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body = &result.response.body;
        
        // Category-specific pattern checks
        match self.category {
            InjectionCategory::SqlInjection => {
                findings.extend(self.check_sql_patterns(result, body));
            }
            InjectionCategory::Xss => {
                findings.extend(self.check_xss_patterns(result, body));
            }
            InjectionCategory::Ssti => {
                findings.extend(self.check_ssti_patterns(result, body));
            }
            InjectionCategory::CommandInjection => {
                findings.extend(self.check_cmd_patterns(result, body));
            }
            InjectionCategory::Xxe => {
                findings.extend(self.check_xxe_patterns(result, body));
            }
            InjectionCategory::LdapInjection => {
                findings.extend(self.check_ldap_patterns(result, body));
            }
            InjectionCategory::XPathInjection => {
                findings.extend(self.check_xpath_patterns(result, body));
            }
            InjectionCategory::HeaderInjection => {
                findings.extend(self.check_header_patterns(result, body));
            }
            _ => {}
        }
        
        findings
    }
    
    /// Check SQL-specific patterns
    fn check_sql_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let sql_patterns = [
            (r"(?i)union.*select", "UNION SELECT detected"),
            (r"(?i)select.*from.*information_schema", "Information schema access"),
            (r"(?i)select.*from.*sys\.", "System table access"),
            (r"(?i)select.*from.*mysql\.", "MySQL system table access"),
            (r"(?i)select.*from.*pg_", "PostgreSQL system catalog access"),
            (r"(?i)waitfor.*delay", "WAITFOR DELAY detected"),
            (r"(?i)pg_sleep", "pg_sleep detected"),
            (r"(?i)benchmark\s*\(", "BENCHMARK function detected"),
            (r"(?i)sleep\s*\(", "SLEEP function detected"),
        ];
        
        for (pattern, desc) in &sql_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(body)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.85,
                    severity: Severity::High,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the pattern is reproducible".to_string(),
                        "Attempt to extract data using the identified technique".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "sql-injection".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check XSS-specific patterns
    fn check_xss_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let xss_patterns = [
            (r"<script[^>]*>.*alert\s*\(", "Script tag with alert"),
            (r"<img[^>]+onerror\s*=", "Image onerror handler"),
            (r"<svg[^>]+onload\s*=", "SVG onload handler"),
            (r"on\w+\s*=\s*[\"']?\s*alert\s*\(", "Event handler with alert"),
            (r"javascript\s*:", "JavaScript protocol"),
            (r"vbscript\s*:", "VBScript protocol"),
            (r"data\s*:\s*text/html", "Data URI with HTML"),
            (r"expression\s*\(", "CSS expression"),
        ];
        
        for (pattern, desc) in &xss_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.9,
                    severity: Severity::High,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the XSS payload executes in a browser context".to_string(),
                        "Check if CSP or other mitigations prevent execution".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "xss".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check SSTI-specific patterns
    fn check_ssti_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let ssti_patterns = [
            (r"49", "7*7=49 detected (Jinja2/Twig/Freemarker)"),
            (r"__class__", "Python class attribute exposure"),
            (r"__mro__", "Python MRO exposure"),
            (r"__subclasses__", "Python subclass enumeration"),
            (r"java\.lang\.runtime", "Java Runtime class exposure"),
            (r"processbuilder", "Java ProcessBuilder exposure"),
            (r"freemarker\.template", "Freemarker template exposure"),
            (r"velocity\.context", "Velocity context exposure"),
        ];
        
        for (pattern, desc) in &ssti_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.9,
                    severity: Severity::Critical,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the template engine is identified correctly".to_string(),
                        "Test with non-destructive payloads first".to_string(),
                        "Check for RCE potential via template engine features".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "ssti".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check command injection patterns
    fn check_cmd_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let cmd_patterns = [
            (r"uid=\d+\(.*\)", "Linux id command output"),
            (r"gid=\d+\(.*\)", "Linux gid output"),
            (r"root:", "Root user in /etc/passwd"),
            (r"\[.*\]\s*#", "Root shell prompt"),
            (r"c:\\windows", "Windows directory listing"),
            (r"volume serial number", "Windows volume info"),
            (r"directory of", "Windows directory output"),
        ];
        
        for (pattern, desc) in &cmd_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.9,
                    severity: Severity::Critical,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the command output is reproducible".to_string(),
                        "Test with different commands to confirm RCE".to_string(),
                        "Check for privilege escalation possibilities".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "command-injection".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check XXE patterns
    fn check_xxe_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let xxe_patterns = [
            (r"root:x:\d+:\d+:", "/etc/passwd content"),
            (r"\[fonts\]", "Windows win.ini content"),
            (r"for 16-bit app support", "Windows win.ini content"),
            (r"amazonaws\.com", "AWS metadata exposure"),
            (r"169\.254\.169\.254", "Metadata service IP"),
        ];
        
        for (pattern, desc) in &xxe_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.95,
                    severity: Severity::Critical,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the file read is reproducible".to_string(),
                        "Test for SSRF via XXE".to_string(),
                        "Check for internal network access".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "xxe".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check LDAP injection patterns
    fn check_ldap_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let ldap_patterns = [
            (r"(?i)ldap.*search.*result", "LDAP search result exposure"),
            (r"(?i)cn=.*ou=.*dc=", "LDAP DN structure exposure"),
            (r"(?i)objectclass=", "LDAP objectClass exposure"),
            (r"(?i)uid=.*ou=.*dc=", "LDAP user DN exposure"),
            (r"(?i)ldap.*bind.*success", "LDAP bind success"),
            (r"(?i)authentication.*success", "Authentication success"),
        ];
        
        for (pattern, desc) in &ldap_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.85,
                    severity: Severity::High,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the LDAP data exposure is reproducible".to_string(),
                        "Check if authentication bypass is possible".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "ldap-injection".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check XPath injection patterns
    fn check_xpath_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let xpath_patterns = [
            (r"(?i)xpath.*result", "XPath query result exposure"),
            (r"(?i)node.*set", "XPath node set exposure"),
            (r"(?i)xml.*document", "XML document structure exposure"),
            (r"(?i)element.*name", "XML element name exposure"),
            (r"(?i)attribute.*value", "XML attribute value exposure"),
        ];
        
        for (pattern, desc) in &xpath_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.85,
                    severity: Severity::High,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the XPath data exposure is reproducible".to_string(),
                        "Check if XML structure can be enumerated".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "xpath-injection".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Check Header injection patterns
    fn check_header_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
        let mut findings = Vec::new();
        let body_lower = body.to_lowercase();
        
        let header_patterns = [
            (r"(?i)set-cookie.*\r\n", "Set-Cookie header injection"),
            (r"(?i)location.*\r\n", "Location header injection"),
            (r"(?i)content-length.*\r\n", "Content-Length header injection"),
            (r"(?i)transfer-encoding.*\r\n", "Transfer-Encoding header injection"),
            (r"(?i)x-forwarded-for.*\r\n", "X-Forwarded-For header injection"),
            (r"(?i)cache-control.*\r\n", "Cache-Control header injection"),
        ];
        
        for (pattern, desc) in &header_patterns {
            if regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
                let finding = InjectionTestResult {
                    category: self.category,
                    parameter: result.parameter.clone(),
                    location: result.location,
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    detection_method: DetectionMethod::PatternMatch,
                    confidence: 0.9,
                    severity: Severity::High,
                    evidence: InjectionEvidence {
                        original_request: Some(result.request.clone()),
                        triggering_response: result.response.clone(),
                        baseline_response: result.baseline_response.clone(),
                        diff: None,
                        matched_patterns: vec![pattern.to_string()],
                        timing_info: None,
                    },
                    reproducible_request: ReproducibleRequest {
                        method: result.request.method.clone(),
                        url: result.request.url.clone(),
                        headers: result.request.headers.clone(),
                        body: result.request.body.clone(),
                        parameter: result.parameter.clone(),
                        payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                        location: result.location,
                    },
                    verification_steps: vec![
                        "Verify the header injection is reproducible".to_string(),
                        "Check for response splitting or cache poisoning".to_string(),
                    ],
                    tags: vec!["pattern-match".to_string(), "header-injection".to_string()],
                };
                
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Compute diff between two responses
    fn compute_diff(&self, baseline: &HttpResponseSnapshot, test: &HttpResponseSnapshot) -> ResponseDiff {
        let status_changed = baseline.status != test.status;
        let length_diff = test.body_length as i64 - baseline.body_length as i64;
        
        // Header changes
        let mut header_changes = Vec::new();
        let all_keys: std::collections::HashSet<_> = baseline.headers.keys().chain(test.headers.keys()).collect();
        for key in all_keys {
            let old = baseline.headers.get(key).cloned();
            let new = test.headers.get(key).cloned();
            if old != new {
                header_changes.push(crate::injection::mod::HeaderChange {
                    name: key.clone(),
                    old_value: old,
                    new_value: new,
                });
            }
        }
        
        // Body similarity (simple Jaccard-like)
        let baseline_words: std::collections::HashSet<_> = baseline.body.split_whitespace().collect();
        let test_words: std::collections::HashSet<_> = test.body.split_whitespace().collect();
        let intersection = baseline_words.intersection(&test_words).count();
        let union = baseline_words.union(&test_words).count();
        let body_similarity = if union > 0 { intersection as f64 / union as f64 } else { 1.0 };
        
        // New patterns (simplified - words in test but not in baseline)
        let new_patterns: Vec<String> = test_words.difference(&baseline_words)
            .take(10)
            .map(|s| s.to_string())
            .collect();
        
        let removed_patterns: Vec<String> = baseline_words.difference(&test_words)
            .take(10)
            .map(|s| s.to_string())
            .collect();
        
        ResponseDiff {
            status_changed,
            length_diff,
            header_changes,
            body_similarity,
            new_patterns,
            removed_patterns,
        }
    }
    
    /// Check if a pattern is suspicious
    fn is_suspicious_pattern(&self, pattern: &str) -> bool {
        let suspicious = [
            "password", "secret", "token", "key", "api", "auth", "credential",
            "database", "connection", "query", "select", "insert", "update", "delete",
            "admin", "root", "uid", "gid", "passwd", "shadow", "config",
        ];
        
        let pattern_lower = pattern.to_lowercase();
        suspicious.iter().any(|s| pattern_lower.contains(s))
    }
}

impl ResponseAnalyzer for BuiltinResponseAnalyzer {
    fn analyze(&self, result: &TestResult, baseline: Option<&HttpResponseSnapshot>) -> Vec<InjectionTestResult> {
        self.analyze_response(result, baseline)
    }
    
    fn supported_methods(&self) -> Vec<DetectionMethod> {
        vec![
            DetectionMethod::ErrorBased,
            DetectionMethod::BooleanBased,
            DetectionMethod::TimeBased,
            DetectionMethod::Reflection,
            DetectionMethod::PatternMatch,
            DetectionMethod::Differential,
        ]
    }
    
    fn category(&self) -> InjectionCategory {
        self.category
    }
}

/// Error pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorPattern {
    pattern: String,
    description: String,
    severity: Severity,
    detection_method: DetectionMethod,
}

/// Reproducible request for findings
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReproducibleRequest {
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    parameter: String,
    payload: String,
    location: ParameterLocation,
}

/// Factory for creating response analyzers
pub fn create_response_analyzer(category: InjectionCategory) -> Box<dyn ResponseAnalyzer> {
    Box::new(BuiltinResponseAnalyzer::new(category))
}