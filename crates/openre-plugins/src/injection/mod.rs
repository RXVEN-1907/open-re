//! Injection Testing Framework
//!
//! A modular, safe, and extensible framework for injection vulnerability testing.
//! Provides shared components for payload generation, request mutation, response analysis,
//! and confidence scoring across all injection vulnerability types.

pub mod payload_engine;
pub mod request_engine;
pub mod response_analyzer;
pub mod confidence_scoring;
pub mod safety_controls;
pub mod injection_plugin;

use openre_core::ids::PluginId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base configuration for all injection plugins
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InjectionPluginConfig {
    /// Plugin-specific settings
    pub settings: HashMap<String, serde_json::Value>,
    /// Enable/disable specific test categories
    pub enabled_tests: Vec<String>,
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
    /// Safety controls
    pub safety: SafetyConfig,
}

impl Default for InjectionPluginConfig {
    fn default() -> Self {
        let mut settings = HashMap::new();
        settings.insert("aggressive_mode".to_string(), serde_json::json!(false));
        settings.insert("verify_ssl".to_string(), serde_json::json!(true));
        
        Self {
            settings,
            enabled_checks: vec![],
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-injection-tester/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            safety: SafetyConfig::default(),
        }
    }
}

/// Safety configuration for injection testing
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SafetyConfig {
    /// Maximum requests per test
    pub max_requests_per_test: usize,
    /// Maximum total requests per scan
    pub max_total_requests: usize,
    /// Request rate limit (requests per second)
    pub rate_limit_rps: f64,
    /// Maximum payload count per parameter
    pub max_payloads_per_param: usize,
    /// Maximum concurrency
    pub max_concurrency: usize,
    /// Request timeout in seconds
    pub request_timeout_secs: u64,
    /// Allowed target scopes (for scope enforcement)
    pub allowed_scopes: Vec<String>,
    /// Blocked payloads (dangerous patterns)
    pub blocked_patterns: Vec<String>,
    /// Require explicit authorization
    pub require_authorization: bool,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            max_requests_per_test: 100,
            max_total_requests: 10000,
            rate_limit_rps: 10.0,
            max_payloads_per_param: 50,
            max_concurrency: 5,
            request_timeout_secs: 30,
            allowed_scopes: vec![],
            blocked_patterns: vec![
                "DROP TABLE".to_string(),
                "DELETE FROM".to_string(),
                "TRUNCATE".to_string(),
                "SHUTDOWN".to_string(),
                "REBOOT".to_string(),
                "rm -rf".to_string(),
                "format".to_string(),
                "mkfs".to_string(),
            ],
            require_authorization: true,
        }
    }
}

/// Injection test category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionCategory {
    /// SQL Injection
    SqlInjection,
    /// NoSQL Injection
    NoSqlInjection,
    /// Cross-Site Scripting
    Xss,
    /// Server-Side Template Injection
    Ssti,
    /// Command Injection
    CommandInjection,
    /// XML External Entity
    Xxe,
    /// LDAP Injection
    LdapInjection,
    /// XPath Injection
    XPathInjection,
    /// Header Injection
    HeaderInjection,
    /// Custom category
    Custom,
}

/// Injection test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionTestResult {
    /// Test category
    pub category: InjectionCategory,
    /// Parameter tested
    pub parameter: String,
    /// Parameter location (query, body, header, cookie)
    pub location: ParameterLocation,
    /// Payload that triggered the finding
    pub payload: String,
    /// Detection method used
    pub detection_method: DetectionMethod,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Severity
    pub severity: Severity,
    /// Evidence
    pub evidence: InjectionEvidence,
    /// Reproducible request
    pub reproducible_request: ReproducibleRequest,
    /// Verification steps
    pub verification_steps: Vec<String>,
    /// Tags
    pub tags: Vec<String>,
}

/// Parameter location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterLocation {
    Query,
    Body,
    JsonBody,
    XmlBody,
    MultipartForm,
    Header,
    Cookie,
    Path,
}

/// Detection method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    /// Error-based detection
    ErrorBased,
    /// Boolean-based blind detection
    BooleanBased,
    /// Time-based blind detection
    TimeBased,
    /// Reflection-based detection
    Reflection,
    /// Pattern matching
    PatternMatch,
    /// Differential analysis
    Differential,
    /// Out-of-band detection
    OutOfBand,
    /// Heuristic analysis
    Heuristic,
}

/// Severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Injection evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionEvidence {
    /// Original request
    pub original_request: Option<HttpRequestSnapshot>,
    /// Response that triggered detection
    pub triggering_response: HttpResponseSnapshot,
    /// Baseline response for comparison
    pub baseline_response: Option<HttpResponseSnapshot>,
    /// Diff between baseline and triggering response
    pub diff: Option<ResponseDiff>,
    /// Matched patterns
    pub matched_patterns: Vec<String>,
    /// Timing information (for time-based)
    pub timing_info: Option<TimingInfo>,
}

/// HTTP request snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestSnapshot {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// HTTP response snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseSnapshot {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub body_length: usize,
    pub response_time_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Response diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub length_diff: i64,
    pub header_changes: Vec<HeaderChange>,
    pub body_similarity: f64,
    pub new_patterns: Vec<String>,
    pub removed_patterns: Vec<String>,
}

/// Header change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderChange {
    pub name: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// Timing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingInfo {
    pub baseline_ms: u64,
    pub test_ms: u64,
    pub diff_ms: i64,
    pub threshold_ms: u64,
    pub is_significant: bool,
}

/// Reproducible request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibleRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub parameter: String,
    pub payload: String,
    pub location: ParameterLocation,
}

/// Common trait for all injection plugins
pub trait InjectionPlugin {
    /// Get the injection category
    fn injection_category(&self) -> InjectionCategory;
    
    /// Get the plugin's version
    fn version(&self) -> &'static str;
    
    /// Get the plugin's description
    fn description(&self) -> &'static str;
    
    /// Get the plugin's references
    fn references(&self) -> Vec<SecurityReference>;
    
    /// Validate the plugin configuration
    fn validate_config(&self, config: &InjectionPluginConfig) -> crate::sdk::Result<(), String>;
    
    /// Get payload engine for this injection type
    fn payload_engine(&self) -> Box<dyn PayloadEngine>;
    
    /// Get response analyzer for this injection type
    fn response_analyzer(&self) -> Box<dyn ResponseAnalyzer>;
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
            id: "A03:2021".to_string(),
            url: "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
            description: "OWASP Top 10 2021 - Injection".to_string(),
        },
        SecurityReference {
            ref_type: "CWE".to_string(),
            id: "CWE-89".to_string(),
            url: "https://cwe.mitre.org/data/definitions/89.html".to_string(),
            description: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')".to_string(),
        },
        SecurityReference {
            ref_type: "CWE".to_string(),
            id: "CWE-79".to_string(),
            url: "https://cwe.mitre.org/data/definitions/79.html".to_string(),
            description: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')".to_string(),
        },
    ]
}