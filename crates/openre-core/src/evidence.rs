//! Standardized Evidence Schema for findings with verification support

use crate::ids::{EvidenceId, FindingId, VerificationId};
use crate::result::{Confidence, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Comprehensive evidence for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    /// Finding this evidence belongs to
    pub finding_id: FindingId,
    /// Exact condition that triggered the finding
    pub trigger_condition: TriggerCondition,
    /// HTTP interaction that triggered the finding
    pub http_interaction: Option<HttpInteraction>,
    /// Analysis of the response that confirmed the finding
    pub response_analysis: ResponseAnalysis,
    /// Configuration extracted that proves the finding
    pub configuration_extracted: Option<ConfigurationEvidence>,
    /// Technology context when finding was discovered
    pub technology_context: TechnologyContext,
    /// Exact steps to reproduce the finding
    pub reproduction_steps: Vec<ReproductionStep>,
    /// Negative evidence (what was checked and was negative)
    pub negative_evidence: Vec<NegativeEvidence>,
    /// Evidence quality score (0.0 - 1.0)
    pub quality_score: f32,
    /// Evidence completeness (0.0 - 1.0)
    pub completeness: f32,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Exact condition that triggered a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TriggerCondition {
    /// Header missing
    HeaderMissing { header: String, expected: String },
    /// Header value matches pattern
    HeaderValue { header: String, value: String, pattern: String },
    /// Status code matches
    StatusCode { code: u16, expected_range: String },
    /// Body pattern matches
    BodyPattern { pattern: String, match_type: PatternType },
    /// Technology detected
    TechnologyDetected { technology: String, version: Option<String>, confidence: f32 },
    /// Parameter reflection detected
    ParameterReflection { param: String, location: ReflectionLocation },
    /// Authentication bypass successful
    AuthBypass { method: AuthBypassMethod, evidence: String },
    /// Information disclosure pattern
    InformationDisclosure { pattern: String, data_type: String },
    /// Injection successful
    InjectionSuccessful { payload: String, injection_type: InjectionType },
    /// File accessible
    FileAccessible { path: String, file_type: String },
    /// Custom trigger condition
    Custom { description: String, data: serde_json::Value },
}

/// Pattern matching types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    Regex,
    Substring,
    Exact,
    XPath,
    JsonPath,
    Custom,
}

/// Reflection locations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReflectionLocation {
    ResponseBody,
    ResponseHeader,
    LocationHeader,
    ErrorPage,
    JavaScript,
    Custom,
}

/// Authentication bypass methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthBypassMethod {
    SqlInjection,
    DefaultCredentials,
    SessionFixation,
    JwtAlgorithmConfusion,
    JwtNoneAlgorithm,
    PathTraversal,
    HorizontalPrivilegeEscalation,
    VerticalPrivilegeEscalation,
    BrokenAccessControl,
    Custom,
}

/// Injection types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InjectionType {
    Sql,
    NoSql,
    Command,
    Ldap,
    Xpath,
    Xss,
    Ssti,
    Xxe,
    Header,
    Custom,
}

/// HTTP interaction (request/response pair)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInteraction {
    /// Request that triggered the finding
    pub request: HttpRequestEvidence,
    /// Response that confirmed the finding
    pub response: HttpResponseEvidence,
    /// Timing information
    pub timings: TimingEvidence,
    /// TLS information
    pub tls_info: Option<TlsEvidence>,
    /// Sequence number if part of a multi-step interaction
    pub sequence: Option<u32>,
}

/// HTTP request evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestEvidence {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub query_params: HashMap<String, String>,
    pub path_params: HashMap<String, String>,
    pub cookies: HashMap<String, String>,
    pub size_bytes: Option<u64>,
    pub curl_command: Option<String>,
}

/// HTTP response evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseEvidence {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub size_bytes: Option<u64>,
    pub response_time_ms: Option<u64>,
    pub tls_info: Option<TlsEvidence>,
    pub redirected_from: Option<String>,
    pub redirected_to: Option<String>,
}

/// TLS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsEvidence {
    pub version: String,
    pub cipher_suite: String,
    pub certificate: Option<CertificateInfo>,
    pub ocsp_stapling: bool,
    pub hsts: bool,
    pub hpkp: bool,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub serial_number: String,
    pub fingerprint_sha256: String,
    pub san: Vec<String>,
    pub key_algorithm: String,
    pub key_size: u32,
    pub signature_algorithm: String,
}

/// Timing evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingEvidence {
    pub total_ms: u64,
    pub dns_ms: Option<u64>,
    pub connect_ms: Option<u64>,
    pub tls_handshake_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub download_ms: Option<u64>,
}

/// Analysis of response confirming the finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAnalysis {
    /// What in the response confirmed the finding
    pub confirmation_indicators: Vec<ConfirmationIndicator>,
    /// Extracted data (e.g., leaked information, error messages)
    pub extracted_data: Vec<ExtractedData>,
    /// Diff from baseline/expected response
    pub diff_from_baseline: Option<ResponseDiff>,
    /// Confidence in analysis (0.0 - 1.0)
    pub confidence: f32,
}

/// Indicators that confirm a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationIndicator {
    pub indicator_type: ConfirmationIndicatorType,
    pub description: String,
    pub location: String,
    pub matched_content: Option<String>,
    pub confidence: f32,
}

/// Types of confirmation indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationIndicatorType {
    ErrorMessage,
    StackTrace,
    VersionDisclosure,
    DataLeakage,
    BehaviorChange,
    HeaderPresent,
    HeaderAbsent,
    StatusCode,
    TimingAnomaly,
    ContentLengthAnomaly,
    Custom,
}

/// Extracted data from response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedData {
    pub data_type: ExtractedDataType,
    pub value: String,
    pub context: String,
    pub sensitivity: SensitivityLevel,
    pub pii_detected: bool,
}

/// Types of extracted data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractedDataType {
    Email,
    Phone,
    Ssn,
    CreditCard,
    ApiKey,
    Password,
    Token,
    SessionId,
    InternalIp,
    FilePath,
    DatabaseName,
    TableName,
    Version,
    Config,
    Custom,
}

/// Sensitivity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Response diff from baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseDiff {
    pub baseline_status: u16,
    pub current_status: u16,
    pub baseline_body_hash: String,
    pub current_body_hash: String,
    pub diff_summary: String,
    pub significant_changes: Vec<SignificantChange>,
}

/// Significant changes in response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignificantChange {
    pub change_type: ChangeType,
    pub location: String,
    pub baseline_value: Option<String>,
    pub current_value: Option<String>,
    pub impact: ChangeImpact,
}

/// Change types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
    StatusCodeChanged,
    HeaderAdded,
    HeaderRemoved,
    HeaderModified,
}

/// Change impact
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeImpact {
    Low,
    Medium,
    High,
    Critical,
}

/// Configuration evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationEvidence {
    pub config_type: ConfigType,
    pub config_source: ConfigSource,
    pub extracted_config: serde_json::Value,
    pub relevant_keys: Vec<String>,
    pub misconfigurations: Vec<Misconfiguration>,
}

/// Configuration types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigType {
    WebServer,
    Application,
    Database,
    Cache,
    LoadBalancer,
    Waf,
    Cdn,
    Dns,
    Ssl,
    Framework,
    Custom,
}

/// Configuration sources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    ExposedFile,
    ApiEndpoint,
    ErrorMessage,
    Header,
    Metadata,
    DefaultFile,
    BackupFile,
    GitRepository,
    Custom,
}

/// Misconfiguration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misconfiguration {
    pub key: String,
    pub current_value: serde_json::Value,
    pub recommended_value: serde_json::Value,
    pub severity: Severity,
    pub description: String,
    pub references: Vec<String>,
}

/// Technology context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyContext {
    pub technologies: Vec<TechnologyInfo>,
    pub framework: Option<FrameworkInfo>,
    pub server: Option<ServerInfo>,
    pub database: Option<DatabaseInfo>,
    pub cloud_provider: Option<CloudProviderInfo>,
}

/// Technology information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyInfo {
    pub name: String,
    pub version: Option<String>,
    pub category: String,
    pub confidence: f32,
    pub detection_method: String,
}

/// Framework information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkInfo {
    pub name: String,
    pub version: Option<String>,
    pub language: String,
    pub known_vulnerabilities: Vec<String>,
}

/// Server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: Option<String>,
    pub os: Option<String>,
    pub modules: Vec<String>,
}

/// Database information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfo {
    pub type_: String,
    pub version: Option<String>,
    pub exposed: bool,
}

/// Cloud provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderInfo {
    pub provider: String,
    pub region: Option<String>,
    pub services: Vec<String>,
}

/// Reproduction step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproductionStep {
    pub step_number: u32,
    pub description: String,
    pub action: ReproductionAction,
    pub expected_result: String,
    pub actual_result: Option<String>,
    pub prerequisites: Vec<String>,
    pub tools_required: Vec<String>,
    pub difficulty: ReproductionDifficulty,
    pub verified: bool,
}

/// Reproduction actions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReproductionAction {
    HttpRequest {
        method: String,
        url: String,
        headers: HashMap<String, String>,
        body: Option<String>,
    },
    CliCommand {
        command: String,
        args: Vec<String>,
    },
    BrowserAction {
        action: String,
        selector: String,
        value: Option<String>,
    },
    FileOperation {
        operation: String,
        path: String,
        content: Option<String>,
    },
    NetworkAction {
        action: String,
        target: String,
        params: HashMap<String, String>,
    },
    Custom {
        description: String,
    },
}

/// Reproduction difficulty
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionDifficulty {
    Trivial,
    Easy,
    Moderate,
    Difficult,
    VeryDifficult,
}

/// Negative evidence (what was checked and was negative)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegativeEvidence {
    pub check_performed: String,
    pub expected_if_vulnerable: String,
    pub actual_result: String,
    pub confidence_ruled_out: f32,
    pub check_type: NegativeCheckType,
}

/// Types of negative checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeCheckType {
    HeaderCheck,
    StatusCodeCheck,
    BodyPatternCheck,
    TimingCheck,
    ConfigurationCheck,
    VersionCheck,
    Custom,
}

/// Verification method for findings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Safe HTTP request to verify
    SafeRequest { method: String, path: String, expected_indicators: Vec<String> },
    /// Check for specific headers
    HeaderCheck { headers: Vec<String> },
    /// Check for specific status codes
    StatusCodeCheck { expected: Vec<u16> },
    /// Check for body patterns
    BodyPatternCheck { patterns: Vec<String> },
    /// Differential check (with/without auth, etc.)
    DifferentialCheck { baseline: String, modified: String },
    /// Configuration check
    ConfigurationCheck { config_key: String, expected: String },
    /// Version check
    VersionCheck { technology: String, min_version: String, max_version: Option<String> },
    /// Rate limit check
    RateLimitCheck { endpoint: String, requests: u32, window_seconds: u32 },
    /// CORS check
    CorsCheck { origins: Vec<String>, endpoint: String },
    /// Directory listing check
    DirectoryListingCheck { path: String },
    /// Authentication check
    AuthenticationCheck { method: String, endpoint: String },
    /// SSL/TLS check
    SslTlsCheck { endpoint: String },
    /// Custom verification method
    Custom { description: String, script: String },
}

impl std::fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationMethod::SafeRequest { method, path, .. } => {
                write!(f, "SafeRequest({} {})", method, path)
            }
            VerificationMethod::HeaderCheck { headers } => {
                write!(f, "HeaderCheck({})", headers.join(", "))
            }
            VerificationMethod::StatusCodeCheck { expected } => {
                write!(f, "StatusCodeCheck({:?})", expected)
            }
            VerificationMethod::BodyPatternCheck { patterns } => {
                write!(f, "BodyPatternCheck({})", patterns.join(", "))
            }
            VerificationMethod::DifferentialCheck { baseline, modified } => {
                write!(f, "DifferentialCheck({} vs {})", baseline, modified)
            }
            VerificationMethod::ConfigurationCheck { config_key, expected } => {
                write!(f, "ConfigurationCheck({}={})", config_key, expected)
            }
            VerificationMethod::VersionCheck { technology, min_version, max_version } => write!(
                f,
                "VersionCheck({}>={}{})",
                technology,
                min_version,
                max_version.as_ref().map(|v| format!("<{}", v)).unwrap_or_default()
            ),
            VerificationMethod::RateLimitCheck { endpoint, requests, window_seconds } => {
                write!(f, "RateLimitCheck({} {} req/{}s)", endpoint, requests, window_seconds)
            }
            VerificationMethod::CorsCheck { origins, endpoint } => {
                write!(f, "CorsCheck({} on {})", origins.join(", "), endpoint)
            }
            VerificationMethod::DirectoryListingCheck { path } => {
                write!(f, "DirectoryListingCheck({})", path)
            }
            VerificationMethod::AuthenticationCheck { method, endpoint } => {
                write!(f, "AuthenticationCheck({} on {})", method, endpoint)
            }
            VerificationMethod::SslTlsCheck { endpoint } => write!(f, "SslTlsCheck({})", endpoint),
            VerificationMethod::Custom { description, .. } => write!(f, "Custom({})", description),
        }
    }
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verification_id: VerificationId,
    pub finding_id: FindingId,
    pub status: VerificationStatus,
    pub evidence: VerificationEvidence,
    pub confidence: f32,
    pub notes: String,
    pub verified_at: DateTime<Utc>,
    pub verified_by: String,
    pub method_used: VerificationMethod,
    pub duration_ms: u64,
}

/// Verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Verification succeeded, finding is real
    Confirmed,
    /// Strong indicators but not definitive
    Likely,
    /// Could not verify (e.g., need auth, rate limited)
    Unconfirmed,
    /// Verification failed, finding may be false positive
    NotReproducible,
    /// Verification error (network, timeout, etc.)
    Error,
    /// Verification skipped
    Skipped,
}

/// Evidence from verification
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerificationEvidence {
    pub http_interaction: Option<HttpInteraction>,
    pub response_analysis: Option<ResponseAnalysis>,
    pub configuration_extracted: Option<ConfigurationEvidence>,
    pub differential_results: Option<DifferentialResults>,
    pub screenshots: Vec<String>,
    pub logs: Vec<String>,
}

impl VerificationEvidence {
    /// Create an empty verification evidence
    pub fn default_empty() -> Self {
        Self::default()
    }
}

/// Differential check results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifferentialResults {
    pub baseline_response: HttpResponseEvidence,
    pub modified_response: HttpResponseEvidence,
    pub differences: Vec<SignificantChange>,
    pub conclusion: String,
}

/// Verifier trait for implementing finding verifiers
pub trait FindingVerifier: Send + Sync {
    /// Check if this verifier can verify the given finding
    fn can_verify(&self, finding: &crate::result::Finding) -> bool;

    /// Get the verification method used
    fn verification_method(&self) -> VerificationMethod;

    /// Perform verification (returns a future)
    fn verify<'a>(
        &'a self,
        finding: &'a crate::result::Finding,
        client: &'a reqwest::Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>;
}

/// Blanket implementation for Box<dyn FindingVerifier>
impl FindingVerifier for Box<dyn FindingVerifier> {
    fn can_verify(&self, finding: &crate::result::Finding) -> bool {
        self.as_ref().can_verify(finding)
    }

    fn verification_method(&self) -> VerificationMethod {
        self.as_ref().verification_method()
    }

    fn verify<'a>(
        &'a self,
        finding: &'a crate::result::Finding,
        client: &'a reqwest::Client,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>> {
        self.as_ref().verify(finding, client)
    }
}

/// Built-in verifiers for common finding types
pub mod builtin_verifiers {
    use super::*;
    use crate::result::{Category, Finding};
    use reqwest::Client;
    use std::collections::HashMap;

    /// Verifier for security headers (HSTS, CSP, X-Frame-Options, etc.)
    pub struct SecurityHeaderVerifier;

    impl FindingVerifier for SecurityHeaderVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            matches!(
                finding.category,
                Category::SecurityMisconfiguration | Category::InformationDisclosure
            ) && finding.title.to_lowercase().contains("header")
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::HeaderCheck {
                headers: vec![
                    "strict-transport-security".to_string(),
                    "content-security-policy".to_string(),
                    "x-frame-options".to_string(),
                    "x-content-type-options".to_string(),
                    "referrer-policy".to_string(),
                    "permissions-policy".to_string(),
                ],
            }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                let target = &finding.target;
                let start = std::time::Instant::now();

                match client.head(target).send().await {
                    Ok(response) => {
                        let headers: HashMap<String, String> = response
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                            .collect();

                        let mut missing = Vec::new();
                        let mut present = Vec::new();

                        for header in &[
                            "strict-transport-security",
                            "content-security-policy",
                            "x-frame-options",
                            "x-content-type-options",
                        ] {
                            if headers.contains_key(*header) {
                                present.push(header.to_string());
                            } else {
                                missing.push(header.to_string());
                            }
                        }

                        let status = if missing.is_empty() {
                            VerificationStatus::NotReproducible // Header present, finding may be FP
                        } else if missing.len() >= 2 {
                            VerificationStatus::Confirmed // Multiple headers missing
                        } else {
                            VerificationStatus::Likely // One header missing
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
                                        status_code: response.status().as_u16(),
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
                            notes: format!("Missing headers: {:?}", missing),
                            verified_at: Utc::now(),
                            verified_by: "SecurityHeaderVerifier".to_string(),
                            method_used: self.verification_method(),
                            duration_ms: start.elapsed().as_millis() as u64,
                        }
                    }
                    Err(e) => VerificationResult {
                        verification_id: VerificationId::new(),
                        finding_id: finding.id,
                        status: VerificationStatus::Error,
                        evidence: VerificationEvidence {
                            http_interaction: None,
                            response_analysis: None,
                            configuration_extracted: None,
                            differential_results: None,
                            screenshots: Vec::new(),
                            logs: vec![e.to_string()],
                        },
                        confidence: 0.0,
                        notes: format!("Verification failed: {}", e),
                        verified_at: Utc::now(),
                        verified_by: "SecurityHeaderVerifier".to_string(),
                        method_used: self.verification_method(),
                        duration_ms: start.elapsed().as_millis() as u64,
                    },
                }
            })
        }
    }

    /// Verifier for information disclosure
    pub struct InfoDisclosureVerifier;

    impl FindingVerifier for InfoDisclosureVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            finding.category == Category::InformationDisclosure
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::SafeRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                expected_indicators: vec![
                    "server".to_string(),
                    "x-powered-by".to_string(),
                    "version".to_string(),
                    ".git".to_string(),
                    "directory listing".to_string(),
                ],
            }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                // Simplified implementation
                VerificationResult {
                    verification_id: VerificationId::new(),
                    finding_id: finding.id,
                    status: VerificationStatus::Unconfirmed,
                    evidence: VerificationEvidence {
                        http_interaction: None,
                        response_analysis: None,
                        configuration_extracted: None,
                        differential_results: None,
                        screenshots: Vec::new(),
                        logs: Vec::new(),
                    },
                    confidence: 0.5,
                    notes: "Info disclosure verification requires specific implementation"
                        .to_string(),
                    verified_at: Utc::now(),
                    verified_by: "InfoDisclosureVerifier".to_string(),
                    method_used: self.verification_method(),
                    duration_ms: 0,
                }
            })
        }
    }

    /// Verifier for technology detection
    pub struct TechnologyVerifier;

    impl FindingVerifier for TechnologyVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            finding.category == Category::SecurityMisconfiguration
                && finding.title.to_lowercase().contains("technology")
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::SafeRequest {
                method: "GET".to_string(),
                path: "/".to_string(),
                expected_indicators: vec!["server".to_string(), "x-powered-by".to_string()],
            }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                VerificationResult {
                    verification_id: VerificationId::new(),
                    finding_id: finding.id,
                    status: VerificationStatus::Unconfirmed,
                    evidence: VerificationEvidence {
                        http_interaction: None,
                        response_analysis: None,
                        configuration_extracted: None,
                        differential_results: None,
                        screenshots: Vec::new(),
                        logs: Vec::new(),
                    },
                    confidence: 0.5,
                    notes: "Technology verification requires specific implementation".to_string(),
                    verified_at: Utc::now(),
                    verified_by: "TechnologyVerifier".to_string(),
                    method_used: self.verification_method(),
                    duration_ms: 0,
                }
            })
        }
    }

    /// Verifier for authentication issues
    pub struct AuthVerifier;

    impl FindingVerifier for AuthVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            matches!(
                finding.category,
                Category::BrokenAuthentication | Category::BrokenAccessControl
            )
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::DifferentialCheck {
                baseline: "with_auth".to_string(),
                modified: "without_auth".to_string(),
            }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                VerificationResult {
                    verification_id: VerificationId::new(),
                    finding_id: finding.id,
                    status: VerificationStatus::Unconfirmed,
                    evidence: VerificationEvidence {
                        http_interaction: None,
                        response_analysis: None,
                        configuration_extracted: None,
                        differential_results: None,
                        screenshots: Vec::new(),
                        logs: Vec::new(),
                    },
                    confidence: 0.5,
                    notes: "Auth verification requires specific implementation".to_string(),
                    verified_at: Utc::now(),
                    verified_by: "AuthVerifier".to_string(),
                    method_used: self.verification_method(),
                    duration_ms: 0,
                }
            })
        }
    }

    /// Verifier for rate limiting
    pub struct RateLimitVerifier;

    impl FindingVerifier for RateLimitVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            finding.title.to_lowercase().contains("rate limit")
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::RateLimitCheck {
                endpoint: "/".to_string(),
                requests: 20,
                window_seconds: 60,
            }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                VerificationResult {
                    verification_id: VerificationId::new(),
                    finding_id: finding.id,
                    status: VerificationStatus::Unconfirmed,
                    evidence: VerificationEvidence {
                        http_interaction: None,
                        response_analysis: None,
                        configuration_extracted: None,
                        differential_results: None,
                        screenshots: Vec::new(),
                        logs: Vec::new(),
                    },
                    confidence: 0.5,
                    notes: "Rate limit verification requires specific implementation".to_string(),
                    verified_at: Utc::now(),
                    verified_by: "RateLimitVerifier".to_string(),
                    method_used: self.verification_method(),
                    duration_ms: 0,
                }
            })
        }
    }

    /// Verifier for directory listing
    pub struct DirectoryListingVerifier;

    impl FindingVerifier for DirectoryListingVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            finding.title.to_lowercase().contains("directory")
                || finding.title.to_lowercase().contains("listing")
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::DirectoryListingCheck { path: "/".to_string() }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                VerificationResult {
                    verification_id: VerificationId::new(),
                    finding_id: finding.id,
                    status: VerificationStatus::Unconfirmed,
                    evidence: VerificationEvidence {
                        http_interaction: None,
                        response_analysis: None,
                        configuration_extracted: None,
                        differential_results: None,
                        screenshots: Vec::new(),
                        logs: Vec::new(),
                    },
                    confidence: 0.5,
                    notes: "Directory listing verification requires specific implementation"
                        .to_string(),
                    verified_at: Utc::now(),
                    verified_by: "DirectoryListingVerifier".to_string(),
                    method_used: self.verification_method(),
                    duration_ms: 0,
                }
            })
        }
    }

    /// Verifier for CORS
    pub struct CorsVerifier;

    impl FindingVerifier for CorsVerifier {
        fn can_verify(&self, finding: &Finding) -> bool {
            finding.title.to_lowercase().contains("cors")
        }

        fn verification_method(&self) -> VerificationMethod {
            VerificationMethod::CorsCheck {
                origins: vec!["https://evil.com".to_string()],
                endpoint: "/".to_string(),
            }
        }

        fn verify<'a>(
            &'a self,
            finding: &'a Finding,
            client: &'a Client,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = VerificationResult> + Send + 'a>>
        {
            Box::pin(async move {
                VerificationResult {
                    verification_id: VerificationId::new(),
                    finding_id: finding.id,
                    status: VerificationStatus::Unconfirmed,
                    evidence: VerificationEvidence {
                        http_interaction: None,
                        response_analysis: None,
                        configuration_extracted: None,
                        differential_results: None,
                        screenshots: Vec::new(),
                        logs: Vec::new(),
                    },
                    confidence: 0.5,
                    notes: "CORS verification requires specific implementation".to_string(),
                    verified_at: Utc::now(),
                    verified_by: "CorsVerifier".to_string(),
                    method_used: self.verification_method(),
                    duration_ms: 0,
                }
            })
        }
    }

    /// Get all built-in verifiers
    pub fn get_all_verifiers() -> Vec<Box<dyn FindingVerifier>> {
        vec![
            Box::new(SecurityHeaderVerifier),
            Box::new(InfoDisclosureVerifier),
            Box::new(TechnologyVerifier),
            Box::new(AuthVerifier),
            Box::new(RateLimitVerifier),
            Box::new(DirectoryListingVerifier),
            Box::new(CorsVerifier),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{EvidenceId, FindingId, VerificationId};
    use crate::result::{Category, Confidence, Finding, Severity};
    use chrono::Utc;
    use std::collections::HashMap;

    #[test]
    fn test_finding_evidence_creation() {
        let evidence = FindingEvidence {
            finding_id: FindingId::new(),
            trigger_condition: TriggerCondition::HeaderMissing {
                header: "Content-Security-Policy".to_string(),
                expected: "default-src 'self'".to_string(),
            },
            http_interaction: None,
            response_analysis: ResponseAnalysis {
                confirmation_indicators: vec![],
                extracted_data: vec![],
                diff_from_baseline: None,
                confidence: 0.9,
            },
            configuration_extracted: None,
            technology_context: TechnologyContext {
                technologies: vec![],
                framework: None,
                server: None,
                database: None,
                cloud_provider: None,
            },
            reproduction_steps: vec![],
            negative_evidence: vec![],
            quality_score: 0.8,
            completeness: 0.7,
            timestamp: Utc::now(),
        };

        assert_eq!(evidence.quality_score, 0.8);
        assert_eq!(evidence.completeness, 0.7);
    }

    #[test]
    fn test_trigger_conditions() {
        let conditions = vec![
            TriggerCondition::HeaderMissing {
                header: "X-Frame-Options".to_string(),
                expected: "DENY".to_string(),
            },
            TriggerCondition::BodyPattern {
                pattern: "SQL syntax error".to_string(),
                match_type: PatternType::Substring,
            },
            TriggerCondition::TechnologyDetected {
                technology: "Apache".to_string(),
                version: Some("2.4.41".to_string()),
                confidence: 0.95,
            },
            TriggerCondition::ParameterReflection {
                param: "search".to_string(),
                location: ReflectionLocation::ResponseBody,
            },
        ];

        for condition in conditions {
            let json = serde_json::to_string(&condition).unwrap();
            let deserialized: TriggerCondition = serde_json::from_str(&json).unwrap();
            // Just verify serialization works
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_verification_methods() {
        let methods = vec![
            VerificationMethod::SafeRequest {
                method: "GET".to_string(),
                path: "/test".to_string(),
                expected_indicators: vec!["test".to_string()],
            },
            VerificationMethod::HeaderCheck { headers: vec!["server".to_string()] },
            VerificationMethod::StatusCodeCheck { expected: vec![200, 404] },
            VerificationMethod::BodyPatternCheck { patterns: vec!["error".to_string()] },
            VerificationMethod::DifferentialCheck {
                baseline: "with_auth".to_string(),
                modified: "without_auth".to_string(),
            },
        ];

        for method in methods {
            let json = serde_json::to_string(&method).unwrap();
            let deserialized: VerificationMethod = serde_json::from_str(&json).unwrap();
            assert!(!json.is_empty());
        }
    }

    #[test]
    fn test_verification_result() {
        let result = VerificationResult {
            verification_id: VerificationId::new(),
            finding_id: FindingId::new(),
            status: VerificationStatus::Confirmed,
            evidence: VerificationEvidence {
                http_interaction: None,
                response_analysis: None,
                configuration_extracted: None,
                differential_results: None,
                screenshots: Vec::new(),
                logs: Vec::new(),
            },
            confidence: 0.9,
            notes: "Verified".to_string(),
            verified_at: Utc::now(),
            verified_by: "test".to_string(),
            method_used: VerificationMethod::HeaderCheck { headers: vec!["server".to_string()] },
            duration_ms: 100,
        };

        assert_eq!(result.status, VerificationStatus::Confirmed);
        assert_eq!(result.confidence, 0.9);
    }
}
