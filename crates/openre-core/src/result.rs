//! Standardized finding model for all plugins

use crate::ids::{FindingId, ScanId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational - no direct security impact
    Info,
    /// Low severity - minor security issue
    Low,
    /// Medium severity - moderate security issue
    Medium,
    /// High severity - significant security issue
    High,
    /// Critical severity - severe security issue
    Critical,
}

impl Severity {
    /// Get numeric value for sorting
    pub fn value(&self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Get color for display
    pub fn color(&self) -> &'static str {
        match self {
            Severity::Info => "blue",
            Severity::Low => "green",
            Severity::Medium => "yellow",
            Severity::High => "orange",
            Severity::Critical => "red",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(format!("Invalid severity: {}", s)),
        }
    }
}

/// Confidence levels for findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Very low confidence - speculative
    VeryLow,
    /// Low confidence - weak evidence
    Low,
    /// Medium confidence - reasonable evidence
    Medium,
    /// High confidence - strong evidence
    High,
    /// Very high confidence - confirmed
    VeryHigh,
}

impl Confidence {
    /// Get numeric value for sorting
    pub fn value(&self) -> u8 {
        match self {
            Confidence::VeryLow => 0,
            Confidence::Low => 1,
            Confidence::Medium => 2,
            Confidence::High => 3,
            Confidence::VeryHigh => 4,
        }
    }

    /// Get percentage representation
    pub fn percentage(&self) -> u8 {
        match self {
            Confidence::VeryLow => 10,
            Confidence::Low => 30,
            Confidence::Medium => 50,
            Confidence::High => 80,
            Confidence::VeryHigh => 95,
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::VeryLow => write!(f, "very_low"),
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
            Confidence::VeryHigh => write!(f, "very_high"),
        }
    }
}

impl std::str::FromStr for Confidence {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "very_low" => Ok(Confidence::VeryLow),
            "low" => Ok(Confidence::Low),
            "medium" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            "very_high" => Ok(Confidence::VeryHigh),
            _ => Err(format!("Invalid confidence: {}", s)),
        }
    }
}

/// Finding categories
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Injection vulnerabilities
    Injection,
    /// Broken authentication
    BrokenAuthentication,
    /// Sensitive data exposure
    SensitiveDataExposure,
    /// XML External Entities
    Xxe,
    /// Broken access control
    BrokenAccessControl,
    /// Security misconfiguration
    SecurityMisconfiguration,
    /// Cross-site scripting
    Xss,
    /// Insecure deserialization
    InsecureDeserialization,
    /// Using components with known vulnerabilities
    VulnerableComponents,
    /// Insufficient logging and monitoring
    InsufficientLogging,
    /// Server-side request forgery
    Ssrf,
    /// Cross-site request forgery
    Csrf,
    /// Information disclosure
    InformationDisclosure,
    /// Denial of service
    DenialOfService,
    /// Business logic error
    BusinessLogic,
    /// Cryptographic issues
    Cryptographic,
    /// Configuration issue
    Configuration,
    /// Custom category
    Custom(String),
}

impl Category {
    /// Get OWASP Top 10 mapping
    pub fn owasp_category(&self) -> Option<&'static str> {
        match self {
            Category::Injection => Some("A03:2021 - Injection"),
            Category::BrokenAuthentication => {
                Some("A07:2021 - Identification and Authentication Failures")
            }
            Category::SensitiveDataExposure => Some("A02:2021 - Cryptographic Failures"),
            Category::Xxe => Some("A05:2021 - Security Misconfiguration"),
            Category::BrokenAccessControl => Some("A01:2021 - Broken Access Control"),
            Category::SecurityMisconfiguration => Some("A05:2021 - Security Misconfiguration"),
            Category::Xss => Some("A03:2021 - Injection"),
            Category::InsecureDeserialization => {
                Some("A08:2021 - Software and Data Integrity Failures")
            }
            Category::VulnerableComponents => Some("A06:2021 - Vulnerable and Outdated Components"),
            Category::InsufficientLogging => {
                Some("A09:2021 - Security Logging and Monitoring Failures")
            }
            Category::Ssrf => Some("A10:2021 - Server-Side Request Forgery"),
            _ => None,
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Custom(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl std::str::FromStr for Category {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "injection" => Ok(Category::Injection),
            "broken_authentication" => Ok(Category::BrokenAuthentication),
            "sensitive_data_exposure" => Ok(Category::SensitiveDataExposure),
            "xxe" => Ok(Category::Xxe),
            "broken_access_control" => Ok(Category::BrokenAccessControl),
            "security_misconfiguration" => Ok(Category::SecurityMisconfiguration),
            "xss" => Ok(Category::Xss),
            "insecure_deserialization" => Ok(Category::InsecureDeserialization),
            "vulnerable_components" => Ok(Category::VulnerableComponents),
            "insufficient_logging" => Ok(Category::InsufficientLogging),
            "ssrf" => Ok(Category::Ssrf),
            "csrf" => Ok(Category::Csrf),
            "information_disclosure" => Ok(Category::InformationDisclosure),
            "denial_of_service" => Ok(Category::DenialOfService),
            "business_logic" => Ok(Category::BusinessLogic),
            "cryptographic" => Ok(Category::Cryptographic),
            "configuration" => Ok(Category::Configuration),
            _ => Ok(Category::Custom(s.to_string())),
        }
    }
}

/// Evidence supporting a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Description of evidence
    pub description: String,
    /// Raw data (request/response, code snippet, etc.)
    pub data: Option<serde_json::Value>,
    /// Source location (file, line, URL, etc.)
    pub location: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// HTTP request details (when evidence_type is HttpRequest)
    pub http_request: Option<HttpRequestEvidence>,
    /// HTTP response details (when evidence_type is HttpResponse)
    pub http_response: Option<HttpResponseEvidence>,
    /// Timing information
    pub timing: Option<TimingEvidence>,
    /// Payload used to trigger the finding
    pub payload: Option<PayloadEvidence>,
    /// Reproduction steps
    pub reproduction_steps: Option<ReproductionSteps>,
    /// Plugin that generated this evidence
    pub plugin_source: Option<String>,
    /// Timestamp when evidence was captured
    pub timestamp: DateTime<Utc>,
}

impl Evidence {
    /// Create new evidence with minimal required fields
    pub fn new(evidence_type: EvidenceType, description: String) -> Self {
        Self {
            evidence_type,
            description,
            data: None,
            location: None,
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: None,
            timestamp: Utc::now(),
        }
    }
}

/// HTTP request evidence details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequestEvidence {
    /// HTTP method
    pub method: String,
    /// Full URL
    pub url: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Request body
    pub body: Option<String>,
    /// Query parameters
    pub query_params: HashMap<String, String>,
    /// Path parameters
    pub path_params: HashMap<String, String>,
    /// Cookies
    pub cookies: HashMap<String, String>,
    /// Request size in bytes
    pub size_bytes: Option<u64>,
}

/// HTTP response evidence details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponseEvidence {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: Option<String>,
    /// Response size in bytes
    pub size_bytes: Option<u64>,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// TLS information
    pub tls_info: Option<TlsInfo>,
}

/// TLS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    /// TLS version
    pub version: String,
    /// Cipher suite
    pub cipher_suite: String,
    /// Certificate info
    pub certificate: Option<CertificateInfo>,
}

/// Certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject
    pub subject: String,
    /// Issuer
    pub issuer: String,
    /// Valid from
    pub valid_from: DateTime<Utc>,
    /// Valid to
    pub valid_to: DateTime<Utc>,
    /// Serial number
    pub serial_number: String,
    /// Fingerprint (SHA256)
    pub fingerprint_sha256: String,
}

/// Timing evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingEvidence {
    /// Total request duration in milliseconds
    pub total_ms: u64,
    /// DNS resolution time in milliseconds
    pub dns_ms: Option<u64>,
    /// TCP connection time in milliseconds
    pub connect_ms: Option<u64>,
    /// TLS handshake time in milliseconds
    pub tls_handshake_ms: Option<u64>,
    /// Time to first byte in milliseconds
    pub ttfb_ms: Option<u64>,
    /// Content download time in milliseconds
    pub download_ms: Option<u64>,
}

/// Payload evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEvidence {
    /// The payload that was used
    pub payload: String,
    /// Payload type (e.g., "sql_injection", "xss", "path_traversal")
    pub payload_type: String,
    /// Encoding used (e.g., "url", "base64", "none")
    pub encoding: Option<String>,
    /// Parameter/location where payload was injected
    pub injection_point: String,
    /// Expected behavior
    pub expected_behavior: Option<String>,
    /// Actual behavior observed
    pub actual_behavior: Option<String>,
}

/// Reproduction steps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproductionSteps {
    /// Step-by-step instructions
    pub steps: Vec<String>,
    /// Prerequisites
    pub prerequisites: Vec<String>,
    /// Expected outcome
    pub expected_outcome: String,
    /// Actual outcome
    pub actual_outcome: String,
    /// Difficulty level
    pub difficulty: ReproductionDifficulty,
    /// Whether reproduction was verified
    pub verified: bool,
}

/// Reproduction difficulty
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReproductionDifficulty {
    /// Trivial to reproduce
    Trivial,
    /// Easy to reproduce
    Easy,
    /// Moderate difficulty
    Moderate,
    /// Difficult to reproduce
    Difficult,
    /// Very difficult / requires specific conditions
    VeryDifficult,
}

/// Type of evidence
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// HTTP request that triggered the finding
    HttpRequest,
    /// HTTP response showing the vulnerability
    HttpResponse,
    /// Code snippet
    CodeSnippet,
    /// Configuration file excerpt
    ConfigExcerpt,
    /// Log entry
    LogEntry,
    /// Screenshot
    Screenshot,
    /// Custom evidence type
    Custom(String),
}

impl std::fmt::Display for EvidenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceType::HttpRequest => write!(f, "HTTP Request"),
            EvidenceType::HttpResponse => write!(f, "HTTP Response"),
            EvidenceType::CodeSnippet => write!(f, "Code Snippet"),
            EvidenceType::ConfigExcerpt => write!(f, "Config Excerpt"),
            EvidenceType::LogEntry => write!(f, "Log Entry"),
            EvidenceType::Screenshot => write!(f, "Screenshot"),
            EvidenceType::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Reference to external resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reference {
    /// Reference type
    pub reference_type: ReferenceType,
    /// Title
    pub title: String,
    /// URL
    pub url: String,
    /// Description
    pub description: Option<String>,
}

/// Type of reference
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceType {
    /// CVE identifier
    Cve,
    /// CWE identifier
    Cwe,
    /// OWASP reference
    Owasp,
    /// Vendor advisory
    VendorAdvisory,
    /// Blog post or article
    Article,
    /// Documentation
    Documentation,
    /// Tool output
    ToolOutput,
    /// Custom reference
    Custom(String),
}

/// Standardized finding model - all plugins must return findings using this schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique finding ID
    pub id: FindingId,
    /// Finding title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: Severity,
    /// Confidence level
    pub confidence: Confidence,
    /// Finding category
    pub category: Category,
    /// Target that was scanned
    pub target: String,
    /// Target type
    pub target_type: String,
    /// Evidence supporting the finding
    pub evidence: Vec<Evidence>,
    /// External references
    pub references: Vec<Reference>,
    /// Plugin that discovered this finding
    pub plugin_source: String,
    /// Plugin version
    pub plugin_version: String,
    /// Timestamp when finding was discovered
    pub timestamp: DateTime<Utc>,
    /// Scan ID this finding belongs to
    pub scan_id: ScanId,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Whether finding has been verified
    pub verified: bool,
    /// False positive indicator
    pub false_positive: bool,
    /// Risk score (0-100)
    pub risk_score: Option<u8>,
    /// CVSS vector string (if applicable)
    pub cvss_vector: Option<String>,
    /// CVSS score (if applicable)
    pub cvss_score: Option<f32>,
    /// CWE identifiers
    pub cwe_ids: Vec<String>,
    /// CAPEC identifiers
    pub capec_ids: Vec<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_attack_ids: Vec<String>,
    /// OWASP Top 10 category
    pub owasp_category: Option<String>,
    /// Deduplication fingerprint
    pub fingerprint: Option<String>,
    /// Related finding IDs (for correlation)
    pub related_findings: Vec<FindingId>,
    /// Remediation guidance
    pub remediation: Option<RemediationGuidance>,
    /// Exploitability assessment
    pub exploitability: Option<ExploitabilityAssessment>,
    /// Business impact assessment
    pub business_impact: Option<BusinessImpactAssessment>,
}

/// Remediation guidance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationGuidance {
    /// Summary of remediation
    pub summary: String,
    /// Detailed steps
    pub steps: Vec<String>,
    /// Code examples (if applicable)
    pub code_examples: Vec<CodeExample>,
    /// References for remediation
    pub references: Vec<Reference>,
    /// Estimated effort
    pub effort: RemediationEffort,
    /// Priority
    pub priority: RemediationPriority,
}

/// Code example for remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    /// Language
    pub language: String,
    /// Vulnerable code
    pub vulnerable: String,
    /// Fixed code
    pub fixed: String,
    /// Explanation
    pub explanation: String,
}

/// Remediation effort
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationEffort {
    /// Trivial fix (configuration change, etc.)
    Trivial,
    /// Low effort (few lines of code)
    Low,
    /// Medium effort (refactoring required)
    Medium,
    /// High effort (architectural changes)
    High,
    /// Very high effort (major redesign)
    VeryHigh,
}

/// Remediation priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemediationPriority {
    /// Immediate - critical risk
    Immediate,
    /// High - should be fixed soon
    High,
    /// Medium - fix in next sprint
    Medium,
    /// Low - fix when convenient
    Low,
    /// Deferred - accepted risk
    Deferred,
}

/// Exploitability assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityAssessment {
    /// Exploitability score (0-10)
    pub score: f32,
    /// Attack vector
    pub attack_vector: AttackVector,
    /// Attack complexity
    pub attack_complexity: AttackComplexity,
    /// Privileges required
    pub privileges_required: PrivilegesRequired,
    /// User interaction
    pub user_interaction: UserInteraction,
    /// Scope
    pub scope: Scope,
    /// Whether exploit code is publicly available
    pub exploit_available: bool,
    /// Whether exploit is actively exploited in the wild
    pub exploited_in_wild: bool,
    /// EPSS score (if available)
    pub epss_score: Option<f32>,
}

/// Attack vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    /// Network exploitable
    Network,
    /// Adjacent network
    Adjacent,
    /// Local access required
    Local,
    /// Physical access required
    Physical,
}

/// Attack complexity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackComplexity {
    /// Low complexity
    Low,
    /// High complexity
    High,
}

/// Privileges required
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegesRequired {
    /// No privileges required
    None,
    /// Low privileges required
    Low,
    /// High privileges required
    High,
}

/// User interaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserInteraction {
    /// No user interaction required
    None,
    /// User interaction required
    Required,
}

/// Scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Unchanged scope
    Unchanged,
    /// Changed scope
    Changed,
}

/// Business impact assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpactAssessment {
    /// Impact score (0-10)
    pub score: f32,
    /// Confidentiality impact
    pub confidentiality: ImpactLevel,
    /// Integrity impact
    pub integrity: ImpactLevel,
    /// Availability impact
    pub availability: ImpactLevel,
    /// Asset criticality
    pub asset_criticality: AssetCriticality,
    /// Regulatory impact
    pub regulatory_impact: Option<RegulatoryImpact>,
}

/// Impact level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImpactLevel {
    /// No impact
    None,
    /// Low impact
    Low,
    /// High impact
    High,
}

/// Asset criticality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetCriticality {
    /// Non-critical asset
    Low,
    /// Important asset
    Medium,
    /// Critical asset
    High,
    /// Mission-critical asset
    Critical,
}

/// Configuration for creating a new Finding
#[derive(Debug, Clone)]
pub struct FindingConfig {
    /// Finding title
    pub title: String,
    /// Finding description
    pub description: String,
    /// Finding severity
    pub severity: Severity,
    /// Finding confidence
    pub confidence: Confidence,
    /// Finding category
    pub category: Category,
    /// Target of the finding
    pub target: String,
    /// Type of the target
    pub target_type: String,
    /// Source plugin name
    pub plugin_source: String,
    /// Source plugin version
    pub plugin_version: String,
    /// Scan ID this finding belongs to
    pub scan_id: ScanId,
}

/// Regulatory impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryImpact {
    /// Regulations affected
    pub regulations: Vec<String>,
    /// Compliance frameworks
    pub frameworks: Vec<String>,
    /// Potential fines/penalties
    pub potential_fines: Option<String>,
}

impl Finding {
    /// Create a new finding from configuration
    pub fn new(config: FindingConfig) -> Self {
        let owasp_category = config.category.owasp_category().map(|s| s.to_string());
        Self {
            id: FindingId::new(),
            title: config.title,
            description: config.description,
            severity: config.severity,
            confidence: config.confidence,
            category: config.category,
            target: config.target,
            target_type: config.target_type,
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: config.plugin_source,
            plugin_version: config.plugin_version,
            timestamp: Utc::now(),
            scan_id: config.scan_id,
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: None,
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category,
            fingerprint: None,
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    /// Add evidence
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Add reference
    pub fn with_reference(mut self, reference: Reference) -> Self {
        self.references.push(reference);
        self
    }

    /// Add tag
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set verified status
    pub fn with_verified(mut self, verified: bool) -> Self {
        self.verified = verified;
        self
    }

    /// Set false positive status
    pub fn with_false_positive(mut self, false_positive: bool) -> Self {
        self.false_positive = false_positive;
        self
    }

    /// Set risk score
    pub fn with_risk_score(mut self, score: u8) -> Self {
        self.risk_score = Some(score.min(100));
        self
    }

    /// Set CVSS vector
    pub fn with_cvss(mut self, vector: String, score: f32) -> Self {
        self.cvss_vector = Some(vector);
        self.cvss_score = Some(score);
        self
    }

    /// Add CWE ID
    pub fn with_cwe(mut self, cwe_id: String) -> Self {
        self.cwe_ids.push(cwe_id);
        self
    }

    /// Add CAPEC ID
    pub fn with_capec(mut self, capec_id: String) -> Self {
        self.capec_ids.push(capec_id);
        self
    }

    /// Add MITRE ATT&CK technique ID
    pub fn with_mitre_attack(mut self, technique_id: String) -> Self {
        self.mitre_attack_ids.push(technique_id);
        self
    }

    /// Set fingerprint for deduplication
    pub fn with_fingerprint(mut self, fingerprint: String) -> Self {
        self.fingerprint = Some(fingerprint);
        self
    }

    /// Add related finding
    pub fn with_related_finding(mut self, finding_id: FindingId) -> Self {
        self.related_findings.push(finding_id);
        self
    }

    /// Set remediation guidance
    pub fn with_remediation(mut self, remediation: RemediationGuidance) -> Self {
        self.remediation = Some(remediation);
        self
    }

    /// Set exploitability assessment
    pub fn with_exploitability(mut self, exploitability: ExploitabilityAssessment) -> Self {
        self.exploitability = Some(exploitability);
        self
    }

    /// Set business impact assessment
    pub fn with_business_impact(mut self, business_impact: BusinessImpactAssessment) -> Self {
        self.business_impact = Some(business_impact);
        self
    }

    /// Calculate risk score based on severity and confidence
    pub fn calculate_risk_score(&self) -> u8 {
        let severity_weight = self.severity.value() as u16 * 20; // 0-80
        let confidence_weight = self.confidence.value() as u16 * 5; // 0-20
        ((severity_weight + confidence_weight).min(100)) as u8
    }

    /// Calculate advanced risk score considering exploitability and business impact
    pub fn calculate_advanced_risk_score(&self) -> u8 {
        let base_score = self.calculate_risk_score() as f32;

        // Adjust based on exploitability
        let exploitability_multiplier = self
            .exploitability
            .as_ref()
            .map(|e| {
                // Higher exploitability = higher risk
                1.0 + (e.score / 10.0) * 0.3 // Up to 30% increase
            })
            .unwrap_or(1.0);

        // Adjust based on business impact
        let impact_multiplier = self
            .business_impact
            .as_ref()
            .map(|b| {
                // Higher business impact = higher risk
                1.0 + (b.score / 10.0) * 0.2 // Up to 20% increase
            })
            .unwrap_or(1.0);

        // Adjust based on asset criticality
        let asset_multiplier = self
            .business_impact
            .as_ref()
            .map(|b| match b.asset_criticality {
                AssetCriticality::Critical => 1.25,
                AssetCriticality::High => 1.15,
                AssetCriticality::Medium => 1.05,
                AssetCriticality::Low => 1.0,
            })
            .unwrap_or(1.0);

        let adjusted =
            base_score * exploitability_multiplier * impact_multiplier * asset_multiplier;
        adjusted.min(100.0) as u8
    }

    /// Get a short summary of the finding
    pub fn summary(&self) -> String {
        format!("[{}] {} - {} ({})", self.severity, self.title, self.target, self.plugin_source)
    }

    /// Generate a fingerprint for deduplication
    pub fn generate_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.title.as_bytes());
        hasher.update(self.target.as_bytes());
        hasher.update(self.category.to_string().as_bytes());
        // Include location from first evidence if available
        if let Some(evidence) = self.evidence.first() {
            if let Some(loc) = &evidence.location {
                hasher.update(loc.as_bytes());
            }
        }
        format!("{:x}", hasher.finalize())[..16].to_string()
    }
}

/// Finding filter for querying findings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FindingFilter {
    /// Filter by severity
    pub severity: Option<Vec<Severity>>,
    /// Filter by confidence
    pub confidence: Option<Vec<Confidence>>,
    /// Filter by category
    pub category: Option<Vec<Category>>,
    /// Filter by target
    pub target: Option<String>,
    /// Filter by plugin source
    pub plugin_source: Option<String>,
    /// Filter by scan ID
    pub scan_id: Option<ScanId>,
    /// Filter by verified status
    pub verified: Option<bool>,
    /// Filter by false positive status
    pub false_positive: Option<bool>,
    /// Filter by tags
    pub tags: Option<Vec<String>>,
    /// Filter by date range
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
    /// Search in title/description
    pub search: Option<String>,
    /// Minimum risk score
    pub min_risk_score: Option<u8>,
    /// Maximum risk score
    pub max_risk_score: Option<u8>,
    /// Filter by CWE ID
    pub cwe_id: Option<String>,
    /// Filter by CAPEC ID
    pub capec_id: Option<String>,
    /// Filter by MITRE ATT&CK ID
    pub mitre_attack_id: Option<String>,
    /// Filter by OWASP category
    pub owasp_category: Option<String>,
    /// Filter by fingerprint (for deduplication)
    pub fingerprint: Option<String>,
    /// Filter by remediation priority
    pub remediation_priority: Option<RemediationPriority>,
    /// Filter by exploitability score range
    pub min_exploitability_score: Option<f32>,
    pub max_exploitability_score: Option<f32>,
    /// Filter by business impact score range
    pub min_business_impact_score: Option<f32>,
    pub max_business_impact_score: Option<f32>,
}

/// Finding sort options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSort {
    /// Sort by severity (highest first)
    SeverityDesc,
    /// Sort by severity (lowest first)
    SeverityAsc,
    /// Sort by confidence (highest first)
    ConfidenceDesc,
    /// Sort by timestamp (newest first)
    TimestampDesc,
    /// Sort by timestamp (oldest first)
    TimestampAsc,
    /// Sort by risk score (highest first)
    RiskScoreDesc,
    /// Sort by target (alphabetical)
    TargetAsc,
}

/// Finding statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingStats {
    /// Total findings
    pub total: usize,
    /// Findings by severity
    pub by_severity: HashMap<Severity, usize>,
    /// Findings by confidence
    pub by_confidence: HashMap<Confidence, usize>,
    /// Findings by category
    pub by_category: HashMap<Category, usize>,
    /// Findings by plugin
    pub by_plugin: HashMap<String, usize>,
    /// Verified findings
    pub verified: usize,
    /// False positives
    pub false_positives: usize,
    /// Average risk score
    pub avg_risk_score: f32,
    /// Maximum risk score
    pub max_risk_score: u8,
    /// Findings by OWASP category
    pub by_owasp_category: HashMap<String, usize>,
    /// Findings by CWE
    pub by_cwe: HashMap<String, usize>,
    /// Average advanced risk score
    pub avg_advanced_risk_score: f32,
    /// Maximum advanced risk score
    pub max_advanced_risk_score: u8,
    /// Findings by remediation priority
    pub by_remediation_priority: HashMap<RemediationPriority, usize>,
    /// Findings with exploit available
    pub exploit_available_count: usize,
    /// Findings exploited in wild
    pub exploited_in_wild_count: usize,
}
