//! Result Aggregator - Standardized finding model for all plugins

use crate::error::{ScannerError, ScannerResult};
use openre_core::ids::FindingId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};
use uuid::Uuid;

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
    type Err = ScannerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            _ => Err(ScannerError::ResultAggregation(format!("Invalid severity: {}", s))),
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
    type Err = ScannerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "very_low" => Ok(Confidence::VeryLow),
            "low" => Ok(Confidence::Low),
            "medium" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            "very_high" => Ok(Confidence::VeryHigh),
            _ => Err(ScannerError::ResultAggregation(format!("Invalid confidence: {}", s))),
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
            Category::BrokenAuthentication => Some("A07:2021 - Identification and Authentication Failures"),
            Category::SensitiveDataExposure => Some("A02:2021 - Cryptographic Failures"),
            Category::Xxe => Some("A05:2021 - Security Misconfiguration"),
            Category::BrokenAccessControl => Some("A01:2021 - Broken Access Control"),
            Category::SecurityMisconfiguration => Some("A05:2021 - Security Misconfiguration"),
            Category::Xss => Some("A03:2021 - Injection"),
            Category::InsecureDeserialization => Some("A08:2021 - Software and Data Integrity Failures"),
            Category::VulnerableComponents => Some("A06:2021 - Vulnerable and Outdated Components"),
            Category::InsufficientLogging => Some("A09:2021 - Security Logging and Monitoring Failures"),
            Category::Ssrf => Some("A10:2021 - Server-Side Request Forgery"),
            _ => None,
        }
    }
}

impl std::fmt::Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::Custom(s) => write!(f, "{}", s),
            _ => write!(f, "{:?}", self).map(|_| ()).unwrap_or(()),
        }
    }
}

impl std::str::FromStr for Category {
    type Err = ScannerError;

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
    pub scan_id: openre_core::ids::ScanId,
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
}

impl Finding {
    /// Create a new finding
    pub fn new(
        title: String,
        description: String,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        target: String,
        target_type: String,
        plugin_source: String,
        plugin_version: String,
        scan_id: openre_core::ids::ScanId,
    ) -> Self {
        Self {
            id: FindingId::new(),
            title,
            description,
            severity,
            confidence,
            category,
            target,
            target_type,
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source,
            plugin_version,
            timestamp: Utc::now(),
            scan_id,
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: None,
            cvss_vector: None,
            cvss_score: None,
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

    /// Calculate risk score based on severity and confidence
    pub fn calculate_risk_score(&self) -> u8 {
        let severity_weight = self.severity.value() as u16 * 20; // 0-80
        let confidence_weight = self.confidence.value() as u16 * 5; // 0-20
        ((severity_weight + confidence_weight).min(100)) as u8
    }

    /// Get a short summary of the finding
    pub fn summary(&self) -> String {
        format!("[{}] {} - {} ({})", self.severity, self.title, self.target, self.plugin_source)
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
    pub scan_id: Option<openre_core::ids::ScanId>,
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
    /// Sort by target
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
}

/// Result Aggregator - aggregates findings from multiple plugins
pub struct ResultAggregator {
    /// Findings storage
    findings: Arc<dashmap::DashMap<FindingId, Finding>>,
    /// Findings by scan ID
    by_scan: Arc<dashmap::DashMap<openre_core::ids::ScanId, Vec<FindingId>>>,
}

impl ResultAggregator {
    /// Create a new result aggregator
    pub fn new() -> Self {
        Self {
            findings: Arc::new(dashmap::DashMap::new()),
            by_scan: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Add a finding
    pub fn add_finding(&self, finding: Finding) -> FindingId {
        let id = finding.id;
        let scan_id = finding.scan_id;
        self.findings.insert(id, finding);
        self.by_scan.entry(scan_id).or_default().push(id);
        id
    }

    /// Add multiple findings
    pub fn add_findings(&self, findings: Vec<Finding>) -> Vec<FindingId> {
        let mut ids = Vec::new();
        for finding in findings {
            ids.push(self.add_finding(finding));
        }
        ids
    }

    /// Get a finding by ID
    pub fn get_finding(&self, id: &FindingId) -> Option<Finding> {
        self.findings.get(id).map(|f| f.clone())
    }

    /// Get all findings for a scan
    pub fn get_findings_for_scan(&self, scan_id: &openre_core::ids::ScanId) -> Vec<Finding> {
        self.by_scan.get(scan_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.findings.get(id).map(|f| f.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get findings with filter
    pub fn get_findings(&self, filter: FindingFilter, sort: FindingSort, limit: usize, offset: usize) -> Vec<Finding> {
        let mut results: Vec<Finding> = self.findings.iter()
            .filter_map(|entry| {
                let finding = entry.value();
                if self.matches_filter(finding, &filter) {
                    Some(finding.clone())
                } else {
                    None
                }
            })
            .collect();

        // Sort
        self.sort_findings(&mut results, sort);

        // Paginate
        results.into_iter().skip(offset).take(limit).collect()
    }

    /// Check if finding matches filter
    fn matches_filter(&self, finding: &Finding, filter: &FindingFilter) -> bool {
        if let Some(severities) = &filter.severity {
            if !severities.contains(&finding.severity) {
                return false;
            }
        }
        if let Some(confidences) = &filter.confidence {
            if !confidences.contains(&finding.confidence) {
                return false;
            }
        }
        if let Some(categories) = &filter.category {
            if !categories.contains(&finding.category) {
                return false;
            }
        }
        if let Some(target) = &filter.target {
            if !finding.target.contains(target) {
                return false;
            }
        }
        if let Some(plugin) = &filter.plugin_source {
            if finding.plugin_source != *plugin {
                return false;
            }
        }
        if let Some(scan_id) = &filter.scan_id {
            if finding.scan_id != *scan_id {
                return false;
            }
        }
        if let Some(verified) = filter.verified {
            if finding.verified != verified {
                return false;
            }
        }
        if let Some(false_positive) = filter.false_positive {
            if finding.false_positive != false_positive {
                return false;
            }
        }
        if let Some(tags) = &filter.tags {
            if !tags.iter().all(|t| finding.tags.contains(t)) {
                return false;
            }
        }
        if let Some(date_from) = filter.date_from {
            if finding.timestamp < date_from {
                return false;
            }
        }
        if let Some(date_to) = filter.date_to {
            if finding.timestamp > date_to {
                return false;
            }
        }
        if let Some(search) = &filter.search {
            let search_lower = search.to_lowercase();
            if !finding.title.to_lowercase().contains(&search_lower)
                && !finding.description.to_lowercase().contains(&search_lower) {
                return false;
            }
        }
        if let Some(min_score) = filter.min_risk_score {
            if finding.risk_score.unwrap_or(0) < min_score {
                return false;
            }
        }
        if let Some(max_score) = filter.max_risk_score {
            if finding.risk_score.unwrap_or(100) > max_score {
                return false;
            }
        }
        true
    }

    /// Sort findings
    fn sort_findings(&self, findings: &mut [Finding], sort: FindingSort) {
        match sort {
            FindingSort::SeverityDesc => findings.sort_by(|a, b| b.severity.cmp(&a.severity)),
            FindingSort::SeverityAsc => findings.sort_by(|a, b| a.severity.cmp(&b.severity)),
            FindingSort::ConfidenceDesc => findings.sort_by(|a, b| b.confidence.cmp(&a.confidence)),
            FindingSort::TimestampDesc => findings.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)),
            FindingSort::TimestampAsc => findings.sort_by(|a, b| a.timestamp.cmp(&b.timestamp)),
            FindingSort::RiskScoreDesc => findings.sort_by(|a, b| {
                b.risk_score.unwrap_or(0).cmp(&a.risk_score.unwrap_or(0))
            }),
            FindingSort::TargetAsc => findings.sort_by(|a, b| a.target.cmp(&b.target)),
        }
    }

    /// Get finding statistics
    pub fn get_stats(&self, scan_id: Option<openre_core::ids::ScanId>) -> FindingStats {
        let findings: Vec<Finding> = if let Some(scan_id) = scan_id {
            self.get_findings_for_scan(&scan_id)
        } else {
            self.findings.iter().map(|f| f.clone()).collect()
        };

        let mut by_severity = HashMap::new();
        let mut by_confidence = HashMap::new();
        let mut by_category = HashMap::new();
        let mut by_plugin = HashMap::new();
        let mut verified = 0;
        let mut false_positives = 0;
        let mut total_risk_score = 0u32;
        let mut risk_score_count = 0;

        for finding in &findings {
            *by_severity.entry(finding.severity).or_insert(0) += 1;
            *by_confidence.entry(finding.confidence).or_insert(0) += 1;
            *by_category.entry(finding.category.clone()).or_insert(0) += 1;
            *by_plugin.entry(finding.plugin_source.clone()).or_insert(0) += 1;
            if finding.verified {
                verified += 1;
            }
            if finding.false_positive {
                false_positives += 1;
            }
            if let Some(score) = finding.risk_score {
                total_risk_score += score as u32;
                risk_score_count += 1;
            }
        }

        FindingStats {
            total: findings.len(),
            by_severity,
            by_confidence,
            by_category,
            by_plugin,
            verified,
            false_positives,
            avg_risk_score: if risk_score_count > 0 {
                total_risk_score as f32 / risk_score_count as f32
            } else {
                0.0
            },
        }
    }

    /// Update a finding
    pub fn update_finding(&self, finding: Finding) -> ScannerResult<()> {
        if self.findings.contains_key(&finding.id) {
            self.findings.insert(finding.id, finding);
            Ok(())
        } else {
            Err(ScannerError::FindingNotFound(finding.id.to_string()))
        }
    }

    /// Delete a finding
    pub fn delete_finding(&self, id: &FindingId) -> bool {
        if let Some((_, finding)) = self.findings.remove(id) {
            if let Some(mut ids) = self.by_scan.get_mut(&finding.scan_id) {
                ids.retain(|fid| fid != id);
            }
            true
        } else {
            false
        }
    }

    /// Get all findings
    pub fn list_all(&self) -> Vec<Finding> {
        self.findings.iter().map(|f| f.clone()).collect()
    }

    /// Count findings
    pub fn count(&self) -> usize {
        self.findings.len()
    }

    /// Count findings for scan
    pub fn count_for_scan(&self, scan_id: &openre_core::ids::ScanId) -> usize {
        self.by_scan.get(scan_id).map(|ids| ids.len()).unwrap_or(0)
    }
}

impl Default for ResultAggregator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::VeryHigh > Confidence::High);
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
        assert!(Confidence::Low > Confidence::VeryLow);
    }

    #[test]
    fn test_finding_creation() {
        let scan_id = openre_core::ids::ScanId::new();
        let finding = Finding::new(
            "SQL Injection".to_string(),
            "SQL injection in login form".to_string(),
            Severity::High,
            Confidence::High,
            Category::Injection,
            "https://example.com/login".to_string(),
            "rest_api".to_string(),
            "sql-injection-scanner".to_string(),
            "1.0.0".to_string(),
            scan_id,
        );

        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::High);
        assert_eq!(finding.category, Category::Injection);
        assert!(!finding.id.to_string().is_empty());
    }

    #[test]
    fn test_finding_risk_score() {
        let scan_id = openre_core::ids::ScanId::new();
        let finding = Finding::new(
            "Test".to_string(),
            "Test".to_string(),
            Severity::Critical,
            Confidence::VeryHigh,
            Category::Injection,
            "target".to_string(),
            "type".to_string(),
            "plugin".to_string(),
            "1.0".to_string(),
            scan_id,
        );

        let score = finding.calculate_risk_score();
        assert_eq!(score, 100); // Max score
    }

    #[test]
    fn test_result_aggregator() {
        let aggregator = ResultAggregator::new();
        let scan_id = openre_core::ids::ScanId::new();

        let finding = Finding::new(
            "Test".to_string(),
            "Test".to_string(),
            Severity::Medium,
            Confidence::Medium,
            Category::Xss,
            "target".to_string(),
            "type".to_string(),
            "plugin".to_string(),
            "1.0".to_string(),
            scan_id,
        );

        let id = aggregator.add_finding(finding);
        assert_eq!(aggregator.count(), 1);
        assert_eq!(aggregator.count_for_scan(&scan_id), 1);

        let retrieved = aggregator.get_finding(&id).unwrap();
        assert_eq!(retrieved.title, "Test");
    }

    #[test]
    fn test_finding_filter() {
        let aggregator = ResultAggregator::new();
        let scan_id = openre_core::ids::ScanId::new();

        let finding1 = Finding::new(
            "High Severity".to_string(),
            "Desc".to_string(),
            Severity::High,
            Confidence::High,
            Category::Injection,
            "target1".to_string(),
            "type".to_string(),
            "plugin1".to_string(),
            "1.0".to_string(),
            scan_id,
        );

        let finding2 = Finding::new(
            "Low Severity".to_string(),
            "Desc".to_string(),
            Severity::Low,
            Confidence::Low,
            Category::Xss,
            "target2".to_string(),
            "type".to_string(),
            "plugin2".to_string(),
            "1.0".to_string(),
            scan_id,
        );

        aggregator.add_finding(finding1);
        aggregator.add_finding(finding2);

        let filter = FindingFilter {
            severity: Some(vec![Severity::High]),
            ..Default::default()
        };

        let results = aggregator.get_findings(filter, FindingSort::SeverityDesc, 10, 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::High);
    }
}