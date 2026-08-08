//! Core types for the intelligence module

use openre_core::result::{Finding, Severity, Confidence, Category};
use openre_core::ids::{FindingId, ScanId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Enhanced correlation between findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedCorrelation {
    /// Correlated finding IDs
    pub finding_ids: Vec<FindingId>,

    /// Correlation type
    pub correlation_type: CorrelationType,

    /// Confidence in the correlation (0.0-1.0)
    pub confidence: f32,

    /// Description of the relationship
    pub description: String,

    /// Evidence supporting the correlation
    pub evidence: Vec<String>,

    /// Combined risk assessment
    pub combined_risk: RiskAssessment,

    /// Suggested mitigation approach
    pub mitigation_approach: String,
}

/// Types of correlations between findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// Missing CSP + Reflected XSS increases risk confidence
    CspXssChain,

    /// Directory listing + Git metadata exposure forms information disclosure chain
    InfoDisclosureChain,

    /// Multiple related findings strengthen each other
    Strengthening,

    /// One finding weakens another (false positive indicator)
    Weakening,

    /// Shared root cause across multiple findings
    SharedRootCause,

    /// Temporal correlation (findings close in time)
    Temporal,

    /// Spatial correlation (same target/endpoint)
    Spatial,

    /// Causal relationship (one finding enables another)
    Causal,
}

/// Combined risk assessment for correlated findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Individual risk scores
    pub individual_scores: Vec<u8>,

    /// Combined risk score (0-100)
    pub combined_score: u8,

    /// Explanation of how risks combine
    pub explanation: String,
}

/// CVE information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveInfo {
    /// CVE identifier
    pub cve_id: String,

    /// Severity
    pub severity: Severity,

    /// CVSS score
    pub cvss_score: Option<f32>,

    /// CVSS vector
    pub cvss_vector: Option<String>,

    /// Description
    pub description: String,

    /// Affected versions
    pub affected_versions: Vec<VersionRange>,

    /// Fixed versions
    pub fixed_versions: Vec<String>,

    /// References
    pub references: Vec<CveReference>,

    /// CWE IDs
    pub cwe_ids: Vec<String>,

    /// Published date
    pub published_date: DateTime<Utc>,

    /// Last modified date
    pub last_modified_date: DateTime<Utc>,
}

/// Version range for affected software
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionRange {
    /// Start version (inclusive)
    pub start_version: Option<String>,

    /// End version (exclusive)
    pub end_version: Option<String>,

    /// Whether this is a vulnerable range
    pub is_vulnerable: bool,
}

/// CVE reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveReference {
    /// Reference URL
    pub url: String,

    /// Reference description
    pub description: Option<String>,
}

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    /// Package name
    pub name: String,

    /// Current version
    pub version: String,

    /// Latest version
    pub latest_version: Option<String>,

    /// Whether this is an outdated dependency
    pub is_outdated: bool,

    /// Known vulnerabilities
    pub vulnerabilities: Vec<DependencyVulnerability>,

    /// Upgrade recommendation
    pub upgrade_recommendation: Option<UpgradeRecommendation>,

    /// Ecosystem (npm, cargo, pip, etc.)
    pub ecosystem: String,
}

/// Dependency vulnerability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyVulnerability {
    /// CVE ID or advisory ID
    pub id: String,

    /// Severity
    pub severity: Severity,

    /// Description
    pub description: String,

    /// CVSS score
    pub cvss_score: Option<f32>,

    /// Affected version ranges
    pub affected_ranges: Vec<VersionRange>,

    /// Fixed in versions
    pub fixed_in: Vec<String>,
}

/// Upgrade recommendation for a dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeRecommendation {
    /// Recommended version to upgrade to
    pub target_version: String,

    /// Risk level of the upgrade
    pub risk_level: DependencyUpgradeRisk,

    /// Description of what the upgrade fixes
    pub fixes_description: String,
}

/// Risk level for dependency upgrades
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyUpgradeRisk {
    /// Low risk - safe to upgrade
    Low,

    /// Medium risk - some breaking changes possible
    Medium,

    /// High risk - likely breaking changes
    High,

    /// Critical risk - major breaking changes
    Critical,
}

/// Knowledge base entry linking findings to security standards
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBaseEntry {
    /// Finding ID this entry is for
    pub finding_id: FindingId,

    /// CWE identifiers
    pub cwe_ids: Vec<String>,

    /// OWASP Top 10 categories
    pub owasp_categories: Vec<String>,

    /// CAPEC identifiers
    pub capec_ids: Vec<String>,

    /// CVE identifiers (if applicable)
    pub cve_ids: Vec<String>,

    /// MITRE ATT&CK techniques
    pub mitre_attack_techniques: Vec<String>,

    /// Secure coding guidelines
    pub secure_coding_guidelines: Vec<SecureCodingGuideline>,

    /// References to standards
    pub standards_references: Vec<StandardReference>,
}

/// Secure coding guideline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureCodingGuideline {
    /// Title of the guideline
    pub title: String,

    /// Description
    pub description: String,

    /// Language-specific examples
    pub examples: HashMap<String, String>,

    /// References
    pub references: Vec<String>,
}

/// Reference to a security standard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardReference {
    /// Standard name (e.g., "NIST SP 800-53", "ISO 27001")
    pub standard: String,

    /// Specific controls or sections
    pub controls: Vec<String>,

    /// URL to the reference
    pub url: Option<String>,
}

/// Root cause analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseAnalysis {
    /// Root cause finding ID
    pub root_cause_id: FindingId,

    /// Related findings that stem from this root cause
    pub related_findings: Vec<FindingId>,

    /// Description of the root cause
    pub description: String,

    /// Impact assessment
    pub impact_assessment: String,

    /// Remediation approach for the root cause
    pub remediation_approach: String,

    /// Priority for addressing the root cause
    pub priority: RemediationPriority,
}

/// Remediation priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationPriority {
    Immediate,
    High,
    Medium,
    Low,
    Deferred,
}

/// Scan difference analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiffAnalysis {
    /// Baseline scan ID
    pub baseline_scan_id: ScanId,

    /// Current scan ID
    pub current_scan_id: ScanId,

    /// New findings
    pub new_findings: Vec<Finding>,

    /// Fixed findings
    pub fixed_findings: Vec<Finding>,

    /// Regressed findings (reappeared)
    pub regressed_findings: Vec<Finding>,

    /// Severity changes
    pub severity_changes: Vec<SeverityChange>,

    /// Technology changes
    pub technology_changes: Vec<TechnologyChange>,

    /// Risk trend analysis
    pub risk_trend: RiskTrend,
}

/// Severity change in a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityChange {
    /// Finding fingerprint for matching
    pub fingerprint: String,

    /// Previous severity
    pub previous_severity: Severity,

    /// Current severity
    pub current_severity: Severity,

    /// Change magnitude (-1 to +1)
    pub change_magnitude: i8,
}

/// Technology change detected between scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyChange {
    /// Technology name
    pub technology: String,

    /// Change type
    pub change_type: TechnologyChangeType,

    /// Description of the change
    pub description: String,
}

/// Types of technology changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnologyChangeType {
    /// New technology detected
    Added,

    /// Technology removed
    Removed,

    /// Version changed
    VersionChanged,

    /// Configuration changed
    ConfigurationChanged,
}

/// Risk trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTrend {
    /// Overall risk change (-100 to +100)
    pub overall_change: i8,

    /// Trend direction
    pub trend_direction: TrendDirection,

    /// Key factors contributing to the trend
    pub key_factors: Vec<String>,
}

/// Trend direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Improving,
    Worsening,
    Stable,
    Mixed,
}

/// Workflow metadata for findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingWorkflowMetadata {
    /// Finding ID
    pub finding_id: FindingId,

    /// Whether the finding has been acknowledged
    pub acknowledged: bool,

    /// Acknowledgment timestamp
    pub acknowledged_at: Option<DateTime<Utc>>,

    /// User who acknowledged
    pub acknowledged_by: Option<String>,

    /// Whether this is marked as a false positive
    pub is_false_positive: bool,

    /// False positive marking timestamp
    pub false_positive_marked_at: Option<DateTime<Utc>>,

    /// Reason for false positive marking
    pub false_positive_reason: Option<String>,

    /// User who marked as false positive
    pub false_positive_marked_by: Option<String>,

    /// Custom notes about the finding
    pub notes: Vec<FindingNote>,

    /// Tags associated with the finding
    pub tags: Vec<String>,

    /// Custom labels
    pub labels: HashMap<String, String>,

    /// Ignore rules (if any)
    pub ignore_rules: Vec<IgnoreRule>,
}

/// Note about a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingNote {
    /// Note content
    pub content: String,

    /// Author
    pub author: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Rule to ignore specific findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreRule {
    /// Rule ID
    pub id: String,

    /// Reason for ignoring
    pub reason: String,

    /// Author
    pub author: String,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp (if any)
    pub expires_at: Option<DateTime<Utc>>,

    /// Scope of the rule
    pub scope: IgnoreScope,
}

/// Scope for ignore rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreScope {
    /// Target patterns to match
    pub targets: Vec<String>,

    /// Finding categories to match
    pub categories: Vec<Category>,

    /// Severity levels to match
    pub severities: Vec<Severity>,

    /// Custom tags to match
    pub tags: Vec<String>,
}