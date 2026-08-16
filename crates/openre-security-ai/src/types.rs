//! Core result types for the AI Security Analyst

use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Category, Confidence, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Explanation of a security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingExplanation {
    /// The finding being explained
    pub finding_id: FindingId,

    /// Why the finding exists (grounded in evidence)
    pub root_cause: String,

    /// Why it matters from a security perspective
    pub security_impact: String,

    /// Attack scenarios that could exploit this
    pub attack_scenarios: Vec<String>,

    /// Confidence assessment of the explanation
    pub confidence: ExplanationConfidence,

    /// Considerations for false positive evaluation
    pub false_positive_considerations: Vec<String>,

    /// Key evidence that supports this explanation
    pub supporting_evidence: Vec<EvidenceReference>,

    /// Model metadata for reproducibility
    pub model_info: ModelInfo,
}

/// Confidence level for AI explanations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExplanationConfidence {
    /// High confidence - strongly supported by evidence
    High,
    /// Medium confidence - reasonably supported
    Medium,
    /// Low confidence - speculative or uncertain
    Low,
    /// Uncertain - model explicitly states uncertainty
    Uncertain { reason: String },
}

/// Reference to specific evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceReference {
    /// Type of evidence being referenced
    pub evidence_type: String,

    /// Brief description of the evidence
    pub description: String,

    /// Location/context of the evidence
    pub location: Option<String>,
}

/// Remediation plan for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    /// The finding being remediated
    pub finding_id: FindingId,

    /// Summary of the remediation approach
    pub summary: String,

    /// Step-by-step implementation guidance
    pub steps: Vec<RemediationStep>,

    /// Code examples showing vulnerable vs fixed code
    pub code_examples: Vec<CodeExample>,

    /// Verification steps to confirm the fix
    pub verification_steps: Vec<String>,

    /// Estimated effort level
    pub effort: RemediationEffort,

    /// Priority level for implementation
    pub priority: RemediationPriority,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// A step in the remediation process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    /// Description of what to do
    pub description: String,

    /// Why this step is important
    pub rationale: String,
}

/// Code example showing before/after
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    /// Programming language
    pub language: String,

    /// Vulnerable code snippet
    pub vulnerable: String,

    /// Fixed code snippet
    pub fixed: String,

    /// Explanation of the fix
    pub explanation: String,
}

/// Effort required for remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Priority for remediation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RemediationPriority {
    Immediate,
    High,
    Medium,
    Low,
    Deferred,
}

/// Correlation report showing relationships between findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationReport {
    /// Scan ID this report is for
    pub scan_id: ScanId,

    /// Correlated finding groups
    pub correlations: Vec<CorrelationGroup>,

    /// Overall risk assessment
    pub risk_assessment: String,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// A group of correlated findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationGroup {
    /// Findings that are related
    pub finding_ids: Vec<FindingId>,

    /// Description of how they're related
    pub relationship: String,

    /// Combined risk when these findings are exploited together
    pub combined_risk: String,

    /// Suggested mitigation approach for the group
    pub mitigation_approach: String,
}

/// Prioritized list of findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedFindings {
    /// Scan ID this prioritization is for
    pub scan_id: ScanId,

    /// Findings sorted by priority
    pub findings: Vec<PrioritizedFinding>,

    /// Rationale for the prioritization
    pub rationale: String,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// A finding with priority information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrioritizedFinding {
    /// The finding ID
    pub finding_id: FindingId,

    /// Priority level
    pub priority: RemediationPriority,

    /// Reason for this priority level
    pub reason: String,

    /// Estimated impact if exploited
    pub estimated_impact: String,

    /// Estimated effort to fix
    pub estimated_effort: RemediationEffort,
}

/// Executive summary for different audiences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    /// Scan ID this summary is for
    pub scan_id: ScanId,

    /// Target audience
    pub audience: Audience,

    /// Key findings summary
    pub key_findings: Vec<SummaryFinding>,

    /// Overall risk assessment
    pub risk_assessment: String,

    /// Recommended actions
    pub recommended_actions: Vec<String>,

    /// Business impact (for executive audience)
    pub business_impact: Option<String>,

    /// Technical details (for technical audiences)
    pub technical_details: Option<Vec<String>>,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// Target audience for summaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Audience {
    Developer,
    SecurityEngineer,
    Manager,
    Executive,
}

/// Simplified finding for summaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryFinding {
    /// Finding ID
    pub finding_id: FindingId,

    /// Title
    pub title: String,

    /// Severity
    pub severity: Severity,

    /// Brief description
    pub brief: String,

    /// Priority for this audience
    pub priority: RemediationPriority,
}

/// Response to a natural language query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// The original question
    pub question: String,

    /// The answer based on findings
    pub answer: String,

    /// Findings that support this answer
    pub supporting_findings: Vec<FindingReference>,

    /// Confidence in the answer
    pub confidence: ExplanationConfidence,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// Reference to a finding in a query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingReference {
    /// Finding ID
    pub finding_id: FindingId,

    /// Relevance to the query
    pub relevance: String,
}

/// Comparison between two scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanComparison {
    /// Base scan ID
    pub base_scan_id: ScanId,

    /// Target scan ID
    pub target_scan_id: ScanId,

    /// New findings in target scan
    pub new_findings: Vec<FindingId>,

    /// Fixed findings (in base but not target)
    pub fixed_findings: Vec<FindingId>,

    /// Findings with increased risk
    pub increased_risk: Vec<RiskChange>,

    /// Findings with decreased risk
    pub decreased_risk: Vec<RiskChange>,

    /// Overall comparison summary
    pub summary: String,

    /// Security posture assessment
    pub security_posture_assessment: String,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// Change in risk for a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskChange {
    /// Finding ID
    pub finding_id: FindingId,

    /// Description of the change
    pub description: String,

    /// Previous risk score
    pub previous_risk: u8,

    /// Current risk score
    pub current_risk: u8,
}

/// Model information for reproducibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Model name/identifier
    pub model: String,

    /// Model version if applicable
    pub version: Option<String>,

    /// Timestamp of analysis
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
