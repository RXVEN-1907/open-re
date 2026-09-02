//! Evidence-Grounded LLM Service for open-re
//!
//! This module provides a service that ensures all LLM responses are grounded
//! in actual evidence from security findings. Every claim must reference
//! specific evidence IDs using the format [Evidence: <id>].

use openre_core::evidence::{FindingEvidence, TriggerCondition};
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Finding, Severity};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

/// Errors for grounded LLM service
#[derive(Debug, Error)]
pub enum GroundedError {
    #[error("Evidence grounding validation failed: {0}")]
    GroundingValidation(String),

    #[error("Missing evidence reference for claim: {0}")]
    MissingEvidenceReference(String),

    #[error("Invalid evidence ID format: {0}")]
    InvalidEvidenceId(String),

    #[error("Template not found: {0}")]
    TemplateNotFound(String),

    #[error("Prompt compilation failed: {0}")]
    PromptCompilation(String),

    #[error("LLM provider error: {0}")]
    ProviderError(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("AI service error: {0}")]
    AiError(String),

    #[error("Core error: {0}")]
    CoreError(#[from] openre_core::Error),
}

pub type GroundedResult<T> = Result<T, GroundedError>;

/// Evidence reference with ID for grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedEvidenceReference {
    /// Unique evidence ID
    pub evidence_id: String,

    /// Type of evidence
    pub evidence_type: String,

    /// Brief description
    pub description: String,

    /// Full evidence content (truncated for prompt)
    pub content_preview: String,
}

/// LLM Explanation grounded in evidence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmExplanation {
    /// Finding ID being explained
    pub finding_id: FindingId,

    /// Root cause analysis grounded in evidence
    pub root_cause: String,

    /// Security impact assessment grounded in evidence
    pub security_impact: String,

    /// Attack scenarios with evidence references
    pub attack_scenarios: Vec<GroundedAttackScenario>,

    /// Confidence level
    pub confidence: ExplanationConfidence,

    /// False positive considerations with evidence
    pub false_positive_considerations: Vec<String>,

    /// All evidence references used in this explanation
    pub evidence_references: Vec<GroundedEvidenceReference>,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// Attack scenario with evidence grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedAttackScenario {
    /// Description of attack scenario
    pub description: String,

    /// Evidence IDs supporting this scenario
    pub supporting_evidence: Vec<String>,

    /// Likelihood assessment
    pub likelihood: LikelihoodLevel,
}

/// Confidence levels for explanations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ExplanationConfidence {
    High,
    Medium,
    Low,
    Uncertain { reason: String },
}

/// Likelihood levels
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum LikelihoodLevel {
    Certain,
    Likely,
    Possible,
    Unlikely,
    Speculative,
}

/// LLM Correlation grounded in shared evidence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmCorrelation {
    /// Scan ID
    pub scan_id: ScanId,

    /// Correlated finding groups
    pub correlations: Vec<GroundedCorrelationGroup>,

    /// Overall risk assessment with evidence
    pub risk_assessment: String,

    /// Evidence references used across all correlations
    pub evidence_references: Vec<GroundedEvidenceReference>,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// A group of correlated findings sharing evidence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedCorrelationGroup {
    /// Finding IDs in this correlation group
    pub finding_ids: Vec<FindingId>,

    /// Type of correlation
    pub correlation_type: CorrelationType,

    /// Description of the relationship grounded in shared evidence
    pub relationship: String,

    /// Shared evidence IDs that link these findings
    pub shared_evidence_ids: Vec<String>,

    /// Combined risk when exploited together
    pub combined_risk: String,

    /// Mitigation approach for the group
    pub mitigation_approach: String,
}

/// Types of correlations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CorrelationType {
    /// Same root cause (e.g., missing input validation)
    SharedRootCause,
    /// Attack chain (one finding enables another)
    AttackChain,
    /// Same technology component affected
    SharedTechnology,
    /// Same attack vector
    SharedAttackVector,
    /// Common configuration issue
    SharedConfiguration,
}

/// LLM Remediation grounded in evidence + technology context
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LlmRemediation {
    /// Finding ID being remediated
    pub finding_id: FindingId,

    /// Summary of remediation approach
    pub summary: String,

    /// Step-by-step implementation guidance with evidence references
    pub steps: Vec<GroundedRemediationStep>,

    /// Code examples showing vulnerable vs fixed code
    pub code_examples: Vec<GroundedCodeExample>,

    /// Verification steps to confirm the fix
    pub verification_steps: Vec<GroundedVerificationStep>,

    /// Estimated effort level
    pub effort: RemediationEffort,

    /// Priority level
    pub priority: RemediationPriority,

    /// Technology-specific guidance
    pub technology_guidance: Vec<TechnologyGuidance>,

    /// Evidence references used
    pub evidence_references: Vec<GroundedEvidenceReference>,

    /// Model metadata
    pub model_info: ModelInfo,
}

/// Remediation step with evidence grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedRemediationStep {
    /// Step number
    pub step_number: u32,

    /// Description of what to do
    pub description: String,

    /// Why this step is important (grounded in evidence)
    pub rationale: String,

    /// Evidence IDs supporting this step
    pub supporting_evidence: Vec<String>,

    /// Technology-specific notes
    pub technology_notes: Option<String>,
}

/// Code example with evidence grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedCodeExample {
    /// Programming language / framework
    pub language: String,

    /// Vulnerable code snippet
    pub vulnerable: String,

    /// Fixed code snippet
    pub fixed: String,

    /// Explanation of the fix (grounded in evidence)
    pub explanation: String,

    /// Evidence IDs that demonstrate the vulnerability
    pub vulnerability_evidence: Vec<String>,
}

/// Verification step with evidence grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedVerificationStep {
    /// Description of verification
    pub description: String,

    /// Expected result if fixed
    pub expected_result: String,

    /// Evidence IDs that would confirm fix
    pub confirmation_evidence: Vec<String>,
}

/// Technology-specific remediation guidance
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TechnologyGuidance {
    /// Technology name (e.g., "nginx", "Spring Boot", "React")
    pub technology: String,

    /// Version if applicable
    pub version: Option<String>,

    /// Configuration changes needed
    pub config_changes: Vec<String>,

    /// Framework-specific mitigation
    pub framework_mitigation: Option<String>,

    /// Evidence IDs related to this technology
    pub related_evidence: Vec<String>,
}

/// Effort levels
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Priority levels
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RemediationPriority {
    Immediate,
    High,
    Medium,
    Low,
    Deferred,
}

/// Model information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelInfo {
    pub model: String,
    pub version: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Grounding validation result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundingValidationResult {
    /// Whether all claims are grounded
    pub fully_grounded: bool,

    /// Claims that are properly grounded
    pub grounded_claims: Vec<GroundedClaim>,

    /// Claims missing evidence references
    pub ungrounded_claims: Vec<UngroundedClaim>,

    /// Evidence IDs referenced in response
    pub referenced_evidence_ids: Vec<String>,

    /// Evidence IDs available but not referenced
    pub unused_evidence_ids: Vec<String>,
}

/// A claim with evidence grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroundedClaim {
    /// The claim text
    pub claim: String,

    /// Evidence IDs supporting this claim
    pub evidence_ids: Vec<String>,

    /// Confidence in this claim
    pub confidence: f32,
}

/// A claim lacking evidence grounding
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UngroundedClaim {
    /// The claim text
    pub claim: String,

    /// Reason why it's ungrounded
    pub reason: String,

    /// Suggested evidence to look for
    pub suggested_evidence: Vec<String>,
}

/// System prompt template that enforces evidence grounding format
pub const SYSTEM_PROMPT: &str = r#"You are a security analyst AI that MUST ground every claim in evidence.

CRITICAL RULES:
1. Every factual claim MUST reference evidence using the format: [Evidence: <evidence_id>]
2. Evidence IDs are provided in the context. Use ONLY those IDs.
3. If you cannot support a claim with provided evidence, state "Insufficient evidence to confirm" instead.
4. Do not invent evidence IDs, technologies, or attack details not in the provided context.
5. For code examples, reference the specific evidence showing the vulnerability.
6. For remediation steps, cite the evidence that necessitates each step.

RESPONSE FORMAT:
- Provide structured JSON output matching the requested schema
- Include an "evidence_references" array listing all evidence IDs used
- Each claim in your analysis should have inline [Evidence: <id>] citations
- Confidence levels must reflect evidence quality (High/Medium/Low/Uncertain)

FAILURE TO FOLLOW THESE RULES WILL RESULT IN REJECTION OF YOUR RESPONSE."#;

/// Template for explaining a finding with evidence injection
pub const EXPLAIN_TEMPLATE: &str = r#"Analyze the following security finding and provide a detailed explanation grounded in the provided evidence.

FINDING:
- Title: {{finding_title}}
- Description: {{finding_description}}
- Severity: {{severity}}
- Confidence: {{confidence}}
- Category: {{category}}
- Target: {{target}}

EVIDENCE ({{evidence_count}} pieces):
{{evidence_details}}

TECHNOLOGY CONTEXT:
{{technology_context}}

REQUIRED OUTPUT (JSON):
{
  "root_cause": "Root cause analysis with [Evidence: <id>] citations",
  "security_impact": "Security impact assessment with [Evidence: <id>] citations",
  "attack_scenarios": [
    {
      "description": "Attack scenario description",
      "supporting_evidence": ["evidence_id1", "evidence_id2"],
      "likelihood": "Likely|Possible|Unlikely|Speculative"
    }
  ],
  "confidence": "High|Medium|Low|Uncertain",
  "uncertainty_reason": "Required if confidence is Uncertain",
  "false_positive_considerations": ["Consideration 1", "Consideration 2"],
  "evidence_references": [
    {"evidence_id": "id1", "evidence_type": "HttpResponse", "description": "Brief description", "content_preview": "..."}
  ]
}"#;

/// Template for correlating findings with shared evidence
pub const CORRELATE_TEMPLATE: &str = r#"Analyze the following security findings and identify correlations grounded in SHARED EVIDENCE.

FINDINGS:
{{findings_summary}}

SHARED EVIDENCE ANALYSIS:
{{shared_evidence_analysis}}

REQUIRED OUTPUT (JSON):
{
  "correlations": [
    {
      "finding_ids": ["finding_id1", "finding_id2"],
      "correlation_type": "SharedRootCause|AttackChain|SharedTechnology|SharedAttackVector|SharedConfiguration",
      "relationship": "Description of relationship with [Evidence: <id>] citations",
      "shared_evidence_ids": ["evidence_id1", "evidence_id2"],
      "combined_risk": "Combined risk assessment with [Evidence: <id>] citations",
      "mitigation_approach": "Joint mitigation approach with [Evidence: <id>] citations"
    }
  ],
  "risk_assessment": "Overall risk assessment with [Evidence: <id>] citations",
  "evidence_references": [
    {"evidence_id": "id1", "evidence_type": "HttpResponse", "description": "Brief description", "content_preview": "..."}
  ]
}

IMPORTANT: Only create correlations where findings SHARE specific evidence IDs. Do not correlate based on similarity alone."#;

/// Template for suggesting remediation with evidence + technology context
pub const REMEDIATION_TEMPLATE: &str = r#"Generate a remediation plan for the following security finding, grounded in evidence and technology context.

FINDING:
- Title: {{finding_title}}
- Description: {{finding_description}}
- Category: {{category}}
- Target: {{target}}
- Severity: {{severity}}

EVIDENCE:
{{evidence_details}}

TECHNOLOGY CONTEXT:
{{technology_context}}

REQUIRED OUTPUT (JSON):
{
  "summary": "Remediation summary with [Evidence: <id>] citations",
  "steps": [
    {
      "step_number": 1,
      "description": "Step description",
      "rationale": "Why this step is needed with [Evidence: <id>] citations",
      "supporting_evidence": ["evidence_id1"],
      "technology_notes": "Technology-specific notes if applicable"
    }
  ],
  "code_examples": [
    {
      "language": "Language/Framework",
      "vulnerable": "Vulnerable code snippet",
      "fixed": "Fixed code snippet",
      "explanation": "Fix explanation with [Evidence: <id>] citations",
      "vulnerability_evidence": ["evidence_id1"]
    }
  ],
  "verification_steps": [
    {
      "description": "Verification step",
      "expected_result": "Expected result if fixed",
      "confirmation_evidence": ["evidence_id1"]
    }
  ],
  "effort": "Trivial|Low|Medium|High|VeryHigh",
  "priority": "Immediate|High|Medium|Low|Deferred",
  "technology_guidance": [
    {
      "technology": "nginx",
      "version": "1.18.0",
      "config_changes": ["Add security headers"],
      "framework_mitigation": "Use nginx security headers module",
      "related_evidence": ["evidence_id1"]
    }
  ],
  "evidence_references": [
    {"evidence_id": "id1", "evidence_type": "HttpResponse", "description": "Brief description", "content_preview": "..."}
  ]
}"#;

/// Template for executive summary
pub const EXECUTIVE_SUMMARY_TEMPLATE: &str = r#"Create an executive summary for a {{audience}} audience about security scan {{scan_id}} targeting {{target}}.

KEY FINDINGS (top {{max_findings}}):
{{key_findings_summary}}

EVIDENCE HIGHLIGHTS:
{{evidence_highlights}}

REQUIRED OUTPUT (JSON):
{
  "key_findings": [
    {
      "finding_id": "id",
      "title": "Title",
      "severity": "Critical|High|Medium|Low|Info",
      "brief": "Brief description",
      "priority": "Immediate|High|Medium|Low|Deferred"
    }
  ],
  "risk_assessment": "Overall risk assessment with [Evidence: <id>] citations",
  "recommended_actions": ["Action 1 with [Evidence: <id>]", "Action 2 with [Evidence: <id>]"],
  "business_impact": "Business impact for executive audience with [Evidence: <id>] citations",
  "technical_details": ["Technical detail 1 with [Evidence: <id>]", "Technical detail 2 with [Evidence: <id>]"],
  "evidence_references": [
    {"evidence_id": "id1", "evidence_type": "HttpResponse", "description": "Brief description", "content_preview": "..."}
  ]
}"#;

/// Template for scan comparison
pub const COMPARE_SCANS_TEMPLATE: &str = r#"Compare two security scans and identify changes grounded in evidence.

BASE SCAN ({{base_scan_id}}):
{{base_findings_summary}}

CURRENT SCAN ({{current_scan_id}}):
{{current_findings_summary}}

EVIDENCE CHANGES:
{{evidence_changes}}

REQUIRED OUTPUT (JSON):
{
  "new_findings": ["finding_id1", "finding_id2"],
  "fixed_findings": ["finding_id1", "finding_id2"],
  "increased_risk": [
    {
      "finding_id": "id",
      "description": "Risk increase description with [Evidence: <id>] citations",
      "previous_risk": 0-100,
      "current_risk": 0-100
    }
  ],
  "decreased_risk": [
    {
      "finding_id": "id",
      "description": "Risk decrease description with [Evidence: <id>] citations",
      "previous_risk": 0-100,
      "current_risk": 0-100
    }
  ],
  "summary": "Overall comparison summary with [Evidence: <id>] citations",
  "security_posture_assessment": "Security posture assessment with [Evidence: <id>] citations",
  "evidence_references": [
    {"evidence_id": "id1", "evidence_type": "HttpResponse", "description": "Brief description", "content_preview": "..."}
  ]
}"#;

/// Prompt templates for evidence-grounded LLM operations
#[derive(Debug, Clone)]
pub struct PromptTemplates {
    pub system_prompt: String,
    pub explain_template: String,
    pub correlate_template: String,
    pub remediation_template: String,
    pub executive_summary_template: String,
    pub compare_scans_template: String,
}

impl Default for PromptTemplates {
    fn default() -> Self {
        Self {
            system_prompt: SYSTEM_PROMPT.to_string(),
            explain_template: EXPLAIN_TEMPLATE.to_string(),
            correlate_template: CORRELATE_TEMPLATE.to_string(),
            remediation_template: REMEDIATION_TEMPLATE.to_string(),
            executive_summary_template: EXECUTIVE_SUMMARY_TEMPLATE.to_string(),
            compare_scans_template: COMPARE_SCANS_TEMPLATE.to_string(),
        }
    }
}

/// Grounded LLM Service - matches implementation plan specification
pub struct GroundedLlmService {
    /// AI service for LLM inference
    pub ai_service: Arc<dyn openre_core::traits::AiService>,
    /// Evidence store for retrieving finding evidence
    pub evidence_store: Arc<dyn openre_core::traits::EvidenceStore>,
    /// Prompt templates with evidence injection
    pub prompt_templates: PromptTemplates,
    /// Whether to enforce strict grounding validation
    strict_grounding: bool,
}

impl GroundedLlmService {
    /// Create a new grounded LLM service with required dependencies
    pub fn new(
        ai_service: Arc<dyn openre_core::traits::AiService>,
        evidence_store: Arc<dyn openre_core::traits::EvidenceStore>,
    ) -> Self {
        Self {
            ai_service,
            evidence_store,
            prompt_templates: PromptTemplates::default(),
            strict_grounding: true,
        }
    }

    /// Create with custom prompt templates
    pub fn with_templates(
        ai_service: Arc<dyn openre_core::traits::AiService>,
        evidence_store: Arc<dyn openre_core::traits::EvidenceStore>,
        prompt_templates: PromptTemplates,
    ) -> Self {
        Self { ai_service, evidence_store, prompt_templates, strict_grounding: true }
    }

    /// Create with custom strictness
    pub fn with_strict_grounding(mut self, strict: bool) -> Self {
        self.strict_grounding = strict;
        self
    }

    /// Explain a finding with evidence grounding
    pub async fn explain_finding(
        &self,
        finding: &Finding,
        evidence: &FindingEvidence,
    ) -> GroundedResult<LlmExplanation> {
        // Build evidence details for prompt
        let evidence_details = self.format_evidence_for_prompt(evidence);
        let technology_context = self.format_technology_context(&evidence.technology_context);

        // Prepare variables for template
        let mut variables = HashMap::new();
        variables.insert("finding_title".to_string(), finding.title.clone());
        variables.insert("finding_description".to_string(), finding.description.clone());
        variables.insert("severity".to_string(), format!("{:?}", finding.severity));
        variables.insert("confidence".to_string(), format!("{:?}", finding.confidence));
        variables.insert("category".to_string(), format!("{:?}", finding.category));
        variables.insert("target".to_string(), finding.target.clone());
        variables.insert("evidence_count".to_string(), "1".to_string());
        variables.insert("evidence_details".to_string(), evidence_details);
        variables.insert("technology_context".to_string(), technology_context);

        // Render user prompt
        let user_prompt =
            self.render_template(&self.prompt_templates.explain_template, &variables)?;

        // Create full prompt with system prompt
        let full_prompt = format!("{}\n\n{}", self.prompt_templates.system_prompt, user_prompt);

        // Execute request using AI service
        let response = self
            .ai_service
            .infer(full_prompt)
            .await
            .map_err(|e| GroundedError::AiError(e.to_string()))?;

        // Parse and validate response
        let explanation = self.parse_and_validate_explanation(&response, evidence)?;

        Ok(explanation)
    }

    /// Correlate findings with shared evidence
    pub async fn correlate_findings(
        &self,
        findings: &[Finding],
        all_evidence: &[FindingEvidence],
    ) -> GroundedResult<LlmCorrelation> {
        // Build findings summary
        let findings_summary = findings
            .iter()
            .map(|f| {
                format!(
                    "- {} (ID: {}, Severity: {:?}, Category: {:?})",
                    f.title, f.id, f.severity, f.category
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Build shared evidence analysis
        let shared_evidence_analysis = self.analyze_shared_evidence(findings, all_evidence);

        let mut variables = HashMap::new();
        variables.insert("findings_summary".to_string(), findings_summary);
        variables.insert("shared_evidence_analysis".to_string(), shared_evidence_analysis);

        let user_prompt =
            self.render_template(&self.prompt_templates.correlate_template, &variables)?;
        let full_prompt = format!("{}\n\n{}", self.prompt_templates.system_prompt, user_prompt);

        let response = self
            .ai_service
            .infer(full_prompt)
            .await
            .map_err(|e| GroundedError::AiError(e.to_string()))?;

        let correlation = self.parse_and_validate_correlation(&response, all_evidence)?;

        Ok(correlation)
    }

    /// Suggest remediation grounded in evidence and technology context
    pub async fn suggest_remediation(
        &self,
        finding: &Finding,
        evidence: &FindingEvidence,
    ) -> GroundedResult<LlmRemediation> {
        let evidence_details = self.format_evidence_for_prompt(evidence);
        let technology_context = self.format_technology_context(&evidence.technology_context);

        let mut variables = HashMap::new();
        variables.insert("finding_title".to_string(), finding.title.clone());
        variables.insert("finding_description".to_string(), finding.description.clone());
        variables.insert("category".to_string(), format!("{:?}", finding.category));
        variables.insert("target".to_string(), finding.target.clone());
        variables.insert("severity".to_string(), format!("{:?}", finding.severity));
        variables.insert("evidence_details".to_string(), evidence_details);
        variables.insert("technology_context".to_string(), technology_context);

        let user_prompt =
            self.render_template(&self.prompt_templates.remediation_template, &variables)?;
        let full_prompt = format!("{}\n\n{}", self.prompt_templates.system_prompt, user_prompt);

        let response = self
            .ai_service
            .infer(full_prompt)
            .await
            .map_err(|e| GroundedError::AiError(e.to_string()))?;

        let remediation = self.parse_and_validate_remediation(&response, evidence)?;

        Ok(remediation)
    }

    /// Validate grounding of a response against evidence
    pub fn validate_grounding(
        &self,
        response: &str,
        evidence: &FindingEvidence,
    ) -> GroundedResult<GroundingValidationResult> {
        // Extract evidence IDs from evidence
        let evidence_id = self.extract_evidence_id(evidence);
        let available_ids = vec![evidence_id.clone()];

        // Extract referenced evidence IDs from response
        let referenced_ids = self.extract_referenced_evidence_ids(response);

        // Check for ungrounded claims
        let mut grounded_claims = Vec::new();
        let mut ungrounded_claims = Vec::new();

        // Split response into claims (simplified - by sentences)
        let claims = self.split_into_claims(response);

        for claim in claims {
            let claim_evidence_ids = self.extract_referenced_evidence_ids(&claim);
            if claim_evidence_ids.is_empty() && self.claim_requires_evidence(&claim) {
                ungrounded_claims.push(UngroundedClaim {
                    claim: claim.clone(),
                    reason: "No evidence reference found".to_string(),
                    suggested_evidence: available_ids.clone(),
                });
            } else if !claim_evidence_ids.is_empty() {
                // Validate all referenced IDs exist
                for id in &claim_evidence_ids {
                    if !available_ids.contains(id) {
                        ungrounded_claims.push(UngroundedClaim {
                            claim: claim.clone(),
                            reason: format!("References unknown evidence ID: {}", id),
                            suggested_evidence: available_ids.clone(),
                        });
                    }
                }
                grounded_claims.push(GroundedClaim {
                    claim,
                    evidence_ids: claim_evidence_ids,
                    confidence: 0.8,
                });
            }
        }

        let fully_grounded = ungrounded_claims.is_empty();
        let unused_evidence_ids: Vec<String> =
            available_ids.iter().filter(|id| !referenced_ids.contains(id)).cloned().collect();

        Ok(GroundingValidationResult {
            fully_grounded,
            grounded_claims,
            ungrounded_claims,
            referenced_evidence_ids: referenced_ids,
            unused_evidence_ids,
        })
    }

    /// Generate executive summary
    pub async fn executive_summary(
        &self,
        scan_id: ScanId,
        findings: &[Finding],
        evidence_list: &[FindingEvidence],
        audience: Audience,
        max_findings: usize,
    ) -> GroundedResult<ExecutiveSummary> {
        let key_findings = findings.iter().take(max_findings).cloned().collect::<Vec<_>>();
        let key_findings_summary = key_findings
            .iter()
            .map(|f| format!("- {} (ID: {}, Severity: {:?})", f.title, f.id, f.severity))
            .collect::<Vec<_>>()
            .join("\n");

        let evidence_highlights = self.format_evidence_highlights(evidence_list);

        let mut variables = HashMap::new();
        variables.insert("audience".to_string(), format!("{:?}", audience));
        variables.insert("scan_id".to_string(), scan_id.to_string());
        variables.insert(
            "target".to_string(),
            findings.first().map(|f| f.target.clone()).unwrap_or_default(),
        );
        variables.insert("max_findings".to_string(), max_findings.to_string());
        variables.insert("key_findings_summary".to_string(), key_findings_summary);
        variables.insert("evidence_highlights".to_string(), evidence_highlights);

        let user_prompt =
            self.render_template(&self.prompt_templates.executive_summary_template, &variables)?;
        let full_prompt = format!("{}\n\n{}", self.prompt_templates.system_prompt, user_prompt);

        let response = self
            .ai_service
            .infer(full_prompt)
            .await
            .map_err(|e| GroundedError::AiError(e.to_string()))?;

        let summary = self.parse_and_validate_executive_summary(&response, evidence_list)?;

        Ok(summary)
    }

    /// Compare two scans
    pub async fn compare_scans(
        &self,
        baseline_id: ScanId,
        current_id: ScanId,
        baseline_findings: &[Finding],
        current_findings: &[Finding],
        baseline_evidence: &[FindingEvidence],
        current_evidence: &[FindingEvidence],
    ) -> GroundedResult<ScanComparison> {
        let base_findings_summary = baseline_findings
            .iter()
            .map(|f| format!("- {} (ID: {}, Severity: {:?})", f.title, f.id, f.severity))
            .collect::<Vec<_>>()
            .join("\n");

        let current_findings_summary = current_findings
            .iter()
            .map(|f| format!("- {} (ID: {}, Severity: {:?})", f.title, f.id, f.severity))
            .collect::<Vec<_>>()
            .join("\n");

        let evidence_changes = self.analyze_evidence_changes(baseline_evidence, current_evidence);

        let mut variables = HashMap::new();
        variables.insert("base_scan_id".to_string(), baseline_id.to_string());
        variables.insert("current_scan_id".to_string(), current_id.to_string());
        variables.insert("base_findings_summary".to_string(), base_findings_summary);
        variables.insert("current_findings_summary".to_string(), current_findings_summary);
        variables.insert("evidence_changes".to_string(), evidence_changes);

        let user_prompt =
            self.render_template(&self.prompt_templates.compare_scans_template, &variables)?;
        let full_prompt = format!("{}\n\n{}", self.prompt_templates.system_prompt, user_prompt);

        let response = self
            .ai_service
            .infer(full_prompt)
            .await
            .map_err(|e| GroundedError::AiError(e.to_string()))?;

        let comparison =
            self.parse_and_validate_comparison(&response, baseline_evidence, current_evidence)?;

        Ok(comparison)
    }

    /// Render a template with variables
    fn render_template(
        &self,
        template: &str,
        variables: &HashMap<String, String>,
    ) -> GroundedResult<String> {
        let mut result = template.to_string();
        for (key, value) in variables {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, value);
        }
        Ok(result)
    }

    fn format_evidence_for_prompt(&self, evidence: &FindingEvidence) -> String {
        let mut parts = Vec::new();

        // Trigger condition
        parts.push(format!("Trigger: {:?}", evidence.trigger_condition));

        // HTTP interaction
        if let Some(http) = &evidence.http_interaction {
            parts.push(format!("Request: {} {}", http.request.method, http.request.url));
            if let Some(body) = &http.request.body {
                parts.push(format!("Request Body: {}", body.chars().take(500).collect::<String>()));
            }
            parts.push(format!("Response Status: {}", http.response.status_code));
            if let Some(body) = &http.response.body {
                parts.push(format!(
                    "Response Body: {}",
                    body.chars().take(1000).collect::<String>()
                ));
            }
        }

        // Response analysis
        parts.push(format!(
            "Response Analysis Confidence: {}",
            evidence.response_analysis.confidence
        ));
        for indicator in &evidence.response_analysis.confirmation_indicators {
            parts.push(format!(
                "  - {:?}: {} (confidence: {})",
                indicator.indicator_type, indicator.description, indicator.confidence
            ));
        }
        for extracted in &evidence.response_analysis.extracted_data {
            parts.push(format!(
                "  - Extracted {:?}: {} (sensitivity: {:?})",
                extracted.data_type, extracted.value, extracted.sensitivity
            ));
        }

        // Configuration evidence
        if let Some(config) = &evidence.configuration_extracted {
            parts.push(format!("Configuration Type: {:?}", config.config_type));
            parts.push(format!("Misconfigurations: {}", config.misconfigurations.len()));
            for misconfig in &config.misconfigurations {
                parts.push(format!(
                    "  - {}: {} -> {} ({:?})",
                    misconfig.key,
                    misconfig.current_value,
                    misconfig.recommended_value,
                    misconfig.severity
                ));
            }
        }

        // Technology context
        if !evidence.technology_context.technologies.is_empty() {
            parts.push("Technologies:".to_string());
            for tech in &evidence.technology_context.technologies {
                parts.push(format!(
                    "  - {} {} ({}, confidence: {})",
                    tech.name,
                    tech.version.as_deref().unwrap_or(""),
                    tech.category,
                    tech.confidence
                ));
            }
        }

        // Reproduction steps
        if !evidence.reproduction_steps.is_empty() {
            parts.push("Reproduction Steps:".to_string());
            for step in &evidence.reproduction_steps {
                parts.push(format!("  {}. {}", step.step_number, step.description));
            }
        }

        // Negative evidence
        if !evidence.negative_evidence.is_empty() {
            parts.push("Negative Evidence (ruled out):".to_string());
            for neg in &evidence.negative_evidence {
                parts.push(format!("  - Checked: {}, Expected if vulnerable: {}, Actual: {} (confidence ruled out: {})",
                    neg.check_performed, neg.expected_if_vulnerable, neg.actual_result, neg.confidence_ruled_out));
            }
        }

        parts.join("\n")
    }

    fn format_technology_context(
        &self,
        tech_context: &openre_core::evidence::TechnologyContext,
    ) -> String {
        let mut parts = Vec::new();

        if !tech_context.technologies.is_empty() {
            parts.push("Detected Technologies:".to_string());
            for tech in &tech_context.technologies {
                parts.push(format!(
                    "  - {} {} ({})",
                    tech.name,
                    tech.version.as_deref().unwrap_or("unknown"),
                    tech.category
                ));
            }
        }

        if let Some(framework) = &tech_context.framework {
            parts.push(format!(
                "Framework: {} {} ({})",
                framework.name,
                framework.version.as_deref().unwrap_or("unknown"),
                framework.language
            ));
            if !framework.known_vulnerabilities.is_empty() {
                parts.push(format!(
                    "  Known Vulnerabilities: {}",
                    framework.known_vulnerabilities.join(", ")
                ));
            }
        }

        if let Some(server) = &tech_context.server {
            parts.push(format!(
                "Server: {} {} ({})",
                server.name,
                server.version.as_deref().unwrap_or("unknown"),
                server.os.as_deref().unwrap_or("unknown")
            ));
            if !server.modules.is_empty() {
                parts.push(format!("  Modules: {}", server.modules.join(", ")));
            }
        }

        if let Some(db) = &tech_context.database {
            parts.push(format!(
                "Database: {} {} (exposed: {})",
                db.type_,
                db.version.as_deref().unwrap_or("unknown"),
                db.exposed
            ));
        }

        if let Some(cloud) = &tech_context.cloud_provider {
            parts.push(format!(
                "Cloud Provider: {} ({})",
                cloud.provider,
                cloud.region.as_deref().unwrap_or("unknown")
            ));
            if !cloud.services.is_empty() {
                parts.push(format!("  Services: {}", cloud.services.join(", ")));
            }
        }

        if parts.is_empty() {
            "No technology context available".to_string()
        } else {
            parts.join("\n")
        }
    }

    fn format_evidence_highlights(&self, evidence_list: &[FindingEvidence]) -> String {
        evidence_list
            .iter()
            .take(5)
            .enumerate()
            .map(|(i, e)| {
                let mut highlights = Vec::new();
                highlights.push(format!("{}. Evidence for finding {}", i + 1, e.finding_id));
                highlights.push(format!(
                    "   Quality: {:.0}%, Completeness: {:.0}%",
                    e.quality_score * 100.0,
                    e.completeness * 100.0
                ));
                highlights.push(format!("   Trigger: {:?}", e.trigger_condition));
                if let Some(http) = &e.http_interaction {
                    highlights.push(format!(
                        "   HTTP: {} {} -> {}",
                        http.request.method, http.request.url, http.response.status_code
                    ));
                }
                highlights.join("\n")
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    fn analyze_shared_evidence(
        &self,
        _findings: &[Finding],
        evidence_list: &[FindingEvidence],
    ) -> String {
        // Group evidence by technology, attack vector, etc.
        let mut analysis = Vec::new();

        // Group by technology
        let mut tech_groups: HashMap<String, Vec<FindingId>> = HashMap::new();
        for evidence in evidence_list {
            for tech in &evidence.technology_context.technologies {
                tech_groups.entry(tech.name.clone()).or_default().push(evidence.finding_id);
            }
        }

        for (tech, finding_ids) in tech_groups {
            if finding_ids.len() > 1 {
                analysis.push(format!("Shared Technology '{}': Findings {:?}", tech, finding_ids));
            }
        }

        // Group by trigger condition type
        let mut trigger_groups: HashMap<String, Vec<FindingId>> = HashMap::new();
        for evidence in evidence_list {
            let trigger_type = match &evidence.trigger_condition {
                TriggerCondition::HeaderMissing { .. } => "HeaderMissing",
                TriggerCondition::HeaderValue { .. } => "HeaderValue",
                TriggerCondition::StatusCode { .. } => "StatusCode",
                TriggerCondition::BodyPattern { .. } => "BodyPattern",
                TriggerCondition::TechnologyDetected { .. } => "TechnologyDetected",
                TriggerCondition::ParameterReflection { .. } => "ParameterReflection",
                TriggerCondition::AuthBypass { .. } => "AuthBypass",
                TriggerCondition::InformationDisclosure { .. } => "InformationDisclosure",
                TriggerCondition::InjectionSuccessful { .. } => "InjectionSuccessful",
                TriggerCondition::FileAccessible { .. } => "FileAccessible",
                TriggerCondition::Custom { .. } => "Custom",
            };
            trigger_groups.entry(trigger_type.to_string()).or_default().push(evidence.finding_id);
        }

        for (trigger, finding_ids) in trigger_groups {
            if finding_ids.len() > 1 {
                analysis.push(format!("Shared Trigger '{}': Findings {:?}", trigger, finding_ids));
            }
        }

        if analysis.is_empty() {
            "No shared evidence patterns detected".to_string()
        } else {
            analysis.join("\n")
        }
    }

    fn analyze_evidence_changes(
        &self,
        baseline: &[FindingEvidence],
        current: &[FindingEvidence],
    ) -> String {
        let mut changes = Vec::new();

        // Compare by finding ID
        let baseline_map: HashMap<_, _> = baseline.iter().map(|e| (e.finding_id, e)).collect();
        let current_map: HashMap<_, _> = current.iter().map(|e| (e.finding_id, e)).collect();

        for (finding_id, curr_evidence) in &current_map {
            if let Some(base_evidence) = baseline_map.get(finding_id) {
                // Compare quality/completeness
                if curr_evidence.quality_score > base_evidence.quality_score + 0.1 {
                    changes.push(format!(
                        "Finding {}: Evidence quality improved ({:.0}% -> {:.0}%)",
                        finding_id,
                        base_evidence.quality_score * 100.0,
                        curr_evidence.quality_score * 100.0
                    ));
                } else if curr_evidence.quality_score + 0.1 < base_evidence.quality_score {
                    changes.push(format!(
                        "Finding {}: Evidence quality decreased ({:.0}% -> {:.0}%)",
                        finding_id,
                        base_evidence.quality_score * 100.0,
                        curr_evidence.quality_score * 100.0
                    ));
                }

                // Compare trigger conditions
                if format!("{:?}", curr_evidence.trigger_condition)
                    != format!("{:?}", base_evidence.trigger_condition)
                {
                    changes.push(format!("Finding {}: Trigger condition changed", finding_id));
                }
            } else {
                changes.push(format!("Finding {}: New evidence in current scan", finding_id));
            }
        }

        for finding_id in baseline_map.keys() {
            if !current_map.contains_key(finding_id) {
                changes.push(format!("Finding {}: Evidence removed in current scan", finding_id));
            }
        }

        if changes.is_empty() {
            "No significant evidence changes detected".to_string()
        } else {
            changes.join("\n")
        }
    }

    fn extract_evidence_id(&self, evidence: &FindingEvidence) -> String {
        // In real implementation, FindingEvidence would have an ID field
        // For now, generate from finding_id and timestamp
        format!("ev-{}-{}", evidence.finding_id, evidence.timestamp.timestamp())
    }

    fn extract_referenced_evidence_ids(&self, text: &str) -> Vec<String> {
        let mut ids = Vec::new();
        use regex::Regex;
        // Match [Evidence: <id>] pattern
        if let Ok(re) = Regex::new(r"\[Evidence:\s*([^\]]+)\]") {
            for cap in re.captures_iter(text) {
                ids.push(cap[1].trim().to_string());
            }
        }
        ids
    }

    fn split_into_claims(&self, text: &str) -> Vec<String> {
        // Simple sentence splitting - in practice would be more sophisticated
        text.split('.')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.len() > 10)
            .collect()
    }

    fn claim_requires_evidence(&self, claim: &str) -> bool {
        // Heuristics to determine if a claim needs evidence
        let claim_lower = claim.to_lowercase();
        claim_lower.contains("is vulnerable")
            || claim_lower.contains("allows attacker")
            || claim_lower.contains("can be exploited")
            || claim_lower.contains("exposes")
            || claim_lower.contains("leaks")
            || claim_lower.contains("bypass")
            || claim_lower.contains("confirmed")
            || claim_lower.contains("verified")
            || claim_lower.contains("demonstrates")
            || claim_lower.contains("proves")
            || claim_lower.contains("indicates")
            || claim_lower.contains("suggests")
            || claim_lower.contains("root cause")
            || claim_lower.contains("attack vector")
            || claim_lower.contains("impact")
    }

    // ==================== Parsing and Validation ====================

    fn parse_and_validate_explanation(
        &self,
        response: &str,
        evidence: &FindingEvidence,
    ) -> GroundedResult<LlmExplanation> {
        let content = response.trim();

        // Validate grounding if strict
        if self.strict_grounding {
            let validation = self.validate_grounding(content, evidence)?;
            if !validation.fully_grounded {
                warn!("Explanation has ungrounded claims: {:?}", validation.ungrounded_claims);
            }
        }

        // Parse JSON response
        let mut explanation: LlmExplanation = serde_json::from_str(content)?;

        // Ensure finding_id is set
        explanation.finding_id = evidence.finding_id;

        // Add model info
        explanation.model_info = ModelInfo {
            model: "unknown".to_string(),
            version: None,
            timestamp: chrono::Utc::now(),
        };

        Ok(explanation)
    }

    fn parse_and_validate_correlation(
        &self,
        response: &str,
        evidence_list: &[FindingEvidence],
    ) -> GroundedResult<LlmCorrelation> {
        let content = response.trim();

        // Collect all evidence IDs
        let all_evidence_ids: Vec<String> =
            evidence_list.iter().map(|e| self.extract_evidence_id(e)).collect();

        // Validate grounding
        if self.strict_grounding {
            let referenced = self.extract_referenced_evidence_ids(content);
            for id in &referenced {
                if !all_evidence_ids.contains(id) {
                    return Err(GroundedError::GroundingValidation(format!(
                        "Response references unknown evidence ID: {}",
                        id
                    )));
                }
            }
        }

        let mut correlation: LlmCorrelation = serde_json::from_str(content)?;
        correlation.model_info = ModelInfo {
            model: "unknown".to_string(),
            version: None,
            timestamp: chrono::Utc::now(),
        };

        Ok(correlation)
    }

    fn parse_and_validate_remediation(
        &self,
        response: &str,
        evidence: &FindingEvidence,
    ) -> GroundedResult<LlmRemediation> {
        let content = response.trim();

        if self.strict_grounding {
            let validation = self.validate_grounding(content, evidence)?;
            if !validation.fully_grounded {
                warn!("Remediation has ungrounded claims: {:?}", validation.ungrounded_claims);
            }
        }

        let mut remediation: LlmRemediation = serde_json::from_str(content)?;
        remediation.finding_id = evidence.finding_id;
        remediation.model_info = ModelInfo {
            model: "unknown".to_string(),
            version: None,
            timestamp: chrono::Utc::now(),
        };

        Ok(remediation)
    }

    fn parse_and_validate_executive_summary(
        &self,
        response: &str,
        evidence_list: &[FindingEvidence],
    ) -> GroundedResult<ExecutiveSummary> {
        let content = response.trim();

        let all_evidence_ids: Vec<String> =
            evidence_list.iter().map(|e| self.extract_evidence_id(e)).collect();

        if self.strict_grounding {
            let referenced = self.extract_referenced_evidence_ids(content);
            for id in &referenced {
                if !all_evidence_ids.contains(id) {
                    return Err(GroundedError::GroundingValidation(format!(
                        "Response references unknown evidence ID: {}",
                        id
                    )));
                }
            }
        }

        let mut summary: ExecutiveSummary = serde_json::from_str(content)?;
        summary.model_info = ModelInfo {
            model: "unknown".to_string(),
            version: None,
            timestamp: chrono::Utc::now(),
        };

        Ok(summary)
    }

    fn parse_and_validate_comparison(
        &self,
        response: &str,
        baseline_evidence: &[FindingEvidence],
        current_evidence: &[FindingEvidence],
    ) -> GroundedResult<ScanComparison> {
        let content = response.trim();

        let all_evidence_ids: Vec<String> = baseline_evidence
            .iter()
            .chain(current_evidence.iter())
            .map(|e| self.extract_evidence_id(e))
            .collect();

        if self.strict_grounding {
            let referenced = self.extract_referenced_evidence_ids(content);
            for id in &referenced {
                if !all_evidence_ids.contains(id) {
                    return Err(GroundedError::GroundingValidation(format!(
                        "Response references unknown evidence ID: {}",
                        id
                    )));
                }
            }
        }

        let mut comparison: ScanComparison = serde_json::from_str(content)?;
        comparison.model_info = ModelInfo {
            model: "unknown".to_string(),
            version: None,
            timestamp: chrono::Utc::now(),
        };

        Ok(comparison)
    }
}

/// Executive summary for different audiences
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutiveSummary {
    pub scan_id: ScanId,
    pub audience: Audience,
    pub key_findings: Vec<SummaryFinding>,
    pub risk_assessment: String,
    pub recommended_actions: Vec<String>,
    pub business_impact: Option<String>,
    pub technical_details: Option<Vec<String>>,
    pub evidence_references: Vec<GroundedEvidenceReference>,
    pub model_info: ModelInfo,
}

/// Target audience
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Audience {
    Developer,
    SecurityEngineer,
    Manager,
    Executive,
}

/// Simplified finding for summaries
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SummaryFinding {
    pub finding_id: FindingId,
    pub title: String,
    pub severity: Severity,
    pub brief: String,
    pub priority: RemediationPriority,
}

/// Scan comparison result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanComparison {
    pub base_scan_id: ScanId,
    pub target_scan_id: ScanId,
    pub new_findings: Vec<FindingId>,
    pub fixed_findings: Vec<FindingId>,
    pub increased_risk: Vec<RiskChange>,
    pub decreased_risk: Vec<RiskChange>,
    pub summary: String,
    pub security_posture_assessment: String,
    pub evidence_references: Vec<GroundedEvidenceReference>,
    pub model_info: ModelInfo,
}

/// Risk change for comparison
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RiskChange {
    pub finding_id: FindingId,
    pub description: String,
    pub previous_risk: u8,
    pub current_risk: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_config::AiConfig;
    use openre_core::evidence::*;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use std::collections::HashMap;

    fn create_test_finding() -> Finding {
        Finding::new(openre_core::result::FindingConfig {
            title: "Missing CSP Header".to_string(),
            description: "Content-Security-Policy header is missing".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: Category::SecurityMisconfiguration,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0.0".to_string(),
            scan_id: ScanId::new(),
        })
    }

    fn create_test_evidence() -> FindingEvidence {
        FindingEvidence {
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
                technologies: vec![TechnologyInfo {
                    name: "nginx".to_string(),
                    version: Some("1.18.0".to_string()),
                    category: "web_server".to_string(),
                    confidence: 0.95,
                    detection_method: "header".to_string(),
                }],
                framework: None,
                server: Some(ServerInfo {
                    name: "nginx".to_string(),
                    version: Some("1.18.0".to_string()),
                    os: Some("Linux".to_string()),
                    modules: vec![],
                }),
                database: None,
                cloud_provider: None,
            },
            reproduction_steps: vec![],
            negative_evidence: vec![],
            quality_score: 0.85,
            completeness: 0.8,
            timestamp: Utc::now(),
        }
    }

    #[test]
    fn test_system_prompt_contains_evidence_format() {
        assert!(SYSTEM_PROMPT.contains("[Evidence:"));
        assert!(SYSTEM_PROMPT.contains("evidence_id"));
        assert!(SYSTEM_PROMPT.contains("ground"));
    }

    #[test]
    fn test_explain_template_has_placeholders() {
        assert!(EXPLAIN_TEMPLATE.contains("{{finding_title}}"));
        assert!(EXPLAIN_TEMPLATE.contains("{{evidence_details}}"));
        assert!(EXPLAIN_TEMPLATE.contains("{{technology_context}}"));
        assert!(EXPLAIN_TEMPLATE.contains("[Evidence:"));
    }

    #[test]
    fn test_correlate_template_enforces_shared_evidence() {
        assert!(CORRELATE_TEMPLATE.contains("SHARED EVIDENCE"));
        assert!(CORRELATE_TEMPLATE.contains("shared_evidence_ids"));
        assert!(CORRELATE_TEMPLATE.contains("correlation_type"));
    }

    #[test]
    fn test_remediation_template_has_technology_guidance() {
        assert!(REMEDIATION_TEMPLATE.contains("technology_guidance"));
        assert!(REMEDIATION_TEMPLATE.contains("technology_notes"));
        assert!(REMEDIATION_TEMPLATE.contains("vulnerability_evidence"));
    }

    // Mock AI service for testing
    struct MockAiService;

    #[async_trait::async_trait]
    impl openre_core::traits::AiService for MockAiService {
        async fn infer(&self, _request: String) -> openre_core::Result<String> {
            Ok("{}".to_string())
        }

        async fn batch_infer(&self, _requests: Vec<String>) -> openre_core::Result<Vec<String>> {
            Ok(vec![])
        }
    }

    // Mock evidence store for testing
    struct MockEvidenceStore;

    #[async_trait::async_trait]
    impl openre_core::traits::EvidenceStore for MockEvidenceStore {
        async fn get_evidence(
            &self,
            _finding_id: FindingId,
        ) -> openre_core::Result<Option<FindingEvidence>> {
            Ok(None)
        }

        async fn get_evidence_batch(
            &self,
            _finding_ids: &[FindingId],
        ) -> openre_core::Result<Vec<FindingEvidence>> {
            Ok(vec![])
        }

        async fn get_scan_evidence(
            &self,
            _scan_id: ScanId,
        ) -> openre_core::Result<Vec<FindingEvidence>> {
            Ok(vec![])
        }

        async fn store_evidence(&self, _evidence: &FindingEvidence) -> openre_core::Result<()> {
            Ok(())
        }

        async fn delete_evidence(&self, _finding_id: FindingId) -> openre_core::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_validate_grounding_extracts_ids() {
        let service = GroundedLlmService::new(Arc::new(MockAiService), Arc::new(MockEvidenceStore));

        let response = r#"The finding is confirmed [Evidence: ev-123]. The attack vector is proven [Evidence: ev-456]."#;
        let ids = service.extract_referenced_evidence_ids(response);
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"ev-123".to_string()));
        assert!(ids.contains(&"ev-456".to_string()));
    }

    #[test]
    fn test_claim_requires_evidence_detection() {
        let service = GroundedLlmService::new(Arc::new(MockAiService), Arc::new(MockEvidenceStore));

        assert!(service.claim_requires_evidence("The finding is confirmed vulnerable"));
        assert!(service.claim_requires_evidence("This allows attackers to execute code"));
        assert!(service.claim_requires_evidence("The root cause is missing validation"));
        assert!(!service.claim_requires_evidence("This is a general statement"));
    }
}
