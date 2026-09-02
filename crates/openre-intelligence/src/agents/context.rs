//! Agent context and related types

use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use crate::agents::agent_trait::{AgentContext, AiService, CancellationToken, ScanStorage, SharedState, TelemetryHandle};
use async_trait::async_trait;
use openre_core::ids::{FindingId, ScanId, WorkflowId};
use openre_core::result::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Input for Recon agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconInput {
    /// Target URL
    pub target: String,
    /// Maximum depth for crawling
    pub max_depth: Option<usize>,
    /// Include authentication endpoints
    pub include_auth: bool,
    /// Include parameter discovery
    pub include_params: bool,
    /// Custom headers
    pub headers: HashMap<String, String>,
    /// Timeout in seconds
    pub timeout_seconds: Option<u64>,
}

/// Output from Recon agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconOutput {
    /// Discovered URLs
    pub urls: Vec<DiscoveredUrl>,
    /// Discovered endpoints
    pub endpoints: Vec<DiscoveredEndpoint>,
    /// Detected technologies
    pub technologies: Vec<DetectedTechnology>,
    /// Authentication endpoints
    pub auth_endpoints: Vec<AuthEndpoint>,
    /// Forms discovered
    pub forms: Vec<DiscoveredForm>,
}

/// Discovered URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredUrl {
    pub url: String,
    pub method: String,
    pub status_code: Option<u16>,
    pub discovered_via: String,
    pub response_headers: HashMap<String, String>,
    pub technologies: Vec<String>,
    pub parameters: Vec<String>,
    pub forms: Vec<String>,
    pub auth_info: Option<String>,
}

/// Discovered endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    pub path: String,
    pub methods: Vec<String>,
    pub parameters: Vec<EndpointParameter>,
    pub authentication: Option<String>,
    pub sensitivity: String,
    pub technology_stack: Vec<String>,
}

/// Endpoint parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointParameter {
    pub name: String,
    pub param_type: String,
    pub location: String, // query, body, header, path
    pub required: bool,
    pub description: Option<String>,
}

/// Detected technology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTechnology {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f32,
    pub categories: Vec<String>,
    pub evidence: Vec<String>,
}

/// Authentication endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEndpoint {
    pub url: String,
    pub auth_type: String, // form, basic, oauth, saml, etc.
    pub login_form: Option<DiscoveredForm>,
    pub password_reset: Option<String>,
    pub registration: Option<String>,
}

/// Discovered form
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    pub url: String,
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
    pub has_csrf: bool,
    pub has_file_upload: bool,
}

/// Form field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub required: bool,
    pub autocomplete: Option<String>,
}

/// Input for WebAnalysis agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAnalysisInput {
    /// Target URL
    pub target: String,
    /// Findings from recon
    pub recon_output: Option<ReconOutput>,
    /// Scan ID
    pub scan_id: Option<ScanId>,
    /// Specific tests to run
    pub tests: Option<Vec<String>>,
    /// Exclude tests
    pub exclude_tests: Option<Vec<String>>,
    /// Custom configuration
    pub config: HashMap<String, serde_json::Value>,
}

/// Output from WebAnalysis agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAnalysisOutput {
    /// Findings discovered
    pub findings: Vec<Finding>,
    /// Technology stack analyzed
    pub technology_stack: Vec<DetectedTechnology>,
    /// Security headers analysis
    pub security_headers: HashMap<String, String>,
    /// Client-side issues
    pub client_side_issues: Vec<ClientSideIssue>,
}

/// Client-side issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSideIssue {
    pub url: String,
    pub issue_type: String,
    pub severity: String,
    pub description: String,
    pub evidence: Vec<String>,
}

/// Input for ApiAnalysis agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAnalysisInput {
    /// Target URL
    pub target: String,
    /// API schema (OpenAPI, GraphQL SDL)
    pub schema: Option<String>,
    /// Schema format
    pub schema_format: Option<String>, // openapi, graphql
    /// Authentication tokens
    pub auth_tokens: HashMap<String, String>,
    /// Findings from recon
    pub recon_output: Option<ReconOutput>,
}

/// Output from ApiAnalysis agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAnalysisOutput {
    /// Findings discovered
    pub findings: Vec<Finding>,
    /// Endpoints analyzed
    pub endpoints: Vec<ApiEndpoint>,
    /// Schema issues
    pub schema_issues: Vec<SchemaIssue>,
}

/// API endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub path: String,
    pub method: String,
    pub parameters: Vec<EndpointParameter>,
    pub authentication: Option<String>,
    pub rate_limited: bool,
    pub schema_validation: bool,
}

/// Schema issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaIssue {
    pub path: String,
    pub issue_type: String,
    pub severity: String,
    pub description: String,
}

/// Input for Correlation agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationInput {
    /// Findings to correlate
    pub findings: Vec<Finding>,
    /// Application map (optional)
    pub app_map: Option<serde_json::Value>,
    /// Minimum confidence for correlations
    pub min_confidence: Option<f32>,
    /// Correlation types to include
    pub correlation_types: Option<Vec<String>>,
}

/// Output from Correlation agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationOutput {
    /// Correlations found
    pub correlations: Vec<Correlation>,
    /// Attack paths built
    pub attack_paths: Vec<AttackPath>,
    /// Root causes identified
    pub root_causes: Vec<RootCause>,
}

/// Correlation between findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub source_finding: FindingId,
    pub target_finding: FindingId,
    pub correlation_type: String,
    pub confidence: f32,
    pub description: String,
    pub evidence: Vec<String>,
    pub combined_risk: u8,
}

/// Attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub id: String,
    pub name: String,
    pub nodes: Vec<AttackPathNode>,
    pub edges: Vec<AttackPathEdge>,
    pub overall_risk: u8,
    pub entry_points: Vec<String>,
    pub impact: String,
}

/// Attack path node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathNode {
    pub id: String,
    pub node_type: String, // asset, entry_point, weakness, pivot, impact
    pub finding_id: Option<FindingId>,
    pub endpoint_id: Option<String>,
    pub asset_id: Option<String>,
    pub evidence: Vec<String>,
    pub risk_contribution: f32,
}

/// Attack path edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathEdge {
    pub from: String,
    pub to: String,
    pub relationship: String,
    pub evidence: Vec<String>,
    pub confidence: f32,
}

/// Root cause
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub id: String,
    pub finding_id: FindingId,
    pub related_findings: Vec<FindingId>,
    pub description: String,
    pub impact_assessment: String,
    pub remediation_approach: String,
    pub priority: String,
}

/// Input for Verification agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationInput {
    /// Findings to verify
    pub findings: Vec<Finding>,
    /// Verification methods to use
    pub methods: Option<Vec<String>>,
    /// Only safe checks
    pub safe_only: bool,
    /// Target URL for context
    pub target: String,
}

/// Output from Verification agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationOutput {
    /// Verification results
    pub results: Vec<VerificationResult>,
    /// Summary
    pub summary: VerificationSummary,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub finding_id: FindingId,
    pub status: String, // confirmed, likely, unconfirmed, not_reproducible, error
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub notes: String,
    pub method_used: String,
}

/// Verification summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub total: usize,
    pub confirmed: usize,
    pub likely: usize,
    pub unconfirmed: usize,
    pub not_reproducible: usize,
    pub errors: usize,
}

/// Input for Remediation agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationInput {
    /// Findings to remediate
    pub findings: Vec<Finding>,
    /// Target application info
    pub target: String,
    /// Technology stack
    pub technologies: Vec<DetectedTechnology>,
    /// Preferred fix types
    pub fix_types: Option<Vec<String>>,
}

/// Output from Remediation agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOutput {
    /// Remediation suggestions
    pub suggestions: Vec<RemediationSuggestion>,
    /// Fix verification results
    pub verification: Vec<FixVerification>,
}

/// Remediation suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSuggestion {
    pub finding_id: FindingId,
    pub title: String,
    pub description: String,
    pub fix_type: String, // config_change, code_change, library_update, waf_rule
    pub code_example: Option<String>,
    pub config_example: Option<String>,
    pub references: Vec<String>,
    pub effort: String, // low, medium, high
    pub priority: String,
}

/// Fix verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixVerification {
    pub finding_id: FindingId,
    pub verified: bool,
    pub confidence: f32,
    pub evidence: Vec<String>,
    pub notes: String,
}

/// Input for Reporting agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingInput {
    /// Scan ID
    pub scan_id: ScanId,
    /// Findings
    pub findings: Vec<Finding>,
    /// Correlations
    pub correlations: Option<Vec<Correlation>>,
    /// Attack paths
    pub attack_paths: Option<Vec<AttackPath>>,
    /// Verification results
    pub verification: Option<Vec<VerificationResult>>,
    /// Remediation suggestions
    pub remediation: Option<Vec<RemediationSuggestion>>,
    /// Report format
    pub format: String, // json, html, pdf, sarif
    /// Report type
    pub report_type: String, // executive, technical, compliance
}

/// Output from Reporting agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportingOutput {
    /// Generated report
    pub report: String,
    /// Report format
    pub format: String,
    /// Report metadata
    pub metadata: ReportMetadata,
}

/// Report metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub scan_id: ScanId,
    pub total_findings: usize,
    pub findings_by_severity: HashMap<String, usize>,
    pub report_type: String,
}

/// Input for Research agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchInput {
    /// Finding to research
    pub finding: Finding,
    /// Research types
    pub research_types: Vec<String>, // cve, cwe, capec, mitre, exploit
    /// Technology context
    pub technologies: Vec<DetectedTechnology>,
}

/// Output from Research agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResearchOutput {
    /// CVE matches
    pub cve_matches: Vec<CveMatch>,
    /// CWE mappings
    pub cwe_mappings: Vec<CweMapping>,
    /// CAPEC mappings
    pub capec_mappings: Vec<CapecMapping>,
    /// MITRE ATT&CK mappings
    pub mitre_mappings: Vec<MitreMapping>,
    /// Exploit information
    pub exploits: Vec<ExploitInfo>,
}

/// CVE match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMatch {
    pub cve_id: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub description: String,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub exploit_available: bool,
    pub exploit_maturity: Option<String>,
    pub patch_available: bool,
}

/// CWE mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CweMapping {
    pub cwe_id: String,
    pub name: String,
    pub description: String,
    pub related_weaknesses: Vec<String>,
}

/// CAPEC mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapecMapping {
    pub capec_id: String,
    pub name: String,
    pub description: String,
    pub likelihood: String,
    pub typical_severity: String,
}

/// MITRE ATT&CK mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub name: String,
    pub tactic: String,
    pub description: String,
    pub detection: Vec<String>,
}

/// Exploit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitInfo {
    pub source: String, // exploit-db, metasploit, etc.
    pub id: String,
    pub title: String,
    pub description: String,
    pub platform: String,
    pub type_: String,
    pub verified: bool,
}

/// Implement AgentInput for all input types
impl crate::agents::agent_trait::AgentInput for ReconInput {}
impl crate::agents::agent_trait::AgentInput for WebAnalysisInput {}
impl crate::agents::agent_trait::AgentInput for ApiAnalysisInput {}
impl crate::agents::agent_trait::AgentInput for CorrelationInput {}
impl crate::agents::agent_trait::AgentInput for VerificationInput {}
impl crate::agents::agent_trait::AgentInput for RemediationInput {}
impl crate::agents::agent_trait::AgentInput for ReportingInput {}
impl crate::agents::agent_trait::AgentInput for ResearchInput {}

/// Implement AgentOutput for all output types
impl crate::agents::agent_trait::AgentOutput for ReconOutput {}
impl crate::agents::agent_trait::AgentOutput for WebAnalysisOutput {}
impl crate::agents::agent_trait::AgentOutput for ApiAnalysisOutput {}
impl crate::agents::agent_trait::AgentOutput for CorrelationOutput {}
impl crate::agents::agent_trait::AgentOutput for VerificationOutput {}
impl crate::agents::agent_trait::AgentOutput for RemediationOutput {}
impl crate::agents::agent_trait::AgentOutput for ReportingOutput {}
impl crate::agents::agent_trait::AgentOutput for ResearchOutput {}