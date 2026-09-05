//! Stub types for intelligence features (replacing openre-intelligence)

use thiserror::Error;
use chrono::{DateTime, Utc};
use openre_core::ids::{FindingId, ScanId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Intelligence error
#[derive(Error, Debug)]
pub enum IntelligenceError {
    #[error("Correlation failed: {0}")]
    CorrelationError(String),

    #[error("Remediation failed: {0}")]
    RemediationError(String),

    #[error("Exploit generation failed: {0}")]
    ExploitError(String),

    #[error("Knowledge base error: {0}")]
    KnowledgeBaseError(String),

    #[error("Workflow error: {0}")]
    WorkflowError(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Finding structure (matches openre_core::result::Finding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: FindingId,
    pub scan_id: ScanId,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub confidence: Confidence,
    pub location: Option<String>,
    pub evidence: serde_json::Value,
    pub remediation: Option<String>,
    pub remediation_effort: Option<String>,
    pub remediation_priority: Option<String>,
    pub references: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub capec_ids: Vec<String>,
    pub owasp_ids: Vec<String>,
    pub mitre_ids: Vec<String>,
    pub cvss_score: Option<f32>,
    pub risk_score: Option<f32>,
    pub exploitability: Option<String>,
    pub is_verified: bool,
    pub false_positive: bool,
    pub tags: Vec<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Category {
    Injection,
    BrokenAuth,
    SensitiveData,
    Xxe,
    BrokenAccess,
    SecurityMisconfig,
    Xss,
    InsecureDeserialization,
    VulnerableComponents,
    InsufficientLogging,
    Ssrf,
    Csrf,
    Idor,
    OpenRedirect,
    PathTraversal,
    CommandInjection,
    LdapInjection,
    TemplateInjection,
    Deserialization,
    JwtIssues,
    OAuthIssues,
    WebsocketIssues,
    GraphqlIssues,
    RateLimiting,
    Cors,
    Csp,
    CookieSecurity,
    InfoDisclosure,
    TechFingerprint,
    TlsIssues,
    HttpMethods,
    SslConfig,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Confidence {
    VeryHigh,
    High,
    Medium,
    Low,
    VeryLow,
}

/// Correlation engine stub
#[derive(Debug, Clone)]
pub struct CorrelationEngine;

impl CorrelationEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn correlate(&self, _findings: &[Finding]) -> anyhow::Result<Vec<Correlation>> {
        Ok(vec![])
    }
}

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Correlation {
    pub finding_a: Finding,
    pub finding_b: Finding,
    pub correlation_type: CorrelationType,
    pub confidence: f32,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CorrelationType {
    SameRootCause,
    ChainedExploit,
    SharedComponent,
    RelatedAttackVector,
    Duplicate,
    Strengthening,
    Mitigating,
}

/// Remediation engine stub
#[derive(Debug, Clone)]
pub struct RemediationEngine;

impl RemediationEngine {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate_plan(
        &self,
        _finding: &Finding,
        _environment: Environment,
        _compliance: Option<ComplianceFramework>,
    ) -> anyhow::Result<RemediationPlan> {
        Ok(RemediationPlan::default())
    }

    pub async fn quick_fix(&self, _finding: &Finding, _language: Option<Language>) -> anyhow::Result<QuickFix> {
        Ok(QuickFix::default())
    }

    pub async fn generate_report(
        &self,
        _findings: &[Finding],
        _group_by: GroupBy,
    ) -> anyhow::Result<RemediationReport> {
        Ok(RemediationReport::default())
    }

    pub async fn verify(&self, _finding: &Finding, _target: &str) -> anyhow::Result<VerificationResult> {
        Ok(VerificationResult {
            remediated: false,
            evidence: "Not implemented".to_string(),
        })
    }
}

/// Remediation plan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub summary: String,
    pub steps: Vec<RemediationStep>,
    pub references: Vec<String>,
    pub total_effort: String,
    pub critical_path: Vec<String>,
}

/// Remediation step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStep {
    pub title: String,
    pub description: String,
    pub effort: String,
    pub priority: Priority,
    pub code_example: Option<String>,
}

/// Quick fix
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuickFix {
    pub description: String,
    pub code: Option<String>,
    pub config: Option<String>,
    pub commands: Option<Vec<String>>,
}

/// Remediation report
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationReport {
    pub groups: Vec<RemediationGroup>,
    pub total_effort: String,
    pub critical_path: Vec<String>,
}

/// Remediation group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationGroup {
    pub name: String,
    pub count: usize,
    pub items: Vec<RemediationItem>,
}

/// Remediation item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationItem {
    pub finding_title: String,
    pub priority: Priority,
    pub effort: String,
    pub summary: String,
}

/// Verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub remediated: bool,
    pub evidence: String,
}

/// Exploit generator stub
#[derive(Debug, Clone)]
pub struct ExploitGenerator;

impl ExploitGenerator {
    pub fn new() -> Self {
        Self
    }

    pub async fn generate(
        &self,
        _finding: &Finding,
        _language: Language,
        _template: Option<&str>,
        _target: Option<&str>,
        _safe: bool,
    ) -> anyhow::Result<Exploit> {
        Ok(Exploit {
            code: "// Exploit generation not implemented".to_string(),
            language: _language.to_string(),
            template: _template.unwrap_or("custom").to_string(),
            safe: _safe,
            requires: vec![],
        })
    }

    pub fn list_templates(
        &self,
        _category: Option<VulnCategory>,
        _language: Option<Language>,
    ) -> Vec<ExploitTemplate> {
        vec![]
    }

    pub async fn validate(
        &self,
        _code: &str,
        _target: &str,
        _dry_run: bool,
    ) -> anyhow::Result<ValidationResult> {
        Ok(ValidationResult {
            works: false,
            details: "Not implemented".to_string(),
            evidence: vec![],
        })
    }

    pub fn get_template(&self, _name: &str) -> Option<ExploitTemplate> {
        None
    }
}

/// Exploit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Exploit {
    pub code: String,
    pub language: String,
    pub template: String,
    pub safe: bool,
    pub requires: Vec<String>,
}

/// Exploit template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitTemplate {
    pub name: String,
    pub category: VulnCategory,
    pub language: Language,
    pub description: String,
    pub safe: bool,
    pub code: String,
}

/// Validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub works: bool,
    pub details: String,
    pub evidence: Vec<String>,
}

/// Vulnerability category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VulnCategory {
    Sqli,
    Xss,
    Rce,
    Ssrf,
    Xxe,
    PathTraversal,
    CommandInjection,
    LdapInjection,
    TemplateInjection,
    Deserialization,
    AuthBypass,
    Idor,
    Csrf,
    OpenRedirect,
}

/// Programming language
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    Python,
    Bash,
    JavaScript,
    TypeScript,
    Go,
    Rust,
    Ruby,
    Php,
    Java,
    CSharp,
    PowerShell,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Python => write!(f, "python"),
            Language::Bash => write!(f, "bash"),
            Language::JavaScript => write!(f, "javascript"),
            Language::TypeScript => write!(f, "typescript"),
            Language::Go => write!(f, "go"),
            Language::Rust => write!(f, "rust"),
            Language::Ruby => write!(f, "ruby"),
            Language::Php => write!(f, "php"),
            Language::Java => write!(f, "java"),
            Language::CSharp => write!(f, "csharp"),
            Language::PowerShell => write!(f, "powershell"),
        }
    }
}

/// Environment for remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Environment {
    Development,
    Staging,
    Production,
    CiCd,
}

/// Compliance framework
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    Owasp,
    PciDss,
    Hipaa,
    Gdpr,
    Soc2,
    Iso27001,
    Nist,
}

/// Priority for remediation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Group by for reports
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupBy {
    Severity,
    Category,
    Component,
    Compliance,
}

/// Exploit template detail for show command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitTemplateDetail {
    pub name: String,
    pub category: VulnCategory,
    pub language: Language,
    pub description: String,
    pub safe: bool,
    pub code: String,
}