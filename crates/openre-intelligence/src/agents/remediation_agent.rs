//! Remediation agent implementation

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, SecurityAgent, BaseAgent};
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use crate::remediation::RemediationVerifier;
use async_trait::async_trait;
use openre_core::ids::AgentId;
use openre_core::ids::FindingId;
use openre_core::result::Finding;
use std::sync::Arc;

/// Remediation agent for suggesting and verifying fixes
pub struct RemediationAgent {
    base: BaseAgent,
    remediation_verifier: Arc<RemediationVerifier>,
}

impl RemediationAgent {
    /// Create a new remediation agent
    pub fn new(remediation_verifier: Arc<RemediationVerifier>) -> Self {
        let base = BaseAgent::new("remediation-agent".to_string(), AgentType::Remediation);
        Self { base, remediation_verifier }
    }
}

#[async_trait]
impl SecurityAgent for RemediationAgent {
    type Input = RemediationInput;
    type Output = RemediationOutput;

    fn agent_id(&self) -> AgentId {
        self.base.agent_id()
    }

    fn agent_type(&self) -> AgentType {
        self.base.agent_type()
    }

    fn capabilities(&self) -> Vec<AgentCapability> {
        self.base.capabilities()
    }

    fn name(&self) -> &str {
        self.base.name()
    }

    async fn execute(&self, input: Self::Input, _ctx: AgentContext) -> anyhow::Result<AgentResult<Self::Output>> {
        let started_at = std::time::Instant::now();

        let mut suggestions = Vec::new();
        let mut verification = Vec::new();

        for finding in &input.findings {
            // Generate remediation suggestions based on finding type (inlined)
            let (title, description, fix_type, code_example, config_example, effort, priority) = match finding.category {
                openre_core::result::Category::Injection => (
                    "Fix SQL/Command Injection".to_string(),
                    "Use parameterized queries and input validation".to_string(),
                    "code_change".to_string(),
                    Some("// Bad: query = \"SELECT * FROM users WHERE id = \" + user_input;\n// Good: query = \"SELECT * FROM users WHERE id = ?\"; stmt.bind(user_input);".to_string()),
                    None,
                    "medium".to_string(),
                    "high".to_string(),
                ),
                openre_core::result::Category::Xss => (
                    "Fix Cross-Site Scripting".to_string(),
                    "Implement proper output encoding and Content Security Policy".to_string(),
                    "code_change".to_string(),
                    Some("// Bad: element.innerHTML = user_input;\n// Good: element.textContent = user_input;".to_string()),
                    Some("Content-Security-Policy: default-src 'self'; script-src 'self'".to_string()),
                    "medium".to_string(),
                    "high".to_string(),
                ),
                openre_core::result::Category::BrokenAuthentication => (
                    "Fix Authentication Issue".to_string(),
                    "Implement proper authentication checks and session management".to_string(),
                    "config_change".to_string(),
                    None,
                    Some("session.cookie_httponly = true\nsession.cookie_secure = true\nsession.use_strict_mode = true".to_string()),
                    "low".to_string(),
                    "high".to_string(),
                ),
                openre_core::result::Category::SecurityMisconfiguration => (
                    "Fix Security Misconfiguration".to_string(),
                    "Apply secure configuration settings".to_string(),
                    "config_change".to_string(),
                    None,
                    Some("# Example secure headers\nX-Frame-Options: DENY\nX-Content-Type-Options: nosniff\nStrict-Transport-Security: max-age=31536000".to_string()),
                    "low".to_string(),
                    "medium".to_string(),
                ),
                _ => (
                    "General Remediation".to_string(),
                    "Review and address the finding".to_string(),
                    "code_change".to_string(),
                    None,
                    None,
                    "medium".to_string(),
                    "medium".to_string(),
                ),
            };

            let suggestion = RemediationSuggestion {
                finding_id: finding.id,
                title,
                description,
                fix_type,
                code_example,
                config_example,
                references: Vec::new(),
                effort,
                priority,
            };
            suggestions.push(suggestion);

            // Verify if there's a baseline scan to compare against
            // In a real implementation, this would use the remediation_verifier
            verification.push(FixVerification {
                finding_id: finding.id,
                verified: false,
                confidence: 0.0,
                evidence: Vec::new(),
                notes: "Baseline scan required for verification".to_string(),
            });
        }

        let output = RemediationOutput {
            suggestions,
            verification,
        };

        let duration_ms = started_at.elapsed().as_millis() as u64;
        Ok(AgentResult::success(output, duration_ms))
    }

    async fn health_check(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}