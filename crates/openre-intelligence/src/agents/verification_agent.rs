//! Verification agent implementation

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, SecurityAgent, BaseAgent};
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use crate::verification::VerificationEngine;
use async_trait::async_trait;
use openre_core::ids::FindingId;
use openre_core::result::Finding;
use std::sync::Arc;

/// Verification agent for verifying findings with safe checks
pub struct VerificationAgent {
    base: BaseAgent,
    verification_engine: Arc<VerificationEngine>,
}

impl VerificationAgent {
    /// Create a new verification agent
    pub fn new(verification_engine: Arc<VerificationEngine>) -> Self {
        let base = BaseAgent::new("verification-agent".to_string(), AgentType::Verification);
        Self { base, verification_engine }
    }
}

#[async_trait]
impl SecurityAgent for VerificationAgent {
    type Input = VerificationInput;
    type Output = VerificationOutput;

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

        let mut results = Vec::new();

        for finding in &input.findings {
            // Use the verification engine to verify the finding
            match self.verification_engine.verify_finding(finding).await {
                Ok(evidence_result) => {
                    let status = match evidence_result.status {
                        openre_core::evidence::VerificationStatus::Confirmed => "confirmed",
                        openre_core::evidence::VerificationStatus::Likely => "likely",
                        openre_core::evidence::VerificationStatus::Unconfirmed => "unconfirmed",
                        openre_core::evidence::VerificationStatus::NotReproducible => "not_reproducible",
                        openre_core::evidence::VerificationStatus::Error => "error",
                        openre_core::evidence::VerificationStatus::Skipped => "skipped",
                    };

                    let notes = evidence_result.notes.clone();
                    results.push(VerificationResult {
                        finding_id: evidence_result.finding_id,
                        status: status.to_string(),
                        confidence: evidence_result.confidence,
                        evidence: vec![notes.clone()],
                        notes,
                        method_used: "verification_engine".to_string(),
                    });
                }
                Err(e) => {
                    results.push(VerificationResult {
                        finding_id: finding.id,
                        status: "error".to_string(),
                        confidence: 0.0,
                        evidence: Vec::new(),
                        notes: e.to_string(),
                        method_used: "verification_engine".to_string(),
                    });
                }
            }
        }

        let summary = VerificationSummary {
            total: results.len(),
            confirmed: results.iter().filter(|r| r.status == "confirmed").count(),
            likely: results.iter().filter(|r| r.status == "likely").count(),
            unconfirmed: results.iter().filter(|r| r.status == "unconfirmed").count(),
            not_reproducible: results.iter().filter(|r| r.status == "not_reproducible").count(),
            errors: results.iter().filter(|r| r.status == "error").count(),
        };

        let output = VerificationOutput {
            results,
            summary,
        };

        let duration_ms = started_at.elapsed().as_millis() as u64;
        Ok(AgentResult::success(output, duration_ms))
    }

    async fn health_check(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}