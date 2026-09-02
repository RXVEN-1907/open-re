//! Correlation agent implementation

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, SecurityAgent, BaseAgent};
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use crate::correlation::CorrelationEngine;
use async_trait::async_trait;
use openre_core::ids::FindingId;
use openre_core::result::Finding;
use std::sync::Arc;

/// Correlation agent for correlating findings and building attack paths
pub struct CorrelationAgent {
    base: BaseAgent,
    correlation_engine: Arc<CorrelationEngine>,
}

impl CorrelationAgent {
    /// Create a new correlation agent
    pub fn new(correlation_engine: Arc<CorrelationEngine>) -> Self {
        let base = BaseAgent::new("correlation-agent".to_string(), AgentType::Correlation);
        Self { base, correlation_engine }
    }
}

#[async_trait]
impl SecurityAgent for CorrelationAgent {
    type Input = CorrelationInput;
    type Output = CorrelationOutput;

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

        // Correlate findings using the correlation engine
        let relationships = self.correlation_engine.correlate_findings(&input.findings).await?;

        // Convert to our correlation format
        let correlations: Vec<Correlation> = relationships.into_iter().map(|rel| {
            Correlation {
                source_finding: rel.source_finding,
                target_finding: rel.target_finding,
                correlation_type: format!("{:?}", rel.relationship_type),
                confidence: rel.confidence,
                description: rel.explanation,
                evidence: rel.evidence.iter().map(|e| e.description.clone()).collect(),
                combined_risk: 0, // Would calculate based on findings
            }
        }).collect();

        // Build attack paths (simplified)
        let attack_paths = Vec::new();
        let root_causes = Vec::new();

        let output = CorrelationOutput {
            correlations,
            attack_paths,
            root_causes,
        };

        let duration_ms = started_at.elapsed().as_millis() as u64;
        Ok(AgentResult::success(output, duration_ms))
    }

    async fn health_check(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}