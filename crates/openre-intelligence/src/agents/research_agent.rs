//! Research agent implementation

use crate::agents::context::*;
use crate::agents::agent_trait::{AgentContext, SecurityAgent, BaseAgent};
use crate::agents::types::{AgentCapability, AgentHealth, AgentResult, AgentType};
use openre_core::ids::AgentId;
use crate::cve_intelligence::CveIntelligence;
use crate::knowledge_base::KnowledgeBase;
use async_trait::async_trait;
use openre_core::result::Finding;
use std::sync::Arc;

/// Research agent for fetching CVE, CWE, CAPEC, ATT&CK data
pub struct ResearchAgent {
    base: BaseAgent,
    cve_intelligence: Arc<CveIntelligence>,
    knowledge_base: Arc<KnowledgeBase>,
}

impl ResearchAgent {
    /// Create a new research agent
    pub fn new(cve_intelligence: Arc<CveIntelligence>, knowledge_base: Arc<KnowledgeBase>) -> Self {
        let base = BaseAgent::new("research-agent".to_string(), AgentType::Research);
        Self { base, cve_intelligence, knowledge_base }
    }
}

#[async_trait]
impl SecurityAgent for ResearchAgent {
    type Input = ResearchInput;
    type Output = ResearchOutput;

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

        let mut cve_matches = Vec::new();
        let mut cwe_mappings = Vec::new();
        let mut capec_mappings = Vec::new();
        let mut mitre_mappings = Vec::new();
        let mut exploits = Vec::new();

        // Look up CVEs based on finding and technologies
        for tech in &input.technologies {
            if let Some(version) = &tech.version {
                if let Ok(cves) = self.cve_intelligence.search_cves(&tech.name, version).await {
                    for cve in cves {
                        cve_matches.push(CveMatch {
                            cve_id: cve.cve_id,
                            cvss_score: cve.cvss_score,
                            cvss_vector: cve.cvss_vector,
                            description: cve.description,
                            affected_versions: cve.affected_versions.iter().map(|v| v.to_string()).collect(),
                            fixed_versions: cve.fixed_versions,
                            exploit_available: false,
                            exploit_maturity: None,
                            patch_available: false,
                        });
                    }
                }
            }
        }

        // Get CWE mappings from knowledge base
        if let Some(entry) = self.knowledge_base.get_entry(&input.finding.id).await {
            for cwe_id in &entry.cwe_ids {
                cwe_mappings.push(CweMapping {
                    cwe_id: cwe_id.clone(),
                    name: "CWE Entry".to_string(),
                    description: "See CWE database".to_string(),
                    related_weaknesses: Vec::new(),
                });
            }
            for capec_id in &entry.capec_ids {
                capec_mappings.push(CapecMapping {
                    capec_id: capec_id.clone(),
                    name: "CAPEC Entry".to_string(),
                    description: "See CAPEC database".to_string(),
                    likelihood: "Medium".to_string(),
                    typical_severity: "Medium".to_string(),
                });
            }
            for attack_id in &entry.mitre_attack_techniques {
                mitre_mappings.push(MitreMapping {
                    technique_id: attack_id.clone(),
                    name: "ATT&CK Technique".to_string(),
                    tactic: "Unknown".to_string(),
                    description: "See MITRE ATT&CK".to_string(),
                    detection: Vec::new(),
                });
            }
        }

        let output = ResearchOutput {
            cve_matches,
            cwe_mappings,
            capec_mappings,
            mitre_mappings,
            exploits,
        };

        let duration_ms = started_at.elapsed().as_millis() as u64;
        Ok(AgentResult::success(output, duration_ms))
    }

    async fn health_check(&self) -> AgentHealth {
        AgentHealth::Healthy
    }
}