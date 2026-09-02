//! Finding Relationship types for representing connections between security findings

use crate::ids::{FindingId, RelationshipId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents a relationship between two findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRelationship {
    /// Unique relationship ID
    pub id: RelationshipId,
    /// Source finding ID
    pub source_finding: FindingId,
    /// Target finding ID
    pub target_finding: FindingId,
    /// Type of relationship
    pub relationship_type: FindingRelationshipType,
    /// Human-readable explanation
    pub explanation: String,
    /// Evidence supporting this relationship
    pub evidence: Vec<RelationshipEvidence>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// How this relationship changes risk assessment
    pub risk_impact: RiskImpact,
    /// CWE IDs that support this relationship type
    pub supporting_cwes: Vec<String>,
    /// CAPEC IDs that support this relationship type
    pub supporting_capecs: Vec<String>,
    /// MITRE ATT&CK technique IDs
    pub supporting_attack_techniques: Vec<String>,
    /// Timestamp when relationship was discovered
    pub discovered_at: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of relationships between findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingRelationshipType {
    /// Finding A enables exploitation of Finding B
    Enables,
    /// Finding A increases severity/impact of Finding B
    Amplifies,
    /// Finding B requires Finding A to be exploitable
    Requires,
    /// Both findings stem from the same underlying root cause
    SameRootCause,
    /// Finding A leads to Finding B in an exploit chain
    ChainedExploit,
    /// Finding A mitigates Finding B (e.g., CSP mitigates XSS)
    Mitigates,
    /// Same issue reported by different plugins/scanners
    Duplicate,
    /// Findings share the same vulnerable component
    SharedComponent,
    /// Findings affect the same endpoint/parameter
    SharedAttackSurface,
    /// One finding provides information that helps exploit another
    InformationLeakage,
    /// Findings form a privilege escalation chain
    PrivilegeEscalation,
    /// Findings form a lateral movement chain
    LateralMovement,
    /// Findings form a data exfiltration chain
    DataExfiltration,
    /// One finding is a prerequisite for another
    Prerequisite,
    /// Findings are mutually exclusive (one prevents the other)
    MutuallyExclusive,
    /// Temporal relationship (findings discovered close in time)
    Temporal,
    /// Spatial relationship (findings in same component/module)
    Spatial,
    /// Custom relationship type
    Custom,
}

/// Evidence supporting a finding relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipEvidence {
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// Description of the evidence
    pub description: String,
    /// Structured data supporting the evidence
    pub data: serde_json::Value,
    /// Source of the evidence
    pub source: EvidenceSource,
    /// Confidence in this specific evidence (0.0 - 1.0)
    pub confidence: f32,
    /// Related finding IDs
    pub related_findings: Vec<FindingId>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Types of evidence for relationships
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceType {
    /// HTTP request/response showing the relationship
    HttpInteraction,
    /// Configuration file showing the relationship
    Configuration,
    /// Code pattern indicating the relationship
    CodePattern,
    /// CVE/CWE/CAPEC database match
    DatabaseMatch,
    /// Manual analysis
    ManualAnalysis,
    /// Automated correlation engine
    AutomatedCorrelation,
    /// AI/ML inference
    AiInference,
    /// Exploit demonstration
    ExploitDemo,
    /// Patch/diff analysis
    PatchAnalysis,
    /// Runtime observation
    RuntimeObservation,
    /// Log analysis
    LogAnalysis,
    /// Memory/heap analysis
    MemoryAnalysis,
    /// Network traffic analysis
    NetworkTraffic,
    /// Custom evidence type
    Custom,
}

/// Sources of evidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Scanner plugin
    Scanner,
    /// Manual analysis by human
    Manual,
    /// CVE database
    Cve,
    /// CWE database
    Cwe,
    /// CAPEC database
    Capec,
    /// MITRE ATT&CK
    MitreAttack,
    /// Exploit database
    ExploitDb,
    /// Vendor advisory
    VendorAdvisory,
    /// Security research publication
    Research,
    /// AI/ML model
    AiModel,
    /// Custom source
    Custom,
}

/// Risk impact of a finding relationship
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskImpact {
    /// Base risk score change (-100 to +100)
    pub score_delta: i16,
    /// Risk level change
    pub level_change: RiskLevelChange,
    /// Explanation of risk impact
    pub explanation: String,
    /// Affected risk factors
    pub affected_factors: Vec<RiskFactor>,
    /// Confidence in risk assessment (0.0 - 1.0)
    pub confidence: f32,
}

/// Risk level change direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevelChange {
    /// Risk significantly increased
    SignificantIncrease,
    /// Risk moderately increased
    ModerateIncrease,
    /// Risk slightly increased
    SlightIncrease,
    /// No significant change
    NoChange,
    /// Risk slightly decreased
    SlightDecrease,
    /// Risk moderately decreased
    ModerateDecrease,
    /// Risk significantly decreased
    SignificantDecrease,
}

/// Risk factors affected by relationships
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactor {
    /// Exploitability
    Exploitability,
    /// Impact/Consequence
    Impact,
    /// Attack complexity
    AttackComplexity,
    /// Privileges required
    PrivilegesRequired,
    /// User interaction
    UserInteraction,
    /// Scope
    Scope,
    /// Confidentiality
    Confidentiality,
    /// Integrity
    Integrity,
    /// Availability
    Availability,
    /// Detectability
    Detectability,
    /// Remediation difficulty
    RemediationDifficulty,
}

/// Collection of finding relationships for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRelationshipGraph {
    /// All relationships
    pub relationships: Vec<FindingRelationship>,
    /// Finding IDs in this graph
    pub finding_ids: Vec<FindingId>,
    /// Graph metadata
    pub metadata: RelationshipGraphMetadata,
}

/// Metadata for relationship graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipGraphMetadata {
    /// Total relationships
    pub total_relationships: usize,
    /// Relationships by type
    pub by_type: HashMap<FindingRelationshipType, usize>,
    /// Average confidence
    pub average_confidence: f32,
    /// Highest confidence
    pub max_confidence: f32,
    /// Lowest confidence
    pub min_confidence: f32,
    /// Timestamp of graph generation
    pub generated_at: DateTime<Utc>,
    /// Correlation engine version
    pub engine_version: String,
}

impl FindingRelationshipGraph {
    /// Create a new empty relationship graph
    pub fn new() -> Self {
        Self {
            relationships: Vec::new(),
            finding_ids: Vec::new(),
            metadata: RelationshipGraphMetadata {
                total_relationships: 0,
                by_type: HashMap::new(),
                average_confidence: 0.0,
                max_confidence: 0.0,
                min_confidence: 0.0,
                generated_at: Utc::now(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
            },
        }
    }

    /// Add a relationship to the graph
    pub fn add_relationship(&mut self, relationship: FindingRelationship) {
        // Update finding IDs
        if !self.finding_ids.contains(&relationship.source_finding) {
            self.finding_ids.push(relationship.source_finding);
        }
        if !self.finding_ids.contains(&relationship.target_finding) {
            self.finding_ids.push(relationship.target_finding);
        }

        // Update metadata
        *self.metadata.by_type.entry(relationship.relationship_type).or_insert(0) += 1;
        self.metadata.total_relationships = self.relationships.len() + 1;

        // Update confidence stats
        let confidences: Vec<f32> = self.relationships.iter().map(|r| r.confidence).collect();
        if !confidences.is_empty() {
            self.metadata.average_confidence =
                confidences.iter().sum::<f32>() / confidences.len() as f32;
            self.metadata.max_confidence = confidences.iter().fold(0.0f32, |a, &b| a.max(b));
            self.metadata.min_confidence = confidences.iter().fold(1.0f32, |a, &b| a.min(b));
        } else {
            self.metadata.average_confidence = relationship.confidence;
            self.metadata.max_confidence = relationship.confidence;
            self.metadata.min_confidence = relationship.confidence;
        }

        self.relationships.push(relationship);
    }

    /// Get relationships for a specific finding
    pub fn get_relationships_for_finding(
        &self,
        finding_id: &FindingId,
    ) -> Vec<&FindingRelationship> {
        self.relationships
            .iter()
            .filter(|r| r.source_finding == *finding_id || r.target_finding == *finding_id)
            .collect()
    }

    /// Get relationships of a specific type
    pub fn get_relationships_by_type(
        &self,
        rel_type: FindingRelationshipType,
    ) -> Vec<&FindingRelationship> {
        self.relationships.iter().filter(|r| r.relationship_type == rel_type).collect()
    }

    /// Get incoming relationships (where finding is target)
    pub fn get_incoming(&self, finding_id: &FindingId) -> Vec<&FindingRelationship> {
        self.relationships.iter().filter(|r| r.target_finding == *finding_id).collect()
    }

    /// Get outgoing relationships (where finding is source)
    pub fn get_outgoing(&self, finding_id: &FindingId) -> Vec<&FindingRelationship> {
        self.relationships.iter().filter(|r| r.source_finding == *finding_id).collect()
    }

    /// Find all findings that enable the given finding
    pub fn get_enablers(&self, finding_id: &FindingId) -> Vec<FindingId> {
        self.relationships
            .iter()
            .filter(|r| {
                r.target_finding == *finding_id
                    && r.relationship_type == FindingRelationshipType::Enables
            })
            .map(|r| r.source_finding)
            .collect()
    }

    /// Find all findings that the given finding enables
    pub fn get_enabled(&self, finding_id: &FindingId) -> Vec<FindingId> {
        self.relationships
            .iter()
            .filter(|r| {
                r.source_finding == *finding_id
                    && r.relationship_type == FindingRelationshipType::Enables
            })
            .map(|r| r.target_finding)
            .collect()
    }

    /// Find exploit chains starting from a finding
    pub fn find_exploit_chains(
        &self,
        start_finding: &FindingId,
        max_depth: usize,
    ) -> Vec<Vec<FindingId>> {
        let mut chains = Vec::new();
        self.dfs_chains(start_finding, &mut vec![], &mut chains, max_depth);
        chains
    }

    fn dfs_chains(
        &self,
        current: &FindingId,
        path: &mut Vec<FindingId>,
        chains: &mut Vec<Vec<FindingId>>,
        max_depth: usize,
    ) {
        path.push(*current);

        if path.len() > max_depth {
            path.pop();
            return;
        }

        // Find chained exploit relationships
        let next_findings: Vec<FindingId> = self
            .relationships
            .iter()
            .filter(|r| {
                r.source_finding == *current
                    && r.relationship_type == FindingRelationshipType::ChainedExploit
            })
            .map(|r| r.target_finding)
            .collect();

        if next_findings.is_empty() {
            // End of chain
            if path.len() > 1 {
                chains.push(path.clone());
            }
        } else {
            for next in next_findings {
                if !path.contains(&next) {
                    self.dfs_chains(&next, path, chains, max_depth);
                }
            }
        }

        path.pop();
    }

    /// Export to DOT format for visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph FindingRelationships {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled];\n");

        // Define colors for relationship types
        let type_colors = [
            (FindingRelationshipType::Enables, "green"),
            (FindingRelationshipType::Amplifies, "red"),
            (FindingRelationshipType::Requires, "blue"),
            (FindingRelationshipType::SameRootCause, "purple"),
            (FindingRelationshipType::ChainedExploit, "orange"),
            (FindingRelationshipType::Mitigates, "lightgreen"),
            (FindingRelationshipType::Duplicate, "gray"),
            (FindingRelationshipType::SharedComponent, "lightblue"),
            (FindingRelationshipType::SharedAttackSurface, "yellow"),
            (FindingRelationshipType::InformationLeakage, "lightyellow"),
            (FindingRelationshipType::PrivilegeEscalation, "darkred"),
            (FindingRelationshipType::LateralMovement, "darkblue"),
            (FindingRelationshipType::DataExfiltration, "darkgreen"),
            (FindingRelationshipType::Prerequisite, "cyan"),
            (FindingRelationshipType::MutuallyExclusive, "pink"),
            (FindingRelationshipType::Temporal, "lightgray"),
            (FindingRelationshipType::Spatial, "lightcyan"),
            (FindingRelationshipType::Custom, "white"),
        ];

        // Add nodes (findings)
        for finding_id in &self.finding_ids {
            dot.push_str(&format!(
                "  finding_{} [label=\"{}\", fillcolor=lightgray];\n",
                finding_id.0, finding_id.0
            ));
        }

        // Add edges (relationships)
        for rel in &self.relationships {
            let color = type_colors
                .iter()
                .find(|(t, _)| *t == rel.relationship_type)
                .map(|(_, c)| *c)
                .unwrap_or("black");

            let label = format!("{:?}", rel.relationship_type);
            dot.push_str(&format!(
                "  finding_{} -> finding_{} [label=\"{}\", color={}, penwidth={}];\n",
                rel.source_finding.0,
                rel.target_finding.0,
                label,
                color,
                (rel.confidence * 3.0).max(1.0) as u32
            ));
        }

        dot.push_str("}\n");
        dot
    }
}

impl Default for FindingRelationshipGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Filter for querying relationships
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelationshipFilter {
    /// Filter by source finding
    pub source_finding: Option<FindingId>,
    /// Filter by target finding
    pub target_finding: Option<FindingId>,
    /// Filter by relationship type
    pub relationship_type: Option<FindingRelationshipType>,
    /// Minimum confidence
    pub min_confidence: Option<f32>,
    /// Maximum confidence
    pub max_confidence: Option<f32>,
    /// Filter by risk impact level change
    pub risk_level_change: Option<RiskLevelChange>,
    /// Filter by evidence type
    pub evidence_type: Option<EvidenceType>,
    /// Filter by evidence source
    pub evidence_source: Option<EvidenceSource>,
    /// Date range
    pub date_from: Option<DateTime<Utc>>,
    pub date_to: Option<DateTime<Utc>>,
}

/// Statistics for finding relationships
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationshipStats {
    /// Total relationships
    pub total: usize,
    /// By relationship type
    pub by_type: HashMap<FindingRelationshipType, usize>,
    /// By risk impact level
    pub by_risk_impact: HashMap<RiskLevelChange, usize>,
    /// Average confidence
    pub avg_confidence: f32,
    /// Findings with most relationships
    pub top_connected_findings: Vec<(FindingId, usize)>,
    /// Longest exploit chain length
    pub longest_chain_length: usize,
    /// Number of exploit chains
    pub exploit_chain_count: usize,
    /// Number of duplicate pairs
    pub duplicate_pairs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{FindingId, RelationshipId};

    #[test]
    fn test_finding_relationship_creation() {
        let source = FindingId::new();
        let target = FindingId::new();

        let relationship = FindingRelationship {
            id: RelationshipId::new(),
            source_finding: source,
            target_finding: target,
            relationship_type: FindingRelationshipType::Enables,
            explanation: "Missing CSP enables XSS exploitation".to_string(),
            evidence: vec![RelationshipEvidence {
                evidence_type: EvidenceType::Configuration,
                description: "CSP header missing".to_string(),
                data: serde_json::json!({"header": "Content-Security-Policy", "present": false}),
                source: EvidenceSource::Scanner,
                confidence: 0.9,
                related_findings: vec![source, target],
                timestamp: Utc::now(),
            }],
            confidence: 0.85,
            risk_impact: RiskImpact {
                score_delta: 25,
                level_change: RiskLevelChange::ModerateIncrease,
                explanation: "Missing CSP removes defense-in-depth against XSS".to_string(),
                affected_factors: vec![RiskFactor::Exploitability, RiskFactor::Impact],
                confidence: 0.8,
            },
            supporting_cwes: vec!["CWE-79".to_string(), "CWE-693".to_string()],
            supporting_capecs: vec!["CAPEC-86".to_string()],
            supporting_attack_techniques: vec!["T1059.007".to_string()],
            discovered_at: Utc::now(),
            metadata: HashMap::new(),
        };

        assert_eq!(relationship.source_finding, source);
        assert_eq!(relationship.target_finding, target);
        assert_eq!(relationship.relationship_type, FindingRelationshipType::Enables);
        assert_eq!(relationship.evidence.len(), 1);
    }

    #[test]
    fn test_relationship_graph() {
        let mut graph = FindingRelationshipGraph::new();

        let f1 = FindingId::new();
        let f2 = FindingId::new();
        let f3 = FindingId::new();

        graph.add_relationship(FindingRelationship {
            id: RelationshipId::new(),
            source_finding: f1,
            target_finding: f2,
            relationship_type: FindingRelationshipType::ChainedExploit,
            explanation: "Test".to_string(),
            evidence: vec![],
            confidence: 0.8,
            risk_impact: RiskImpact {
                score_delta: 10,
                level_change: RiskLevelChange::SlightIncrease,
                explanation: "Test".to_string(),
                affected_factors: vec![],
                confidence: 0.7,
            },
            supporting_cwes: vec![],
            supporting_capecs: vec![],
            supporting_attack_techniques: vec![],
            discovered_at: Utc::now(),
            metadata: HashMap::new(),
        });

        graph.add_relationship(FindingRelationship {
            id: RelationshipId::new(),
            source_finding: f2,
            target_finding: f3,
            relationship_type: FindingRelationshipType::ChainedExploit,
            explanation: "Test chain".to_string(),
            evidence: vec![],
            confidence: 0.9,
            risk_impact: RiskImpact {
                score_delta: 30,
                level_change: RiskLevelChange::ModerateIncrease,
                explanation: "Test".to_string(),
                affected_factors: vec![],
                confidence: 0.8,
            },
            supporting_cwes: vec![],
            supporting_capecs: vec![],
            supporting_attack_techniques: vec![],
            discovered_at: Utc::now(),
            metadata: HashMap::new(),
        });

        assert_eq!(graph.relationships.len(), 2);
        assert_eq!(graph.finding_ids.len(), 3);

        // Test exploit chain finding
        let chains = graph.find_exploit_chains(&f1, 5);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].len(), 3);
        assert_eq!(chains[0][0], f1);
        assert_eq!(chains[0][1], f2);
        assert_eq!(chains[0][2], f3);
    }

    #[test]
    fn test_get_relationships() {
        let mut graph = FindingRelationshipGraph::new();
        let f1 = FindingId::new();
        let f2 = FindingId::new();

        graph.add_relationship(FindingRelationship {
            id: RelationshipId::new(),
            source_finding: f1,
            target_finding: f2,
            relationship_type: FindingRelationshipType::Enables,
            explanation: "Test".to_string(),
            evidence: vec![],
            confidence: 0.8,
            risk_impact: RiskImpact {
                score_delta: 10,
                level_change: RiskLevelChange::SlightIncrease,
                explanation: "Test".to_string(),
                affected_factors: vec![],
                confidence: 0.7,
            },
            supporting_cwes: vec![],
            supporting_capecs: vec![],
            supporting_attack_techniques: vec![],
            discovered_at: Utc::now(),
            metadata: HashMap::new(),
        });

        let outgoing = graph.get_outgoing(&f1);
        assert_eq!(outgoing.len(), 1);

        let incoming = graph.get_incoming(&f2);
        assert_eq!(incoming.len(), 1);

        let enablers = graph.get_enablers(&f2);
        assert_eq!(enablers.len(), 1);
        assert_eq!(enablers[0], f1);

        let enabled = graph.get_enabled(&f1);
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0], f2);
    }

    #[test]
    fn test_to_dot() {
        let mut graph = FindingRelationshipGraph::new();
        let f1 = FindingId::new();
        let f2 = FindingId::new();

        graph.add_relationship(FindingRelationship {
            id: RelationshipId::new(),
            source_finding: f1,
            target_finding: f2,
            relationship_type: FindingRelationshipType::Enables,
            explanation: "Test".to_string(),
            evidence: vec![],
            confidence: 0.8,
            risk_impact: RiskImpact {
                score_delta: 10,
                level_change: RiskLevelChange::SlightIncrease,
                explanation: "Test".to_string(),
                affected_factors: vec![],
                confidence: 0.7,
            },
            supporting_cwes: vec![],
            supporting_capecs: vec![],
            supporting_attack_techniques: vec![],
            discovered_at: Utc::now(),
            metadata: HashMap::new(),
        });

        let dot = graph.to_dot();
        assert!(dot.contains("digraph FindingRelationships"));
        assert!(dot.contains(&format!("finding_{}", f1.0)));
        assert!(dot.contains(&format!("finding_{}", f2.0)));
        assert!(dot.contains("Enables"));
    }
}
