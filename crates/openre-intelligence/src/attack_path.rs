//! Attack Path Graph - Build exploitation paths from findings and relationships

use crate::{error::IntelligenceError, IntelligenceResult};
use openre_core::app_map::HttpMethod;
use openre_core::attack_path::{
    AttackComplexity, AttackNodeType, AttackPath, AttackPathEdge, AttackPathNode, AttackStage,
    AttackTechnique, AttackVector, BusinessImpact, DetectionMethod, DetectionOpportunity,
    EntryPoint, EvidenceRef, ExploitabilityInfo, FalsePositiveLikelihood, ImpactAssessment,
    ImpactDetail, ImpactLevel, MitigationEffectiveness, MitigationPriority,
    MitigationRecommendation, Prerequisite, PrerequisiteType, PrivilegeLevel, PrivilegesRequired,
    RemediationEffort, RiskLevel, RiskScore, RiskScoreBreakdown, Scope, UserInteraction,
};
use openre_core::ids::{
    AssetId, AttackPathId, EntryPointId, EvidenceId, FindingId, NodeId, RelationshipId,
};
use openre_core::relationships::{
    EvidenceSource, EvidenceType as RelationshipEvidenceType, FindingRelationship,
    FindingRelationshipGraph, FindingRelationshipType, RelationshipEvidence, RiskImpact,
    RiskLevelChange,
};
use openre_core::result::{
    Category, Confidence, EvidenceType as ResultEvidenceType, Finding, Severity,
};
use petgraph::algo::all_simple_paths;
use petgraph::graph::{DiGraph, NodeIndex};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Attack path graph builder
pub struct AttackPathBuilder {
    findings: Vec<Finding>,
    relationships: FindingRelationshipGraph,
    target: String,
}

impl AttackPathBuilder {
    /// Create a new attack path builder
    pub fn new(
        findings: Vec<Finding>,
        relationships: FindingRelationshipGraph,
        target: String,
    ) -> Self {
        Self { findings, relationships, target }
    }

    /// Build attack paths from findings and relationships
    pub fn build_attack_paths(&self) -> IntelligenceResult<Vec<AttackPath>> {
        let mut paths = Vec::new();

        // Build the graph
        let graph = self.build_graph()?;

        // Find entry points (publicly accessible findings)
        let entry_points = self.identify_entry_points(&graph)?;

        // Find impact nodes (high severity findings)
        let impact_nodes = self.identify_impact_nodes(&graph)?;

        // Find all paths from entry points to impact nodes
        for entry in &entry_points {
            for impact in &impact_nodes {
                let paths_found = self.find_paths(&graph, *entry, *impact)?;
                for path in paths_found {
                    let attack_path = self.build_attack_path_from_graph_path(&graph, path)?;
                    if attack_path.overall_risk.score > 0 {
                        paths.push(attack_path);
                    }
                }
            }
        }

        // Sort by risk score (highest first)
        paths.sort_by(|a, b| b.overall_risk.score.cmp(&a.overall_risk.score));

        // Deduplicate similar paths
        paths = self.deduplicate_paths(paths);

        Ok(paths)
    }

    /// Build a petgraph from findings and relationships
    fn build_graph(&self) -> IntelligenceResult<DiGraph<AttackPathNode, FindingRelationshipType>> {
        let mut graph = DiGraph::new();
        let mut node_indices = HashMap::new();

        // Add finding nodes
        for finding in &self.findings {
            let node = self.finding_to_node(finding)?;
            let idx = graph.add_node(node);
            node_indices.insert(finding.id, idx);
        }

        // Add relationship edges
        for rel in &self.relationships.relationships {
            if let (Some(&from_idx), Some(&to_idx)) =
                (node_indices.get(&rel.source_finding), node_indices.get(&rel.target_finding))
            {
                graph.add_edge(from_idx, to_idx, rel.relationship_type);
            }
        }

        Ok(graph)
    }

    /// Convert a finding to an attack path node
    fn finding_to_node(&self, finding: &Finding) -> IntelligenceResult<AttackPathNode> {
        let node_type = self.determine_node_type(finding);
        let risk_contribution = self.calculate_risk_contribution(finding);

        Ok(AttackPathNode {
            id: NodeId::new(),
            node_type,
            finding_id: Some(finding.id),
            endpoint_id: self.extract_endpoint_id(finding),
            asset_id: None,
            label: finding.title.clone(),
            description: finding.description.clone(),
            evidence: finding
                .evidence
                .iter()
                .map(|e| EvidenceRef {
                    evidence_id: EvidenceId::new(),
                    description: e.description.clone(),
                    evidence_type: match &e.evidence_type {
                        ResultEvidenceType::HttpRequest => {
                            RelationshipEvidenceType::HttpInteraction
                        }
                        ResultEvidenceType::HttpResponse => {
                            RelationshipEvidenceType::HttpInteraction
                        }
                        ResultEvidenceType::CodeSnippet => RelationshipEvidenceType::CodePattern,
                        ResultEvidenceType::ConfigExcerpt => {
                            RelationshipEvidenceType::Configuration
                        }
                        ResultEvidenceType::LogEntry => RelationshipEvidenceType::LogAnalysis,
                        ResultEvidenceType::Screenshot => RelationshipEvidenceType::Custom,
                        ResultEvidenceType::Custom(_) => RelationshipEvidenceType::Custom,
                    },
                })
                .collect(),
            risk_contribution,
            is_choke_point: false,
            is_branch_point: false,
            order: 0,
            metadata: HashMap::new(),
        })
    }

    /// Determine the node type based on finding characteristics
    fn determine_node_type(&self, finding: &Finding) -> AttackNodeType {
        // Check if it's an entry point (publicly accessible)
        let is_public = finding.evidence.iter().any(|e| {
            e.location.as_ref().map(|l| l.contains("public") || l.contains("/")).unwrap_or(false)
        });

        if is_public
            && matches!(
                finding.category,
                Category::InformationDisclosure | Category::SecurityMisconfiguration
            )
        {
            return AttackNodeType::EntryPoint;
        }

        // Check for impact findings (high/critical severity)
        if matches!(finding.severity, Severity::High | Severity::Critical) {
            return AttackNodeType::Impact;
        }

        // Check for pivot findings (auth bypass, privilege escalation)
        if finding.title.to_lowercase().contains("auth")
            || finding.title.to_lowercase().contains("bypass")
            || finding.title.to_lowercase().contains("privilege")
            || finding.title.to_lowercase().contains("escalation")
        {
            return AttackNodeType::Pivot;
        }

        // Default to weakness
        AttackNodeType::Weakness
    }

    /// Calculate risk contribution of a finding
    fn calculate_risk_contribution(&self, finding: &Finding) -> f32 {
        let severity_score = match finding.severity {
            Severity::Critical => 100.0,
            Severity::High => 75.0,
            Severity::Medium => 50.0,
            Severity::Low => 25.0,
            Severity::Info => 10.0,
        };

        let confidence_score = match finding.confidence {
            Confidence::VeryHigh => 1.0,
            Confidence::High => 0.8,
            Confidence::Medium => 0.6,
            Confidence::Low => 0.4,
            Confidence::VeryLow => 0.2,
        };

        let result = severity_score * confidence_score;
        if result < 100.0 {
            result
        } else {
            100.0
        }
    }

    /// Extract endpoint ID from finding evidence
    fn extract_endpoint_id(&self, finding: &Finding) -> Option<String> {
        finding.evidence.first().and_then(|e| e.location.as_ref()).map(|l| l.clone())
    }

    /// Identify entry points in the graph
    fn identify_entry_points(
        &self,
        graph: &DiGraph<AttackPathNode, FindingRelationshipType>,
    ) -> IntelligenceResult<Vec<NodeIndex>> {
        let mut entry_points = Vec::new();

        for idx in graph.node_indices() {
            if let Some(node) = graph.node_weight(idx) {
                if matches!(node.node_type, AttackNodeType::EntryPoint) {
                    entry_points.push(idx);
                }
            }
        }

        Ok(entry_points)
    }

    /// Identify impact nodes in the graph
    fn identify_impact_nodes(
        &self,
        graph: &DiGraph<AttackPathNode, FindingRelationshipType>,
    ) -> IntelligenceResult<Vec<NodeIndex>> {
        let mut impact_nodes = Vec::new();

        for idx in graph.node_indices() {
            if let Some(node) = graph.node_weight(idx) {
                if matches!(node.node_type, AttackNodeType::Impact) {
                    impact_nodes.push(idx);
                }
            }
        }

        Ok(impact_nodes)
    }

    /// Find all paths from entry to impact
    fn find_paths(
        &self,
        graph: &DiGraph<AttackPathNode, FindingRelationshipType>,
        from: NodeIndex,
        to: NodeIndex,
    ) -> IntelligenceResult<Vec<Vec<NodeIndex>>> {
        // Use all_simple_paths to find all paths up to a reasonable length
        let paths: Vec<Vec<NodeIndex>> = all_simple_paths::<Vec<_>, _>(graph, from, to, 0, None)
            .filter(|path| path.len() <= 10) // Limit path length
            .collect();

        Ok(paths)
    }

    /// Build an AttackPath from a graph path
    fn build_attack_path_from_graph_path(
        &self,
        graph: &DiGraph<AttackPathNode, FindingRelationshipType>,
        path: Vec<NodeIndex>,
    ) -> IntelligenceResult<AttackPath> {
        let mut attack_path = AttackPath::new(
            format!("Attack Path {}", uuid::Uuid::new_v4()),
            format!(
                "Attack path from {} to {}",
                graph.node_weight(path[0]).map(|n| n.label.clone()).unwrap_or_default(),
                graph
                    .node_weight(*path.last().unwrap())
                    .map(|n| n.label.clone())
                    .unwrap_or_default()
            ),
        );

        // Add nodes
        for (order, &idx) in path.iter().enumerate() {
            if let Some(mut node) = graph.node_weight(idx).cloned() {
                node.order = order;
                // Mark choke points (nodes with high degree)
                let in_degree = graph.edges_directed(idx, petgraph::Direction::Incoming).count();
                let out_degree = graph.edges_directed(idx, petgraph::Direction::Outgoing).count();
                node.is_choke_point = (in_degree + out_degree) > 2;
                node.is_branch_point = out_degree > 1;
                attack_path.add_node(node);
            }
        }

        // Add edges
        for i in 0..path.len() - 1 {
            if let Some(edge) = graph.find_edge(path[i], path[i + 1]) {
                if let Some(rel_type) = graph.edge_weight(edge) {
                    let from_node = graph.node_weight(path[i]).unwrap();
                    let to_node = graph.node_weight(path[i + 1]).unwrap();

                    attack_path.add_edge(AttackPathEdge {
                        from: from_node.id,
                        to: to_node.id,
                        relationship: *rel_type,
                        evidence: Vec::new(),
                        confidence: 0.8,
                        exploitability: ExploitabilityInfo {
                            score: 7.0,
                            attack_vector: AttackVector::Network,
                            attack_complexity: AttackComplexity::Low,
                            privileges_required: PrivilegesRequired::None,
                            user_interaction: UserInteraction::None,
                            scope: Scope::Unchanged,
                            exploit_available: true,
                            exploited_in_wild: false,
                            epss_score: None,
                        },
                        estimated_time: Some(chrono::Duration::minutes(5)),
                        required_privileges: PrivilegeLevel::None,
                        user_interaction_required: false,
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        // Add entry points
        if let Some(first_node) = graph.node_weight(path[0]) {
            if matches!(first_node.node_type, AttackNodeType::EntryPoint) {
                attack_path.add_entry_point(EntryPoint {
                    id: EntryPointId::new(),
                    entry_type: openre_core::attack_path::EntryPointType::WebEndpoint,
                    location: self.target.clone(),
                    method: None,
                    parameters: Vec::new(),
                    auth_required: false,
                    technologies: Vec::new(),
                    attack_surface: openre_core::attack_path::AttackSurface {
                        parameter_count: 1,
                        endpoint_count: 1,
                        validation_coverage: 0.0,
                        auth_coverage: 0.0,
                        rate_limit_coverage: 0.0,
                        waf_coverage: 0.0,
                    },
                    confidence: 0.9,
                });
            }
        }

        // Calculate risk
        attack_path.calculate_risk();

        Ok(attack_path)
    }

    /// Deduplicate similar attack paths
    fn deduplicate_paths(&self, mut paths: Vec<AttackPath>) -> Vec<AttackPath> {
        let mut unique = Vec::new();
        let mut seen = HashSet::new();

        for path in paths {
            // Create a signature from node IDs
            let signature: Vec<NodeId> = path.nodes.iter().map(|n| n.id).collect();
            let sig_str = format!("{:?}", signature);

            if !seen.contains(&sig_str) {
                seen.insert(sig_str);
                unique.push(path);
            }
        }

        unique
    }
}

/// Attack path analyzer for finding critical paths
pub struct AttackPathAnalyzer;

impl AttackPathAnalyzer {
    /// Find the most critical attack path
    pub fn find_critical_path(paths: &[AttackPath]) -> Option<&AttackPath> {
        paths.iter().max_by_key(|p| p.overall_risk.score)
    }

    /// Find all choke points across attack paths
    pub fn find_choke_points(paths: &[AttackPath]) -> HashMap<NodeId, usize> {
        let mut choke_points = HashMap::new();

        for path in paths {
            for node in &path.nodes {
                if node.is_choke_point {
                    *choke_points.entry(node.id).or_insert(0) += 1;
                }
            }
        }

        choke_points
    }

    /// Get attack path statistics
    pub fn get_statistics(paths: &[AttackPath]) -> AttackPathStatistics {
        let total = paths.len();
        let critical = paths.iter().filter(|p| p.overall_risk.level >= RiskLevel::Critical).count();
        let high = paths.iter().filter(|p| p.overall_risk.level >= RiskLevel::High).count();
        let avg_length = if total > 0 {
            paths.iter().map(|p| p.nodes.len()).sum::<usize>() as f32 / total as f32
        } else {
            0.0
        };

        AttackPathStatistics {
            total_paths: total,
            critical_paths: critical,
            high_risk_paths: high,
            average_length: avg_length,
            max_risk_score: paths.iter().map(|p| p.overall_risk.score).max().unwrap_or(0),
        }
    }
}

/// Attack path statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathStatistics {
    pub total_paths: usize,
    pub critical_paths: usize,
    pub high_risk_paths: usize,
    pub average_length: f32,
    pub max_risk_score: u8,
}

/// MITRE ATT&CK technique mapping for findings
pub fn map_findings_to_attack_techniques(findings: &[Finding]) -> Vec<AttackTechnique> {
    let mut techniques = Vec::new();

    for finding in findings {
        // Map based on category and title
        let technique = match finding.category {
            Category::Injection => Some(AttackTechnique {
                technique_id: "T1059.007".to_string(),
                technique_name: "JavaScript/JScript".to_string(),
                tactic: "Execution".to_string(),
                sub_technique: None,
                description: "Adversaries may execute JavaScript code for execution.".to_string(),
                detection: vec!["Monitor for script execution".to_string()],
                mitigation: vec!["CSP".to_string(), "Input validation".to_string()],
                related_nodes: vec![],
            }),
            Category::BrokenAuthentication => Some(AttackTechnique {
                technique_id: "T1078".to_string(),
                technique_name: "Valid Accounts".to_string(),
                tactic: "Initial Access".to_string(),
                sub_technique: None,
                description: "Adversaries may obtain and abuse credentials of existing accounts."
                    .to_string(),
                detection: vec!["Monitor for unusual login patterns".to_string()],
                mitigation: vec!["MFA".to_string(), "Password policies".to_string()],
                related_nodes: vec![],
            }),
            Category::SensitiveDataExposure => Some(AttackTechnique {
                technique_id: "T1005".to_string(),
                technique_name: "Data from Local System".to_string(),
                tactic: "Collection".to_string(),
                sub_technique: None,
                description: "Adversaries may search local system for sensitive data.".to_string(),
                detection: vec!["Monitor for file access".to_string()],
                mitigation: vec!["Encryption".to_string(), "Access controls".to_string()],
                related_nodes: vec![],
            }),
            Category::SecurityMisconfiguration => Some(AttackTechnique {
                technique_id: "T1590.005".to_string(),
                technique_name: "Active Directory Reconnaissance".to_string(),
                tactic: "Reconnaissance".to_string(),
                sub_technique: None,
                description: "Adversaries may gather information about the target's configuration."
                    .to_string(),
                detection: vec!["Monitor for configuration queries".to_string()],
                mitigation: vec!["Secure configuration".to_string()],
                related_nodes: vec![],
            }),
            Category::Xss => Some(AttackTechnique {
                technique_id: "T1189".to_string(),
                technique_name: "Drive-by Compromise".to_string(),
                tactic: "Initial Access".to_string(),
                sub_technique: None,
                description: "Adversaries may compromise a system via a user visiting a website."
                    .to_string(),
                detection: vec!["Monitor for suspicious script execution".to_string()],
                mitigation: vec!["CSP".to_string(), "Input validation".to_string()],
                related_nodes: vec![],
            }),
            _ => None,
        };

        if let Some(mut tech) = technique {
            // Convert FindingId to NodeId for related_nodes
            tech.related_nodes = vec![NodeId::from_uuid(finding.id.as_uuid())];
            techniques.push(tech);
        }
    }

    techniques
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::attack_path::{
        AttackPath, AttackPathNode, RiskLevel, RiskScore, RiskScoreBreakdown,
    };
    use openre_core::ids::{FindingId, NodeId, RelationshipId, ScanId};
    use openre_core::relationships::{
        EvidenceSource, FindingRelationship, FindingRelationshipGraph, FindingRelationshipType,
        RelationshipEvidence, RiskImpact, RiskLevelChange,
    };
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use uuid::Uuid;

    fn create_test_finding(
        title: &str,
        category: Category,
        severity: Severity,
        target: &str,
        risk_score: Option<u8>,
    ) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity,
            confidence: Confidence::High,
            category,
            target: target.to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: Default::default(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score,
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some(Uuid::new_v4().to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[test]
    fn test_attack_path_builder() {
        let finding1 = create_test_finding(
            "Public API endpoint",
            Category::InformationDisclosure,
            Severity::Low,
            "https://example.com",
            Some(20),
        );

        let finding2 = create_test_finding(
            "SQL Injection",
            Category::Injection,
            Severity::Critical,
            "https://example.com/api",
            Some(90),
        );

        let finding3 = create_test_finding(
            "Admin panel access",
            Category::BrokenAuthentication,
            Severity::High,
            "https://example.com/admin",
            Some(80),
        );

        let mut relationships = FindingRelationshipGraph::new();
        relationships.add_relationship(FindingRelationship {
            id: openre_core::ids::RelationshipId::new(),
            source_finding: finding1.id,
            target_finding: finding2.id,
            relationship_type: FindingRelationshipType::Enables,
            explanation: "API endpoint enables SQL injection".to_string(),
            evidence: vec![],
            confidence: 0.8,
            risk_impact: RiskImpact {
                score_delta: 20,
                level_change: RiskLevelChange::ModerateIncrease,
                explanation: "Test".to_string(),
                affected_factors: vec![],
                confidence: 0.7,
            },
            supporting_cwes: vec![],
            supporting_capecs: vec![],
            supporting_attack_techniques: vec![],
            discovered_at: Utc::now(),
            metadata: Default::default(),
        });

        relationships.add_relationship(FindingRelationship {
            id: openre_core::ids::RelationshipId::new(),
            source_finding: finding2.id,
            target_finding: finding3.id,
            relationship_type: FindingRelationshipType::ChainedExploit,
            explanation: "SQL injection leads to admin access".to_string(),
            evidence: vec![],
            confidence: 0.85,
            risk_impact: RiskImpact {
                score_delta: 30,
                level_change: RiskLevelChange::SignificantIncrease,
                explanation: "Test".to_string(),
                affected_factors: vec![],
                confidence: 0.8,
            },
            supporting_cwes: vec![],
            supporting_capecs: vec![],
            supporting_attack_techniques: vec![],
            discovered_at: Utc::now(),
            metadata: Default::default(),
        });

        let builder = AttackPathBuilder::new(
            vec![finding1, finding2, finding3],
            relationships,
            "https://example.com".to_string(),
        );

        let paths = builder.build_attack_paths().unwrap();
        assert!(!paths.is_empty());

        // Should have at least one path from entry to impact
        let path = &paths[0];
        assert!(path.nodes.len() >= 2);
        assert!(path.edges.len() >= 1);
    }

    fn create_test_attack_path(score: u8, level: RiskLevel, choke_points: Vec<bool>) -> AttackPath {
        let nodes: Vec<AttackPathNode> = choke_points
            .iter()
            .enumerate()
            .map(|(i, &is_choke)| AttackPathNode {
                id: NodeId::new(),
                node_type: if i == 0 { AttackNodeType::EntryPoint } else { AttackNodeType::Impact },
                finding_id: None,
                endpoint_id: None,
                asset_id: None,
                label: format!("Node {}", i),
                description: "Test".to_string(),
                evidence: vec![],
                risk_contribution: score as f32,
                is_choke_point: is_choke,
                is_branch_point: false,
                order: i,
                metadata: HashMap::new(),
            })
            .collect();

        AttackPath {
            id: AttackPathId::new(),
            name: "Test Path".to_string(),
            description: "Test".to_string(),
            nodes,
            edges: vec![],
            overall_risk: RiskScore {
                score,
                level,
                breakdown: RiskScoreBreakdown {
                    exploitability: 0.0,
                    impact: 0.0,
                    attack_complexity: 0.0,
                    privileges_required: 0.0,
                    user_interaction: 0.0,
                    scope: 0.0,
                    detectability: 0.0,
                    remediation_difficulty: 0.0,
                },
                explanation: "Test".to_string(),
            },
            entry_points: vec![],
            impact: ImpactAssessment {
                overall_impact: ImpactLevel::None,
                confidentiality: ImpactDetail {
                    level: ImpactLevel::None,
                    description: String::new(),
                    evidence: vec![],
                    cvss_score: None,
                },
                integrity: ImpactDetail {
                    level: ImpactLevel::None,
                    description: String::new(),
                    evidence: vec![],
                    cvss_score: None,
                },
                availability: ImpactDetail {
                    level: ImpactLevel::None,
                    description: String::new(),
                    evidence: vec![],
                    cvss_score: None,
                },
                business: BusinessImpact {
                    level: ImpactLevel::None,
                    description: String::new(),
                    affected_processes: vec![],
                    downtime_estimate_hours: None,
                    revenue_impact: None,
                    reputation_impact: None,
                },
                regulatory: None,
                affected_assets: vec![],
                records_exposed: None,
                financial_impact: None,
            },
            attack_techniques: vec![],
            prerequisites: vec![],
            detection_opportunities: vec![],
            mitigations: vec![],
            confidence: 0.8,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            tags: vec![],
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_find_critical_path() {
        let paths = vec![
            create_test_attack_path(50, RiskLevel::Medium, vec![false]),
            create_test_attack_path(90, RiskLevel::Critical, vec![false]),
        ];

        let critical = AttackPathAnalyzer::find_critical_path(&paths);
        assert!(critical.is_some());
        assert_eq!(critical.unwrap().overall_risk.score, 90);
    }

    #[test]
    fn test_find_choke_points() {
        let paths = vec![
            create_test_attack_path(50, RiskLevel::Medium, vec![true, false]),
            create_test_attack_path(70, RiskLevel::High, vec![true, true]),
        ];

        let choke_points = AttackPathAnalyzer::find_choke_points(&paths);
        assert_eq!(choke_points.len(), 3);
    }

    #[test]
    fn test_map_findings_to_attack_techniques() {
        let findings = vec![
            create_test_finding(
                "SQL Injection",
                Category::Injection,
                Severity::Critical,
                "https://example.com",
                Some(90),
            ),
            create_test_finding(
                "XSS",
                Category::Xss,
                Severity::High,
                "https://example.com",
                Some(70),
            ),
        ];

        let techniques = map_findings_to_attack_techniques(&findings);
        assert_eq!(techniques.len(), 2);
        assert_eq!(techniques[0].technique_id, "T1059.007"); // Injection
        assert_eq!(techniques[1].technique_id, "T1189"); // XSS
    }
}
