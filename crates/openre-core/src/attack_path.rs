//! Attack Path types for representing exploitation paths through an application

use crate::ids::{AssetId, AttackPathId, EntryPointId, EvidenceId, FindingId, NodeId};
use crate::relationships::FindingRelationshipType;
use crate::result::{Confidence, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attack path representing a chain of exploitable findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    /// Unique attack path ID
    pub id: AttackPathId,
    /// Human-readable name
    pub name: String,
    /// Description of the attack path
    pub description: String,
    /// Nodes in the attack path
    pub nodes: Vec<AttackPathNode>,
    /// Edges connecting nodes
    pub edges: Vec<AttackPathEdge>,
    /// Overall risk score (0-100)
    pub overall_risk: RiskScore,
    /// Entry points for this attack path
    pub entry_points: Vec<EntryPoint>,
    /// Impact assessment
    pub impact: ImpactAssessment,
    /// MITRE ATT&CK techniques mapped
    pub attack_techniques: Vec<AttackTechnique>,
    /// Prerequisites for this attack path
    pub prerequisites: Vec<Prerequisite>,
    /// Detection opportunities
    pub detection_opportunities: Vec<DetectionOpportunity>,
    /// Mitigation recommendations
    pub mitigations: Vec<MitigationRecommendation>,
    /// Confidence in this attack path (0.0 - 1.0)
    pub confidence: f32,
    /// Timestamp of creation
    pub created_at: DateTime<Utc>,
    /// Last updated
    pub updated_at: DateTime<Utc>,
    /// Tags
    pub tags: Vec<String>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Node in an attack path graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathNode {
    /// Unique node ID
    pub id: NodeId,
    /// Type of node
    pub node_type: AttackNodeType,
    /// Associated finding ID (if applicable)
    pub finding_id: Option<FindingId>,
    /// Associated endpoint ID (if applicable)
    pub endpoint_id: Option<String>,
    /// Associated asset ID (if applicable)
    pub asset_id: Option<AssetId>,
    /// Human-readable label
    pub label: String,
    /// Detailed description
    pub description: String,
    /// Evidence supporting this node
    pub evidence: Vec<EvidenceRef>,
    /// Risk contribution of this node (0-100)
    pub risk_contribution: f32,
    /// Whether this node is a critical choke point
    pub is_choke_point: bool,
    /// Whether this node is a branching point
    pub is_branch_point: bool,
    /// Order in the attack path (for linear paths)
    pub order: usize,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Types of nodes in an attack path
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackNodeType {
    /// Target asset (application, server, database)
    Asset,
    /// Publicly accessible entry point
    EntryPoint,
    /// Vulnerability/weakness
    Weakness,
    /// Intermediate pivot step (auth bypass, privilege escalation)
    Pivot,
    /// Final impact (data access, RCE, etc.)
    Impact,
    /// Defensive control that can be bypassed
    Defense,
    /// Credential/secret
    Credential,
    /// Network segment
    NetworkSegment,
    /// Custom node type
    Custom,
}

/// Edge connecting two nodes in an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathEdge {
    /// Source node ID
    pub from: NodeId,
    /// Target node ID
    pub to: NodeId,
    /// Type of relationship
    pub relationship: FindingRelationshipType,
    /// Evidence supporting this edge
    pub evidence: Vec<EvidenceRef>,
    /// Confidence in this edge (0.0 - 1.0)
    pub confidence: f32,
    /// Exploitability of this transition
    pub exploitability: ExploitabilityInfo,
    /// Estimated time to exploit
    pub estimated_time: Option<chrono::Duration>,
    /// Required privileges
    pub required_privileges: PrivilegeLevel,
    /// Whether user interaction is required
    pub user_interaction_required: bool,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Exploitability information for an attack path edge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitabilityInfo {
    /// Exploitability score (0.0 - 10.0)
    pub score: f32,
    /// Attack vector
    pub attack_vector: AttackVector,
    /// Attack complexity
    pub attack_complexity: AttackComplexity,
    /// Privileges required
    pub privileges_required: PrivilegesRequired,
    /// User interaction
    pub user_interaction: UserInteraction,
    /// Scope
    pub scope: Scope,
    /// Whether exploit code is publicly available
    pub exploit_available: bool,
    /// Whether actively exploited in the wild
    pub exploited_in_wild: bool,
    /// EPSS score if available
    pub epss_score: Option<f32>,
}

/// Attack vector (CVSS)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

/// Attack complexity (CVSS)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackComplexity {
    Low,
    Medium,
    High,
}

/// Privileges required (CVSS)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

/// User interaction (CVSS)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserInteraction {
    None,
    Required,
}

/// Scope (CVSS)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Unchanged,
    Changed,
}

/// Privilege level for attack path steps
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeLevel {
    None,
    Low,
    Medium,
    High,
    System,
}

/// Reference to evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub evidence_id: EvidenceId,
    pub description: String,
    pub evidence_type: crate::relationships::EvidenceType,
}

/// Risk score with breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Overall score (0-100)
    pub score: u8,
    /// Risk level
    pub level: RiskLevel,
    /// Breakdown by factor
    pub breakdown: RiskScoreBreakdown,
    /// Explanation
    pub explanation: String,
}

/// Risk levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    None = 0,
    VeryLow = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl RiskLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0 => RiskLevel::None,
            1..=20 => RiskLevel::VeryLow,
            21..=40 => RiskLevel::Low,
            41..=60 => RiskLevel::Medium,
            61..=80 => RiskLevel::High,
            81..=100 => RiskLevel::Critical,
            _ => RiskLevel::Critical,
        }
    }
}

/// Risk score breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoreBreakdown {
    pub exploitability: f32,
    pub impact: f32,
    pub attack_complexity: f32,
    pub privileges_required: f32,
    pub user_interaction: f32,
    pub scope: f32,
    pub detectability: f32,
    pub remediation_difficulty: f32,
}

/// Entry point for an attack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    /// Unique entry point ID
    pub id: EntryPointId,
    /// Type of entry point
    pub entry_type: EntryPointType,
    /// URL or location
    pub location: String,
    /// HTTP method if applicable
    pub method: Option<crate::app_map::HttpMethod>,
    /// Parameters
    pub parameters: Vec<String>,
    /// Authentication required
    pub auth_required: bool,
    /// Technology stack
    pub technologies: Vec<String>,
    /// Exposed attack surface
    pub attack_surface: AttackSurface,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,
}

/// Types of entry points
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryPointType {
    WebEndpoint,
    ApiEndpoint,
    FileUpload,
    AdminPanel,
    LoginPage,
    ApiDocumentation,
    DirectoryListing,
    ExposedService,
    DefaultCredential,
    SupplyChain,
    PhysicalAccess,
    SocialEngineering,
    Custom,
}

/// Attack surface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    /// Number of parameters
    pub parameter_count: usize,
    /// Number of endpoints
    pub endpoint_count: usize,
    /// Input validation coverage (0.0 - 1.0)
    pub validation_coverage: f32,
    /// Authentication coverage (0.0 - 1.0)
    pub auth_coverage: f32,
    /// Rate limiting coverage (0.0 - 1.0)
    pub rate_limit_coverage: f32,
    /// WAF coverage (0.0 - 1.0)
    pub waf_coverage: f32,
}

/// Impact assessment for an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    /// Overall impact level
    pub overall_impact: ImpactLevel,
    /// Confidentiality impact
    pub confidentiality: ImpactDetail,
    /// Integrity impact
    pub integrity: ImpactDetail,
    /// Availability impact
    pub availability: ImpactDetail,
    /// Business impact
    pub business: BusinessImpact,
    /// Regulatory impact
    pub regulatory: Option<RegulatoryImpact>,
    /// Affected assets
    pub affected_assets: Vec<AssetId>,
    /// Estimated records exposed
    pub records_exposed: Option<u64>,
    /// Estimated financial impact
    pub financial_impact: Option<FinancialImpact>,
}

/// Impact levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Detail for a specific impact dimension
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactDetail {
    pub level: ImpactLevel,
    pub description: String,
    pub evidence: Vec<EvidenceRef>,
    pub cvss_score: Option<f32>,
}

/// Business impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessImpact {
    pub level: ImpactLevel,
    pub description: String,
    pub affected_processes: Vec<String>,
    pub downtime_estimate_hours: Option<f32>,
    pub revenue_impact: Option<String>,
    pub reputation_impact: Option<String>,
}

/// Regulatory impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegulatoryImpact {
    pub regulations: Vec<String>,
    pub potential_fines: Option<String>,
    pub notification_requirements: Vec<String>,
    pub compliance_frameworks: Vec<String>,
}

/// Financial impact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialImpact {
    pub estimated_cost_usd: Option<f64>,
    pub cost_breakdown: HashMap<String, f64>,
    pub currency: String,
}

/// MITRE ATT&CK technique mapped to attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub sub_technique: Option<String>,
    pub description: String,
    pub detection: Vec<String>,
    pub mitigation: Vec<String>,
    pub related_nodes: Vec<NodeId>,
}

/// Prerequisite for an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prerequisite {
    pub description: String,
    pub prerequisite_type: PrerequisiteType,
    pub satisfied: bool,
    pub evidence: Vec<EvidenceRef>,
}

/// Types of prerequisites
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteType {
    /// Valid credentials required
    Credentials,
    /// Network access required
    NetworkAccess,
    /// Specific user role required
    UserRole,
    /// Specific configuration required
    Configuration,
    /// Specific software version required
    SoftwareVersion,
    /// Physical access required
    PhysicalAccess,
    /// Social engineering required
    SocialEngineering,
    /// Time window required
    TimeWindow,
    /// Custom prerequisite
    Custom,
}

/// Detection opportunity for an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionOpportunity {
    pub stage: AttackStage,
    pub description: String,
    pub detection_method: DetectionMethod,
    pub data_sources: Vec<String>,
    pub mitre_detection: Vec<String>,
    pub confidence: f32,
    pub false_positive_likelihood: FalsePositiveLikelihood,
}

/// Stages of an attack
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStage {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
    Unknown,
}

/// Detection methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    LogAnalysis,
    NetworkTrafficAnalysis,
    EndpointMonitoring,
    UserBehaviorAnalytics,
    ThreatIntelligence,
    DeceptionTechnology,
    FileIntegrityMonitoring,
    ApiMonitoring,
    Custom,
}

/// False positive likelihood
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FalsePositiveLikelihood {
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Mitigation recommendation for an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitigationRecommendation {
    pub priority: MitigationPriority,
    pub title: String,
    pub description: String,
    pub affected_nodes: Vec<NodeId>,
    pub affected_edges: Vec<(NodeId, NodeId)>,
    pub effort: RemediationEffort,
    pub effectiveness: MitigationEffectiveness,
    pub implementation_steps: Vec<String>,
    pub references: Vec<String>,
    pub compensating_controls: Vec<String>,
}

/// Mitigation priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationPriority {
    Immediate,
    High,
    Medium,
    Low,
    Deferred,
}

/// Remediation effort
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationEffort {
    Trivial,
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Mitigation effectiveness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationEffectiveness {
    Complete,
    Significant,
    Partial,
    Minimal,
    None,
}

impl AttackPath {
    /// Create a new attack path
    pub fn new(name: String, description: String) -> Self {
        let now = Utc::now();
        Self {
            id: AttackPathId::new(),
            name,
            description,
            nodes: Vec::new(),
            edges: Vec::new(),
            overall_risk: RiskScore {
                score: 0,
                level: RiskLevel::None,
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
                explanation: String::new(),
            },
            entry_points: Vec::new(),
            impact: ImpactAssessment {
                overall_impact: ImpactLevel::None,
                confidentiality: ImpactDetail {
                    level: ImpactLevel::None,
                    description: String::new(),
                    evidence: Vec::new(),
                    cvss_score: None,
                },
                integrity: ImpactDetail {
                    level: ImpactLevel::None,
                    description: String::new(),
                    evidence: Vec::new(),
                    cvss_score: None,
                },
                availability: ImpactDetail {
                    level: ImpactLevel::None,
                    description: String::new(),
                    evidence: Vec::new(),
                    cvss_score: None,
                },
                business: BusinessImpact {
                    level: ImpactLevel::None,
                    description: String::new(),
                    affected_processes: Vec::new(),
                    downtime_estimate_hours: None,
                    revenue_impact: None,
                    reputation_impact: None,
                },
                regulatory: None,
                affected_assets: Vec::new(),
                records_exposed: None,
                financial_impact: None,
            },
            attack_techniques: Vec::new(),
            prerequisites: Vec::new(),
            detection_opportunities: Vec::new(),
            mitigations: Vec::new(),
            confidence: 0.0,
            created_at: now,
            updated_at: now,
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a node to the attack path
    pub fn add_node(&mut self, node: AttackPathNode) {
        self.nodes.push(node);
        self.updated_at = Utc::now();
    }

    /// Add an edge to the attack path
    pub fn add_edge(&mut self, edge: AttackPathEdge) {
        self.edges.push(edge);
        self.updated_at = Utc::now();
    }

    /// Add an entry point
    pub fn add_entry_point(&mut self, entry_point: EntryPoint) {
        self.entry_points.push(entry_point);
        self.updated_at = Utc::now();
    }

    /// Add an attack technique
    pub fn add_attack_technique(&mut self, technique: AttackTechnique) {
        self.attack_techniques.push(technique);
        self.updated_at = Utc::now();
    }

    /// Add a prerequisite
    pub fn add_prerequisite(&mut self, prerequisite: Prerequisite) {
        self.prerequisites.push(prerequisite);
        self.updated_at = Utc::now();
    }

    /// Add a detection opportunity
    pub fn add_detection_opportunity(&mut self, detection: DetectionOpportunity) {
        self.detection_opportunities.push(detection);
        self.updated_at = Utc::now();
    }

    /// Add a mitigation
    pub fn add_mitigation(&mut self, mitigation: MitigationRecommendation) {
        self.mitigations.push(mitigation);
        self.updated_at = Utc::now();
    }

    /// Calculate overall risk score
    pub fn calculate_risk(&mut self) {
        // Simplified risk calculation based on nodes and edges
        let mut total_risk: f32 = 0.0;
        let mut total_weight: f32 = 0.0;

        for node in &self.nodes {
            total_risk += node.risk_contribution;
            total_weight += 1.0;
        }

        for edge in &self.edges {
            total_risk += edge.exploitability.score * 10.0; // Scale to 0-100
            total_weight += 1.0;
        }

        let score =
            if total_weight > 0.0 { (total_risk / total_weight).min(100.0) as u8 } else { 0 };

        self.overall_risk = RiskScore {
            score,
            level: RiskLevel::from_score(score),
            breakdown: RiskScoreBreakdown {
                exploitability: self.edges.iter().map(|e| e.exploitability.score).sum::<f32>()
                    / self.edges.len().max(1) as f32,
                impact: self.impact.overall_impact as u8 as f32 * 20.0,
                attack_complexity: self
                    .edges
                    .iter()
                    .map(|e| match e.exploitability.attack_complexity {
                        AttackComplexity::Low => 80.0,
                        AttackComplexity::Medium => 55.0,
                        AttackComplexity::High => 30.0,
                    })
                    .sum::<f32>()
                    / self.edges.len().max(1) as f32,
                privileges_required: self
                    .edges
                    .iter()
                    .map(|e| match e.exploitability.privileges_required {
                        PrivilegesRequired::None => 90.0,
                        PrivilegesRequired::Low => 50.0,
                        PrivilegesRequired::High => 10.0,
                    })
                    .sum::<f32>()
                    / self.edges.len().max(1) as f32,
                user_interaction: self
                    .edges
                    .iter()
                    .map(|e| if e.user_interaction_required { 30.0 } else { 90.0 })
                    .sum::<f32>()
                    / self.edges.len().max(1) as f32,
                scope: self
                    .edges
                    .iter()
                    .map(|e| match e.exploitability.scope {
                        Scope::Changed => 80.0,
                        Scope::Unchanged => 40.0,
                    })
                    .sum::<f32>()
                    / self.edges.len().max(1) as f32,
                detectability: self
                    .detection_opportunities
                    .iter()
                    .map(|d| match d.false_positive_likelihood {
                        FalsePositiveLikelihood::VeryLow => 90.0,
                        FalsePositiveLikelihood::Low => 70.0,
                        FalsePositiveLikelihood::Medium => 50.0,
                        FalsePositiveLikelihood::High => 30.0,
                        FalsePositiveLikelihood::VeryHigh => 10.0,
                    })
                    .sum::<f32>()
                    / self.detection_opportunities.len().max(1) as f32,
                remediation_difficulty: self
                    .mitigations
                    .iter()
                    .map(|m| match m.effort {
                        RemediationEffort::Trivial => 90.0,
                        RemediationEffort::Low => 70.0,
                        RemediationEffort::Medium => 50.0,
                        RemediationEffort::High => 30.0,
                        RemediationEffort::VeryHigh => 10.0,
                    })
                    .sum::<f32>()
                    / self.mitigations.len().max(1) as f32,
            },
            explanation: format!(
                "Attack path '{}' with {} nodes and {} edges",
                self.name,
                self.nodes.len(),
                self.edges.len()
            ),
        };
    }

    /// Get the linear sequence of nodes (for simple paths)
    pub fn get_linear_path(&self) -> Vec<AttackPathNode> {
        let mut sorted = self.nodes.clone();
        sorted.sort_by_key(|n| n.order);
        sorted
    }

    /// Find all paths from entry points to impact nodes (returns node IDs)
    pub fn find_all_paths(&self) -> Vec<Vec<NodeId>> {
        let mut paths = Vec::new();
        let entry_nodes: Vec<&AttackPathNode> = self
            .nodes
            .iter()
            .filter(|n| matches!(n.node_type, AttackNodeType::EntryPoint))
            .collect();

        for entry in entry_nodes {
            self.dfs_paths(entry, &mut vec![], &mut paths);
        }

        paths
    }

    fn dfs_paths(
        &self,
        current: &AttackPathNode,
        path: &mut Vec<NodeId>,
        paths: &mut Vec<Vec<NodeId>>,
    ) {
        path.push(current.id);

        // Check if this is an impact node
        if matches!(current.node_type, AttackNodeType::Impact) {
            paths.push(path.clone());
        } else {
            // Find outgoing edges
            let next_nodes: Vec<&AttackPathNode> = self
                .edges
                .iter()
                .filter(|e| e.from == current.id)
                .filter_map(|e| self.nodes.iter().find(|n| n.id == e.to))
                .collect();

            for next in next_nodes {
                if !path.iter().any(|id| *id == next.id) {
                    self.dfs_paths(next, path, paths);
                }
            }
        }

        path.pop();
    }

    /// Export to DOT format for visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph AttackPath {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=filled];\n");

        // Node colors by type
        let node_colors = [
            (AttackNodeType::Asset, "lightblue"),
            (AttackNodeType::EntryPoint, "lightgreen"),
            (AttackNodeType::Weakness, "orange"),
            (AttackNodeType::Pivot, "yellow"),
            (AttackNodeType::Impact, "red"),
            (AttackNodeType::Defense, "lightgray"),
            (AttackNodeType::Credential, "purple"),
            (AttackNodeType::NetworkSegment, "cyan"),
            (AttackNodeType::Custom, "white"),
        ];

        // Add nodes
        for node in &self.nodes {
            let color = node_colors
                .iter()
                .find(|(t, _)| *t == node.node_type)
                .map(|(_, c)| *c)
                .unwrap_or("white");

            let shape = match node.node_type {
                AttackNodeType::EntryPoint => "ellipse",
                AttackNodeType::Impact => "diamond",
                AttackNodeType::Asset => "folder",
                _ => "box",
            };

            let label = node.label.replace('"', "\\\"");
            dot.push_str(&format!(
                "  node_{} [label=\"{}\", fillcolor={}, shape={}];\n",
                node.id.0, label, color, shape
            ));

            // Mark choke points
            if node.is_choke_point {
                dot.push_str(&format!("  node_{} [peripheries=2];\n", node.id.0));
            }
        }

        // Add edges
        let edge_colors = [
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
            (FindingRelationshipType::Custom, "black"),
        ];

        for edge in &self.edges {
            let color = edge_colors
                .iter()
                .find(|(t, _)| *t == edge.relationship)
                .map(|(_, c)| *c)
                .unwrap_or("black");

            let label = format!("{:?}", edge.relationship);
            dot.push_str(&format!(
                "  node_{} -> node_{} [label=\"{}\", color={}, penwidth={}];\n",
                edge.from.0,
                edge.to.0,
                label,
                color,
                (edge.confidence * 3.0).max(1.0) as u32
            ));
        }

        dot.push_str("}\n");
        dot
    }

    /// Export to Mermaid format
    pub fn to_mermaid(&self) -> String {
        let mut mermaid = String::new();
        mermaid.push_str("graph LR\n");

        // Add nodes
        for node in &self.nodes {
            let label = node.label.replace('"', "#quot;");
            let (shape, end_shape) = match node.node_type {
                AttackNodeType::EntryPoint => ("([", "])"),
                AttackNodeType::Impact => ("[[", "]]"),
                AttackNodeType::Asset => ("[[", "]]"),
                _ => ("[", "]"),
            };

            mermaid.push_str(&format!("  node_{}{} {} {}]\n", node.id.0, shape, label, end_shape));
        }

        // Add edges
        for edge in &self.edges {
            let label = format!("{:?}", edge.relationship);
            mermaid
                .push_str(&format!("  node_{} -->|{}| node_{}\n", edge.from.0, label, edge.to.0));
        }

        mermaid
    }
}

/// Collection of attack paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathCollection {
    pub paths: Vec<AttackPath>,
    pub metadata: AttackPathCollectionMetadata,
}

/// Metadata for attack path collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPathCollectionMetadata {
    pub total_paths: usize,
    pub by_risk_level: HashMap<RiskLevel, usize>,
    pub by_impact_level: HashMap<ImpactLevel, usize>,
    pub average_confidence: f32,
    pub generated_at: DateTime<Utc>,
    pub target: String,
}

impl AttackPathCollection {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            metadata: AttackPathCollectionMetadata {
                total_paths: 0,
                by_risk_level: HashMap::new(),
                by_impact_level: HashMap::new(),
                average_confidence: 0.0,
                generated_at: Utc::now(),
                target: String::new(),
            },
        }
    }

    pub fn add_path(&mut self, path: AttackPath) {
        *self.metadata.by_risk_level.entry(path.overall_risk.level).or_insert(0) += 1;
        *self.metadata.by_impact_level.entry(path.impact.overall_impact).or_insert(0) += 1;
        self.metadata.total_paths = self.paths.len() + 1;
        self.paths.push(path);
    }

    pub fn get_critical_paths(&self) -> Vec<&AttackPath> {
        self.paths.iter().filter(|p| p.overall_risk.level >= RiskLevel::Critical).collect()
    }

    pub fn get_high_risk_paths(&self) -> Vec<&AttackPath> {
        self.paths.iter().filter(|p| p.overall_risk.level >= RiskLevel::High).collect()
    }

    pub fn sort_by_risk(&mut self) {
        self.paths.sort_by(|a, b| b.overall_risk.score.cmp(&a.overall_risk.score));
    }
}

impl Default for AttackPathCollection {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app_map::HttpMethod;
    use crate::ids::{AssetId, AttackPathId, EntryPointId, EvidenceId, FindingId, NodeId};

    #[test]
    fn test_attack_path_creation() {
        let mut path = AttackPath::new(
            "XSS to Data Exfiltration".to_string(),
            "Reflected XSS leads to session hijacking and data theft".to_string(),
        );

        let entry_node = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::EntryPoint,
            finding_id: None,
            endpoint_id: Some("/search".to_string()),
            asset_id: None,
            label: "Search Endpoint".to_string(),
            description: "Reflected XSS in search parameter".to_string(),
            evidence: vec![],
            risk_contribution: 30.0,
            is_choke_point: false,
            is_branch_point: false,
            order: 0,
            metadata: HashMap::new(),
        };

        let weakness_node = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::Weakness,
            finding_id: Some(FindingId::new()),
            endpoint_id: Some("/search".to_string()),
            asset_id: None,
            label: "Reflected XSS".to_string(),
            description: "User input reflected without sanitization".to_string(),
            evidence: vec![],
            risk_contribution: 60.0,
            is_choke_point: true,
            is_branch_point: false,
            order: 1,
            metadata: HashMap::new(),
        };

        let pivot_node = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::Pivot,
            finding_id: Some(FindingId::new()),
            endpoint_id: None,
            asset_id: None,
            label: "Session Hijacking".to_string(),
            description: "Steal session cookie via XSS".to_string(),
            evidence: vec![],
            risk_contribution: 80.0,
            is_choke_point: true,
            is_branch_point: true,
            order: 2,
            metadata: HashMap::new(),
        };

        let impact_node = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::Impact,
            finding_id: Some(FindingId::new()),
            endpoint_id: None,
            asset_id: Some(AssetId::new()),
            label: "Data Exfiltration".to_string(),
            description: "Access sensitive user data".to_string(),
            evidence: vec![],
            risk_contribution: 100.0,
            is_choke_point: false,
            is_branch_point: false,
            order: 3,
            metadata: HashMap::new(),
        };

        path.add_node(entry_node.clone());
        path.add_node(weakness_node.clone());
        path.add_node(pivot_node.clone());
        path.add_node(impact_node.clone());

        path.add_edge(AttackPathEdge {
            from: entry_node.id,
            to: weakness_node.id,
            relationship: FindingRelationshipType::Enables,
            evidence: vec![],
            confidence: 0.9,
            exploitability: ExploitabilityInfo {
                score: 8.0,
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::Required,
                scope: Scope::Unchanged,
                exploit_available: true,
                exploited_in_wild: true,
                epss_score: Some(0.75),
            },
            estimated_time: Some(chrono::Duration::minutes(5)),
            required_privileges: PrivilegeLevel::None,
            user_interaction_required: true,
            metadata: HashMap::new(),
        });

        path.add_edge(AttackPathEdge {
            from: weakness_node.id,
            to: pivot_node.id,
            relationship: FindingRelationshipType::ChainedExploit,
            evidence: vec![],
            confidence: 0.85,
            exploitability: ExploitabilityInfo {
                score: 7.0,
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Changed,
                exploit_available: true,
                exploited_in_wild: true,
                epss_score: Some(0.6),
            },
            estimated_time: Some(chrono::Duration::minutes(2)),
            required_privileges: PrivilegeLevel::Low,
            user_interaction_required: false,
            metadata: HashMap::new(),
        });

        path.add_edge(AttackPathEdge {
            from: pivot_node.id,
            to: impact_node.id,
            relationship: FindingRelationshipType::ChainedExploit,
            evidence: vec![],
            confidence: 0.8,
            exploitability: ExploitabilityInfo {
                score: 6.0,
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Medium,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::None,
                scope: Scope::Changed,
                exploit_available: true,
                exploited_in_wild: false,
                epss_score: None,
            },
            estimated_time: Some(chrono::Duration::minutes(10)),
            required_privileges: PrivilegeLevel::Medium,
            user_interaction_required: false,
            metadata: HashMap::new(),
        });

        path.add_entry_point(EntryPoint {
            id: EntryPointId::new(),
            entry_type: EntryPointType::WebEndpoint,
            location: "/search".to_string(),
            method: Some(HttpMethod::Get),
            parameters: vec!["q".to_string()],
            auth_required: false,
            technologies: vec!["nginx".to_string(), "PHP".to_string()],
            attack_surface: AttackSurface {
                parameter_count: 1,
                endpoint_count: 1,
                validation_coverage: 0.0,
                auth_coverage: 0.0,
                rate_limit_coverage: 0.0,
                waf_coverage: 0.0,
            },
            confidence: 0.95,
        });

        path.calculate_risk();

        assert_eq!(path.nodes.len(), 4);
        assert_eq!(path.edges.len(), 3);
        assert!(path.overall_risk.score > 0);
        assert!(!path.find_all_paths().is_empty());
    }

    #[test]
    fn test_to_dot() {
        let mut path = AttackPath::new("Test Path".to_string(), "Test".to_string());

        let n1 = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::EntryPoint,
            finding_id: None,
            endpoint_id: None,
            asset_id: None,
            label: "Entry".to_string(),
            description: "Test".to_string(),
            evidence: vec![],
            risk_contribution: 30.0,
            is_choke_point: false,
            is_branch_point: false,
            order: 0,
            metadata: HashMap::new(),
        };

        let n2 = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::Impact,
            finding_id: None,
            endpoint_id: None,
            asset_id: None,
            label: "Impact".to_string(),
            description: "Test".to_string(),
            evidence: vec![],
            risk_contribution: 90.0,
            is_choke_point: false,
            is_branch_point: false,
            order: 1,
            metadata: HashMap::new(),
        };

        path.add_node(n1.clone());
        path.add_node(n2.clone());
        path.add_edge(AttackPathEdge {
            from: n1.id,
            to: n2.id,
            relationship: FindingRelationshipType::ChainedExploit,
            evidence: vec![],
            confidence: 0.9,
            exploitability: ExploitabilityInfo {
                score: 8.0,
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                exploit_available: true,
                exploited_in_wild: false,
                epss_score: None,
            },
            estimated_time: None,
            required_privileges: PrivilegeLevel::None,
            user_interaction_required: false,
            metadata: HashMap::new(),
        });

        let dot = path.to_dot();
        assert!(dot.contains("digraph AttackPath"));
        assert!(dot.contains("node_"));
        assert!(dot.contains("ChainedExploit"));
    }

    #[test]
    fn test_to_mermaid() {
        let mut path = AttackPath::new("Test Path".to_string(), "Test".to_string());

        let n1 = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::EntryPoint,
            finding_id: None,
            endpoint_id: None,
            asset_id: None,
            label: "Entry".to_string(),
            description: "Test".to_string(),
            evidence: vec![],
            risk_contribution: 30.0,
            is_choke_point: false,
            is_branch_point: false,
            order: 0,
            metadata: HashMap::new(),
        };

        let n2 = AttackPathNode {
            id: NodeId::new(),
            node_type: AttackNodeType::Impact,
            finding_id: None,
            endpoint_id: None,
            asset_id: None,
            label: "Impact".to_string(),
            description: "Test".to_string(),
            evidence: vec![],
            risk_contribution: 90.0,
            is_choke_point: false,
            is_branch_point: false,
            order: 1,
            metadata: HashMap::new(),
        };

        path.add_node(n1.clone());
        path.add_node(n2.clone());
        path.add_edge(AttackPathEdge {
            from: n1.id,
            to: n2.id,
            relationship: FindingRelationshipType::ChainedExploit,
            evidence: vec![],
            confidence: 0.9,
            exploitability: ExploitabilityInfo {
                score: 8.0,
                attack_vector: AttackVector::Network,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
                scope: Scope::Unchanged,
                exploit_available: true,
                exploited_in_wild: false,
                epss_score: None,
            },
            estimated_time: None,
            required_privileges: PrivilegeLevel::None,
            user_interaction_required: false,
            metadata: HashMap::new(),
        });

        let mermaid = path.to_mermaid();
        assert!(mermaid.contains("graph LR"));
        assert!(mermaid.contains("node_"));
        assert!(mermaid.contains("ChainedExploit"));
    }

    #[test]
    fn test_attack_path_collection() {
        let mut collection = AttackPathCollection::new();
        collection.metadata.target = "https://example.com".to_string();

        let mut path1 = AttackPath::new("Path 1".to_string(), "Critical".to_string());
        path1.overall_risk = RiskScore {
            score: 95,
            level: RiskLevel::Critical,
            breakdown: RiskScoreBreakdown {
                exploitability: 9.0,
                impact: 9.0,
                attack_complexity: 8.0,
                privileges_required: 9.0,
                user_interaction: 3.0,
                scope: 8.0,
                detectability: 5.0,
                remediation_difficulty: 4.0,
            },
            explanation: "Critical path".to_string(),
        };
        path1.confidence = 0.9;

        let mut path2 = AttackPath::new("Path 2".to_string(), "High".to_string());
        path2.overall_risk = RiskScore {
            score: 75,
            level: RiskLevel::High,
            breakdown: RiskScoreBreakdown {
                exploitability: 7.0,
                impact: 7.0,
                attack_complexity: 6.0,
                privileges_required: 5.0,
                user_interaction: 5.0,
                scope: 4.0,
                detectability: 6.0,
                remediation_difficulty: 6.0,
            },
            explanation: "High risk path".to_string(),
        };
        path2.confidence = 0.8;

        collection.add_path(path1);
        collection.add_path(path2);

        assert_eq!(collection.paths.len(), 2);
        assert_eq!(collection.get_critical_paths().len(), 1);
        assert_eq!(collection.get_high_risk_paths().len(), 2);

        collection.sort_by_risk();
        assert_eq!(collection.paths[0].overall_risk.score, 95);
        assert_eq!(collection.paths[1].overall_risk.score, 75);
    }
}
