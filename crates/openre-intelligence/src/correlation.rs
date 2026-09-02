//! Enhanced finding correlation engine
//!
//! This module provides systematic pairwise finding analysis, evidence-based relationship inference,
//! confidence scoring, and CWE/CAPEC-based relationship rules.

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use openre_core::ids::{FindingId, RelationshipId};
use openre_core::relationships::{
    EvidenceSource, EvidenceType, FindingRelationship, FindingRelationshipGraph,
    FindingRelationshipType, RelationshipEvidence, RiskFactor, RiskImpact, RiskLevelChange,
};
use openre_core::result::{Category, Finding, Severity};
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// Configuration for the correlation engine
#[derive(Debug, Clone)]
pub struct CorrelationConfig {
    /// Enable CSP + XSS correlation
    pub enable_csp_xss: bool,

    /// Enable directory listing + Git metadata correlation
    pub enable_directory_git: bool,

    /// Enable strengthening/weakening correlations
    pub enable_strengthening_weakening: bool,

    /// Enable shared root cause analysis
    pub enable_root_cause: bool,

    /// Enable CWE/CAPEC-based relationship inference
    pub enable_cwe_capec_inference: bool,

    /// Enable temporal correlation (findings close in time)
    pub enable_temporal: bool,

    /// Enable spatial correlation (same target/endpoint)
    pub enable_spatial: bool,

    /// Minimum confidence threshold for correlations (0.0-1.0)
    pub min_confidence_threshold: f32,

    /// Maximum correlations per finding
    pub max_correlations_per_finding: usize,

    /// Time window for temporal correlation (seconds)
    pub temporal_window_seconds: u64,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enable_csp_xss: true,
            enable_directory_git: true,
            enable_strengthening_weakening: true,
            enable_root_cause: true,
            enable_cwe_capec_inference: true,
            enable_temporal: true,
            enable_spatial: true,
            min_confidence_threshold: 0.3,
            max_correlations_per_finding: 10,
            temporal_window_seconds: 3600, // 1 hour
        }
    }
}

/// Enhanced correlation engine for finding relationships
#[derive(Clone)]
pub struct CorrelationEngine {
    config: CorrelationConfig,
    /// CWE to relationship type mappings
    cwe_relationship_rules: HashMap<String, Vec<CweRelationshipRule>>,
    /// CAPEC to relationship type mappings
    capec_relationship_rules: HashMap<String, Vec<CapecRelationshipRule>>,
}

/// Rule for inferring relationships from CWE
#[derive(Debug, Clone)]
struct CweRelationshipRule {
    cwe_id: String,
    relationship_type: FindingRelationshipType,
    confidence: f32,
    description: String,
}

/// Rule for inferring relationships from CAPEC
#[derive(Debug, Clone)]
struct CapecRelationshipRule {
    capec_id: String,
    relationship_type: FindingRelationshipType,
    confidence: f32,
    description: String,
}

impl CorrelationEngine {
    /// Create a new correlation engine with default configuration
    pub fn new() -> Self {
        let mut engine = Self {
            config: CorrelationConfig::default(),
            cwe_relationship_rules: HashMap::new(),
            capec_relationship_rules: HashMap::new(),
        };
        engine.init_default_rules();
        engine
    }

    /// Create a new correlation engine with custom configuration
    pub fn with_config(config: CorrelationConfig) -> Self {
        let mut engine = Self {
            config,
            cwe_relationship_rules: HashMap::new(),
            capec_relationship_rules: HashMap::new(),
        };
        engine.init_default_rules();
        engine
    }

    /// Initialize default CWE/CAPEC relationship rules
    fn init_default_rules(&mut self) {
        // CWE-based rules
        self.cwe_relationship_rules.insert(
            "CWE-79".to_string(), // XSS
            vec![
                CweRelationshipRule {
                    cwe_id: "CWE-79".to_string(),
                    relationship_type: FindingRelationshipType::Enables,
                    confidence: 0.85,
                    description: "XSS can enable client-side attacks".to_string(),
                },
                CweRelationshipRule {
                    cwe_id: "CWE-693".to_string(), // Missing CSP
                    relationship_type: FindingRelationshipType::Enables,
                    confidence: 0.8,
                    description: "Missing CSP enables XSS exploitation".to_string(),
                },
            ],
        );

        self.cwe_relationship_rules.insert(
            "CWE-89".to_string(), // SQL Injection
            vec![CweRelationshipRule {
                cwe_id: "CWE-89".to_string(),
                relationship_type: FindingRelationshipType::ChainedExploit,
                confidence: 0.9,
                description: "SQL injection can lead to data exfiltration".to_string(),
            }],
        );

        self.cwe_relationship_rules.insert(
            "CWE-22".to_string(), // Path Traversal
            vec![CweRelationshipRule {
                cwe_id: "CWE-22".to_string(),
                relationship_type: FindingRelationshipType::ChainedExploit,
                confidence: 0.85,
                description: "Path traversal can lead to file read/write".to_string(),
            }],
        );

        self.cwe_relationship_rules.insert(
            "CWE-798".to_string(), // Hardcoded Credentials
            vec![CweRelationshipRule {
                cwe_id: "CWE-798".to_string(),
                relationship_type: FindingRelationshipType::Enables,
                confidence: 0.9,
                description: "Hardcoded credentials enable authentication bypass".to_string(),
            }],
        );

        self.cwe_relationship_rules.insert(
            "CWE-200".to_string(), // Information Exposure
            vec![CweRelationshipRule {
                cwe_id: "CWE-200".to_string(),
                relationship_type: FindingRelationshipType::InformationLeakage,
                confidence: 0.8,
                description: "Information exposure enables further attacks".to_string(),
            }],
        );

        // CAPEC-based rules
        self.capec_relationship_rules.insert(
            "CAPEC-86".to_string(), // Embedding Scripts in HTTP Headers
            vec![CapecRelationshipRule {
                capec_id: "CAPEC-86".to_string(),
                relationship_type: FindingRelationshipType::Enables,
                confidence: 0.85,
                description: "Script embedding enables XSS".to_string(),
            }],
        );

        self.capec_relationship_rules.insert(
            "CAPEC-109".to_string(), // Object Relational Mapping Injection
            vec![CapecRelationshipRule {
                capec_id: "CAPEC-109".to_string(),
                relationship_type: FindingRelationshipType::ChainedExploit,
                confidence: 0.9,
                description: "ORM injection enables SQL injection".to_string(),
            }],
        );

        self.capec_relationship_rules.insert(
            "CAPEC-126".to_string(), // Path Traversal
            vec![CapecRelationshipRule {
                capec_id: "CAPEC-126".to_string(),
                relationship_type: FindingRelationshipType::ChainedExploit,
                confidence: 0.85,
                description: "Path traversal enables file access".to_string(),
            }],
        );
    }

    /// Correlate findings to identify relationships and enhance risk confidence
    pub async fn correlate_findings(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships: Vec<FindingRelationship> = Vec::new();

        // Apply different correlation strategies based on configuration
        if self.config.enable_csp_xss {
            let csp_relationships = self.correlate_csp_xss(findings)?;
            relationships.extend(csp_relationships);
        }

        if self.config.enable_directory_git {
            let dir_relationships = self.correlate_directory_git(findings)?;
            relationships.extend(dir_relationships);
        }

        if self.config.enable_strengthening_weakening {
            let str_relationships = self.correlate_strengthening_weakening(findings)?;
            relationships.extend(str_relationships);
        }

        if self.config.enable_root_cause {
            let root_relationships = self.correlate_shared_root_cause(findings)?;
            relationships.extend(root_relationships);
        }

        if self.config.enable_cwe_capec_inference {
            let cwe_relationships = self.correlate_cwe_capec(findings)?;
            relationships.extend(cwe_relationships);
        }

        if self.config.enable_temporal {
            let temp_relationships = self.correlate_temporal(findings)?;
            relationships.extend(temp_relationships);
        }

        if self.config.enable_spatial {
            let spatial_relationships = self.correlate_spatial(findings)?;
            relationships.extend(spatial_relationships);
        }

        // Filter by minimum confidence threshold
        //

        // Limit correlations per finding to prevent explosion
        // TODO: implement limit for FindingRelationship

        Ok(relationships)
    }

    /// Synchronous version of correlate_findings for testing
    pub fn correlate_findings_sync(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships: Vec<FindingRelationship> = Vec::new();

        // Apply different correlation strategies based on configuration
        if self.config.enable_csp_xss {
            let csp_relationships = self.correlate_csp_xss(findings)?;
            relationships.extend(self.correlate_csp_xss(findings)?);
        }

        if self.config.enable_directory_git {
            let dir_relationships = self.correlate_directory_git(findings)?;
            relationships.extend(self.correlate_directory_git(findings)?);
        }

        if self.config.enable_strengthening_weakening {
            let str_relationships = self.correlate_strengthening_weakening(findings)?;
            relationships.extend(self.correlate_strengthening_weakening(findings)?);
        }

        if self.config.enable_root_cause {
            let root_relationships = self.correlate_shared_root_cause(findings)?;
            relationships.extend(self.correlate_shared_root_cause(findings)?);
        }

        if self.config.enable_cwe_capec_inference {
            let cwe_relationships = self.correlate_cwe_capec(findings)?;
            relationships.extend(self.correlate_cwe_capec(findings)?);
        }

        if self.config.enable_temporal {
            let temp_relationships = self.correlate_temporal(findings)?;
            relationships.extend(self.correlate_temporal(findings)?);
        }

        if self.config.enable_spatial {
            let spatial_relationships = self.correlate_spatial(findings)?;
            relationships.extend(self.correlate_spatial(findings)?);
        }

        // Filter by minimum confidence threshold
        //

        // Limit correlations per finding to prevent explosion
        // TODO: implement limit for FindingRelationship

        Ok(relationships)
    }

    /// Correlate findings into a relationship graph
    pub async fn correlate_findings_graph(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<FindingRelationshipGraph> {
        let relationships = self.correlate_findings(findings).await?;
        let mut graph = FindingRelationshipGraph::new();
        for rel in relationships {
            graph.add_relationship(rel.into());
        }
        Ok(graph)
    }

    /// Synchronous version of correlate_findings_graph for testing
    pub fn correlate_findings_graph_sync(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<FindingRelationshipGraph> {
        let relationships = self.correlate_findings_sync(findings)?;
        let mut graph = FindingRelationshipGraph::new();
        for rel in relationships {
            graph.add_relationship(rel.into());
        }
        Ok(graph)
    }

    /// Correlate missing CSP with reflected XSS findings
    fn correlate_csp_xss(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Find CSP missing findings
        let csp_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.category == Category::SecurityMisconfiguration
                    && (f.title.to_lowercase().contains("csp")
                        || f.title.to_lowercase().contains("content-security-policy"))
                    && f.title.to_lowercase().contains("missing")
            })
            .collect();

        // Find reflected XSS findings
        let xss_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| f.category == Category::Xss && f.title.to_lowercase().contains("reflected"))
            .collect();

        // Create correlations between CSP and XSS findings on the same target
        for csp_finding in &csp_findings {
            for xss_finding in &xss_findings {
                if csp_finding.target == xss_finding.target {
                    let relationship = FindingRelationship {
                        id: RelationshipId::new(),
                        source_finding: csp_finding.id,
                        target_finding: xss_finding.id,
                        relationship_type: FindingRelationshipType::Enables,
                        explanation: "Missing Content Security Policy (CSP) increases the risk and exploitability of reflected XSS vulnerabilities on the same target.".to_string(),
                        evidence: vec![
                            RelationshipEvidence {
                                evidence_type: openre_core::relationships::EvidenceType::Configuration,
                                description: format!("Finding '{}' indicates missing CSP policy", csp_finding.title),
                                data: serde_json::json!({"finding_id": csp_finding.id.to_string()}),
                                source: openre_core::relationships::EvidenceSource::Scanner,
                                confidence: 0.9,
                                related_findings: vec![csp_finding.id, xss_finding.id],
                                timestamp: chrono::Utc::now(),
                            },
                            RelationshipEvidence {
                                evidence_type: openre_core::relationships::EvidenceType::HttpInteraction,
                                description: format!("Finding '{}' indicates reflected XSS vulnerability", xss_finding.title),
                                data: serde_json::json!({"finding_id": xss_finding.id.to_string()}),
                                source: openre_core::relationships::EvidenceSource::Scanner,
                                confidence: 0.9,
                                related_findings: vec![csp_finding.id, xss_finding.id],
                                timestamp: chrono::Utc::now(),
                            },
                            RelationshipEvidence {
                                evidence_type: openre_core::relationships::EvidenceType::DatabaseMatch,
                                description: "CSP headers provide an additional layer of protection against XSS attacks".to_string(),
                                data: serde_json::json!({"cwe": ["CWE-693", "CWE-79"]}),
                                source: openre_core::relationships::EvidenceSource::Cwe,
                                confidence: 0.85,
                                related_findings: vec![csp_finding.id, xss_finding.id],
                                timestamp: chrono::Utc::now(),
                            },
                        ],
                        confidence: 0.85,
                        risk_impact: openre_core::relationships::RiskImpact {
                            score_delta: 25,
                            level_change: openre_core::relationships::RiskLevelChange::ModerateIncrease,
                            explanation: "The combination of missing CSP and reflected XSS creates a higher risk profile as there's no secondary protection against XSS exploitation.".to_string(),
                            affected_factors: vec![openre_core::relationships::RiskFactor::Exploitability, openre_core::relationships::RiskFactor::Impact],
                            confidence: 0.8,
                        },
                        supporting_cwes: vec!["CWE-693".to_string(), "CWE-79".to_string()],
                        supporting_capecs: vec!["CAPEC-86".to_string()],
                        supporting_attack_techniques: vec!["T1059.007".to_string()],
                        discovered_at: chrono::Utc::now(),
                        metadata: HashMap::new(),
                    };
                    relationships.push(relationship);
                }
            }
        }

        Ok(relationships)
    }

    /// Correlate directory listing with Git metadata exposure
    fn correlate_directory_git(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Find directory listing findings
        let dir_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                (f.category == Category::InformationDisclosure
                    && f.title.to_lowercase().contains("directory"))
                    || (f.category == Category::Configuration
                        && f.title.to_lowercase().contains("listing"))
            })
            .collect();

        // Find Git metadata exposure findings
        let git_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.category == Category::InformationDisclosure
                    && (f.title.to_lowercase().contains("git")
                        || f.description.to_lowercase().contains(".git"))
            })
            .collect();

        // Create correlations between directory listing and Git metadata on the same target
        for dir_finding in &dir_findings {
            for git_finding in &git_findings {
                if dir_finding.id != git_finding.id && dir_finding.target == git_finding.target {
                    let relationship = FindingRelationship {
                        id: RelationshipId::new(),
                        source_finding: dir_finding.id,
                        target_finding: git_finding.id,
                        relationship_type: FindingRelationshipType::ChainedExploit,
                        explanation: "Directory listing combined with exposed Git metadata forms a critical information disclosure chain that can lead to source code exposure.".to_string(),
                        evidence: vec![
                            RelationshipEvidence {
                                evidence_type: EvidenceType::HttpInteraction,
                                description: format!("Finding '{}' indicates directory listing is enabled", dir_finding.title),
                                data: serde_json::json!({"finding_id": dir_finding.id.to_string()}),
                                source: EvidenceSource::Scanner,
                                confidence: 0.95,
                                related_findings: vec![dir_finding.id, git_finding.id],
                                timestamp: chrono::Utc::now(),
                            },
                            RelationshipEvidence {
                                evidence_type: EvidenceType::HttpInteraction,
                                description: format!("Finding '{}' indicates Git metadata exposure", git_finding.title),
                                data: serde_json::json!({"finding_id": git_finding.id.to_string()}),
                                source: EvidenceSource::Scanner,
                                confidence: 0.95,
                                related_findings: vec![dir_finding.id, git_finding.id],
                                timestamp: chrono::Utc::now(),
                            },
                            RelationshipEvidence {
                                evidence_type: EvidenceType::DatabaseMatch,
                                description: "Together these findings enable attackers to reconstruct source code and understand application structure".to_string(),
                                data: serde_json::json!({"cwe": ["CWE-548", "CWE-200"]}),
                                source: EvidenceSource::Cwe,
                                confidence: 0.9,
                                related_findings: vec![dir_finding.id, git_finding.id],
                                timestamp: chrono::Utc::now(),
                            },
                        ],
                        confidence: 0.9,
                        risk_impact: RiskImpact {
                            score_delta: 30,
                            level_change: RiskLevelChange::SignificantIncrease,
                            explanation: "The combination creates an information disclosure chain that significantly increases the risk of source code exposure and application understanding.".to_string(),
                            affected_factors: vec![RiskFactor::Confidentiality, RiskFactor::Impact],
                            confidence: 0.85,
                        },
                        supporting_cwes: vec!["CWE-548".to_string(), "CWE-200".to_string()],
                        supporting_capecs: vec!["CAPEC-126".to_string()],
                        supporting_attack_techniques: vec!["T1590.005".to_string()],
                        discovered_at: chrono::Utc::now(),
                        metadata: HashMap::new(),
                    };
                    relationships.push(relationship);
                }
            }
        }

        Ok(relationships)
    }

    /// Correlate findings that strengthen or weaken each other
    fn correlate_strengthening_weakening(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Group findings by target for more efficient correlation
        let mut findings_by_target: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            findings_by_target.entry(&finding.target).or_default().push(finding);
        }

        // For each target, look for strengthening/weakening patterns
        for (_target, target_findings) in findings_by_target {
            // Look for multiple findings of the same category that might strengthen each other
            let mut category_count: HashMap<Category, Vec<&Finding>> = HashMap::new();
            for finding in &target_findings {
                category_count.entry(finding.category.clone()).or_default().push(finding);
            }

            // Create strengthening correlations for categories with multiple findings
            for (category, category_findings) in category_count {
                if category_findings.len() > 1 {
                    let finding_ids: Vec<FindingId> =
                        category_findings.iter().map(|f| f.id).collect();

                    // Calculate average confidence based on number of findings
                    let confidence = (0.5 + (category_findings.len() as f32 * 0.1)).min(0.9);

                    let category_name = match category {
                        Category::Injection => "injection",
                        Category::Xss => "XSS",
                        Category::BrokenAuthentication => "authentication",
                        Category::SensitiveDataExposure => "data exposure",
                        Category::SecurityMisconfiguration => "misconfiguration",
                        _ => "security",
                    };

                    let relationship = FindingRelationship {
                        id: RelationshipId::new(),
                        source_finding: finding_ids[0],
                        target_finding: finding_ids[1],
                        relationship_type: FindingRelationshipType::Amplifies,
                        confidence,
                        explanation: format!("Multiple {} findings on the same target amplify each other, indicating a systemic issue.", category_name),
                        evidence: category_findings.iter().map(|f|
                            RelationshipEvidence {
                                evidence_type: EvidenceType::AutomatedCorrelation,
                                description: format!("Finding '{}' (ID: {}) indicates a {} issue", f.title, f.id, category_name),
                                data: serde_json::json!({"finding_id": f.id.to_string()}),
                                source: EvidenceSource::Scanner,
                                confidence,
                                related_findings: finding_ids.clone(),
                                timestamp: chrono::Utc::now(),
                            }
                        ).collect(),
                        risk_impact: RiskImpact {
                            score_delta: 20,
                            level_change: RiskLevelChange::ModerateIncrease,
                            explanation: format!("Multiple {} findings on target '{}' indicate a systemic issue rather than isolated vulnerabilities.",
                                category_name, _target),
                            affected_factors: vec![RiskFactor::Exploitability, RiskFactor::Impact],
                            confidence,
                        },
                        supporting_cwes: Vec::new(),
                        supporting_capecs: Vec::new(),
                        supporting_attack_techniques: Vec::new(),
                        discovered_at: chrono::Utc::now(),
                        metadata: HashMap::new(),
                    };
                    relationships.push(relationship);
                }
            }
        }

        Ok(relationships)
    }

    /// Correlate findings with shared root cause
    fn correlate_shared_root_cause(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Group findings by plugin source and category
        let mut plugin_category_map: HashMap<(String, Category), Vec<&Finding>> = HashMap::new();
        for finding in findings {
            plugin_category_map
                .entry((finding.plugin_source.clone(), finding.category.clone()))
                .or_default()
                .push(finding);
        }

        // Look for findings from the same plugin that might share root cause
        for ((plugin, category), category_findings) in plugin_category_map {
            if category_findings.len() > 1 {
                let finding_ids: Vec<FindingId> = category_findings.iter().map(|f| f.id).collect();

                let relationship = FindingRelationship {
                    id: RelationshipId::new(),
                    source_finding: finding_ids[0],
                    target_finding: finding_ids[1],
                    relationship_type: FindingRelationshipType::SameRootCause,
                    confidence: 0.75,
                    explanation: format!("Multiple {} findings from plugin '{}' may share the same root cause.",
                        match category {
                            Category::Injection => "injection",
                            Category::Xss => "XSS",
                            Category::BrokenAuthentication => "authentication",
                            Category::SensitiveDataExposure => "data exposure",
                            Category::SecurityMisconfiguration => "misconfiguration",
                            _ => "security",
                        }, plugin),
                    evidence: category_findings.iter().map(|f|
                        RelationshipEvidence {
                            evidence_type: EvidenceType::AutomatedCorrelation,
                            description: format!("Finding '{}' from plugin '{}'", f.title, plugin),
                            data: serde_json::json!({"finding_id": f.id.to_string(), "plugin": plugin}),
                            source: EvidenceSource::Scanner,
                            confidence: 0.75,
                            related_findings: finding_ids.clone(),
                            timestamp: chrono::Utc::now(),
                        }
                    ).collect(),
                    risk_impact: RiskImpact {
                        score_delta: 15,
                        level_change: RiskLevelChange::SlightIncrease,
                        explanation: "Shared root cause suggests fixing one may resolve multiple findings".to_string(),
                        affected_factors: vec![RiskFactor::RemediationDifficulty],
                        confidence: 0.7,
                    },
                    supporting_cwes: Vec::new(),
                    supporting_capecs: Vec::new(),
                    supporting_attack_techniques: Vec::new(),
                    discovered_at: chrono::Utc::now(),
                    metadata: HashMap::new(),
                };
                relationships.push(relationship);
            }
        }

        Ok(relationships)
    }

    /// Correlate findings using CWE/CAPEC database
    fn correlate_cwe_capec(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Group findings by CWE
        let mut cwe_map: HashMap<String, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            for cwe in &finding.cwe_ids {
                cwe_map.entry(cwe.clone()).or_default().push(finding);
            }
        }

        // Create relationships for findings sharing CWEs
        for (cwe_id, cwe_findings) in cwe_map {
            if cwe_findings.len() > 1 {
                if let Some(rules) = self.cwe_relationship_rules.get(&cwe_id) {
                    for rule in rules {
                        let finding_ids: Vec<FindingId> =
                            cwe_findings.iter().map(|f| f.id).collect();

                        let relationship = FindingRelationship {
                            id: RelationshipId::new(),
                            source_finding: finding_ids[0],
                            target_finding: finding_ids[1],
                            relationship_type: rule.relationship_type,
                            confidence: rule.confidence,
                            explanation: rule.description.clone(),
                            evidence: vec![RelationshipEvidence {
                                evidence_type: EvidenceType::DatabaseMatch,
                                description: format!("Shared CWE: {}", cwe_id),
                                data: serde_json::json!({"cwe_id": cwe_id}),
                                source: EvidenceSource::Cwe,
                                confidence: rule.confidence,
                                related_findings: finding_ids.clone(),
                                timestamp: chrono::Utc::now(),
                            }],
                            risk_impact: RiskImpact {
                                score_delta: 10,
                                level_change: RiskLevelChange::SlightIncrease,
                                explanation: format!(
                                    "Findings sharing CWE {} may be related",
                                    cwe_id
                                ),
                                affected_factors: vec![RiskFactor::Exploitability],
                                confidence: rule.confidence,
                            },
                            supporting_cwes: vec![cwe_id.clone()],
                            supporting_capecs: Vec::new(),
                            supporting_attack_techniques: Vec::new(),
                            discovered_at: chrono::Utc::now(),
                            metadata: HashMap::new(),
                        };
                        relationships.push(relationship);
                    }
                }
            }
        }

        // Group findings by CAPEC
        let mut capec_map: HashMap<String, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            for capec in &finding.capec_ids {
                capec_map.entry(capec.clone()).or_default().push(finding);
            }
        }

        // Create relationships for findings sharing CAPECs
        for (capec_id, capec_findings) in capec_map {
            if capec_findings.len() > 1 {
                if let Some(rules) = self.capec_relationship_rules.get(&capec_id) {
                    for rule in rules {
                        let finding_ids: Vec<FindingId> =
                            capec_findings.iter().map(|f| f.id).collect();

                        let relationship = FindingRelationship {
                            id: RelationshipId::new(),
                            source_finding: finding_ids[0],
                            target_finding: finding_ids[1],
                            relationship_type: rule.relationship_type,
                            confidence: rule.confidence,
                            explanation: rule.description.clone(),
                            evidence: vec![RelationshipEvidence {
                                evidence_type: EvidenceType::DatabaseMatch,
                                description: format!("Shared CAPEC: {}", capec_id),
                                data: serde_json::json!({"capec_id": capec_id}),
                                source: EvidenceSource::Capec,
                                confidence: rule.confidence,
                                related_findings: finding_ids.clone(),
                                timestamp: chrono::Utc::now(),
                            }],
                            risk_impact: RiskImpact {
                                score_delta: 15,
                                level_change: RiskLevelChange::SlightIncrease,
                                explanation: format!(
                                    "Findings sharing CAPEC {} may be related",
                                    capec_id
                                ),
                                affected_factors: vec![
                                    RiskFactor::Exploitability,
                                    RiskFactor::AttackComplexity,
                                ],
                                confidence: rule.confidence,
                            },
                            supporting_cwes: Vec::new(),
                            supporting_capecs: vec![capec_id.clone()],
                            supporting_attack_techniques: Vec::new(),
                            discovered_at: chrono::Utc::now(),
                            metadata: HashMap::new(),
                        };
                        relationships.push(relationship);
                    }
                }
            }
        }

        Ok(relationships)
    }

    /// Correlate findings temporally (discovered close in time)
    fn correlate_temporal(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Sort findings by timestamp
        let mut sorted_findings = findings.to_vec();
        sorted_findings.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Check adjacent findings within time window
        for i in 0..sorted_findings.len() {
            for j in (i + 1)..sorted_findings.len() {
                let time_diff = (sorted_findings[j].timestamp - sorted_findings[i].timestamp)
                    .num_seconds()
                    .abs() as u64;

                if time_diff <= self.config.temporal_window_seconds {
                    if sorted_findings[i].target == sorted_findings[j].target {
                        let relationship = FindingRelationship {
                            id: RelationshipId::new(),
                            source_finding: sorted_findings[i].id,
                            target_finding: sorted_findings[j].id,
                            relationship_type: FindingRelationshipType::Temporal,
                            confidence: 0.4,
                            explanation: format!("Findings discovered within {} seconds of each other on the same target", time_diff),
                            evidence: vec![
                                RelationshipEvidence {
                                    evidence_type: EvidenceType::AutomatedCorrelation,
                                    description: format!("Time difference: {} seconds", time_diff),
                                    data: serde_json::json!({"time_diff_seconds": time_diff}),
                                    source: EvidenceSource::Scanner,
                                    confidence: 0.4,
                                    related_findings: vec![sorted_findings[i].id, sorted_findings[j].id],
                                    timestamp: chrono::Utc::now(),
                                },
                            ],
                            risk_impact: RiskImpact {
                                score_delta: 5,
                                level_change: RiskLevelChange::NoChange,
                                explanation: "Temporal proximity suggests possible relationship".to_string(),
                                affected_factors: vec![],
                                confidence: 0.3,
                            },
                            supporting_cwes: Vec::new(),
                            supporting_capecs: Vec::new(),
                            supporting_attack_techniques: Vec::new(),
                            discovered_at: chrono::Utc::now(),
                            metadata: HashMap::new(),
                        };
                        relationships.push(relationship);
                    }
                } else {
                    break; // Findings are sorted, so further ones will be even further in time
                }
            }
        }

        Ok(relationships)
    }

    /// Correlate findings spatially (same endpoint/parameter)
    fn correlate_spatial(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<FindingRelationship>> {
        let mut relationships = Vec::new();

        // Group findings by target and look for shared endpoints/parameters
        let mut target_findings: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            target_findings.entry(&finding.target).or_default().push(finding);
        }

        for (_target, findings) in target_findings {
            // Check for findings with similar evidence locations
            for i in 0..findings.len() {
                for j in (i + 1)..findings.len() {
                    let loc_i = findings[i].evidence.first().and_then(|e| e.location.as_ref());
                    let loc_j = findings[j].evidence.first().and_then(|e| e.location.as_ref());

                    if let (Some(loc_i), Some(loc_j)) = (loc_i, loc_j) {
                        if loc_i == loc_j {
                            let relationship = FindingRelationship {
                                id: RelationshipId::new(),
                                source_finding: findings[i].id,
                                target_finding: findings[j].id,
                                relationship_type: FindingRelationshipType::SharedAttackSurface,
                                confidence: 0.7,
                                explanation: format!(
                                    "Findings share the same attack surface location: {}",
                                    loc_i
                                ),
                                evidence: vec![RelationshipEvidence {
                                    evidence_type: EvidenceType::HttpInteraction,
                                    description: format!("Shared location: {}", loc_i),
                                    data: serde_json::json!({"location": loc_i}),
                                    source: EvidenceSource::Scanner,
                                    confidence: 0.7,
                                    related_findings: vec![findings[i].id, findings[j].id],
                                    timestamp: chrono::Utc::now(),
                                }],
                                risk_impact: RiskImpact {
                                    score_delta: 10,
                                    level_change: RiskLevelChange::SlightIncrease,
                                    explanation: "Shared attack surface increases combined risk"
                                        .to_string(),
                                    affected_factors: vec![RiskFactor::AttackComplexity],
                                    confidence: 0.6,
                                },
                                supporting_cwes: Vec::new(),
                                supporting_capecs: Vec::new(),
                                supporting_attack_techniques: Vec::new(),
                                discovered_at: chrono::Utc::now(),
                                metadata: HashMap::new(),
                            };
                            relationships.push(relationship);
                        }
                    }
                }
            }
        }

        Ok(relationships)
    }

    /// Limit the number of correlations per finding to prevent explosion
    fn limit_correlations_per_finding(
        &self,
        relationships: &mut Vec<FindingRelationship>,
    ) -> IntelligenceResult<()> {
        if self.config.max_correlations_per_finding == 0 {
            return Ok(());
        }

        // Count correlations per finding
        let mut correlation_count: HashMap<FindingId, usize> = HashMap::new();
        for relationship in relationships.iter() {
            *correlation_count.entry(relationship.source_finding).or_insert(0) += 1;
            *correlation_count.entry(relationship.target_finding).or_insert(0) += 1;
        }

        // If any finding exceeds the limit, we need to filter
        let mut filtered_relationships = Vec::new();
        let mut finding_usage: HashMap<FindingId, usize> = HashMap::new();

        for relationship in relationships.iter() {
            let mut can_add = true;
            for finding_id in [relationship.source_finding, relationship.target_finding] {
                if let Some(count) = finding_usage.get(&finding_id) {
                    if *count >= self.config.max_correlations_per_finding {
                        can_add = false;
                        break;
                    }
                }
            }

            if can_add {
                filtered_relationships.push(relationship.clone());
                *finding_usage.entry(relationship.source_finding).or_insert(0) += 1;
                *finding_usage.entry(relationship.target_finding).or_insert(0) += 1;
            }
        }

        *relationships = filtered_relationships;
        Ok(())
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use uuid::Uuid;

    fn create_test_finding(
        title: &str,
        category: Category,
        target: &str,
        risk_score: Option<u8>,
        cwe_ids: Vec<String>,
        capec_ids: Vec<String>,
    ) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity: Severity::Medium,
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
            cwe_ids,
            capec_ids,
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some(Uuid::new_v4().to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[tokio::test]
    async fn test_csp_xss_correlation() {
        let engine = CorrelationEngine::new();

        let csp_finding = create_test_finding(
            "Missing Content-Security-Policy header",
            Category::SecurityMisconfiguration,
            "https://example.com",
            Some(30),
            vec![],
            vec![],
        );

        let xss_finding = create_test_finding(
            "Reflected XSS in search parameter",
            Category::Xss,
            "https://example.com",
            Some(70),
            vec![],
            vec![],
        );

        let findings = vec![csp_finding.clone(), xss_finding.clone()];
        let relationships = engine.correlate_findings(&findings).await.unwrap();

        assert_eq!(relationships.len(), 1);
        let relationship = &relationships[0];
        assert_eq!(relationship.relationship_type, FindingRelationshipType::Enables);
        let finding_ids = vec![relationship.source_finding, relationship.target_finding];
        assert_eq!(finding_ids.len(), 2);
        assert!(finding_ids.contains(&csp_finding.id));
        assert!(finding_ids.contains(&xss_finding.id));
        assert_eq!(relationship.risk_impact.level_change, RiskLevelChange::ModerateIncrease);
    }

    #[tokio::test]
    async fn test_directory_git_correlation() {
        let engine = CorrelationEngine::new();

        let dir_finding = create_test_finding(
            "Directory listing enabled",
            Category::Configuration,
            "https://example.com",
            Some(40),
            vec![],
            vec![],
        );

        let git_finding = create_test_finding(
            "Exposed .git directory",
            Category::InformationDisclosure,
            "https://example.com",
            Some(75),
            vec![],
            vec![],
        );

        let findings = vec![dir_finding.clone(), git_finding.clone()];
        let relationships = engine.correlate_findings(&findings).await.unwrap();

        assert_eq!(relationships.len(), 1);
        let relationship = &relationships[0];
        assert_eq!(relationship.relationship_type, FindingRelationshipType::ChainedExploit);
        let finding_ids = vec![relationship.source_finding, relationship.target_finding];
        assert_eq!(finding_ids.len(), 2);
        assert!(finding_ids.contains(&dir_finding.id));
        assert!(finding_ids.contains(&git_finding.id));
        assert_eq!(relationship.risk_impact.level_change, RiskLevelChange::SignificantIncrease);
    }

    #[tokio::test]
    async fn test_strengthening_correlation() {
        let engine = CorrelationEngine::new();

        let finding1 = create_test_finding(
            "SQL Injection in login form",
            Category::Injection,
            "https://example.com",
            Some(80),
            vec![],
            vec![],
        );

        let finding2 = create_test_finding(
            "SQL Injection in search parameter",
            Category::Injection,
            "https://example.com",
            Some(75),
            vec![],
            vec![],
        );

        let findings = vec![finding1.clone(), finding2.clone()];
        let relationships = engine.correlate_findings(&findings).await.unwrap();

        assert_eq!(relationships.len(), 1);
        let relationship = &relationships[0];
        assert_eq!(relationship.relationship_type, FindingRelationshipType::Amplifies);
        let finding_ids = vec![relationship.source_finding, relationship.target_finding];
        assert_eq!(finding_ids.len(), 2);
        assert!(finding_ids.contains(&finding1.id));
        assert!(finding_ids.contains(&finding2.id));
    }

    #[tokio::test]
    async fn test_cwe_capec_correlation() {
        let engine = CorrelationEngine::new();

        let finding1 = create_test_finding(
            "XSS in search",
            Category::Xss,
            "https://example.com",
            Some(70),
            vec!["CWE-79".to_string()],
            vec!["CAPEC-86".to_string()],
        );

        let finding2 = create_test_finding(
            "Missing CSP",
            Category::SecurityMisconfiguration,
            "https://example.com",
            Some(30),
            vec!["CWE-693".to_string()],
            vec![],
        );

        let findings = vec![finding1.clone(), finding2.clone()];
        let relationships = engine.correlate_findings(&findings).await.unwrap();

        // Should find relationships based on CWE rules
        let cwe_relationships: Vec<_> =
            relationships.iter().filter(|r| !r.supporting_cwes.is_empty()).collect();
        assert!(!cwe_relationships.is_empty());
    }

    #[tokio::test]
    async fn test_correlation_graph() {
        let engine = CorrelationEngine::new();

        let finding1 = create_test_finding(
            "XSS in search",
            Category::Xss,
            "https://example.com",
            Some(70),
            vec!["CWE-79".to_string()],
            vec![],
        );

        let finding2 = create_test_finding(
            "Missing CSP",
            Category::SecurityMisconfiguration,
            "https://example.com",
            Some(30),
            vec!["CWE-693".to_string()],
            vec![],
        );

        let findings = vec![finding1.clone(), finding2.clone()];
        let graph = engine.correlate_findings_graph(&findings).await.unwrap();

        assert_eq!(graph.relationships.len(), 1);
        assert_eq!(graph.finding_ids.len(), 2);
    }
}
