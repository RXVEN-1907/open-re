//! Deduplication and correlation engine for findings

use crate::ids::FindingId;
use crate::result::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Deduplication engine for findings
pub struct DeduplicationEngine {
    /// Configuration
    config: DeduplicationConfig,
}

/// Configuration for deduplication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationConfig {
    /// Enable title-based deduplication
    pub enable_title_dedup: bool,
    /// Enable location-based deduplication
    pub enable_location_dedup: bool,
    /// Enable fingerprint-based deduplication
    pub enable_fingerprint_dedup: bool,
    /// Similarity threshold for fuzzy matching (0.0-1.0)
    pub similarity_threshold: f32,
    /// Maximum number of findings to compare
    pub max_comparisons: usize,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            enable_title_dedup: true,
            enable_location_dedup: true,
            enable_fingerprint_dedup: true,
            similarity_threshold: 0.85,
            max_comparisons: 10000,
        }
    }
}

/// Deduplication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicationResult {
    /// Original findings count
    pub original_count: usize,
    /// Deduplicated findings count
    pub deduplicated_count: usize,
    /// Number of duplicates removed
    pub duplicates_removed: usize,
    /// Duplicate groups found
    pub duplicate_groups: Vec<DuplicateGroup>,
    /// Merged findings
    pub merged_findings: Vec<Finding>,
}

/// Group of duplicate findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateGroup {
    /// Primary finding (kept)
    pub primary: Finding,
    /// Duplicate findings (merged)
    pub duplicates: Vec<Finding>,
    /// Deduplication reason
    pub reason: DeduplicationReason,
    /// Similarity score
    pub similarity: f32,
}

/// Reason for deduplication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeduplicationReason {
    /// Exact fingerprint match
    ExactFingerprint,
    /// Similar title and target
    SimilarTitleTarget,
    /// Same location and category
    SameLocationCategory,
    /// Same vulnerability pattern
    SamePattern,
    /// Cross-plugin correlation
    CrossPluginCorrelation,
}

/// Correlation engine for finding relationships
pub struct CorrelationEngine {
    /// Configuration
    config: CorrelationConfig,
}

/// Configuration for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Enable temporal correlation (findings close in time)
    pub enable_temporal: bool,
    /// Enable spatial correlation (same target/endpoint)
    pub enable_spatial: bool,
    /// Enable causal correlation (one finding leads to another)
    pub enable_causal: bool,
    /// Time window for temporal correlation (seconds)
    pub temporal_window_seconds: i64,
    /// Maximum correlations per finding
    pub max_correlations: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enable_temporal: true,
            enable_spatial: true,
            enable_causal: true,
            temporal_window_seconds: 3600, // 1 hour
            max_correlations: 10,
        }
    }
}

/// Correlation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Correlated finding pairs
    pub correlations: Vec<FindingCorrelation>,
    /// Correlation chains (sequences of related findings)
    pub chains: Vec<CorrelationChain>,
    /// Attack paths discovered
    pub attack_paths: Vec<AttackPath>,
}

/// Correlation between two findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCorrelation {
    /// First finding ID
    pub finding_a: FindingId,
    /// Second finding ID
    pub finding_b: FindingId,
    /// Correlation type
    pub correlation_type: CorrelationType,
    /// Correlation strength (0.0-1.0)
    pub strength: f32,
    /// Description
    pub description: String,
    /// Evidence supporting correlation
    pub evidence: Vec<String>,
}

/// Type of correlation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// Temporal - findings close in time
    Temporal,
    /// Spatial - same target/endpoint
    Spatial,
    /// Causal - one enables another
    Causal,
    /// Same vulnerability class
    SameClass,
    /// Same attacker pattern
    SameAttacker,
    /// Chained exploitation
    ChainedExploitation,
    /// Shared root cause
    SharedRootCause,
}

/// Chain of correlated findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationChain {
    /// Findings in the chain
    pub findings: Vec<FindingId>,
    /// Chain type
    pub chain_type: ChainType,
    /// Overall confidence
    pub confidence: f32,
    /// Description
    pub description: String,
}

/// Type of correlation chain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainType {
    /// Attack chain (exploitation sequence)
    AttackChain,
    /// Reconnaissance chain
    ReconChain,
    /// Privilege escalation chain
    PrivilegeEscalation,
    /// Data exfiltration chain
    DataExfiltration,
    /// Lateral movement chain
    LateralMovement,
}

/// Attack path discovered through correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    /// Steps in the attack path
    pub steps: Vec<AttackStep>,
    /// Overall risk score
    pub risk_score: u8,
    /// Likelihood
    pub likelihood: Likelihood,
    /// Impact
    pub impact: ImpactLevel,
    /// MITRE ATT&CK techniques
    pub mitre_techniques: Vec<String>,
    /// Description
    pub description: String,
}

/// Step in an attack path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    /// Step number
    pub step: usize,
    /// Finding ID
    pub finding_id: FindingId,
    /// Technique
    pub technique: String,
    /// Description
    pub description: String,
    /// Prerequisites
    pub prerequisites: Vec<String>,
    /// Outcome
    pub outcome: String,
}

/// Likelihood assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Likelihood {
    /// Very unlikely
    VeryLow,
    /// Unlikely
    Low,
    /// Possible
    Medium,
    /// Likely
    High,
    /// Very likely
    VeryHigh,
}

impl DeduplicationEngine {
    /// Create a new deduplication engine
    pub fn new(config: DeduplicationConfig) -> Self {
        Self { config }
    }

    /// Deduplicate findings
    pub fn deduplicate(&self, findings: &mut Vec<Finding>) -> DeduplicationResult {
        let original_count = findings.len();
        let mut duplicate_groups = Vec::new();
        let mut merged_findings = Vec::new();
        let mut processed = HashSet::new();

        // Clone findings for iteration to avoid move issues
        let findings_clone = findings.clone();

        // First pass: exact fingerprint matching
        if self.config.enable_fingerprint_dedup {
            let groups = self.deduplicate_by_fingerprint(&findings_clone, &mut processed);
            duplicate_groups.extend(groups);
        }

        // Second pass: title + target similarity
        if self.config.enable_title_dedup {
            let groups = self.deduplicate_by_title_target(&findings_clone, &mut processed);
            duplicate_groups.extend(groups);
        }

        // Third pass: location + category
        if self.config.enable_location_dedup {
            let groups = self.deduplicate_by_location_category(&findings_clone, &mut processed);
            duplicate_groups.extend(groups);
        }

        // Build merged findings list
        for group in &duplicate_groups {
            merged_findings.push(group.primary.clone());
        }

        // Add non-duplicate findings
        for finding in &findings_clone {
            if !processed.contains(&finding.id) {
                merged_findings.push(finding.clone());
            }
        }

        let deduplicated_count = merged_findings.len();
        let duplicates_removed = original_count - deduplicated_count;

        // Replace findings with deduplicated version
        *findings = merged_findings.clone();

        DeduplicationResult {
            original_count,
            deduplicated_count,
            duplicates_removed,
            duplicate_groups,
            merged_findings,
        }
    }

    /// Deduplicate by exact fingerprint match
    fn deduplicate_by_fingerprint(
        &self,
        findings: &[Finding],
        processed: &mut HashSet<FindingId>,
    ) -> Vec<DuplicateGroup> {
        let mut groups = Vec::new();
        let mut fingerprint_map: HashMap<String, Vec<&Finding>> = HashMap::new();

        for finding in findings {
            if processed.contains(&finding.id) {
                continue;
            }
            if let Some(fp) = &finding.fingerprint {
                fingerprint_map.entry(fp.clone()).or_default().push(finding);
            }
        }

        for (_fingerprint, group) in fingerprint_map {
            if group.len() > 1 {
                // Sort by confidence and severity (highest first)
                let mut sorted = group.clone();
                sorted.sort_by(|a, b| {
                    b.confidence.cmp(&a.confidence)
                        .then_with(|| b.severity.cmp(&a.severity))
                });

                let primary = sorted[0].clone();
                let duplicates = sorted[1..].iter().map(|f| (*f).clone()).collect::<Vec<Finding>>();

                for dup in &duplicates {
                    processed.insert(dup.id);
                }
                processed.insert(primary.id);

                groups.push(DuplicateGroup {
                    primary,
                    duplicates,
                    reason: DeduplicationReason::ExactFingerprint,
                    similarity: 1.0,
                });
            }
        }

        groups
    }

    /// Deduplicate by title and target similarity
    fn deduplicate_by_title_target(
        &self,
        findings: &[Finding],
        processed: &mut HashSet<FindingId>,
    ) -> Vec<DuplicateGroup> {
        let mut groups = Vec::new();
        let unprocessed: Vec<&Finding> = findings.iter()
            .filter(|f| !processed.contains(&f.id))
            .collect();

        for i in 0..unprocessed.len().min(self.config.max_comparisons) {
            if processed.contains(&unprocessed[i].id) {
                continue;
            }

            let mut similar = vec![unprocessed[i]];
            for j in (i + 1)..unprocessed.len().min(self.config.max_comparisons) {
                if processed.contains(&unprocessed[j].id) {
                    continue;
                }

                let similarity = self.calculate_title_target_similarity(unprocessed[i], unprocessed[j]);
                if similarity >= self.config.similarity_threshold {
                    similar.push(unprocessed[j]);
                }
            }

            if similar.len() > 1 {
                // Sort by confidence and severity
                similar.sort_by(|a, b| {
                    b.confidence.cmp(&a.confidence)
                        .then_with(|| b.severity.cmp(&a.severity))
                });

                let primary = similar[0].clone();
                let duplicates = similar[1..].iter().map(|f| (*f).clone()).collect::<Vec<Finding>>();

                for dup in &duplicates {
                    processed.insert(dup.id);
                }
                processed.insert(primary.id);

                groups.push(DuplicateGroup {
                    primary,
                    duplicates,
                    reason: DeduplicationReason::SimilarTitleTarget,
                    similarity: self.config.similarity_threshold,
                });
            }
        }

        groups
    }

    /// Deduplicate by location and category
    fn deduplicate_by_location_category(
        &self,
        findings: &[Finding],
        processed: &mut HashSet<FindingId>,
    ) -> Vec<DuplicateGroup> {
        let mut groups = Vec::new();
        let mut location_category_map: HashMap<(String, Category), Vec<&Finding>> = HashMap::new();

        for finding in findings {
            if processed.contains(&finding.id) {
                continue;
            }
            // Get location from first evidence
            let location = finding.evidence.first()
                .and_then(|e| e.location.clone())
                .unwrap_or_else(|| finding.target.clone());
            
            let key = (location, finding.category.clone());
            location_category_map.entry(key).or_default().push(finding);
        }

        for ((_location, _category), group) in location_category_map {
            if group.len() > 1 {
                let mut sorted = group.clone();
                sorted.sort_by(|a, b| {
                    b.confidence.cmp(&a.confidence)
                        .then_with(|| b.severity.cmp(&a.severity))
                });

                let primary = sorted[0].clone();
                let duplicates = sorted[1..].iter().map(|f| (*f).clone()).collect::<Vec<Finding>>();

                for dup in &duplicates {
                    processed.insert(dup.id);
                }
                processed.insert(primary.id);

                groups.push(DuplicateGroup {
                    primary,
                    duplicates,
                    reason: DeduplicationReason::SameLocationCategory,
                    similarity: 0.9,
                });
            }
        }

        groups
    }

    /// Calculate similarity between two findings based on title and target
    fn calculate_title_target_similarity(&self, a: &Finding, b: &Finding) -> f32 {
        // Simple Jaccard similarity on words
        let a_words: HashSet<&str> = a.title.split_whitespace().chain(a.target.split_whitespace()).collect();
        let b_words: HashSet<&str> = b.title.split_whitespace().chain(b.target.split_whitespace()).collect();

        let intersection = a_words.intersection(&b_words).count();
        let union = a_words.union(&b_words).count();

        if union == 0 {
            0.0
        } else {
            intersection as f32 / union as f32
        }
    }
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(config: CorrelationConfig) -> Self {
        Self { config }
    }

    /// Correlate findings
    pub fn correlate(&self, findings: &[Finding]) -> CorrelationResult {
        let mut correlations = Vec::new();
        let mut chains = Vec::new();
        let mut attack_paths = Vec::new();

        // Temporal correlation
        if self.config.enable_temporal {
            correlations.extend(self.correlate_temporal(findings));
        }

        // Spatial correlation
        if self.config.enable_spatial {
            correlations.extend(self.correlate_spatial(findings));
        }

        // Causal correlation
        if self.config.enable_causal {
            correlations.extend(self.correlate_causal(findings));
        }

        // Same class correlation
        correlations.extend(self.correlate_same_class(findings));

        // Build correlation chains
        chains = self.build_chains(findings, &correlations);

        // Discover attack paths
        attack_paths = self.discover_attack_paths(findings, &chains);

        CorrelationResult {
            correlations,
            chains,
            attack_paths,
        }
    }

    /// Correlate findings by temporal proximity
    fn correlate_temporal(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();
        let mut sorted = findings.to_vec();
        sorted.sort_by_key(|a| a.timestamp);

        for i in 0..sorted.len() {
            for j in (i + 1)..sorted.len() {
                let time_diff = (sorted[j].timestamp - sorted[i].timestamp).num_seconds();
                if time_diff > self.config.temporal_window_seconds {
                    break;
                }

                // Only correlate if same target or related
                if sorted[i].target == sorted[j].target || self.are_targets_related(&sorted[i], &sorted[j]) {
                    let strength = 1.0 - (time_diff as f32 / self.config.temporal_window_seconds as f32);
                    correlations.push(FindingCorrelation {
                        finding_a: sorted[i].id,
                        finding_b: sorted[j].id,
                        correlation_type: CorrelationType::Temporal,
                        strength,
                        description: format!("Findings within {} seconds on related targets", time_diff),
                        evidence: vec![
                            format!("Time difference: {}s", time_diff),
                            format!("Target A: {}", sorted[i].target),
                            format!("Target B: {}", sorted[j].target),
                        ],
                    });
                }
            }
        }

        correlations
    }

    /// Correlate findings by spatial proximity (same target/endpoint)
    fn correlate_spatial(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();

        for i in 0..findings.len() {
            for j in (i + 1)..findings.len() {
                // Correlate if same exact target or related targets (same domain)
                if findings[i].target == findings[j].target || self.are_targets_related(&findings[i], &findings[j]) {
                    correlations.push(FindingCorrelation {
                        finding_a: findings[i].id,
                        finding_b: findings[j].id,
                        correlation_type: CorrelationType::Spatial,
                        strength: 0.8,
                        description: format!("Multiple findings on related targets: {} and {}", findings[i].target, findings[j].target),
                        evidence: vec![
                            format!("Target A: {}", findings[i].target),
                            format!("Category A: {}", findings[i].category),
                            format!("Target B: {}", findings[j].target),
                            format!("Category B: {}", findings[j].category),
                        ],
                    });
                }
            }
        }

        correlations
    }

    /// Correlate findings by causal relationship
    fn correlate_causal(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();

        // Define causal patterns
        let causal_patterns = vec![
            // Recon -> Vulnerability
            (Category::InformationDisclosure, Category::Injection, "Reconnaissance may lead to injection discovery"),
            (Category::InformationDisclosure, Category::BrokenAccessControl, "Information disclosure may reveal access control issues"),
            (Category::SecurityMisconfiguration, Category::BrokenAccessControl, "Misconfiguration may cause access control bypass"),
            (Category::BrokenAuthentication, Category::BrokenAccessControl, "Broken auth may lead to access control bypass"),
            (Category::Injection, Category::SensitiveDataExposure, "Injection may lead to data exposure"),
            (Category::Xss, Category::BrokenAuthentication, "XSS may lead to session hijacking"),
            (Category::Ssrf, Category::SensitiveDataExposure, "SSRF may lead to internal data exposure"),
        ];

        for (cause_cat, effect_cat, description) in causal_patterns {
            let causes: Vec<&Finding> = findings.iter().filter(|f| f.category == cause_cat).collect();
            let effects: Vec<&Finding> = findings.iter().filter(|f| f.category == effect_cat).collect();

            for cause in &causes {
                for effect in &effects {
                    // Check if they're on same or related targets
                    if cause.target == effect.target || self.are_targets_related(cause, effect) {
                        // Check temporal order (cause before effect)
                        if cause.timestamp <= effect.timestamp {
                            correlations.push(FindingCorrelation {
                                finding_a: cause.id,
                                finding_b: effect.id,
                                correlation_type: CorrelationType::Causal,
                                strength: 0.7,
                                description: description.to_string(),
                                evidence: vec![
                                    format!("Cause: {} on {}", cause.category, cause.target),
                                    format!("Effect: {} on {}", effect.category, effect.target),
                                    format!("Time diff: {}s", (effect.timestamp - cause.timestamp).num_seconds()),
                                ],
                            });
                        }
                    }
                }
            }
        }

        correlations
    }

    /// Correlate findings by same vulnerability class
    fn correlate_same_class(&self, findings: &[Finding]) -> Vec<FindingCorrelation> {
        let mut correlations = Vec::new();
        let mut category_map: HashMap<Category, Vec<&Finding>> = HashMap::new();

        for finding in findings {
            category_map.entry(finding.category.clone()).or_default().push(finding);
        }

        for (_category, group) in category_map {
            if group.len() > 1 {
                for i in 0..group.len() {
                    for j in (i + 1)..group.len() {
                        correlations.push(FindingCorrelation {
                            finding_a: group[i].id,
                            finding_b: group[j].id,
                            correlation_type: CorrelationType::SameClass,
                            strength: 0.6,
                            description: format!("Multiple findings of same category: {}", group[i].category),
                            evidence: vec![
                                format!("Category: {}", group[i].category),
                                format!("Target A: {}", group[i].target),
                                format!("Target B: {}", group[j].target),
                                format!("Plugin A: {}", group[i].plugin_source),
                                format!("Plugin B: {}", group[j].plugin_source),
                            ],
                        });
                    }
                }
            }
        }

        correlations
    }

    /// Check if two targets are related
    fn are_targets_related(&self, a: &Finding, b: &Finding) -> bool {
        // Same base domain
        if let (Ok(url_a), Ok(url_b)) = (url::Url::parse(&a.target), url::Url::parse(&b.target)) {
            if url_a.host_str() == url_b.host_str() {
                return true;
            }
        }
        // Same target string prefix
        a.target.starts_with(&b.target) || b.target.starts_with(&a.target)
    }

    /// Build correlation chains
    fn build_chains(&self, findings: &[Finding], correlations: &[FindingCorrelation]) -> Vec<CorrelationChain> {
        let mut chains = Vec::new();
        let mut visited = HashSet::new();

        // Build adjacency list
        let mut adj: HashMap<FindingId, Vec<(FindingId, CorrelationType)>> = HashMap::new();
        for corr in correlations {
            adj.entry(corr.finding_a).or_default().push((corr.finding_b, corr.correlation_type));
            adj.entry(corr.finding_b).or_default().push((corr.finding_a, corr.correlation_type));
        }

        // Find chains using DFS
        for finding in findings {
            if visited.contains(&finding.id) {
                continue;
            }

            let mut chain = Vec::new();
            self.dfs_chain(finding.id, &adj, &mut visited, &mut chain);

            if chain.len() > 1 {
                let chain_type = self.classify_chain(&chain, findings);
                let confidence = self.calculate_chain_confidence(&chain, correlations);
                
                chains.push(CorrelationChain {
                    findings: chain.clone(),
                    chain_type,
                    confidence,
                    description: self.describe_chain(&chain, findings),
                });
            }
        }

        chains
    }

    /// DFS to find correlation chain
    fn dfs_chain(
        &self,
        start: FindingId,
        adj: &HashMap<FindingId, Vec<(FindingId, CorrelationType)>>,
        visited: &mut HashSet<FindingId>,
        chain: &mut Vec<FindingId>,
    ) {
        visited.insert(start);
        chain.push(start);

        if let Some(neighbors) = adj.get(&start) {
            for (neighbor, _corr_type) in neighbors {
                if !visited.contains(neighbor) && chain.len() < self.config.max_correlations {
                    self.dfs_chain(*neighbor, adj, visited, chain);
                }
            }
        }
    }

    /// Classify chain type
    fn classify_chain(&self, chain: &[FindingId], findings: &[Finding]) -> ChainType {
        let categories: Vec<Category> = chain.iter()
            .filter_map(|id| findings.iter().find(|f| f.id == *id).map(|f| f.category.clone()))
            .collect();

        // Check for attack chain patterns
        if categories.windows(2).any(|w| {
            matches!((&w[0], &w[1]),
                (Category::InformationDisclosure, Category::Injection) |
                (Category::InformationDisclosure, Category::BrokenAccessControl) |
                (Category::BrokenAuthentication, Category::BrokenAccessControl) |
                (Category::Injection, Category::SensitiveDataExposure) |
                (Category::Xss, Category::BrokenAuthentication) |
                (Category::Ssrf, Category::SensitiveDataExposure)
            )
        }) {
            return ChainType::AttackChain;
        }

        // Check for privilege escalation
        if categories.iter().any(|c| matches!(c, Category::BrokenAuthentication | Category::BrokenAccessControl)) {
            return ChainType::PrivilegeEscalation;
        }

        // Check for data exfiltration
        if categories.iter().any(|c| matches!(c, Category::SensitiveDataExposure | Category::InformationDisclosure)) {
            return ChainType::DataExfiltration;
        }

        // Check for lateral movement
        if categories.iter().any(|c| matches!(c, Category::Ssrf | Category::BrokenAccessControl)) {
            return ChainType::LateralMovement;
        }

        ChainType::ReconChain
    }

    /// Calculate chain confidence
    fn calculate_chain_confidence(&self, chain: &[FindingId], correlations: &[FindingCorrelation]) -> f32 {
        let mut total_strength = 0.0;
        let mut count = 0;

        for window in chain.windows(2) {
            if let Some(corr) = correlations.iter().find(|c| 
                (c.finding_a == window[0] && c.finding_b == window[1]) ||
                (c.finding_a == window[1] && c.finding_b == window[0])
            ) {
                total_strength += corr.strength;
                count += 1;
            }
        }

        if count == 0 { 0.5 } else { total_strength / count as f32 }
    }

    /// Describe chain
    fn describe_chain(&self, chain: &[FindingId], findings: &[Finding]) -> String {
        let steps: Vec<String> = chain.iter()
            .filter_map(|id| findings.iter().find(|f| f.id == *id))
            .map(|f| format!("{} ({})", f.title, f.category))
            .collect();
        steps.join(" -> ")
    }

    /// Discover attack paths
    fn discover_attack_paths(&self, findings: &[Finding], chains: &[CorrelationChain]) -> Vec<AttackPath> {
        let mut attack_paths = Vec::new();

        for chain in chains {
            if matches!(chain.chain_type, ChainType::AttackChain | ChainType::PrivilegeEscalation | ChainType::DataExfiltration) {
                let steps = self.build_attack_steps(&chain.findings, findings);
                let risk_score = self.calculate_attack_path_risk(&steps, findings);
                let (likelihood, impact) = self.assess_attack_path(&steps, findings);
                let mitre_techniques = self.extract_mitre_techniques(&steps, findings);

                attack_paths.push(AttackPath {
                    steps,
                    risk_score,
                    likelihood,
                    impact,
                    mitre_techniques,
                    description: chain.description.clone(),
                });
            }
        }

        attack_paths
    }

    /// Build attack steps from chain
    fn build_attack_steps(&self, chain: &[FindingId], findings: &[Finding]) -> Vec<AttackStep> {
        chain.iter().enumerate().filter_map(|(idx, id)| {
            findings.iter().find(|f| f.id == *id).map(|f| AttackStep {
                step: idx + 1,
                finding_id: *id,
                technique: f.category.to_string(),
                description: f.description.clone(),
                prerequisites: self.get_prerequisites(f, findings),
                outcome: self.get_outcome(f),
            })
        }).collect()
    }

    /// Get prerequisites for a finding
    fn get_prerequisites(&self, finding: &Finding, all_findings: &[Finding]) -> Vec<String> {
        let mut prereqs = Vec::new();
        
        // Add related findings as prerequisites
        for related_id in &finding.related_findings {
            if let Some(related) = all_findings.iter().find(|f| f.id == *related_id) {
                prereqs.push(format!("{} ({})", related.title, related.category));
            }
        }

        // Add category-specific prerequisites
        match finding.category {
            Category::Injection => prereqs.push("Input validation bypass".to_string()),
            Category::BrokenAuthentication => prereqs.push("Authentication mechanism access".to_string()),
            Category::BrokenAccessControl => prereqs.push("Authenticated session".to_string()),
            Category::Ssrf => prereqs.push("Internal network access".to_string()),
            _ => {}
        }

        prereqs
    }

    /// Get outcome for a finding
    fn get_outcome(&self, finding: &Finding) -> String {
        match finding.category {
            Category::Injection => "Arbitrary code/data execution".to_string(),
            Category::BrokenAuthentication => "Authentication bypass".to_string(),
            Category::BrokenAccessControl => "Unauthorized access".to_string(),
            Category::SensitiveDataExposure => "Data leakage".to_string(),
            Category::Xss => "Client-side code execution".to_string(),
            Category::Ssrf => "Internal service access".to_string(),
            Category::InformationDisclosure => "Information leakage".to_string(),
            _ => "Security impact".to_string(),
        }
    }

    /// Calculate attack path risk
    fn calculate_attack_path_risk(&self, steps: &[AttackStep], findings: &[Finding]) -> u8 {
        let mut max_score = 0u8;
        for step in steps {
            if let Some(finding) = findings.iter().find(|f| f.id == step.finding_id) {
                let score = finding.calculate_advanced_risk_score();
                max_score = max_score.max(score);
            }
        }
        // Boost for chained attacks
        (max_score as f32 * 1.2).min(100.0) as u8
    }

    /// Assess attack path likelihood and impact
    fn assess_attack_path(&self, steps: &[AttackStep], findings: &[Finding]) -> (Likelihood, ImpactLevel) {
        let mut max_exploitability: f32 = 0.0;
        let mut max_impact = ImpactLevel::None;

        for step in steps {
            if let Some(finding) = findings.iter().find(|f| f.id == step.finding_id) {
                if let Some(exploitability) = &finding.exploitability {
                    max_exploitability = max_exploitability.max(exploitability.score);
                }
                if let Some(impact) = &finding.business_impact {
                    max_impact = max_impact.max(impact.confidentiality);
                    max_impact = max_impact.max(impact.integrity);
                    max_impact = max_impact.max(impact.availability);
                }
            }
        }

        let likelihood = match max_exploitability {
            x if x >= 8.0 => Likelihood::VeryHigh,
            x if x >= 6.0 => Likelihood::High,
            x if x >= 4.0 => Likelihood::Medium,
            x if x >= 2.0 => Likelihood::Low,
            _ => Likelihood::VeryLow,
        };

        (likelihood, max_impact)
    }

    /// Extract MITRE ATT&CK techniques from attack path
    fn extract_mitre_techniques(&self, steps: &[AttackStep], findings: &[Finding]) -> Vec<String> {
        let mut techniques = Vec::new();
        for step in steps {
            if let Some(finding) = findings.iter().find(|f| f.id == step.finding_id) {
                techniques.extend(finding.mitre_attack_ids.clone());
            }
        }
        techniques.sort();
        techniques.dedup();
        techniques
    }
}

impl Default for DeduplicationEngine {
    fn default() -> Self {
        Self::new(DeduplicationConfig::default())
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::ScanId;
    use chrono::Utc;

    fn create_test_finding(title: &str, target: &str, category: Category, severity: Severity, confidence: Confidence) -> Finding {
        let scan_id = ScanId::new();
        Finding::new(FindingConfig {
            title: title.to_string(),
            description: "Test description".to_string(),
            severity,
            confidence,
            category,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "test-plugin".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id,
        })
    }

    #[test]
    fn test_deduplication_exact_fingerprint() {
        let mut engine = DeduplicationEngine::default();
        let mut findings = vec![
            create_test_finding("SQL Injection", "http://example.com", Category::Injection, Severity::High, Confidence::High),
            create_test_finding("SQL Injection", "http://example.com", Category::Injection, Severity::Medium, Confidence::Medium),
        ];

        // Set same fingerprint
        let fp = "abc123".to_string();
        findings[0].fingerprint = Some(fp.clone());
        findings[1].fingerprint = Some(fp);

        let result = engine.deduplicate(&mut findings);
        assert_eq!(result.duplicates_removed, 1);
        assert_eq!(result.deduplicated_count, 1);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_deduplication_similar_title() {
        let mut engine = DeduplicationEngine::new(DeduplicationConfig {
            similarity_threshold: 0.7,
            ..Default::default()
        });
        let mut findings = vec![
            create_test_finding("SQL Injection in login", "http://example.com/login", Category::Injection, Severity::High, Confidence::High),
            create_test_finding("SQL Injection in login form", "http://example.com/login", Category::Injection, Severity::Medium, Confidence::Medium),
        ];

        let result = engine.deduplicate(&mut findings);
        assert_eq!(result.duplicates_removed, 1);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_correlation_temporal() {
        let engine = CorrelationEngine::default();
        let mut findings = vec![
            create_test_finding("Info Disclosure", "http://example.com", Category::InformationDisclosure, Severity::Low, Confidence::High),
            create_test_finding("SQL Injection", "http://example.com", Category::Injection, Severity::High, Confidence::High),
        ];

        // Set timestamps close together
        findings[0].timestamp = Utc::now();
        findings[1].timestamp = Utc::now() + chrono::Duration::seconds(30);

        let result = engine.correlate(&findings);
        assert!(!result.correlations.is_empty());
        assert!(result.correlations.iter().any(|c| c.correlation_type == CorrelationType::Temporal));
    }

    #[test]
    fn test_correlation_spatial() {
        let engine = CorrelationEngine::default();
        let findings = vec![
            create_test_finding("XSS", "http://example.com/page1", Category::Xss, Severity::Medium, Confidence::High),
            create_test_finding("SQL Injection", "http://example.com/page2", Category::Injection, Severity::High, Confidence::High),
        ];

        let result = engine.correlate(&findings);
        assert!(result.correlations.iter().any(|c| c.correlation_type == CorrelationType::Spatial));
    }

    #[test]
    fn test_correlation_causal() {
        let engine = CorrelationEngine::default();
        let mut findings = vec![
            create_test_finding("Info Disclosure", "http://example.com", Category::InformationDisclosure, Severity::Low, Confidence::High),
            create_test_finding("SQL Injection", "http://example.com", Category::Injection, Severity::High, Confidence::High),
        ];

        findings[0].timestamp = Utc::now();
        findings[1].timestamp = Utc::now() + chrono::Duration::seconds(60);

        let result = engine.correlate(&findings);
        assert!(result.correlations.iter().any(|c| c.correlation_type == CorrelationType::Causal));
    }
}