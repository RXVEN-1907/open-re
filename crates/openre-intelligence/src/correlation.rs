//! Enhanced finding correlation engine

use crate::{types::*, error::IntelligenceError, IntelligenceResult};
use openre_core::result::{Finding, Category, Severity};
use openre_core::ids::FindingId;
use std::collections::HashMap;
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

    /// Minimum confidence threshold for correlations (0.0-1.0)
    pub min_confidence_threshold: f32,

    /// Maximum correlations per finding
    pub max_correlations_per_finding: usize,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enable_csp_xss: true,
            enable_directory_git: true,
            enable_strengthening_weakening: true,
            enable_root_cause: true,
            min_confidence_threshold: 0.3,
            max_correlations_per_finding: 10,
        }
    }
}

/// Enhanced correlation engine for finding relationships
pub struct CorrelationEngine {
    config: CorrelationConfig,
}

impl CorrelationEngine {
    /// Create a new correlation engine with default configuration
    pub fn new() -> Self {
        Self {
            config: CorrelationConfig::default(),
        }
    }

    /// Create a new correlation engine with custom configuration
    pub fn with_config(config: CorrelationConfig) -> Self {
        Self { config }
    }

    /// Correlate findings to identify relationships and enhance risk confidence
    pub fn correlate_findings(&self, findings: &[Finding]) -> IntelligenceResult<Vec<EnhancedCorrelation>> {
        let mut correlations = Vec::new();

        // Apply different correlation strategies based on configuration
        if self.config.enable_csp_xss {
            correlations.extend(self.correlate_csp_xss(findings)?);
        }

        if self.config.enable_directory_git {
            correlations.extend(self.correlate_directory_git(findings)?);
        }

        if self.config.enable_strengthening_weakening {
            correlations.extend(self.correlate_strengthening_weakening(findings)?);
        }

        // Filter by minimum confidence threshold
        correlations.retain(|c| c.confidence >= self.config.min_confidence_threshold);

        // Limit correlations per finding to prevent explosion
        self.limit_correlations_per_finding(&mut correlations)?;

        Ok(correlations)
    }

    /// Correlate missing CSP with reflected XSS findings
    fn correlate_csp_xss(&self, findings: &[Finding]) -> IntelligenceResult<Vec<EnhancedCorrelation>> {
        let mut correlations = Vec::new();

        // Find CSP missing findings
        let csp_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::SecurityMisconfiguration
                && f.title.to_lowercase().contains("csp")
                && f.title.to_lowercase().contains("missing"))
            .collect();

        // Find reflected XSS findings
        let xss_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::Xss
                && f.title.to_lowercase().contains("reflected"))
            .collect();

        // Create correlations between CSP and XSS findings on the same target
        for csp_finding in &csp_findings {
            for xss_finding in &xss_findings {
                if csp_finding.target == xss_finding.target {
                    let correlation = EnhancedCorrelation {
                        finding_ids: vec![csp_finding.id, xss_finding.id],
                        correlation_type: CorrelationType::CspXssChain,
                        confidence: 0.85, // High confidence
                        description: "Missing Content Security Policy (CSP) increases the risk and exploitability of reflected XSS vulnerabilities on the same target.".to_string(),
                        evidence: vec![
                            format!("Finding '{}' indicates missing CSP policy", csp_finding.title),
                            format!("Finding '{}' indicates reflected XSS vulnerability", xss_finding.title),
                            "CSP headers provide an additional layer of protection against XSS attacks".to_string(),
                        ],
                        combined_risk: RiskAssessment {
                            individual_scores: vec![
                                csp_finding.risk_score.unwrap_or(30),
                                xss_finding.risk_score.unwrap_or(70),
                            ],
                            combined_score: 85, // Higher than individual scores
                            explanation: "The combination of missing CSP and reflected XSS creates a higher risk profile as there's no secondary protection against XSS exploitation.".to_string(),
                        },
                        mitigation_approach: "Implement a comprehensive Content Security Policy (CSP) header to provide defense-in-depth against XSS attacks, in addition to fixing the underlying XSS vulnerability.".to_string(),
                    };
                    correlations.push(correlation);
                }
            }
        }

        Ok(correlations)
    }

    /// Correlate directory listing with Git metadata exposure
    fn correlate_directory_git(&self, findings: &[Finding]) -> IntelligenceResult<Vec<EnhancedCorrelation>> {
        let mut correlations = Vec::new();

        // Find directory listing findings
        let dir_findings: Vec<&Finding> = findings.iter()
            .filter(|f| (f.category == Category::InformationDisclosure
                && f.title.to_lowercase().contains("directory"))
                || (f.category == Category::Configuration
                && f.title.to_lowercase().contains("listing")))
            .collect();

        // Find Git metadata exposure findings
        let git_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::InformationDisclosure
                && (f.title.to_lowercase().contains("git")
                || f.description.to_lowercase().contains(".git")))
            .collect();

        // Create correlations between directory listing and Git metadata on the same target
        for dir_finding in &dir_findings {
            for git_finding in &git_findings {
                if dir_finding.target == git_finding.target {
                    let correlation = EnhancedCorrelation {
                        finding_ids: vec![dir_finding.id, git_finding.id],
                        correlation_type: CorrelationType::InfoDisclosureChain,
                        confidence: 0.9, // Very high confidence
                        description: "Directory listing combined with exposed Git metadata forms a critical information disclosure chain that can lead to source code exposure.".to_string(),
                        evidence: vec![
                            format!("Finding '{}' indicates directory listing is enabled", dir_finding.title),
                            format!("Finding '{}' indicates Git metadata exposure", git_finding.title),
                            "Together these findings enable attackers to reconstruct source code and understand application structure".to_string(),
                        ],
                        combined_risk: RiskAssessment {
                            individual_scores: vec![
                                dir_finding.risk_score.unwrap_or(40),
                                git_finding.risk_score.unwrap_or(75),
                            ],
                            combined_score: 90, // Much higher than individual scores
                            explanation: "The combination creates an information disclosure chain that significantly increases the risk of source code exposure and application understanding.".to_string(),
                        },
                        mitigation_approach: "Disable directory listing and ensure Git metadata (.git directories) are not accessible. Implement proper access controls and web server configuration to prevent information disclosure.".to_string(),
                    };
                    correlations.push(correlation);
                }
            }
        }

        Ok(correlations)
    }

    /// Correlate findings that strengthen or weaken each other
    fn correlate_strengthening_weakening(&self, findings: &[Finding]) -> IntelligenceResult<Vec<EnhancedCorrelation>> {
        let mut correlations = Vec::new();

        // Group findings by target for more efficient correlation
        let mut findings_by_target: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            findings_by_target.entry(&finding.target).or_default().push(finding);
        }

        // For each target, look for strengthening/weakening patterns
        for (target, target_findings) in findings_by_target {
            // Look for multiple findings of the same category that might strengthen each other
            let mut category_count: HashMap<Category, Vec<&Finding>> = HashMap::new();
            for finding in &target_findings {
                category_count.entry(finding.category).or_default().push(finding);
            }

            // Create strengthening correlations for categories with multiple findings
            for (category, category_findings) in category_count {
                if category_findings.len() > 1 {
                    let finding_ids: Vec<FindingId> = category_findings.iter().map(|f| f.id).collect();

                    // Calculate average confidence based on number of findings
                    let confidence = (0.5 + (category_findings.len() as f32 * 0.1)).min(0.9);

                    let correlation = EnhancedCorrelation {
                        finding_ids,
                        correlation_type: CorrelationType::Strengthening,
                        confidence,
                        description: format!("Multiple {} findings on the same target strengthen each other, indicating a systemic issue.",
                            match category {
                                Category::Injection => "injection",
                                Category::Xss => "XSS",
                                Category::BrokenAuthentication => "authentication",
                                Category::SensitiveDataExposure => "data exposure",
                                Category::SecurityMisconfiguration => "misconfiguration",
                                _ => "security",
                            }),
                        evidence: category_findings.iter().map(|f|
                            format!("Finding '{}' (ID: {}) indicates a {} issue", f.title, f.id,
                                match category {
                                    Category::Injection => "injection",
                                    Category::Xss => "XSS",
                                    Category::BrokenAuthentication => "authentication",
                                    Category::SensitiveDataExposure => "data exposure",
                                    Category::SecurityMisconfiguration => "misconfiguration",
                                    _ => "security",
                                })
                        ).collect(),
                        combined_risk: RiskAssessment {
                            individual_scores: category_findings.iter()
                                .map(|f| f.risk_score.unwrap_or(50))
                                .collect(),
                            combined_score: (category_findings.iter()
                                .map(|f| f.risk_score.unwrap_or(50) as u32)
                                .sum::<u32>() / category_findings.len() as u32 + 20).min(100) as u8,
                            explanation: format!("Multiple {} findings on target '{}' indicate a systemic issue rather than isolated vulnerabilities.",
                                match category {
                                    Category::Injection => "injection",
                                    Category::Xss => "XSS",
                                    Category::BrokenAuthentication => "authentication",
                                    Category::SensitiveDataExposure => "data exposure",
                                    Category::SecurityMisconfiguration => "misconfiguration",
                                    _ => "security",
                                }, target),
                        },
                        mitigation_approach: format!("Address the underlying root cause of multiple {} issues on target '{}' through systematic code review and security hardening.",
                            match category {
                                Category::Injection => "injection",
                                Category::Xss => "XSS",
                                Category::BrokenAuthentication => "authentication",
                                Category::SensitiveDataExposure => "data exposure",
                                Category::SecurityMisconfiguration => "misconfiguration",
                                _ => "security",
                            }, target),
                    };
                    correlations.push(correlation);
                }
            }
        }

        Ok(correlations)
    }

    /// Limit the number of correlations per finding to prevent explosion
    fn limit_correlations_per_finding(&self, correlations: &mut Vec<EnhancedCorrelation>) -> IntelligenceResult<()> {
        if self.config.max_correlations_per_finding == 0 {
            return Ok(());
        }

        // Count correlations per finding
        let mut correlation_count: HashMap<FindingId, usize> = HashMap::new();
        for correlation in correlations.iter() {
            for finding_id in &correlation.finding_ids {
                *correlation_count.entry(*finding_id).or_insert(0) += 1;
            }
        }

        // If any finding exceeds the limit, we need to filter
        let mut filtered_correlations = Vec::new();
        let mut finding_usage: HashMap<FindingId, usize> = HashMap::new();

        for correlation in correlations.iter() {
            let mut can_add = true;
            for finding_id in &correlation.finding_ids {
                if let Some(count) = finding_usage.get(finding_id) {
                    if *count >= self.config.max_correlations_per_finding {
                        can_add = false;
                        break;
                    }
                }
            }

            if can_add {
                filtered_correlations.push(correlation.clone());
                for finding_id in &correlation.finding_ids {
                    *finding_usage.entry(*finding_id).or_insert(0) += 1;
                }
            }
        }

        *correlations = filtered_correlations;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openre_core::result::{Finding, Category, Severity, Confidence};
    use openre_core::ids::{FindingId, ScanId};
    use chrono::Utc;
    use uuid::Uuid;

    fn create_test_finding(title: &str, category: Category, target: &str, risk_score: Option<u8>) -> Finding {
        Finding {
            id: FindingId::new_v4(),
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
            scan_id: ScanId::new_v4(),
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
    fn test_csp_xss_correlation() {
        let engine = CorrelationEngine::new();

        let csp_finding = create_test_finding(
            "Missing Content-Security-Policy header",
            Category::SecurityMisconfiguration,
            "https://example.com",
            Some(30)
        );

        let xss_finding = create_test_finding(
            "Reflected XSS in search parameter",
            Category::Xss,
            "https://example.com",
            Some(70)
        );

        let findings = vec![csp_finding.clone(), xss_finding.clone()];
        let correlations = engine.correlate_findings(&findings).unwrap();

        assert_eq!(correlations.len(), 1);
        let correlation = &correlations[0];
        assert_eq!(correlation.correlation_type, CorrelationType::CspXssChain);
        assert_eq!(correlation.finding_ids.len(), 2);
        assert!(correlation.finding_ids.contains(&csp_finding.id));
        assert!(correlation.finding_ids.contains(&xss_finding.id));
        assert_eq!(correlation.combined_risk.combined_score, 85);
    }

    #[test]
    fn test_directory_git_correlation() {
        let engine = CorrelationEngine::new();

        let dir_finding = create_test_finding(
            "Directory listing enabled",
            Category::Configuration,
            "https://example.com",
            Some(40)
        );

        let git_finding = create_test_finding(
            "Exposed .git directory",
            Category::InformationDisclosure,
            "https://example.com",
            Some(75)
        );

        let findings = vec![dir_finding.clone(), git_finding.clone()];
        let correlations = engine.correlate_findings(&findings).unwrap();

        assert_eq!(correlations.len(), 1);
        let correlation = &correlations[0];
        assert_eq!(correlation.correlation_type, CorrelationType::InfoDisclosureChain);
        assert_eq!(correlation.finding_ids.len(), 2);
        assert!(correlation.finding_ids.contains(&dir_finding.id));
        assert!(correlation.finding_ids.contains(&git_finding.id));
        assert_eq!(correlation.combined_risk.combined_score, 90);
    }

    #[test]
    fn test_strengthening_correlation() {
        let engine = CorrelationEngine::new();

        let finding1 = create_test_finding(
            "SQL Injection in login form",
            Category::Injection,
            "https://example.com",
            Some(80)
        );

        let finding2 = create_test_finding(
            "SQL Injection in search parameter",
            Category::Injection,
            "https://example.com",
            Some(75)
        );

        let findings = vec![finding1.clone(), finding2.clone()];
        let correlations = engine.correlate_findings(&findings).unwrap();

        assert_eq!(correlations.len(), 1);
        let correlation = &correlations[0];
        assert_eq!(correlation.correlation_type, CorrelationType::Strengthening);
        assert_eq!(correlation.finding_ids.len(), 2);
        assert!(correlation.finding_ids.contains(&finding1.id));
        assert!(correlation.finding_ids.contains(&finding2.id));
    }
}