//! Root Cause Analysis - Identify underlying issues rather than individual findings

use crate::{types::*, error::IntelligenceError, IntelligenceResult};
use openre_core::result::{Finding, Category, Severity};
use openre_core::ids::FindingId;
use std::collections::{HashMap, HashSet};
use tracing::{debug, info, warn};

/// Configuration for root cause analysis
#[derive(Debug, Clone)]
pub struct RootCauseConfig {
    /// Enable common vulnerability pattern detection
    pub enable_common_patterns: bool,

    /// Enable misconfiguration root cause detection
    pub enable_misconfig_patterns: bool,

    /// Enable authentication/authorization root cause detection
    pub enable_auth_patterns: bool,

    /// Enable input validation root cause detection
    pub enable_input_validation_patterns: bool,

    /// Minimum number of related findings to trigger root cause analysis
    pub min_related_findings: usize,

    /// Confidence threshold for root cause identification (0.0-1.0)
    pub confidence_threshold: f32,
}

impl Default for RootCauseConfig {
    fn default() -> Self {
        Self {
            enable_common_patterns: true,
            enable_misconfig_patterns: true,
            enable_auth_patterns: true,
            enable_input_validation_patterns: true,
            min_related_findings: 3,
            confidence_threshold: 0.6,
        }
    }
}

/// Root cause analyzer for identifying underlying security issues
pub struct RootCauseAnalyzer {
    config: RootCauseConfig,
}

impl RootCauseAnalyzer {
    /// Create a new root cause analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: RootCauseConfig::default(),
        }
    }

    /// Create a new root cause analyzer with custom configuration
    pub fn with_config(config: RootCauseConfig) -> Self {
        Self { config }
    }

    /// Analyze findings to identify root causes
    pub fn analyze_root_causes(&self, findings: &[Finding]) -> IntelligenceResult<Vec<RootCauseAnalysis>> {
        let mut root_causes = Vec::new();

        // Group findings by target for more focused analysis
        let mut findings_by_target: HashMap<&str, Vec<&Finding>> = HashMap::new();
        for finding in findings {
            findings_by_target.entry(&finding.target).or_default().push(finding);
        }

        // Analyze each target separately
        for (target, target_findings) in findings_by_target {
            let mut target_root_causes = self.analyze_target_root_causes(target, &target_findings)?;
            root_causes.append(&mut target_root_causes);
        }

        Ok(root_causes)
    }

    /// Analyze root causes for a specific target
    fn analyze_target_root_causes(&self, target: &str, findings: &[&Finding]) -> IntelligenceResult<Vec<RootCauseAnalysis>> {
        let mut root_causes = Vec::new();

        // Apply different root cause analysis patterns based on configuration
        if self.config.enable_common_patterns {
            root_causes.extend(self.analyze_common_vulnerability_patterns(findings)?);
        }

        if self.config.enable_misconfig_patterns {
            root_causes.extend(self.analyze_misconfiguration_patterns(findings)?);
        }

        if self.config.enable_auth_patterns {
            root_causes.extend(self.analyze_authentication_patterns(findings)?);
        }

        if self.config.enable_input_validation_patterns {
            root_causes.extend(self.analyze_input_validation_patterns(findings)?);
        }

        // Filter by confidence threshold
        root_causes.retain(|rc| rc.priority as u8 >= (self.config.confidence_threshold * 5.0) as u8);

        Ok(root_causes)
    }

    /// Analyze common vulnerability patterns that indicate systemic issues
    fn analyze_common_vulnerability_patterns(&self, findings: &[&Finding]) -> IntelligenceResult<Vec<RootCauseAnalysis>> {
        let mut root_causes = Vec::new();

        // Pattern 1: Multiple injection vulnerabilities suggest lack of input validation/sanitization
        let injection_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::Injection)
            .copied()
            .collect();

        if injection_findings.len() >= self.config.min_related_findings {
            let finding_ids: Vec<FindingId> = injection_findings.iter().map(|f| f.id).collect();

            let root_cause = RootCauseAnalysis {
                root_cause_id: finding_ids[0], // Use first as representative
                related_findings: finding_ids.clone(),
                description: "Multiple injection vulnerabilities detected across the application indicate a systemic lack of proper input validation and sanitization mechanisms.".to_string(),
                impact_assessment: "This root cause allows attackers to manipulate backend systems through various injection vectors including SQL, command, and code injection attacks. The widespread nature suggests inadequate secure coding practices throughout the codebase.".to_string(),
                remediation_approach: "Implement a comprehensive input validation framework that includes:\n1. Centralized input sanitization functions\n2. Parameterized queries for all database operations\n3. Output encoding based on context\n4. Regular security training for developers\n5. Code review checklist focused on injection prevention".to_string(),
                priority: RemediationPriority::Immediate,
            };

            root_causes.push(root_cause);
        }

        // Pattern 2: Multiple XSS vulnerabilities suggest lack of output encoding
        let xss_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::Xss)
            .copied()
            .collect();

        if xss_findings.len() >= self.config.min_related_findings {
            let finding_ids: Vec<FindingId> = xss_findings.iter().map(|f| f.id).collect();

            let root_cause = RootCauseAnalysis {
                root_cause_id: finding_ids[0],
                related_findings: finding_ids.clone(),
                description: "Multiple cross-site scripting (XSS) vulnerabilities across the application indicate a systemic lack of proper output encoding and content security policies.".to_string(),
                impact_assessment: "This root cause enables client-side attacks that can steal user sessions, deface websites, and redirect users to malicious sites. The widespread nature suggests inadequate protection against XSS throughout the codebase.".to_string(),
                remediation_approach: "Implement comprehensive XSS prevention measures:\n1. Context-aware output encoding for all user-generated content\n2. Content Security Policy (CSP) headers\n3. Input validation on sensitive fields\n4. Automated security scanning in CI/CD pipeline\n5. Regular penetration testing".to_string(),
                priority: RemediationPriority::High,
            };

            root_causes.push(root_cause);
        }

        // Pattern 3: Multiple information disclosure issues suggest poor error handling
        let info_disclosure_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::InformationDisclosure)
            .copied()
            .collect();

        if info_disclosure_findings.len() >= self.config.min_related_findings {
            let finding_ids: Vec<FindingId> = info_disclosure_findings.iter().map(|f| f.id).collect();

            let root_cause = RootCauseAnalysis {
                root_cause_id: finding_ids[0],
                related_findings: finding_ids.clone(),
                description: "Multiple information disclosure vulnerabilities indicate poor error handling practices and exposure of sensitive system information.".to_string(),
                impact_assessment: "This root cause allows attackers to gather intelligence about the application architecture, technology stack, and potential attack vectors. This information can be used to craft more targeted attacks.".to_string(),
                remediation_approach: "Implement proper error handling and information disclosure controls:\n1. Generic error messages for users\n2. Detailed logging for developers (not exposed to users)\n3. Remove or secure debug information\n4. Implement proper exception handling\n5. Regular security audits of error responses".to_string(),
                priority: RemediationPriority::High,
            };

            root_causes.push(root_cause);
        }

        Ok(root_causes)
    }

    /// Analyze misconfiguration patterns that indicate systemic issues
    fn analyze_misconfiguration_patterns(&self, findings: &[&Finding]) -> IntelligenceResult<Vec<RootCauseAnalysis>> {
        let mut root_causes = Vec::new();

        // Pattern: Multiple security misconfigurations suggest lack of hardening
        let misconfig_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == Category::SecurityMisconfiguration)
            .copied()
            .collect();

        if misconfig_findings.len() >= 2 { // Lower threshold for misconfigurations
            let finding_ids: Vec<FindingId> = misconfig_findings.iter().map(|f| f.id).collect();

            let root_cause = RootCauseAnalysis {
                root_cause_id: finding_ids[0],
                related_findings: finding_ids.clone(),
                description: "Multiple security misconfigurations indicate a lack of systematic hardening and security configuration management across the infrastructure.".to_string(),
                impact_assessment: "This root cause exposes the application to various attacks due to insecure default configurations, incomplete or ad-hoc hardening, and lack of configuration governance. Misconfigurations can affect servers, databases, frameworks, and cloud services.".to_string(),
                remediation_approach: "Implement comprehensive security hardening:\n1. Standardized security baselines for all components\n2. Automated configuration validation\n3. Regular security assessments\n4. Configuration management tools\n5. Security-focused deployment pipelines".to_string(),
                priority: RemediationPriority::High,
            };

            root_causes.push(root_cause);
        }

        Ok(root_causes)
    }

    /// Analyze authentication/authorization patterns
    fn analyze_authentication_patterns(&self, findings: &[&Finding]) -> IntelligenceResult<Vec<RootCauseAnalysis>> {
        let mut root_causes = Vec::new();

        // Pattern: Multiple auth-related issues suggest weak identity management
        let auth_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.category,
                Category::BrokenAuthentication |
                Category::BrokenAccessControl))
            .copied()
            .collect();

        if auth_findings.len() >= 2 {
            let finding_ids: Vec<FindingId> = auth_findings.iter().map(|f| f.id).collect();

            let root_cause = RootCauseAnalysis {
                root_cause_id: finding_ids[0],
                related_findings: finding_ids.clone(),
                description: "Multiple authentication and access control vulnerabilities indicate weak identity and access management practices.".to_string(),
                impact_assessment: "This root cause allows unauthorized access to sensitive functionality and data. Attackers can bypass authentication, escalate privileges, or access resources they shouldn't have access to, potentially leading to full system compromise.".to_string(),
                remediation_approach: "Implement robust identity and access management:\n1. Strong authentication mechanisms (MFA)\n2. Proper session management\n3. Role-based access control (RBAC)\n4. Regular access reviews\n5. Secure credential storage\n6. Account lockout policies".to_string(),
                priority: RemediationPriority::Immediate,
            };

            root_causes.push(root_cause);
        }

        Ok(root_causes)
    }

    /// Analyze input validation patterns
    fn analyze_input_validation_patterns(&self, findings: &[&Finding]) -> IntelligenceResult<Vec<RootCauseAnalysis>> {
        let mut root_causes = Vec::new();

        // Pattern: Mix of injection, XSS, and validation issues suggest poor input handling
        let validation_related_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.category,
                Category::Injection |
                Category::Xss |
                Category::SecurityMisconfiguration) &&
                (f.title.to_lowercase().contains("validation") ||
                 f.description.to_lowercase().contains("validation") ||
                 f.title.to_lowercase().contains("sanitiz") ||
                 f.description.to_lowercase().contains("sanitiz")))
            .copied()
            .collect();

        if validation_related_findings.len() >= self.config.min_related_findings {
            let finding_ids: Vec<FindingId> = validation_related_findings.iter().map(|f| f.id).collect();

            let root_cause = RootCauseAnalysis {
                root_cause_id: finding_ids[0],
                related_findings: finding_ids.clone(),
                description: "Multiple input validation and sanitization issues indicate a lack of systematic data validation across the application.".to_string(),
                impact_assessment: "This root cause allows various injection attacks, cross-site scripting, and other input-based vulnerabilities. The systemic nature suggests inadequate validation frameworks and poor secure coding practices.".to_string(),
                remediation_approach: "Implement comprehensive input validation:\n1. Centralized validation library\n2. Whitelist-based validation for all inputs\n3. Proper output encoding\n4. Parameterized queries\n5. Regular security training\n6. Automated security scanning".to_string(),
                priority: RemediationPriority::High,
            };

            root_causes.push(root_cause);
        }

        Ok(root_causes)
    }

    /// Correlate findings with identified root causes
    pub fn correlate_findings_with_root_causes(&self, findings: &mut [Finding], root_causes: &[RootCauseAnalysis]) -> IntelligenceResult<()> {
        // Create a mapping of finding ID to root cause IDs
        let mut finding_to_root_causes: HashMap<FindingId, Vec<FindingId>> = HashMap::new();

        for root_cause in root_causes {
            for related_finding_id in &root_cause.related_findings {
                finding_to_root_causes.entry(*related_finding_id)
                    .or_default()
                    .push(root_cause.root_cause_id);
            }
        }

        // Update findings with root cause information
        for finding in findings {
            if let Some(root_cause_ids) = finding_to_root_causes.get(&finding.id) {
                // Add root cause IDs to related_findings
                for root_cause_id in root_cause_ids {
                    if !finding.related_findings.contains(root_cause_id) {
                        finding.related_findings.push(*root_cause_id);
                    }
                }

                // Add metadata about root cause analysis
                finding.metadata.insert(
                    "root_cause_analysis_performed".to_string(),
                    serde_json::Value::Bool(true)
                );
                finding.metadata.insert(
                    "root_cause_count".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(root_cause_ids.len()))
                );

                // Add a note about the root cause
                if let Some(first_root_cause_id) = root_cause_ids.first() {
                    finding.metadata.insert(
                        "primary_root_cause".to_string(),
                        serde_json::Value::String(first_root_cause_id.to_string())
                    );
                }
            }
        }

        Ok(())
    }

    /// Generate a root cause analysis report
    pub fn generate_root_cause_report(&self, root_causes: &[RootCauseAnalysis], all_findings: &[Finding]) -> String {
        let mut report = String::new();
        report.push_str("# Root Cause Analysis Report\n\n");

        if root_causes.is_empty() {
            report.push_str("No significant root causes identified. All findings appear to be isolated issues.\n");
            return report;
        }

        report.push_str(&format!("## Identified Root Causes ({})\n\n", root_causes.len()));

        for (index, root_cause) in root_causes.iter().enumerate() {
            report.push_str(&format!("### Root Cause #{} - {}\n", index + 1,
                match root_cause.priority {
                    RemediationPriority::Immediate => "CRITICAL",
                    RemediationPriority::High => "HIGH",
                    RemediationPriority::Medium => "MEDIUM",
                    RemediationPriority::Low => "LOW",
                    RemediationPriority::Deferred => "INFO",
                }));

            // Find the actual finding for this root cause
            if let Some(cause_finding) = all_findings.iter().find(|f| f.id == root_cause.root_cause_id) {
                report.push_str(&format!("**Primary Finding**: {} - {}\n", cause_finding.title, cause_finding.description));
            }

            report.push_str(&format!("\n**Description**: {}\n\n", root_cause.description));
            report.push_str(&format!("**Impact Assessment**: {}\n\n", root_cause.impact_assessment));
            report.push_str(&format!("**Remediation Approach**: {}\n\n", root_cause.remediation_approach));

            report.push_str(&format!("**Priority**: {:?}\n", root_cause.priority));
            report.push_str(&format!("**Related Findings**: {} total\n", root_cause.related_findings.len()));

            // List related findings
            report.push_str("\n**Related Findings Details**:\n");
            for (i, related_id) in root_cause.related_findings.iter().enumerate() {
                if let Some(related_finding) = all_findings.iter().find(|f| f.id == *related_id) {
                    report.push_str(&format!("{}. {} - {}\n", i + 1, related_finding.title,
                        match related_finding.severity {
                            Severity::Critical => "CRITICAL",
                            Severity::High => "HIGH",
                            Severity::Medium => "MEDIUM",
                            Severity::Low => "LOW",
                            Severity::Info => "INFO",
                        }));
                }
            }

            report.push('\n');
        }

        // Summary statistics
        let total_related_findings: usize = root_causes.iter().map(|rc| rc.related_findings.len()).sum();
        let avg_related_per_root = if !root_causes.is_empty() {
            total_related_findings as f32 / root_causes.len() as f32
        } else {
            0.0
        };

        report.push_str("## Summary\n");
        report.push_str(&format!("- Total root causes identified: {}\n", root_causes.len()));
        report.push_str(&format!("- Total findings linked to root causes: {}\n", total_related_findings));
        report.push_str(&format!("- Average findings per root cause: {:.1}\n", avg_related_per_root));

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openre_core::result::{Finding, Category, Severity, Confidence};
    use openre_core::ids::{FindingId, ScanId};
    use chrono::Utc;
    use std::collections::HashMap;

    fn create_test_finding(title: &str, category: Category, description: &str) -> Finding {
        Finding {
            id: FindingId::new_v4(),
            title: title.to_string(),
            description: description.to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new_v4(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(60),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some("test-fingerprint".to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[test]
    fn test_injection_root_cause_detection() {
        let analyzer = RootCauseAnalyzer::with_config(RootCauseConfig {
            min_related_findings: 2, // Lower for testing
            ..Default::default()
        });

        let findings = vec![
            create_test_finding(
                "SQL Injection in login form",
                Category::Injection,
                "User input concatenated directly into SQL query"
            ),
            create_test_finding(
                "Command Injection in file upload",
                Category::Injection,
                "Shell commands constructed with user input"
            ),
        ];

        let root_causes = analyzer.analyze_root_causes(&findings).unwrap();

        // Should identify one root cause for injection vulnerabilities
        assert_eq!(root_causes.len(), 1);

        let root_cause = &root_causes[0];
        assert_eq!(root_cause.related_findings.len(), 2);
        assert_eq!(root_cause.priority, RemediationPriority::Immediate);
        assert!(root_cause.description.contains("systemic lack of proper input validation"));
    }

    #[test]
    fn test_xss_root_cause_detection() {
        let analyzer = RootCauseAnalyzer::with_config(RootCauseConfig {
            min_related_findings: 2, // Lower for testing
            ..Default::default()
        });

        let findings = vec![
            create_test_finding(
                "Reflected XSS in search parameter",
                Category::Xss,
                "User input reflected without encoding"
            ),
            create_test_finding(
                "Stored XSS in comment field",
                Category::Xss,
                "User comments stored and displayed without sanitization"
            ),
        ];

        let root_causes = analyzer.analyze_root_causes(&findings).unwrap();

        // Should identify one root cause for XSS vulnerabilities
        assert_eq!(root_causes.len(), 1);

        let root_cause = &root_causes[0];
        assert_eq!(root_cause.related_findings.len(), 2);
        assert_eq!(root_cause.priority, RemediationPriority::High);
        assert!(root_cause.description.contains("systemic lack of proper output encoding"));
    }

    #[test]
    fn test_misconfiguration_root_cause_detection() {
        let analyzer = RootCauseAnalyzer::with_config(RootCauseConfig {
            min_related_findings: 2,
            ..Default::default()
        });

        let findings = vec![
            create_test_finding(
                "Missing security headers",
                Category::SecurityMisconfiguration,
                "Security headers not properly configured"
            ),
            create_test_finding(
                "Directory listing enabled",
                Category::SecurityMisconfiguration,
                "Web server allows directory browsing"
            ),
        ];

        let root_causes = analyzer.analyze_root_causes(&findings).unwrap();

        // Should identify one root cause for misconfigurations
        assert_eq!(root_causes.len(), 1);

        let root_cause = &root_causes[0];
        assert_eq!(root_cause.related_findings.len(), 2);
        assert_eq!(root_cause.priority, RemediationPriority::High);
        assert!(root_cause.description.contains("systemic hardening"));
    }

    #[test]
    fn test_finding_correlation() {
        let analyzer = RootCauseAnalyzer::new();

        let mut findings = vec![
            create_test_finding(
                "SQL Injection in login form",
                Category::Injection,
                "User input concatenated directly into SQL query"
            ),
            create_test_finding(
                "Command Injection in file upload",
                Category::Injection,
                "Shell commands constructed with user input"
            ),
        ];

        let root_causes = vec![RootCauseAnalysis {
            root_cause_id: findings[0].id,
            related_findings: vec![findings[0].id, findings[1].id],
            description: "Input validation issues".to_string(),
            impact_assessment: "High risk".to_string(),
            remediation_approach: "Fix input validation".to_string(),
            priority: RemediationPriority::High,
        }];

        analyzer.correlate_findings_with_root_causes(&mut findings, &root_causes).unwrap();

        // Check that findings were updated with root cause information
        for finding in &findings {
            assert!(finding.related_findings.contains(&findings[0].id));
            assert!(finding.metadata.contains_key("root_cause_analysis_performed"));
            assert!(finding.metadata.contains_key("root_cause_count"));
        }
    }
}