//! Security Knowledge Base - Link findings to CWE, OWASP, CAPEC, CVE, and standards

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use openre_core::ids::FindingId;
use openre_core::result::{Category, Finding, Severity};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Configuration for the knowledge base
#[derive(Debug, Clone)]
pub struct KnowledgeBaseConfig {
    /// Enable caching of knowledge base entries
    pub enable_caching: bool,

    /// Cache TTL in seconds (default: 1 day)
    pub cache_ttl_seconds: u64,

    /// Whether to auto-enrich findings with knowledge base data
    pub auto_enrich_findings: bool,
}

impl Default for KnowledgeBaseConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl_seconds: 86400, // 1 day
            auto_enrich_findings: true,
        }
    }
}

/// Security knowledge base linking findings to standards and guidelines
pub struct KnowledgeBase {
    config: KnowledgeBaseConfig,
    cwe_database: HashMap<String, CweEntry>,
    owasp_mappings: HashMap<Category, Vec<String>>,
    capec_database: HashMap<String, CapecEntry>,
    secure_coding_guidelines: HashMap<Category, Vec<SecureCodingGuideline>>,
    standards_references: HashMap<String, Vec<StandardReference>>,
}

/// CWE database entry
#[derive(Debug, Clone)]
struct CweEntry {
    id: String,
    name: String,
    description: String,
    likelihood: String,
    impact: String,
    related_cwes: Vec<String>,
    capec_ids: Vec<String>,
}

/// CAPEC database entry
#[derive(Debug, Clone)]
struct CapecEntry {
    id: String,
    name: String,
    description: String,
    likelihood: String,
    typical_severity: Severity,
    related_cwes: Vec<String>,
    mitigation_strategies: Vec<String>,
}

impl KnowledgeBase {
    /// Create a new knowledge base with default configuration
    pub fn new() -> Self {
        let mut kb = Self {
            config: KnowledgeBaseConfig::default(),
            cwe_database: HashMap::new(),
            owasp_mappings: HashMap::new(),
            capec_database: HashMap::new(),
            secure_coding_guidelines: HashMap::new(),
            standards_references: HashMap::new(),
        };

        // Initialize with core security knowledge
        kb.initialize_core_knowledge();
        kb
    }

    /// Create a new knowledge base with custom configuration
    pub fn with_config(config: KnowledgeBaseConfig) -> Self {
        let mut kb = Self {
            config,
            cwe_database: HashMap::new(),
            owasp_mappings: HashMap::new(),
            capec_database: HashMap::new(),
            secure_coding_guidelines: HashMap::new(),
            standards_references: HashMap::new(),
        };

        kb.initialize_core_knowledge();
        kb
    }

    /// Initialize the knowledge base with core security information
    fn initialize_core_knowledge(&mut self) {
        // Initialize CWE database with common entries
        self.initialize_cwe_database();

        // Initialize OWASP mappings
        self.initialize_owasp_mappings();

        // Initialize CAPEC database
        self.initialize_capec_database();

        // Initialize secure coding guidelines
        self.initialize_secure_coding_guidelines();

        // Initialize standards references
        self.initialize_standards_references();
    }

    /// Initialize CWE database with common entries
    fn initialize_cwe_database(&mut self) {
        let cwes = vec![
            CweEntry {
                id: "CWE-79".to_string(),
                name: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')".to_string(),
                description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.".to_string(),
                likelihood: "High".to_string(),
                impact: "Medium".to_string(),
                related_cwes: vec!["CWE-80".to_string(), "CWE-81".to_string()],
                capec_ids: vec!["CAPEC-66".to_string(), "CAPEC-72".to_string()],
            },
            CweEntry {
                id: "CWE-89".to_string(),
                name: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')".to_string(),
                description: "The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.".to_string(),
                likelihood: "High".to_string(),
                impact: "High".to_string(),
                related_cwes: vec!["CWE-564".to_string(), "CWE-791".to_string()],
                capec_ids: vec!["CAPEC-66".to_string(), "CAPEC-108".to_string()],
            },
            CweEntry {
                id: "CWE-22".to_string(),
                name: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')".to_string(),
                description: "The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory.".to_string(),
                likelihood: "Medium".to_string(),
                impact: "High".to_string(),
                related_cwes: vec!["CWE-23".to_string(), "CWE-36".to_string()],
                capec_ids: vec!["CAPEC-126".to_string(), "CAPEC-177".to_string()],
            },
            CweEntry {
                id: "CWE-287".to_string(),
                name: "Improper Authentication".to_string(),
                description: "When an actor claims to have a given identity, the software does not prove or insufficiently proves that the claim is correct.".to_string(),
                likelihood: "Medium".to_string(),
                impact: "High".to_string(),
                related_cwes: vec!["CWE-284".to_string(), "CWE-306".to_string()],
                capec_ids: vec!["CAPEC-112".to_string(), "CAPEC-555".to_string()],
            },
            CweEntry {
                id: "CWE-732".to_string(),
                name: "Incorrect Permission Assignment for Critical Resource".to_string(),
                description: "The software specifies permissions for a security-critical resource in a way that allows that resource to be read or modified by unintended actors.".to_string(),
                likelihood: "Medium".to_string(),
                impact: "High".to_string(),
                related_cwes: vec!["CWE-275".to_string(), "CWE-733".to_string()],
                capec_ids: vec!["CAPEC-18".to_string(), "CAPEC-67".to_string()],
            },
        ];

        for cwe in cwes {
            self.cwe_database.insert(cwe.id.clone(), cwe);
        }
    }

    /// Initialize OWASP Top 10 mappings
    fn initialize_owasp_mappings(&mut self) {
        self.owasp_mappings.insert(
            Category::Injection,
            vec![
                "A03:2021 - Injection".to_string(),
                "A01:2017 - Injection".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::BrokenAuthentication,
            vec![
                "A07:2021 - Identification and Authentication Failures".to_string(),
                "A02:2017 - Broken Authentication".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::SensitiveDataExposure,
            vec![
                "A02:2021 - Cryptographic Failures".to_string(),
                "A03:2017 - Sensitive Data Exposure".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::Xss,
            vec![
                "A03:2021 - Injection".to_string(),
                "A07:2017 - Cross-Site Scripting (XSS)".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::BrokenAccessControl,
            vec![
                "A01:2021 - Broken Access Control".to_string(),
                "A05:2017 - Broken Access Control".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::SecurityMisconfiguration,
            vec![
                "A05:2021 - Security Misconfiguration".to_string(),
                "A06:2017 - Security Misconfiguration".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::VulnerableComponents,
            vec![
                "A06:2021 - Vulnerable and Outdated Components".to_string(),
                "A09:2017 - Using Components with Known Vulnerabilities".to_string(),
            ],
        );

        self.owasp_mappings.insert(
            Category::Ssrf,
            vec!["A10:2021 - Server-Side Request Forgery (SSRF)".to_string()],
        );
    }

    /// Initialize CAPEC database
    fn initialize_capec_database(&mut self) {
        let capecs = vec![
            CapecEntry {
                id: "CAPEC-66".to_string(),
                name: "SQL Injection".to_string(),
                description: "An adversary injects malicious SQL code into application queries to manipulate the database.".to_string(),
                likelihood: "High".to_string(),
                typical_severity: Severity::High,
                related_cwes: vec!["CWE-89".to_string()],
                mitigation_strategies: vec![
                    "Use parameterized queries or prepared statements".to_string(),
                    "Validate and sanitize all input".to_string(),
                    "Implement least privilege database access".to_string(),
                ],
            },
            CapecEntry {
                id: "CAPEC-72".to_string(),
                name: "Cross Site Scripting".to_string(),
                description: "An adversary injects malicious script code into web pages viewed by other users.".to_string(),
                likelihood: "High".to_string(),
                typical_severity: Severity::Medium,
                related_cwes: vec!["CWE-79".to_string()],
                mitigation_strategies: vec![
                    "Encode output based on context (HTML, JavaScript, CSS)".to_string(),
                    "Use Content Security Policy (CSP) headers".to_string(),
                    "Validate and sanitize input".to_string(),
                ],
            },
        ];

        for capec in capecs {
            self.capec_database.insert(capec.id.clone(), capec);
        }
    }

    /// Initialize secure coding guidelines
    fn initialize_secure_coding_guidelines(&mut self) {
        // XSS Guidelines
        self.secure_coding_guidelines.insert(
            Category::Xss,
            vec![SecureCodingGuideline {
                title: "Output Encoding".to_string(),
                description: "Always encode output based on the context where it will be rendered."
                    .to_string(),
                examples: HashMap::from([
                    (
                        "html".to_string(),
                        r#"// HTML context encoding
String encoded = HtmlUtils.htmlEscape(userInput);"#
                            .to_string(),
                    ),
                    (
                        "javascript".to_string(),
                        r#"// JavaScript context encoding
String encoded = JavaScriptUtils.javaScriptEscape(userInput);"#
                            .to_string(),
                    ),
                ]),
                references: vec![
                    "https://cheatsheetseries.owasp.org/".to_string(),
                    "https://cwe.mitre.org/data/definitions/79.html".to_string(),
                ],
            }],
        );

        // SQL Injection Guidelines
        self.secure_coding_guidelines.insert(Category::Injection, vec![
            SecureCodingGuideline {
                title: "Parameterized Queries".to_string(),
                description: "Use parameterized queries or prepared statements to prevent SQL injection.".to_string(),
                examples: HashMap::from([
                    ("java".to_string(), r#"// Java with PreparedStatement
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, username);
stmt.setString(2, password);"#.to_string()),
                    ("python".to_string(), r#"// Python with parameterized queries
cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s",
               (username, password))"#.to_string()),
                ]),
                references: vec![
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html".to_string(),
                    "https://cwe.mitre.org/data/definitions/89.html".to_string(),
                ],
            }
        ]);
    }

    /// Initialize standards references
    fn initialize_standards_references(&mut self) {
        self.standards_references.insert(
            "CWE-79".to_string(),
            vec![
                StandardReference {
                    standard: "NIST SP 800-53".to_string(),
                    controls: vec!["SI-10".to_string()],
                    url: Some(
                        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
                            .to_string(),
                    ),
                },
                StandardReference {
                    standard: "ISO 27001".to_string(),
                    controls: vec!["A.9.4.2".to_string()],
                    url: Some(
                        "https://www.iso.org/isoiec-27001-information-security.html".to_string(),
                    ),
                },
            ],
        );

        self.standards_references.insert(
            "CWE-89".to_string(),
            vec![
                StandardReference {
                    standard: "NIST SP 800-53".to_string(),
                    controls: vec!["SC-24".to_string(), "SI-10".to_string()],
                    url: Some(
                        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
                            .to_string(),
                    ),
                },
                StandardReference {
                    standard: "ISO 27001".to_string(),
                    controls: vec!["A.9.4.2".to_string(), "A.14.1.3".to_string()],
                    url: Some(
                        "https://www.iso.org/isoiec-27001-information-security.html".to_string(),
                    ),
                },
            ],
        );
    }

    /// Enrich findings with knowledge base information
    pub fn enrich_findings(
        &self,
        findings: &mut [Finding],
    ) -> IntelligenceResult<Vec<KnowledgeBaseEntry>> {
        let mut kb_entries = Vec::new();

        for finding in findings {
            let entry = self.enrich_single_finding(finding)?;
            if let Some(entry) = entry {
                kb_entries.push(entry);
            }
        }

        Ok(kb_entries)
    }

    /// Enrich a single finding with knowledge base information
    fn enrich_single_finding(
        &self,
        finding: &mut Finding,
    ) -> IntelligenceResult<Option<KnowledgeBaseEntry>> {
        let mut cwe_ids = Vec::new();
        let mut owasp_categories = Vec::new();
        let mut capec_ids = Vec::new();
        let mut cve_ids = Vec::new();
        let mut mitre_attack_techniques = Vec::new();

        // Map category to CWE IDs
        match finding.category {
            Category::Xss => {
                cwe_ids.push("CWE-79".to_string());
                capec_ids.extend(["CAPEC-66".to_string(), "CAPEC-72".to_string()]);
                mitre_attack_techniques.push("T1059.007".to_string()); // Command and Scripting Interpreter: JavaScript
            }
            Category::Injection => {
                cwe_ids.push("CWE-89".to_string());
                capec_ids.extend(["CAPEC-66".to_string(), "CAPEC-108".to_string()]);
                mitre_attack_techniques.push("T1505.003".to_string()); // Server Software Component: Web Shell
            }
            Category::SecurityMisconfiguration => {
                cwe_ids.push("CWE-732".to_string());
                capec_ids.push("CAPEC-640".to_string()); // Incorrect Permission Assignment for Critical Resource
            }
            Category::SensitiveDataExposure => {
                cwe_ids.push("CWE-522".to_string()); // Insufficiently Protected Credentials
                mitre_attack_techniques.push("T1530".to_string()); // Data from Cloud Storage Object
            }
            Category::BrokenAuthentication => {
                cwe_ids.push("CWE-798".to_string()); // Use of Hard-coded Credentials
                capec_ids.push("CAPEC-112".to_string()); // Brute Force
                mitre_attack_techniques.push("T1046".to_string()); // Network Service Scanning
            }
            Category::InformationDisclosure => {
                cwe_ids.push("CWE-200".to_string()); // Exposure of Sensitive Information to an Unauthorized Actor
                mitre_attack_techniques.push("T1530".to_string()); // Data from Cloud Storage Object
            }
            _ => {
                // Try to map based on finding title/description keywords
                self.map_by_keywords(finding, &mut cwe_ids, &mut capec_ids);
            }
        }

        // Get OWASP mappings for the category
        if let Some(mappings) = self.owasp_mappings.get(&finding.category) {
            owasp_categories.extend(mappings.clone());
        }

        // Add references to the finding
        for cwe_id in &cwe_ids {
            finding.references.push(openre_core::result::Reference {
                reference_type: openre_core::result::ReferenceType::Cwe,
                title: format!(
                    "CWE-{} - {}",
                    cwe_id.strip_prefix("CWE-").unwrap_or(cwe_id),
                    self.cwe_database
                        .get(cwe_id)
                        .map(|c| &c.name[..])
                        .unwrap_or("Unknown CWE")
                ),
                url: format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    cwe_id.strip_prefix("CWE-").unwrap_or(cwe_id)
                ),
                description: self.cwe_database.get(cwe_id).map(|c| c.description.clone()),
            });

            // Add CAPEC references
            if let Some(cwe_entry) = self.cwe_database.get(cwe_id) {
                for capec_id in &cwe_entry.capec_ids {
                    finding.references.push(openre_core::result::Reference {
                        reference_type: openre_core::result::ReferenceType::Custom(
                            "CAPEC".to_string(),
                        ),
                        title: format!(
                            "CAPEC-{} - {}",
                            capec_id.strip_prefix("CAPEC-").unwrap_or(capec_id),
                            self.capec_database
                                .get(capec_id)
                                .map(|c| &c.name[..])
                                .unwrap_or("Unknown CAPEC")
                        ),
                        url: format!(
                            "https://capec.mitre.org/data/definitions/{}.html",
                            capec_id.strip_prefix("CAPEC-").unwrap_or(capec_id)
                        ),
                        description: self
                            .capec_database
                            .get(capec_id)
                            .map(|c| c.description.clone()),
                    });
                }
            }

            // Add standards references
            if let Some(standards) = self.standards_references.get(cwe_id) {
                for standard in standards {
                    finding.references.push(openre_core::result::Reference {
                        reference_type: openre_core::result::ReferenceType::Custom(
                            "Standard".to_string(),
                        ),
                        title: format!("{} - {}", standard.standard, standard.controls.join(", ")),
                        url: standard.url.clone(),
                        description: None,
                    });
                }
            }
        }

        // Add OWASP references
        for owasp_cat in &owasp_categories {
            finding.references.push(openre_core::result::Reference {
                reference_type: openre_core::result::ReferenceType::Owasp,
                title: owasp_cat.clone(),
                url: "https://owasp.org/www-project-top-ten/".to_string(),
                description: None,
            });
        }

        // Update finding with CWE and CAPEC IDs
        for cwe_id in &cwe_ids {
            if !finding.cwe_ids.contains(cwe_id) {
                finding.cwe_ids.push(cwe_id.clone());
            }
        }

        for capec_id in &capec_ids {
            if !finding.capec_ids.contains(capec_id) {
                finding.capec_ids.push(capec_id.clone());
            }
        }

        // Add MITRE ATT&CK techniques
        for technique in &mitre_attack_techniques {
            if !finding.mitre_attack_ids.contains(technique) {
                finding.mitre_attack_ids.push(technique.clone());
            }
        }

        // Get secure coding guidelines for the category
        let secure_coding_guidelines = self
            .secure_coding_guidelines
            .get(&finding.category)
            .cloned()
            .unwrap_or_default();

        // Create knowledge base entry
        let kb_entry = KnowledgeBaseEntry {
            finding_id: finding.id,
            cwe_ids,
            owasp_categories,
            capec_ids,
            cve_ids,
            mitre_attack_techniques,
            secure_coding_guidelines,
            standards_references: self.get_standards_for_finding(finding),
        };

        // Add knowledge base metadata
        finding.metadata.insert(
            "knowledge_base_enriched".to_string(),
            serde_json::Value::Bool(true),
        );

        Ok(Some(kb_entry))
    }

    /// Map findings to CWE/CAPEC based on keywords in title/description
    fn map_by_keywords(
        &self,
        finding: &Finding,
        cwe_ids: &mut Vec<String>,
        capec_ids: &mut Vec<String>,
    ) {
        let text = format!(
            "{} {}",
            finding.title.to_lowercase(),
            finding.description.to_lowercase()
        );

        if text.contains("sql") && (text.contains("inject") || text.contains("injection")) {
            cwe_ids.push("CWE-89".to_string());
            capec_ids.push("CAPEC-66".to_string());
        } else if text.contains("cross site") && text.contains("script") {
            cwe_ids.push("CWE-79".to_string());
            capec_ids.push("CAPEC-72".to_string());
        } else if text.contains("path traversal") || text.contains("directory traversal") {
            cwe_ids.push("CWE-22".to_string());
            capec_ids.push("CAPEC-126".to_string());
        } else if text.contains("auth") && (text.contains("bypass") || text.contains("fail")) {
            cwe_ids.push("CWE-287".to_string());
            capec_ids.push("CAPEC-112".to_string());
        }
    }

    /// Get standards references for a finding
    fn get_standards_for_finding(&self, finding: &Finding) -> Vec<StandardReference> {
        let mut standards = Vec::new();

        // Add standards based on CWE IDs
        for cwe_id in &finding.cwe_ids {
            if let Some(standard_refs) = self.standards_references.get(cwe_id) {
                standards.extend(standard_refs.clone());
            }
        }

        standards
    }

    /// Get knowledge base entry for a finding
    pub fn get_knowledge_base_entry(&self, finding_id: &FindingId) -> Option<KnowledgeBaseEntry> {
        // In a real implementation, this would look up stored entries
        // For now, we'll return None as entries are created during enrichment
        None
    }

    /// Get CWE information by ID
    pub fn get_cwe_info(&self, cwe_id: &str) -> Option<&CweEntry> {
        self.cwe_database.get(cwe_id)
    }

    /// Get CAPEC information by ID
    pub fn get_capec_info(&self, capec_id: &str) -> Option<&CapecEntry> {
        self.capec_database.get(capec_id)
    }

    /// Generate a knowledge base report for findings
    pub fn generate_knowledge_report(&self, kb_entries: &[KnowledgeBaseEntry]) -> String {
        let mut report = String::new();
        report.push_str("# Security Knowledge Base Report\n\n");

        report.push_str("## Findings Mapped to Security Standards\n\n");

        for entry in kb_entries {
            report.push_str(&format!("### Finding ID: {}\n", entry.finding_id));

            if !entry.cwe_ids.is_empty() {
                report.push_str("- **CWE References**:\n");
                for cwe_id in &entry.cwe_ids {
                    if let Some(cwe) = self.cwe_database.get(cwe_id) {
                        report.push_str(&format!(
                            "  - [{}] {} ({})\n",
                            cwe_id, cwe.name, cwe.description
                        ));
                    } else {
                        report.push_str(&format!("  - {}\n", cwe_id));
                    }
                }
            }

            if !entry.owasp_categories.is_empty() {
                report.push_str("- **OWASP Mappings**:\n");
                for owasp in &entry.owasp_categories {
                    report.push_str(&format!("  - {}\n", owasp));
                }
            }

            if !entry.capec_ids.is_empty() {
                report.push_str("- **CAPEC Attack Patterns**:\n");
                for capec_id in &entry.capec_ids {
                    if let Some(capec) = self.capec_database.get(capec_id) {
                        report.push_str(&format!(
                            "  - [{}] {} ({})\n",
                            capec_id, capec.name, capec.description
                        ));
                    } else {
                        report.push_str(&format!("  - {}\n", capec_id));
                    }
                }
            }

            if !entry.mitre_attack_techniques.is_empty() {
                report.push_str("- **MITRE ATT&CK Techniques**:\n");
                for technique in &entry.mitre_attack_techniques {
                    report.push_str(&format!("  - {}\n", technique));
                }
            }

            report.push('\n');
        }

        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
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
    fn test_xss_knowledge_enrichment() {
        let kb = KnowledgeBase::new();
        let mut finding = create_test_finding(
            "Reflected XSS in search parameter",
            Category::Xss,
            "The application reflects user input directly into the HTML response without proper encoding."
        );

        let entries = kb.enrich_findings(&mut [finding.clone()]).unwrap();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert!(entry.cwe_ids.contains(&"CWE-79".to_string()));
        assert!(!entry.owasp_categories.is_empty());
        assert!(!entry.capec_ids.is_empty());

        // Check that references were added to the finding
        assert!(!finding.references.is_empty());
        assert!(finding.cwe_ids.contains(&"CWE-79".to_string()));
    }

    #[test]
    fn test_sql_injection_knowledge_enrichment() {
        let kb = KnowledgeBase::new();
        let mut finding = create_test_finding(
            "SQL Injection vulnerability in login form",
            Category::Injection,
            "The application constructs SQL queries using string concatenation with user input.",
        );

        let entries = kb.enrich_findings(&mut [finding.clone()]).unwrap();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert!(entry.cwe_ids.contains(&"CWE-89".to_string()));
        assert!(!entry.owasp_categories.is_empty());
        assert!(!entry.capec_ids.is_empty());

        // Check that references were added to the finding
        assert!(!finding.references.is_empty());
        assert!(finding.cwe_ids.contains(&"CWE-89".to_string()));
    }

    #[test]
    fn test_keyword_based_mapping() {
        let kb = KnowledgeBase::new();
        let mut finding = create_test_finding(
            "SQL Injection vulnerability detected",
            Category::Custom("Database".to_string()),
            "User input is concatenated directly into SQL queries without sanitization.",
        );

        let entries = kb.enrich_findings(&mut [finding.clone()]).unwrap();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        // Should map based on keywords in title/description
        assert!(!entry.cwe_ids.is_empty());
        assert!(entry.cwe_ids.contains(&"CWE-89".to_string()));
    }
}
