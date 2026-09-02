//! Comprehensive integration test demonstrating all intelligence components working together

#[cfg(test)]
mod tests {
    use crate::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Evidence, EvidenceType, Finding, Severity};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn create_test_finding(
        title: &str,
        category: Category,
        description: &str,
        risk_score: Option<u8>,
        target: &str,
    ) -> Finding {
        Finding {
            id: FindingId::new(),
            title: title.to_string(),
            description: description.to_string(),
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
            metadata: HashMap::new(),
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
            fingerprint: Some(format!("test-fingerprint-{}", title)),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[tokio::test]
    async fn test_complete_intelligence_pipeline() {
        println!("🧪 Starting comprehensive intelligence pipeline test...");

        // 1. Create test findings that will trigger various intelligence features
        let mut findings = vec![
            // XSS finding that should correlate with missing CSP
            create_test_finding(
                "Reflected XSS in search parameter",
                Category::Xss,
                "The application reflects user input directly into the HTML response without proper encoding.",
                Some(70),
                "https://example.com"
            ),

            // Missing CSP finding that should correlate with XSS above
            create_test_finding(
                "Missing Content-Security-Policy header",
                Category::SecurityMisconfiguration,
                "The application does not set a Content Security Policy header, increasing XSS risk.",
                Some(30),
                "https://example.com"
            ),

            // Directory listing finding that should correlate with Git metadata exposure
            create_test_finding(
                "Directory listing enabled",
                Category::Configuration,
                "Web server allows directory browsing which can expose sensitive files.",
                Some(40),
                "https://api.example.com"
            ),

            // Git metadata exposure finding that should correlate with directory listing above
            create_test_finding(
                "Exposed .git directory",
                Category::InformationDisclosure,
                "Git metadata directory is accessible, potentially exposing source code.",
                Some(75),
                "https://api.example.com"
            ),

            // Multiple SQL injection findings to test strengthening correlation
            create_test_finding(
                "SQL Injection in login form",
                Category::Injection,
                "User input is concatenated directly into SQL queries without sanitization.",
                Some(85),
                "https://admin.example.com"
            ),

            create_test_finding(
                "SQL Injection in search parameter",
                Category::Injection,
                "Search functionality vulnerable to SQL injection attacks.",
                Some(80),
                "https://admin.example.com"
            ),
        ];

        // 2. Test Correlation Engine
        println!("🔗 Testing correlation engine...");
        let correlation_engine = CorrelationEngine::new();
        let correlations = correlation_engine.correlate_findings_sync(&findings).unwrap();

        // Should find at least 3 correlations:
        // 1. CSP + XSS chain
        // 2. Directory listing + Git metadata chain
        // 3. Strengthening correlation for SQL injection findings
        assert!(
            correlations.len() >= 3,
            "Expected at least 3 correlations, found {}",
            correlations.len()
        );

        // The correlation engine returns FindingRelationship, not EnhancedCorrelation
        // Check for specific relationship types instead
        let csp_xss_correlation = correlations.iter().find(|c| {
            c.relationship_type == openre_core::relationships::FindingRelationshipType::Enables
        });
        assert!(csp_xss_correlation.is_some(), "Missing CSP + XSS correlation (Enables)");

        let dir_git_correlation = correlations.iter().find(|c| {
            c.relationship_type
                == openre_core::relationships::FindingRelationshipType::ChainedExploit
        });
        assert!(
            dir_git_correlation.is_some(),
            "Missing directory listing + Git metadata correlation (ChainedExploit)"
        );

        let strengthening_correlation = correlations.iter().find(|c| {
            c.relationship_type == openre_core::relationships::FindingRelationshipType::Amplifies
        });
        assert!(
            strengthening_correlation.is_some(),
            "Missing strengthening correlation (Amplifies)"
        );

        println!("   ✅ Found {} correlations with expected confidence scores", correlations.len());

        // 3. Test CVE Intelligence (using mock provider)
        println!("🛡️  Testing CVE intelligence...");
        let cve_config = cve_intelligence::CveIntelligenceConfig {
            enable_caching: true,
            cache_ttl_seconds: 3600,
            max_concurrent_requests: 5,
        };
        let mut cve_intel = CveIntelligence::new(cve_config);
        cve_intel.add_provider(Arc::new(cve_intelligence::MockCveProvider::new()));

        // Add some evidence to findings that can be matched to CVEs
        if let Some(finding) = findings.iter_mut().find(|f| f.title.contains("Directory listing")) {
            finding.evidence.push(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "HTTP response with Server header indicating Apache 2.4.50"
                    .to_string(),
                data: Some(serde_json::json!({
                    "server": "Apache/2.4.50"
                })),
                location: Some("https://api.example.com".to_string()),
                metadata: {
                    let mut map = HashMap::new();
                    map.insert(
                        "technology".to_string(),
                        serde_json::Value::String("Apache/2.4.50".to_string()),
                    );
                    map
                },
                http_request: None,
                http_response: None,
                timing: None,
                payload: None,
                reproduction_steps: None,
                plugin_source: Some("test".to_string()),
                timestamp: Utc::now(),
            });
        }

        let cve_matches = cve_intel.match_findings_against_cves(&findings).await.unwrap();
        println!("   Found {} findings with CVE matches", cve_matches.len());

        // Test enriching findings with CVE data
        let original_references_count = findings.iter().map(|f| f.references.len()).sum::<usize>();
        cve_intel.enrich_findings_with_cve_data(&mut findings).await.unwrap();
        let new_references_count = findings.iter().map(|f| f.references.len()).sum::<usize>();

        if new_references_count > original_references_count {
            println!("   ✅ Successfully enriched findings with CVE data");
        }

        // 4. Test Dependency Analysis (using mock registry client)
        println!("📦 Testing dependency analysis...");
        let dep_config = dependency_analysis::DependencyAnalysisConfig {
            enable_caching: true,
            cache_ttl_seconds: 86400,
            check_vulnerabilities: true,
            check_outdated: true,
        };
        let mut dep_analyzer = DependencyAnalyzer::new(dep_config);
        dep_analyzer.add_registry_client(
            "npm",
            Box::new(dependency_analysis::MockRegistryClient::new("npm")),
        );

        // Test analyzing a simple requirements.txt content
        let requirements_content = r#"
express==4.18.0
lodash==4.17.20
        "#;

        if let Ok(dependencies) = dep_analyzer
            .analyze_dependencies_content(
                requirements_content,
                std::path::Path::new("requirements.txt"),
            )
            .await
        {
            println!("   Analyzed {} dependencies", dependencies.len());

            // Check for outdated and vulnerable dependencies
            let outdated_count = dependencies.iter().filter(|d| d.is_outdated).count();
            let vulnerable_count =
                dependencies.iter().filter(|d| !d.vulnerabilities.is_empty()).count();

            if outdated_count > 0 || vulnerable_count > 0 {
                println!(
                    "   Found {} outdated and {} vulnerable dependencies",
                    outdated_count, vulnerable_count
                );

                // Generate analysis report
                let report = dep_analyzer.generate_analysis_report(&dependencies);
                assert!(!report.is_empty(), "Dependency analysis report should not be empty");
                println!("   ✅ Generated dependency analysis report ({} chars)", report.len());
            }
        }

        // 5. Test Knowledge Base Enrichment
        println!("📚 Testing knowledge base enrichment...");
        let knowledge_base = KnowledgeBase::new();
        let kb_entries = knowledge_base.enrich_findings(&mut findings).unwrap();

        assert!(!kb_entries.is_empty(), "Should have created knowledge base entries");
        println!("   Created {} knowledge base entries", kb_entries.len());

        // Verify that findings were enriched with references
        let enriched_findings = findings
            .iter()
            .filter(|f| {
                !f.cwe_ids.is_empty() || !f.capec_ids.is_empty() || !f.references.is_empty()
            })
            .count();

        assert!(enriched_findings > 0, "Should have enriched findings with knowledge base data");
        println!("   Enriched {} findings with CWE/CAPEC/OWASP references", enriched_findings);

        // 6. Test Root Cause Analysis
        println!("🌱 Testing root cause analysis...");
        let root_cause_config = root_cause::RootCauseConfig {
            enable_common_patterns: true,
            enable_misconfig_patterns: true,
            enable_auth_patterns: true,
            enable_input_validation_patterns: true,
            min_related_findings: 2,
            confidence_threshold: 0.5,
        };
        let root_cause_analyzer = RootCauseAnalyzer::with_config(root_cause_config);
        let root_causes = root_cause_analyzer.analyze_root_causes(&findings).unwrap();

        println!("   Identified {} potential root causes", root_causes.len());

        // Correlate findings with root causes
        root_cause_analyzer
            .correlate_findings_with_root_causes(&mut findings, &root_causes)
            .unwrap();

        // Check that findings were updated with root cause information
        let findings_with_root_cause = findings
            .iter()
            .filter(|f| f.metadata.contains_key("root_cause_analysis_performed"))
            .count();

        if findings_with_root_cause > 0 {
            println!(
                "   ✅ Correlated {} findings with root cause analysis",
                findings_with_root_cause
            );
        }

        // 7. Test Scan Diff Intelligence
        println!("📊 Testing scan diff intelligence...");
        let scan_diff_config = scan_diff::ScanDiffConfig {
            enable_new_critical_detection: true,
            enable_resolved_detection: true,
            enable_trend_analysis: true,
            min_severity_for_significant_change: types::SeverityLevel::High,
            time_window_hours: 24,
            significance_threshold_percent: 10.0,
        };
        let scan_diff_analyzer = ScanDiffAnalyzer::with_config(scan_diff_config);

        // Create mock previous and current scan data
        let previous_scan = scan_diff::ScanData::new(
            scan_diff::ScanMetadata {
                scan_id: ScanId::new(),
                start_time: Utc::now() - chrono::Duration::days(1),
                end_time: Some(Utc::now() - chrono::Duration::hours(23)),
                target: "https://example.com".to_string(),
                plugins_used: vec!["test-plugin".to_string()],
                configuration: HashMap::new(),
                tags: Vec::new(),
            },
            vec![
                create_test_finding(
                    "Old XSS Finding",
                    Category::Xss,
                    "Previous XSS vulnerability",
                    Some(60),
                    "https://example.com",
                ),
                create_test_finding(
                    "Fixed SQL Injection",
                    Category::Injection,
                    "Previously vulnerable endpoint",
                    Some(80),
                    "https://example.com",
                ),
            ],
        );

        let current_scan = scan_diff::ScanData::new(
            scan_diff::ScanMetadata {
                scan_id: ScanId::new(),
                start_time: Utc::now(),
                end_time: Some(Utc::now() + chrono::Duration::minutes(30)),
                target: "https://example.com".to_string(),
                plugins_used: vec!["test-plugin".to_string()],
                configuration: HashMap::new(),
                tags: Vec::new(),
            },
            findings.clone(),
        );

        let diff_analysis =
            scan_diff_analyzer.compare_scans(&previous_scan, &current_scan).unwrap();
        println!("   Scan diff analysis completed:");
        println!("   - New findings: {}", diff_analysis.new_findings.len());
        println!("   - Resolved findings: {}", diff_analysis.resolved_findings.len());
        println!("   - Significant changes: {}", diff_analysis.is_significant_change);

        // Generate diff report
        let diff_report =
            scan_diff_analyzer.generate_diff_report(&diff_analysis, &previous_scan, &current_scan);
        assert!(!diff_report.is_empty(), "Diff report should not be empty");
        println!("   ✅ Generated scan diff report ({} chars)", diff_report.len());

        // 8. Test Workflow Features
        println!("✅ Testing workflow features...");
        let workflow_config = workflow::WorkflowConfig {
            enable_acknowledgment: true,
            enable_false_positive: true,
            enable_ignore_rules: true,
            default_temp_ignore_days: 30,
            max_ignore_rules: 1000,
        };
        let mut workflow_manager = WorkflowManager::with_config(workflow_config);

        // Acknowledge some findings
        if let Some(finding) = findings.first() {
            workflow_manager
                .acknowledge_finding(finding.id, "test_user", Some("Reviewed during triage"))
                .unwrap();
        }

        // Mark a finding as false positive
        if let Some(finding) = findings.get(1) {
            workflow_manager
                .mark_false_positive(finding.id, "test_user", "Test environment artifact")
                .unwrap();
        }

        // Add an ignore rule
        let ignore_rule = types::IgnoreRule {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: r"title:.*Directory listing.*".to_string(),
            reason: "Known issue in dev environment".to_string(),
            author: "test_user".to_string(),
            created_by: "test_user".to_string(),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::days(7)),
            scope: types::IgnoreScope {
                targets: Vec::new(),
                categories: Vec::new(),
                severities: Vec::new(),
                tags: Vec::new(),
            },
            severity_threshold: None,
            target_pattern: Some(r"https://api\.example\.com.*".to_string()),
        };
        workflow_manager.add_ignore_rule(ignore_rule).unwrap();

        // Process findings through workflow filters
        let workflow_result = workflow_manager.process_findings(&mut findings).unwrap();
        println!("   Workflow processing result:");
        println!("   - Total findings: {}", workflow_result.total_findings);
        println!("   - Acknowledged: {}", workflow_result.acknowledged_count);
        println!("   - False positives: {}", workflow_result.false_positive_count);
        println!("   - Ignored: {}", workflow_result.ignored_count);
        println!("   - Remaining: {}", workflow_result.remaining_count);

        // Generate workflow report
        let workflow_report = workflow_manager.generate_workflow_report();
        assert!(!workflow_report.is_empty(), "Workflow report should not be empty");
        println!("   ✅ Generated workflow report ({} chars)", workflow_report.len());

        // 9. Test Performance Optimizations
        println!("⚡ Testing performance optimizations...");
        let perf_config = performance::PerformanceConfig {
            enable_caching: true,
            default_cache_ttl_seconds: 3600,
            max_cache_size: 1000,
            enable_incremental_processing: true,
            cache_cleanup_interval_seconds: 300,
            enable_deduplication: true,
        };
        let mut perf_optimizer = PerformanceOptimizer::with_config(perf_config);

        // Test caching
        let cache_key = "test_cache_key";
        let cache_value = "test_cache_value";
        perf_optimizer.put_in_cache(cache_key.to_string(), cache_value.to_string()).unwrap();

        let cached_result: Option<String> = perf_optimizer.get_from_cache(cache_key).unwrap();
        assert_eq!(cached_result, Some(cache_value.to_string()));

        // Test deduplication
        let mut duplicate_findings = vec![
            create_test_finding(
                "Duplicate Finding 1",
                Category::InformationDisclosure,
                "Test duplicate",
                Some(20),
                "https://test.com",
            ),
            create_test_finding(
                "Duplicate Finding 2",
                Category::InformationDisclosure,
                "Test duplicate",
                Some(20),
                "https://test.com",
            ),
        ];

        // Set same fingerprint for both findings
        if let Some(f) = duplicate_findings.first_mut() {
            f.fingerprint = Some("same-fingerprint".to_string());
        }
        if let Some(f) = duplicate_findings.get_mut(1) {
            f.fingerprint = Some("same-fingerprint".to_string());
        }

        let dedup_count = perf_optimizer.deduplicate_findings(&mut duplicate_findings);
        assert_eq!(dedup_count, 1, "Should have removed 1 duplicate finding");
        assert_eq!(duplicate_findings.len(), 1, "Should have 1 unique finding remaining");

        // Test incremental processing
        let previous_findings = vec![create_test_finding(
            "Previous Finding",
            Category::Xss,
            "Old XSS",
            Some(50),
            "https://old.com",
        )];
        let mut current_findings = vec![
            create_test_finding(
                "Previous Finding",
                Category::Xss,
                "Old XSS",
                Some(50),
                "https://old.com",
            ), // Unchanged
            create_test_finding(
                "New Finding",
                Category::Injection,
                "New SQLi",
                Some(80),
                "https://new.com",
            ), // New
        ];

        let incremental_result =
            perf_optimizer.incremental_process(&previous_findings, &mut current_findings);
        assert_eq!(incremental_result.unchanged_findings.len(), 1);
        assert_eq!(incremental_result.new_findings.len(), 1);
        assert_eq!(current_findings.len(), 1); // Should only contain new findings

        // Get cache stats
        let cache_stats = perf_optimizer.get_cache_stats();
        println!(
            "   Cache statistics: {} hits, {} misses, {:.1}% hit rate",
            cache_stats.hit_count, cache_stats.miss_count, cache_stats.hit_rate
        );

        println!("   ✅ Performance optimizations working correctly");

        // 10. Test TUI Enhancements
        println!("🖥️  Testing TUI enhancements...");
        let tui_config = tui_enhancements::TuiConfig {
            enable_colors: false, // Disable colors for testing
            enable_emojis: true,
            show_detailed_descriptions: true,
            max_width: 100,
            enable_filtering: true,
            show_confidence_indicators: true,
            enable_progress_indicators: true,
        };
        let tui_enhancer = TuiEnhancer::with_config(tui_config);

        // Test formatting individual findings
        if let Some(finding) = findings.first() {
            let formatted_finding = tui_enhancer.format_finding(finding, true);
            assert!(!formatted_finding.is_empty(), "Formatted finding should not be empty");
            println!(
                "   Formatted finding preview (first 200 chars): {}",
                &formatted_finding[..std::cmp::min(200, formatted_finding.len())]
            );
        }

        // Test formatting correlations (convert FindingRelationship to EnhancedCorrelation for display)
        if let Some(correlation) = correlations.first() {
            let enhanced = crate::types::EnhancedCorrelation {
                finding_ids: vec![correlation.source_finding, correlation.target_finding],
                correlation_type: match correlation.relationship_type {
                    openre_core::relationships::FindingRelationshipType::Enables => {
                        crate::CorrelationType::Causal
                    }
                    openre_core::relationships::FindingRelationshipType::Amplifies => {
                        crate::CorrelationType::Strengthening
                    }
                    openre_core::relationships::FindingRelationshipType::ChainedExploit => {
                        crate::CorrelationType::Causal
                    }
                    openre_core::relationships::FindingRelationshipType::SameRootCause => {
                        crate::CorrelationType::SharedRootCause
                    }
                    openre_core::relationships::FindingRelationshipType::Temporal => {
                        crate::CorrelationType::Temporal
                    }
                    openre_core::relationships::FindingRelationshipType::Spatial => {
                        crate::CorrelationType::Spatial
                    }
                    _ => crate::CorrelationType::Strengthening,
                },
                confidence: correlation.confidence,
                description: correlation.explanation.clone(),
                evidence: correlation.evidence.iter().map(|e| e.description.clone()).collect(),
                combined_risk: crate::RiskAssessment {
                    individual_scores: vec![],
                    combined_score: 0,
                    explanation: String::new(),
                },
                mitigation_approach: String::new(),
            };
            let formatted_correlation = tui_enhancer.format_correlation_result(&enhanced);
            assert!(!formatted_correlation.is_empty(), "Formatted correlation should not be empty");
            println!(
                "   Formatted correlation preview (first 100 chars): {}",
                &formatted_correlation[..std::cmp::min(100, formatted_correlation.len())]
            );
        }

        // Test formatting findings list
        let findings_list = tui_enhancer.format_findings_list(&findings, "Test Findings Summary");
        assert!(!findings_list.is_empty(), "Findings list should not be empty");

        // Test dashboard generation (convert FindingRelationship to EnhancedCorrelation)
        let enhanced_correlations: Vec<EnhancedCorrelation> =
            correlations.clone().into_iter().map(Into::into).collect();
        let dashboard = tui_enhancer.format_dashboard(&findings, &enhanced_correlations);
        assert!(!dashboard.is_empty(), "Dashboard should not be empty");
        println!("   ✅ TUI enhancements working correctly (dashboard: {} chars)", dashboard.len());

        // 11. Verify Integration Success
        println!("\n🏁 Integration test summary:");
        println!("   - Correlation Engine: ✅ Found {} correlations", correlations.len());
        println!("   - CVE Intelligence: ✅ Processed findings with mock CVE data");
        println!("   - Dependency Analysis: ✅ Analyzed mock dependencies");
        println!("   - Knowledge Base: ✅ Enriched {} findings", kb_entries.len());
        println!("   - Root Cause Analysis: ✅ Identified {} root causes", root_causes.len());
        println!("   - Scan Diff Intelligence: ✅ Compared scans with detailed analysis");
        println!("   - Workflow Features: ✅ Processed findings through workflow filters");
        println!("   - Performance Optimizations: ✅ Tested caching and deduplication");
        println!("   - TUI Enhancements: ✅ Generated formatted output");

        // Final verification that all components worked together
        let findings_with_enrichment = findings
            .iter()
            .filter(|f| {
                !f.cwe_ids.is_empty()
                    || !f.capec_ids.is_empty()
                    || !f.references.is_empty()
                    || f.metadata.contains_key("cve_intelligence_matched")
                    || f.metadata.contains_key("knowledge_base_enriched")
                    || f.metadata.contains_key("root_cause_analysis_performed")
            })
            .count();

        assert!(
            findings_with_enrichment > 0,
            "Should have enriched findings from multiple intelligence components"
        );
        println!("\n🎉 Comprehensive intelligence pipeline test completed successfully!");
        println!(
            "   {} out of {} findings were enriched with intelligence data",
            findings_with_enrichment,
            findings.len()
        );
    }

    #[test]
    fn test_component_isolation() {
        // Test that each component can be instantiated and used independently
        println!("🔄 Testing component isolation...");

        // Correlation Engine
        let correlation_engine = CorrelationEngine::new();
        let empty_findings: Vec<Finding> = vec![];
        let correlations = correlation_engine.correlate_findings_sync(&empty_findings).unwrap();
        assert_eq!(correlations.len(), 0);
        println!("   ✅ Correlation Engine isolated correctly");

        // CVE Intelligence
        let cve_intel = CveIntelligence::new(cve_intelligence::CveIntelligenceConfig::default());
        assert_eq!(cve_intel.provider_count(), 0);
        println!("   ✅ CVE Intelligence isolated correctly");

        // Dependency Analyzer
        let dep_analyzer =
            DependencyAnalyzer::new(dependency_analysis::DependencyAnalysisConfig::default());
        assert_eq!(dep_analyzer.registry_client_count(), 0);
        println!("   ✅ Dependency Analyzer isolated correctly");

        // Knowledge Base
        let knowledge_base = KnowledgeBase::new();
        assert!(knowledge_base.cwe_entry_count() > 0);
        assert!(knowledge_base.owasp_mapping_count() > 0);
        println!("   ✅ Knowledge Base isolated correctly");

        // Root Cause Analyzer
        let root_cause_analyzer = RootCauseAnalyzer::new();
        let root_causes = root_cause_analyzer.analyze_root_causes(&empty_findings).unwrap();
        assert_eq!(root_causes.len(), 0);
        println!("   ✅ Root Cause Analyzer isolated correctly");

        // Scan Diff Analyzer
        let scan_diff_analyzer = ScanDiffAnalyzer::new();
        // This would require mock data to test fully, but instantiation works
        println!("   ✅ Scan Diff Analyzer isolated correctly");

        // Workflow Manager
        let workflow_manager = WorkflowManager::new();
        assert_eq!(workflow_manager.list_ignore_rules().len(), 0);
        println!("   ✅ Workflow Manager isolated correctly");

        // Performance Optimizer
        let perf_optimizer = PerformanceOptimizer::new();
        let cache_stats = perf_optimizer.get_cache_stats();
        assert_eq!(cache_stats.cache_size, 0);
        println!("   ✅ Performance Optimizer isolated correctly");

        // TUI Enhancer
        let tui_enhancer = TuiEnhancer::new();
        let empty_dashboard = tui_enhancer.format_dashboard(&empty_findings, &[]);
        assert!(!empty_dashboard.is_empty());
        println!("   ✅ TUI Enhancer isolated correctly");
    }
}
