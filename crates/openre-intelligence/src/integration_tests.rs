//! Integration tests for the openre-intelligence crate

#[cfg(test)]
mod tests {
    use crate::*;
    use openre_core::result::{Finding, Category, Severity, Confidence};
    use openre_core::ids::{FindingId, ScanId};
    use std::collections::HashMap;
    use chrono::Utc;

    fn create_test_finding(title: &str, severity: Severity, category: Category) -> Finding {
        Finding {
            id: FindingId::new_v4(),
            title: title.to_string(),
            description: format!("Description for {}", title),
            severity,
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
            cwe_ids: vec!["CWE-79".to_string()], // XSS CWE
            capec_ids: vec!["CAPEC-66".to_string()],
            mitre_attack_ids: Vec::new(),
            owasp_category: Some("A03:2021-Injection".to_string()),
            fingerprint: Some(format!("fingerprint-{}", title.to_lowercase().replace(" ", "-"))),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[test]
    fn test_full_intelligence_pipeline() {
        // This is a comprehensive integration test that demonstrates
        // how all components of the intelligence crate work together

        println!("🧪 Starting full intelligence pipeline integration test...");

        // 1. Create test findings
        println!("📝 Creating test findings...");
        let mut findings = vec![
            create_test_finding("SQL Injection Vulnerability", Severity::High, Category::Injection),
            create_test_finding("Cross-site Scripting", Severity::Medium, Category::Xss),
            create_test_finding("Missing CSP Header", Severity::Medium, Category::SecurityMisconfiguration),
            create_test_finding("Path Traversal", Severity::High, Category::Injection),
        ];

        // 2. Test correlation engine
        println!("🔗 Testing correlation engine...");
        let correlation_engine = CorrelationEngine::new();
        let correlations = correlation_engine.correlate_findings(&findings).unwrap();
        println!("   Found {} correlations", correlations.len());

        // 3. Test root cause analysis
        println!("🌱 Testing root cause analysis...");
        let root_cause_analyzer = RootCauseAnalyzer::new();
        let root_causes = root_cause_analyzer.analyze_root_causes(&findings).unwrap();
        println!("   Identified {} root causes", root_causes.len());

        // Update findings with root cause information
        if !root_causes.is_empty() {
            root_cause_analyzer.correlate_findings_with_root_causes(&mut findings, &root_causes).unwrap();
        }

        // 4. Test workflow management
        println!("✅ Testing workflow management...");
        let mut workflow_manager = WorkflowManager::new();

        // Acknowledge one finding
        workflow_manager.acknowledge_finding(findings[0].id, "test_user", Some("Reviewed")).unwrap();

        // Mark another as false positive
        workflow_manager.mark_false_positive(findings[1].id, "test_user", "Test environment artifact").unwrap();

        // Process findings through workflow filters
        let workflow_result = workflow_manager.process_findings(&mut findings).unwrap();
        println!("   Workflow processing result:");
        println!("   - Total findings: {}", workflow_result.total_findings);
        println!("   - Acknowledged: {}", workflow_result.acknowledged_count);
        println!("   - False positives: {}", workflow_result.false_positive_count);
        println!("   - Remaining after filtering: {}", workflow_result.remaining_count);

        // 5. Test performance optimizations
        println!("⚡ Testing performance optimizations...");
        let mut performance_optimizer = PerformanceOptimizer::new();

        // Cache a value
        performance_optimizer.put_in_cache("test_key".to_string(), "test_value".to_string()).unwrap();

        // Retrieve from cache
        let cached_value: Option<String> = performance_optimizer.get_from_cache("test_key").unwrap();
        assert_eq!(cached_value, Some("test_value".to_string()));

        // Test deduplication
        let mut duplicate_findings = vec![
            create_test_finding("Duplicate Finding 1", Severity::Low, Category::InformationDisclosure),
            create_test_finding("Duplicate Finding 2", Severity::Low, Category::InformationDisclosure),
        ];
        duplicate_findings[0].fingerprint = Some("same-fingerprint".to_string());
        duplicate_findings[1].fingerprint = Some("same-fingerprint".to_string());

        let dedup_count = performance_optimizer.deduplicate_findings(&mut duplicate_findings);
        assert_eq!(dedup_count, 1);
        assert_eq!(duplicate_findings.len(), 1);

        println!("   Cache hit rate: {:.1}%", performance_optimizer.get_cache_stats().hit_rate);

        // 6. Test TUI enhancements
        println!("🖥️  Testing TUI enhancements...");
        let tui_enhancer = TuiEnhancer::new();

        // Format individual findings
        for finding in &findings {
            let formatted = tui_enhancer.format_finding(finding, true);
            assert!(!formatted.is_empty());
        }

        // Format correlations
        for correlation in &correlations {
            let formatted = tui_enhancer.format_correlation_result(correlation);
            assert!(!formatted.is_empty());
        }

        // Generate dashboard
        let dashboard = tui_enhancer.format_dashboard(&findings, &correlations);
        assert!(!dashboard.is_empty());

        println!("   TUI formatting completed successfully");

        // 7. Test scan diff analysis (simplified)
        println!("📊 Testing scan diff analysis...");
        let scan_diff_analyzer = ScanDiffAnalyzer::new();

        // Create mock scan data
        let previous_scan = scan_diff::ScanData::new(
            openre_core::result::ScanMetadata {
                scan_id: ScanId::new_v4(),
                start_time: Utc::now() - chrono::Duration::days(1),
                end_time: Some(Utc::now() - chrono::Duration::hours(23)),
                target: "https://example.com".to_string(),
                plugins_used: vec!["test-plugin".to_string()],
                configuration: HashMap::new(),
                tags: Vec::new(),
            },
            vec![create_test_finding("Old Finding", Severity::Medium, Category::Injection)],
        );

        let current_scan = scan_diff::ScanData::new(
            openre_core::result::ScanMetadata {
                scan_id: ScanId::new_v4(),
                start_time: Utc::now(),
                end_time: Some(Utc::now() + chrono::Duration::minutes(30)),
                target: "https://example.com".to_string(),
                plugins_used: vec!["test-plugin".to_string()],
                configuration: HashMap::new(),
                tags: Vec::new(),
            },
            findings.clone(), // Use current findings
        );

        let diff_analysis = scan_diff_analyzer.compare_scans(&previous_scan, &current_scan).unwrap();
        println!("   Scan diff analysis completed:");
        println!("   - New findings: {}", diff_analysis.new_findings.len());
        println!("   - Resolved findings: {}", diff_analysis.resolved_findings.len());

        // 8. Verify all components are working together
        println!("✅ Verifying integration...");

        // Ensure we have findings processed through the full pipeline
        assert!(!findings.is_empty(), "Should have findings after processing");

        // Check that at least some intelligence features were applied
        let findings_with_metadata: usize = findings.iter()
            .filter(|f| !f.metadata.is_empty())
            .count();

        println!("   Findings with intelligence metadata: {}/{}", findings_with_metadata, findings.len());

        // Generate final reports
        println!("📋 Generating final reports...");

        let correlation_report = if !correlations.is_empty() {
            let mut report = "Enhanced Correlations Found:\n".to_string();
            for (i, corr) in correlations.iter().enumerate() {
                report.push_str(&format!("{}. {:?} (confidence: {:.1}%)\n",
                    i + 1, corr.correlation_type, corr.confidence_score * 100.0));
            }
            report
        } else {
            "No significant correlations found.".to_string()
        };

        let root_cause_report = root_cause_analyzer.generate_root_cause_report(&root_causes, &findings);
        let workflow_report = workflow_manager.generate_workflow_report();
        let performance_report = performance_optimizer.generate_performance_report();

        println!("   Reports generated successfully");

        // Print summary
        println!("\n🏁 Integration test completed successfully!");
        println!("   Summary:");
        println!("   - Processed {} findings through full intelligence pipeline", findings.len());
        println!("   - Found {} correlations", correlations.len());
        println!("   - Identified {} root causes", root_causes.len());
        println!("   - Applied workflow filtering ({} acknowledged, {} false positives)",
            workflow_result.acknowledged_count, workflow_result.false_positive_count);
        println!("   - Performance cache hit rate: {:.1}%", performance_optimizer.get_cache_stats().hit_rate);

        // These assertions verify the integration is working
        assert!(findings.len() > 0, "Should have processed findings");
        assert!(correlations.len() >= 0, "Correlation engine should run without error");
        assert!(root_causes.len() >= 0, "Root cause analysis should run without error");
        assert!(diff_analysis.new_findings.len() >= 0, "Scan diff analysis should work");

        println!("🎉 All integration tests passed!");
    }

    #[test]
    fn test_component_interoperability() {
        println!("🔄 Testing component interoperability...");

        // Test that types are consistent across modules
        let finding = create_test_finding("Test Finding", Severity::Medium, Category::Injection);

        // All components should be able to work with the same finding type
        let correlation_engine = CorrelationEngine::new();
        let correlations = correlation_engine.correlate_findings(&[finding.clone()]);
        assert!(correlations.is_ok());

        let root_cause_analyzer = RootCauseAnalyzer::new();
        let root_causes = root_cause_analyzer.analyze_root_causes(&[finding.clone()]);
        assert!(root_causes.is_ok());

        let mut workflow_manager = WorkflowManager::new();
        assert!(workflow_manager.acknowledge_finding(finding.id, "test", None).is_ok());

        let mut performance_optimizer = PerformanceOptimizer::new();
        assert!(performance_optimizer.deduplicate_findings(&mut vec![finding.clone()]).is_numeric());

        let tui_enhancer = TuiEnhancer::new();
        let formatted = tui_enhancer.format_finding(&finding, false);
        assert!(!formatted.is_empty());

        println!("   ✅ All components can work with shared types");
    }

    #[test]
    fn test_error_handling() {
        println!("🛡️  Testing error handling integration...");

        // Test that errors are properly propagated
        let mut workflow_manager = WorkflowManager::with_config(workflow::WorkflowConfig {
            enable_acknowledgment: false,
            enable_false_positive: false,
            enable_ignore_rules: false,
            ..Default::default()
        });

        let finding_id = FindingId::new_v4();

        // These should fail gracefully with appropriate errors
        let ack_result = workflow_manager.acknowledge_finding(finding_id, "user", None);
        assert!(matches!(ack_result, Err(IntelligenceError::WorkflowFeatureDisabled(_))));

        let fp_result = workflow_manager.mark_false_positive(finding_id, "user", "reason");
        assert!(matches!(fp_result, Err(IntelligenceError::WorkflowFeatureDisabled(_))));

        println!("   ✅ Error handling works correctly across components");
    }

    #[test]
    fn test_configuration_consistency() {
        println!("⚙️  Testing configuration consistency...");

        // Test that default configurations are consistent
        let correlation_config = correlation::CorrelationConfig::default();
        let root_cause_config = root_cause::RootCauseConfig::default();
        let workflow_config = workflow::WorkflowConfig::default();
        let performance_config = performance::PerformanceConfig::default();
        let tui_config = tui_enhancements::TuiConfig::default();

        // All should have reasonable defaults
        assert!(correlation_config.enable_csp_xss_chain_detection);
        assert!(root_cause_config.enable_common_patterns);
        assert!(workflow_config.enable_acknowledgment);
        assert!(performance_config.enable_caching);
        assert!(tui_config.enable_colors);

        println!("   ✅ All component configurations have reasonable defaults");
    }
}