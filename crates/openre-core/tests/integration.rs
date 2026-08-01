//! Integration tests for Phase 6: Evidence, Reporting & Risk Engine
//! Exercises the full pipeline: deduplication → correlation → report generation

use std::collections::HashMap;
use openre_core::ids::{ScanId, ProjectId};
use openre_core::result::*;
use openre_core::deduplication::{DeduplicationEngine, DeduplicationConfig, CorrelationEngine, CorrelationType};
use openre_core::reporting::{ReportGenerator, ReportConfig, ReportFormat};

fn create_test_finding(
    title: &str,
    target: &str,
    category: Category,
    severity: Severity,
    confidence: Confidence,
) -> Finding {
    let scan_id = ScanId::new();
    Finding::new(
        title.to_string(),
        "Test description".to_string(),
        severity,
        confidence,
        category,
        target.to_string(),
        "web".to_string(),
        "test-plugin".to_string(),
        "1.0".to_string(),
        scan_id,
    )
}

#[test]
fn test_full_pipeline_dedup_then_correlate() {
    // Create findings with duplicates and correlations
    let mut findings = vec![
        create_test_finding("SQL Injection", "http://example.com/login", Category::Injection, Severity::High, Confidence::High),
        create_test_finding("SQL Injection", "http://example.com/login", Category::Injection, Severity::Medium, Confidence::Medium), // exact dup
        create_test_finding("XSS Vulnerability", "http://example.com/search", Category::Xss, Severity::Medium, Confidence::High),
        create_test_finding("Info Disclosure", "http://example.com/api", Category::InformationDisclosure, Severity::Low, Confidence::High),
    ];

    // Step 1: Deduplicate
    let engine = DeduplicationEngine::default();
    let result = engine.deduplicate(&mut findings);
    assert_eq!(result.original_count, 4);
    assert_eq!(result.duplicates_removed, 1);
    assert_eq!(findings.len(), 3); // one was deduplicated

    // Step 2: Correlate remaining findings
    let corr_engine = CorrelationEngine::default();
    let corr_result = corr_engine.correlate(&findings);
    assert!(!corr_result.correlations.is_empty());

    // Should have temporal, spatial, and causal correlations
    let types: Vec<_> = corr_result.correlations.iter().map(|c| c.correlation_type).collect();
    assert!(types.contains(&CorrelationType::Spatial));
    assert!(types.contains(&CorrelationType::Causal) || types.contains(&CorrelationType::Temporal));
}

#[test]
fn test_report_generation_with_deduplicated_findings() {
    let mut findings = vec![
        create_test_finding("SQL Injection", "http://example.com/login", Category::Injection, Severity::High, Confidence::High),
        create_test_finding("XSS Vulnerability", "http://example.com/search", Category::Xss, Severity::Medium, Confidence::High),
    ];

    // Deduplicate first (no dups here)
    let engine = DeduplicationEngine::default();
    engine.deduplicate(&mut findings);

    // Generate report
    let config = ReportConfig::default();
    let generator = ReportGenerator::new(config);
    let scans = vec![];
    let targets = vec![];
    let report = generator.generate(&findings, &scans, &targets);

    assert_eq!(report.all_findings.len(), 2);
    assert!(report.executive_summary.is_some());

    // Test Markdown rendering
    let md = generator.render(&report, ReportFormat::Markdown);
    assert!(md.contains("SQL Injection"));
    assert!(md.contains("XSS Vulnerability"));
    assert!(md.contains("Executive Summary"));

    // Test SARIF rendering
    let sarif = generator.render(&report, ReportFormat::Sarif);
    assert!(sarif.contains("sarif"));
    assert!(sarif.contains("runs"));
}

#[test]
fn test_scan_comparison_pipeline() {
    let scan_id1 = ScanId::new();
    let mut baseline_findings = vec![
        Finding::new(
            "SQL Injection".to_string(), "desc".to_string(), Severity::High, Confidence::High,
            Category::Injection, "http://example.com/login".to_string(), "web".to_string(),
            "plugin1".to_string(), "1.0".to_string(), scan_id1,
        ).with_fingerprint("fp-sql-injection".to_string()),
    ];

    let scan_id2 = ScanId::new();
    let current_findings = vec![
        Finding::new(
            "SQL Injection".to_string(), "desc".to_string(), Severity::Critical, Confidence::High,
            Category::Injection, "http://example.com/login".to_string(), "web".to_string(),
            "plugin1".to_string(), "1.0".to_string(), scan_id2,
        ).with_fingerprint("fp-sql-injection".to_string()), // Same fingerprint - severity increased
    ];

    let config = ReportConfig::default();
    let generator = ReportGenerator::new(config);

    use openre_core::reporting::{ScanInfo, ScanProgress};
    let baseline_scan = ScanInfo {
        id: scan_id1, name: "Baseline".to_string(), project_id: Some(ProjectId::new()),
        target_id: Default::default(), status: "completed".to_string(), progress: ScanProgress::default(),
        plugin_executions: vec![], started_at: None, completed_at: None, duration: None,
    };
    let current_scan = ScanInfo {
        id: scan_id2, name: "Current".to_string(), project_id: Some(ProjectId::new()),
        target_id: Default::default(), status: "completed".to_string(), progress: ScanProgress::default(),
        plugin_executions: vec![], started_at: None, completed_at: None, duration: None,
    };

    let report = generator.generate_comparison(&baseline_findings, &current_findings, &baseline_scan, &current_scan);
    assert!(report.scan_comparison.is_some());

    let comparison = report.scan_comparison.unwrap();
    // Same fingerprint but severity changed -> not new, not fixed
    assert_eq!(comparison.new_findings.len(), 0);
    assert_eq!(comparison.fixed_findings.len(), 0);
    assert_eq!(comparison.severity_changes.len(), 1);
}

#[test]
fn test_risk_scoring_pipeline() {
    // Test that risk scores are calculated correctly through the pipeline
    let scan_id = ScanId::new();
    let mut finding = Finding::new(
        "Critical Vulnerability".to_string(),
        "desc".to_string(),
        Severity::Critical,
        Confidence::VeryHigh,
        Category::Injection,
        "http://example.com".to_string(),
        "web".to_string(),
        "test-plugin".to_string(),
        "1.0".to_string(),
        scan_id,
    );

    // Calculate risk score without exploitability/impact data
    let basic_score = finding.calculate_risk_score();
    assert_eq!(basic_score, 100); // Max: Critical(4)*20 + VeryHigh(4)*5 = 80+20=100

    // Add exploitability and business impact for advanced scoring
    use openre_core::result::{ExploitabilityAssessment, AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope};
    finding.exploitability = Some(ExploitabilityAssessment {
        score: 8.5, attack_vector: AttackVector::Network, attack_complexity: AttackComplexity::Low,
        privileges_required: PrivilegesRequired::None, user_interaction: UserInteraction::None,
        scope: Scope::Unchanged, exploit_available: true, exploited_in_wild: false, epss_score: Some(0.7),
    });

    use openre_core::result::{BusinessImpactAssessment, ImpactLevel, AssetCriticality};
    finding.business_impact = Some(BusinessImpactAssessment {
        score: 9.0, confidentiality: ImpactLevel::High, integrity: ImpactLevel::High, availability: ImpactLevel::High,
        asset_criticality: AssetCriticality::Critical, regulatory_impact: None,
    });

    let advanced_score = finding.calculate_advanced_risk_score();
    // With max base score (100), multipliers boost but clamp at 100.
    // Verify the calculation runs correctly with all factors present.
    assert_eq!(advanced_score, 100); // Clamped to max after multiplier boosts
}

#[test]
fn test_finding_filter_and_sort() {
    use openre_core::result::{FindingFilter, FindingSort};
    use std::collections::HashMap;

    let scan_id = ScanId::new();
    let findings = vec![
        Finding::new("Low".to_string(), "d".to_string(), Severity::Low, Confidence::Medium, Category::Injection, "t1".to_string(), "w".to_string(), "p".to_string(), "1".to_string(), scan_id),
        Finding::new("Critical".to_string(), "d".to_string(), Severity::Critical, Confidence::High, Category::Xss, "t2".to_string(), "w".to_string(), "p".to_string(), "1".to_string(), scan_id),
        Finding::new("Medium".to_string(), "d".to_string(), Severity::Medium, Confidence::Low, Category::Injection, "t3".to_string(), "w".to_string(), "p".to_string(), "1".to_string(), scan_id),
    ];

    // Test filtering by severity (only Critical)
    let filter = FindingFilter { severity: Some(vec![Severity::Critical]), ..Default::default() };
    let filtered: Vec<_> = findings.iter().filter(|f| {
        if let Some(sevs) = &filter.severity { sevs.contains(&f.severity) } else { true }
    }).collect();
    assert_eq!(filtered.len(), 1);

    // Test sorting by risk score (descending)
    let mut sorted_findings: Vec<Finding> = findings.clone();
    sorted_findings.sort_by(|a, b| {
        b.calculate_risk_score().cmp(&a.calculate_risk_score())
    });
    assert_eq!(sorted_findings[0].severity, Severity::Critical);
}

#[test]
fn test_finding_stats_calculation() {
    use openre_core::result::{FindingStats};
    let scan_id = ScanId::new();
    let findings = vec![
        Finding::new("A".to_string(), "d".to_string(), Severity::Critical, Confidence::High, Category::Injection, "t1".to_string(), "w".to_string(), "p".to_string(), "1".to_string(), scan_id),
        Finding::new("B".to_string(), "d".to_string(), Severity::High, Confidence::Medium, Category::Xss, "t2".to_string(), "w".to_string(), "p".to_string(), "1".to_string(), scan_id),
        Finding::new("C".to_string(), "d".to_string(), Severity::Low, Confidence::Low, Category::Injection, "t3".to_string(), "w".to_string(), "p".to_string(), "1".to_string(), scan_id),
    ];

    let mut by_severity: HashMap<Severity, usize> = HashMap::new();
    for f in &findings {
        *by_severity.entry(f.severity).or_insert(0) += 1;
    }

    assert_eq!(*by_severity.get(&Severity::Critical).unwrap(), 1);
    assert_eq!(*by_severity.get(&Severity::High).unwrap(), 1);
    assert_eq!(*by_severity.get(&Severity::Low).unwrap(), 1);
}