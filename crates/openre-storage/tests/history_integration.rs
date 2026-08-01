//! Integration tests for Phase 6 history storage persistence
//! Tests the full pipeline: save → retrieve → verify for all entity types

use openre_core::ids::{ScanId, ProjectId, TargetId, FindingId};
use openre_core::history::{HistoryStorage, HistoryManager};
use openre_core::reporting::{ReportGenerator, ReportConfig, ReportFormat};
// Import types from result.rs via top-level re-export (pub use result::*;)
use openre_core::{
    FindingStats, EvidenceType as CoreEvidenceType, SeverityChange,
    Finding, Severity, Confidence, Category, RiskMetricsSummary, ScanConfigSummary,
    ScanProgressSummary, PluginExecutionInfo,
};
use std::collections::HashMap;
use tempfile::tempdir;

fn create_test_finding(scan_id: ScanId) -> Finding {
    let mut finding = Finding::new(
        "SQL Injection".to_string(),
        "Test SQL injection vulnerability".to_string(),
        Severity::High,
        Confidence::High,
        Category::Injection,
        "http://example.com/login".to_string(),
        "web".to_string(),
        "test-plugin".to_string(),
        "1.0".to_string(),
        scan_id,
    );
    finding.fingerprint = Some("test-fp-1234567890abcdef".to_string());
    finding.risk_score = Some(85);
    finding.cwe_ids = vec!["CWE-89".to_string()];
    finding
}

#[tokio::test]
async fn test_end_to_end_report_lifecycle() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("e2e_test.db");
    let storage = openre_storage::SqliteHistoryStorage::new(&db_path).unwrap();
    storage.ensure_schema().await.unwrap();

    // Create findings and generate a report
    let scan_id = ScanId::new();
    let project_id = ProjectId::new();
    let target_id = TargetId::new();
    let findings: Vec<Finding> = (0..3)
        .map(|_| create_test_finding(scan_id))
        .collect();

    // Generate report using the reporting engine
    let config = ReportConfig { min_severity: Some(Severity::Medium), ..Default::default() };
    let generator = ReportGenerator::new(config);
    let scans = vec![];
    let targets = vec![];
    let report = generator.generate(&findings, &scans, &targets);

    // Render and save as a report artifact
    let markdown = generator.render(&report, ReportFormat::Markdown);
    assert!(markdown.contains("SQL Injection"));

    // Save deduplicated findings to history
    storage.save_deduplicated_findings(&scan_id, &findings).await.unwrap();
    let retrieved = storage.get_deduplicated_findings(&scan_id).await.unwrap();
    assert_eq!(retrieved.len(), 3);
    assert_eq!(retrieved[0].title, "SQL Injection");

    // Save risk metrics
    use openre_core::history::{RiskMetrics, RiskTrends};
    let mut by_severity = HashMap::new();
    by_severity.insert(Severity::High, 3);
    let mut by_category = HashMap::new();
    by_category.insert(Category::Injection, 3);

    let metrics = RiskMetrics {
        id: "test-metrics-1".to_string(),
        project_id,
        scan_id: Some(scan_id),
        timestamp: chrono::Utc::now(),
        overall_risk_score: 85,
        risk_level: openre_core::reporting::RiskLevel::High,
        by_severity,
        by_category,
        avg_risk_score: 85.0,
        max_risk_score: 85,
        critical_count: 0,
        high_count: 3,
        medium_count: 0,
        low_count: 0,
        info_count: 0,
        verified_count: 0,
        false_positive_count: 0,
        exploit_available_count: 0,
        exploited_in_wild_count: 0,
        top_cwes: vec![("CWE-89".to_string(), 3)],
        top_owasp: vec![],
        remediation_priority: HashMap::new(),
        trends: RiskTrends::default(),
    };

    storage.save_risk_metrics(&metrics).await.unwrap();
    let latest = storage.get_latest_risk_metrics(&project_id).await.unwrap().unwrap();
    assert_eq!(latest.overall_risk_score, 85);
    assert_eq!(latest.high_count, 3);

    // Verify scan history tracking works with HistoryManager
    use openre_core::history::{HistoryManager, ScanSummary};
    let manager = HistoryManager::new(Box::new(storage));

    let summary = ScanSummary {
        scan_id,
        project_id: Some(project_id),
        target_id,
        name: "E2E Test Scan".to_string(),
        description: Some("End-to-end test".to_string()),
        status: "completed".to_string(),
        config: ScanConfigSummary {
            name: "Test".to_string(), target_url: "http://example.com".to_string(),
            plugins: vec!["test-plugin".to_string()], rate_limit: Some(10), timeout_seconds: Some(60),
            auth_configured: false, custom_headers_count: 0,
        },
        progress: ScanProgressSummary { total_endpoints: 10, endpoints_scanned: 10, endpoints_failed: 0, percentage: 100.0 },
        finding_stats: FindingStats {
            total: 3, by_severity: HashMap::new(), by_confidence: HashMap::new(), by_category: HashMap::new(),
            by_plugin: HashMap::new(), verified: 0, false_positives: 0, avg_risk_score: 85.0, max_risk_score: 85,
            by_owasp_category: HashMap::new(), by_cwe: HashMap::new(), avg_advanced_risk_score: 85.0,
            max_advanced_risk_score: 85, by_remediation_priority: HashMap::new(), exploit_available_count: 0, exploited_in_wild_count: 0,
        },
        risk_metrics: openre_core::history::RiskMetricsSummary {
            overall_risk_score: 85, risk_level: openre_core::reporting::RiskLevel::High,
            critical_count: 0, high_count: 3, medium_count: 0, low_count: 0, info_count: 0, avg_risk_score: 85.0, max_risk_score: 85,
        },
        plugin_executions: vec![],
        created_at: chrono::Utc::now(), started_at: Some(chrono::Utc::now()), completed_at: Some(chrono::Utc::now()),
        duration_seconds: Some(60), tags: vec!["e2e-test".to_string()],
    };

    manager.record_scan(summary).await.unwrap();
    let retrieved_summary = manager.get_scan_summary(&scan_id).await.unwrap().unwrap();
    assert_eq!(retrieved_summary.name, "E2E Test Scan");
    assert_eq!(retrieved_summary.finding_stats.total, 3);

    // List scan history for project
    let history = manager.get_project_history(&project_id, 10, 0).await.unwrap();
    assert_eq!(history.len(), 1);
}

#[tokio::test]
async fn test_evidence_storage_and_retrieval() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("evidence_test.db");
    let storage = openre_storage::SqliteHistoryStorage::new(&db_path).unwrap();
    storage.ensure_schema().await.unwrap();

    use openre_core::history::StoredEvidence;
    // Use the top-level re-export of EvidenceType from result module
    let evidence_type = CoreEvidenceType::HttpRequest;
    use std::collections::HashMap as Map;

    let scan_id = ScanId::new();
    let finding_id = FindingId::new();

    // Save HTTP evidence
    let http_evidence = StoredEvidence {
        id: "ev-http-1".to_string(),
        finding_id,
        scan_id,
        evidence_type: evidence_type,
        description: "SQL injection payload sent to login endpoint".to_string(),
        data: Some(b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\n' OR 1=1--".to_vec()),
        location: Some("http://example.com/login (username field)".to_string()),
        metadata: Map::new(),
        http_request: None, // Would be populated with HttpRequestEvidence in real usage
        http_response: None,
        timing: None,
        payload: None,
        reproduction_steps: None,
        captured_at: chrono::Utc::now(),
        plugin_source: "sql-injection-scanner".to_string(),
    };

    storage.save_evidence(&http_evidence).await.unwrap();

    // Retrieve and verify
    let retrieved = storage.get_evidence("ev-http-1").await.unwrap().unwrap();
    assert_eq!(retrieved.description, "SQL injection payload sent to login endpoint");
    assert_eq!(retrieved.evidence_type, CoreEvidenceType::HttpRequest);
    assert!(retrieved.data.is_some());

    // List evidence for finding
    let all_evidence = storage.list_evidence_for_finding(&finding_id).await.unwrap();
    assert_eq!(all_evidence.len(), 1);
}

#[tokio::test]
async fn test_scan_comparison_storage() {
    use openre_core::reporting::{ScanComparison, SeverityChange};

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("comparison_test.db");
    let storage = openre_storage::SqliteHistoryStorage::new(&db_path).unwrap();
    storage.ensure_schema().await.unwrap();

    let baseline_scan_id = ScanId::new();
    let current_scan_id = ScanId::new();

    let comparison = ScanComparison {
        baseline_scan_id,
        current_scan_id,
        new_findings: vec![],
        fixed_findings: vec![],
        regressed_findings: vec![],
        severity_changes: vec![SeverityChange {
            fingerprint: "fp-test".to_string(),
            previous_severity: Severity::Medium,
            current_severity: Severity::High,
            title: "Test Finding".to_string(),
            target: "http://example.com".to_string(),
        }],
        evidence_changes: vec![],
        summary: openre_core::reporting::ComparisonSummary {
            new_count: 0, fixed_count: 0, regressed_count: 0, severity_increased: 1,
            severity_decreased: 0, risk_change: 20, compared_at: chrono::Utc::now(),
        },
    };

    storage.save_comparison(&comparison).await.unwrap();

    // Retrieve and verify - need to list comparisons since save generates a new ID
    let comparisons = storage.list_comparisons(None, 10, 0).await.unwrap();
    assert_eq!(comparisons.len(), 1);
    assert_eq!(comparisons[0].severity_changes.len(), 1);
}

#[tokio::test]
async fn test_pagination() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("pagination_test.db");
    let storage = openre_storage::SqliteHistoryStorage::new(&db_path).unwrap();
    storage.ensure_schema().await.unwrap();

    // Save 10 scan summaries with different IDs
    for i in 0..10 {
        use openre_core::history::{ScanSummary, ScanConfigSummary, ScanProgressSummary};
        let summary = ScanSummary {
            scan_id: ScanId::new(),
            project_id: None,
            target_id: TargetId::new(),
            name: format!("Scan {}", i),
            description: Some(format!("Test scan #{}", i)),
            status: "completed".to_string(),
            config: ScanConfigSummary {
                name: format!("Scan {}", i), target_url: "http://example.com".to_string(),
                plugins: vec![], rate_limit: None, timeout_seconds: None, auth_configured: false, custom_headers_count: 0,
            },
            progress: ScanProgressSummary { total_endpoints: 1, endpoints_scanned: 1, endpoints_failed: 0, percentage: 100.0 },
            finding_stats: make_default_finding_stats(),
            risk_metrics: openre_core::history::RiskMetricsSummary {
                overall_risk_score: 50, risk_level: openre_core::reporting::RiskLevel::Medium,
                critical_count: 0, high_count: 0, medium_count: 1, low_count: 0, info_count: 0, avg_risk_score: 50.0, max_risk_score: 50,
            },
            plugin_executions: vec![],
            created_at: chrono::Utc::now(), started_at: None, completed_at: None, duration_seconds: None, tags: vec![],
        };
        storage.save_scan_summary(&summary).await.unwrap();
    }

    // Test pagination - get first 5
    let page1 = storage.list_scan_summaries(None, 5, 0).await.unwrap();
    assert_eq!(page1.len(), 5);

    // Get next 5 (skip 5)
    let page2 = storage.list_scan_summaries(None, 5, 5).await.unwrap();
    assert_eq!(page2.len(), 5);

    // All summaries should have unique IDs
    let mut all_ids: Vec<_> = page1.iter().chain(page2.iter()).map(|s| s.scan_id.to_string()).collect();
    let original_len = all_ids.len();
    all_ids.sort();
    all_ids.dedup();
    assert_eq!(all_ids.len(), original_len, "All scan IDs should be unique");
}

/// Helper to create a default FindingStats for tests (since the struct doesn't impl Default)
fn make_default_finding_stats() -> FindingStats {
    use std::collections::HashMap as Map;
    FindingStats {
        total: 0, by_severity: Map::new(), by_confidence: Map::new(), by_category: Map::new(),
        by_plugin: Map::new(), verified: 0, false_positives: 0, avg_risk_score: 0.0, max_risk_score: 0,
        by_owasp_category: Map::new(), by_cwe: Map::new(), avg_advanced_risk_score: 0.0,
        max_advanced_risk_score: 0, by_remediation_priority: Map::new(), exploit_available_count: 0, exploited_in_wild_count: 0,
    }
}