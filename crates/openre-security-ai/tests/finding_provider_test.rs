mod mock_provider;

use mock_provider::MockFindingProvider;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Category, Confidence, Finding, FindingConfig, Severity};
use openre_security_ai::{FindingProvider, ScanMetadata};

#[tokio::test]
async fn test_mock_finding_provider() {
    let provider = MockFindingProvider::new();

    // Create a scan ID
    let scan_id = ScanId::new();

    // Create a mock finding
    let finding = Finding::new(FindingConfig {
        title: "Test Finding".to_string(),
        description: "This is a test finding".to_string(),
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: Category::Injection,
        target: "http://example.com/test".to_string(),
        target_type: "web_application".to_string(),
        plugin_source: "test_plugin".to_string(),
        plugin_version: "1.0.0".to_string(),
        scan_id,
    });

    let finding_id = finding.id;

    // Add finding to provider
    provider.add_finding(scan_id, finding.clone()).await;

    // Add scan metadata
    let metadata = ScanMetadata {
        scan_id,
        target: "http://example.com".to_string(),
        started_at: chrono::Utc::now(),
        completed_at: None,
        finding_count: 1,
        status: "completed".to_string(),
    };
    provider.add_scan_metadata(metadata.clone()).await;

    // Test getting the finding
    let retrieved = provider.get_finding(scan_id, finding_id).await.unwrap();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.title, "Test Finding");
    assert_eq!(retrieved.severity, Severity::High);

    // Test getting scan metadata
    let retrieved_metadata = provider.get_scan_metadata(scan_id).await.unwrap();
    assert_eq!(retrieved_metadata.target, "http://example.com");
    assert_eq!(retrieved_metadata.finding_count, 1);

    // Test listing findings
    let findings = provider.list_findings(scan_id, None).await.unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].title, "Test Finding");
}
