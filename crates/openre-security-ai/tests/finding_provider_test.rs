use openre_security_ai::{FindingProvider, MockFindingProvider, ScanMetadata};
use openre_core::result::{Finding, Severity, Confidence, Category};
use openre_core::ids::{ScanId, FindingId};

#[tokio::test]
async fn test_mock_finding_provider() {
    let provider = MockFindingProvider::new();

    // Create a scan ID and finding
    let scan_id = ScanId::new();
    let finding_id = FindingId::new();

    // Create a mock finding
    let finding = Finding::new(
        "Test Finding".to_string(),
        "This is a test finding".to_string(),
        Severity::High,
        Confidence::Medium,
        Category::Injection,
        "http://example.com/test".to_string(),
        "web_application".to_string(),
        "test_plugin".to_string(),
        "1.0.0".to_string(),
        scan_id,
    );

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