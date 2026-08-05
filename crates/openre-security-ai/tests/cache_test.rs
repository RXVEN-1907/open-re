use openre_security_ai::cache::{AnalysisCache, TaskType, AnalysisKey};
use openre_core::ids::{ScanId, FindingId};
use std::time::Duration;

#[tokio::test]
async fn test_cache_basic_operations() {
    let cache = AnalysisCache::new(100, 3600); // 100 entries, 1 hour TTL

    let scan_id = ScanId::new();
    let finding_id = FindingId::new();

    let key = AnalysisKey {
        scan_id,
        finding_id: Some(finding_id),
        task_type: TaskType::ExplainFinding,
        template_version: "1.0.0".to_string(),
    };

    // Test putting and getting
    let result = cache.put(key.clone(), "test result".to_string(), Some("test-model".to_string())).await;
    assert!(result.is_ok());

    let cached = cache.get(&key).await;
    assert!(cached.is_some());
    assert_eq!(cached.unwrap(), "test result");

    // Test stats
    let stats = cache.stats();
    assert_eq!(stats.active_entries, 1);
}

#[tokio::test]
async fn test_cache_invalidation() {
    let cache = AnalysisCache::new(100, 3600);

    let scan_id = ScanId::new();
    let finding_id1 = FindingId::new();
    let finding_id2 = FindingId::new();

    // Add entries for two findings
    let key1 = AnalysisKey {
        scan_id,
        finding_id: Some(finding_id1),
        task_type: TaskType::ExplainFinding,
        template_version: "1.0.0".to_string(),
    };

    let key2 = AnalysisKey {
        scan_id,
        finding_id: Some(finding_id2),
        task_type: TaskType::ExplainFinding,
        template_version: "1.0.0".to_string(),
    };

    cache.put(key1.clone(), "result 1".to_string(), None).await.unwrap();
    cache.put(key2.clone(), "result 2".to_string(), None).await.unwrap();

    // Verify both are cached
    assert!(cache.get(&key1).await.is_some());
    assert!(cache.get(&key2).await.is_some());

    // Invalidate first finding
    cache.invalidate_finding(scan_id, finding_id1).await;

    // First should be gone, second should remain
    assert!(cache.get(&key1).await.is_none());
    assert!(cache.get(&key2).await.is_some());
}