// crates/openre-analysis/tests/incremental_test.rs
use openre_analysis::{FingerprintIncrementalAnalyzer, Fingerprint, StageResult, StageMetrics};
use openre_analysis::orchestrator::StageStatus;
use openre_core::ids::{AnalysisId, StageId};
use tempfile::TempDir;
use chrono::Utc;
use serde_json::Value;

fn create_test_stage_result() -> StageResult {
    StageResult {
        stage_id: StageId::new("test"),
        status: StageStatus::Success,
        started_at: Utc::now(),
        completed_at: Utc::now(),
        output: Value::Null,
        metrics: StageMetrics::default(),
        artifacts: Vec::new(),
    }
}

#[tokio::test]
async fn test_fingerprint_change_detection() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("cache");
    let analyzer = FingerprintIncrementalAnalyzer::new(cache_dir).unwrap();

    let binary_path = temp.path().join("test.bin");
    std::fs::write(&binary_path, b"test binary content v1").unwrap();

    let analysis_id = AnalysisId::new();

    let results1 = tokio::time::timeout(std::time::Duration::from_secs(30), analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        let mut map = std::collections::HashMap::new();
        map.insert(StageId::new("identification"), create_test_stage_result());
        Ok(map)
    })).await.unwrap().unwrap();

    assert_eq!(results1.len(), 1);

    let results2 = tokio::time::timeout(std::time::Duration::from_secs(30), analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        panic!("Should not re-analyze unchanged binary");
    })).await.unwrap().unwrap();

    assert_eq!(results2.len(), 1);

    std::fs::write(&binary_path, b"test binary content v2").unwrap();
    let mut reanalyzed = false;
    let results3 = tokio::time::timeout(std::time::Duration::from_secs(30), analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        reanalyzed = true;
        let mut map = std::collections::HashMap::new();
        map.insert(StageId::new("identification"), create_test_stage_result());
        Ok(map)
    })).await.unwrap().unwrap();

    assert!(reanalyzed);
    assert_eq!(results3.len(), 1);
}

#[tokio::test]
async fn test_stage_level_invalidation() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("cache");
    let analyzer = FingerprintIncrementalAnalyzer::new(cache_dir).unwrap();

    let binary_path = temp.path().join("test.bin");
    std::fs::write(&binary_path, b"test").unwrap();
    let analysis_id = AnalysisId::new();

    tokio::time::timeout(std::time::Duration::from_secs(30), analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        let mut map = std::collections::HashMap::new();
        map.insert(StageId::new("identification"), create_test_stage_result());
        map.insert(StageId::new("disassembly"), create_test_stage_result());
        Ok(map)
    })).await.unwrap().unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(30), analyzer.invalidate_stage(&analysis_id, &StageId::new("disassembly"))).await.unwrap();

    let mut disassembly_ran = false;
    let results = tokio::time::timeout(std::time::Duration::from_secs(30), analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        let mut map = std::collections::HashMap::new();
        map.insert(StageId::new("identification"), create_test_stage_result());
        disassembly_ran = true;
        map.insert(StageId::new("disassembly"), create_test_stage_result());
        Ok(map)
    })).await.unwrap().unwrap();

    assert!(disassembly_ran);
}