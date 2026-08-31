// crates/openre-analysis/tests/progress_test.rs
use openre_analysis::progress::{
    JobProgress, JobStatus, ProgressTracker, StageProgress, StageStatus,
};
use openre_core::ids::{JobId, StageId, WorkerId};
use std::sync::Arc;
use tokio::sync::broadcast;

#[tokio::test]
async fn test_progress_tracker_basic() {
    // Create tracker without queue (for testing)
    let tracker = ProgressTracker::new_for_testing();

    let job_id = openre_core::ids::JobId::new();
    let progress = JobProgress {
        job_id,
        status: JobStatus::Running {
            worker_id: WorkerId::new(),
            started_at: chrono::Utc::now(),
            stage: openre_core::ids::StageId::new("test"),
        },
        current_stage: Some(openre_core::ids::StageId::new("test")),
        stage_progress: 0.5,
        overall_progress: 0.25,
        message: "Testing".to_string(),
        started_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        estimated_remaining_secs: Some(100),
        stages: vec![],
    };

    tracker.update_progress(progress.clone()).await.unwrap();
    let retrieved = tracker.get_progress(job_id).await.unwrap();

    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().overall_progress, 0.25);
}

#[tokio::test]
async fn test_progress_subscription() {
    let tracker = ProgressTracker::new_for_testing();

    let mut rx = tracker.subscribe();

    let job_id = openre_core::ids::JobId::new();
    let progress = openre_analysis::progress::JobProgress {
        job_id,
        status: openre_analysis::progress::JobStatus::Running {
            worker_id: openre_core::ids::WorkerId::new(),
            started_at: chrono::Utc::now(),
            stage: openre_core::ids::StageId::new("test"),
        },
        current_stage: Some(openre_core::ids::StageId::new("test")),
        stage_progress: 0.5,
        overall_progress: 0.25,
        message: "Testing".to_string(),
        started_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        estimated_remaining_secs: Some(100),
        stages: vec![],
    };

    // Update progress in a separate task
    let job_id = openre_core::ids::JobId::new();
    let progress = openre_analysis::progress::JobProgress {
        job_id,
        status: openre_analysis::progress::JobStatus::Running {
            worker_id: openre_core::ids::WorkerId::new(),
            started_at: chrono::Utc::now(),
            stage: openre_core::ids::StageId::new("test"),
        },
        current_stage: Some(openre_core::ids::StageId::new("test")),
        stage_progress: 0.75,
        overall_progress: 0.5,
        message: "Testing".to_string(),
        started_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        estimated_remaining_secs: Some(100),
        stages: vec![],
    };

    // Update progress directly (can't clone tracker)
    openre_analysis::progress::ProgressTracker::update_progress_static(&tracker, progress)
        .await
        .unwrap();

    // Try to receive the progress update
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;
    assert!(result.is_ok());
    let received = result.unwrap();
    assert!(received.is_ok());
    assert_eq!(received.unwrap().overall_progress, 0.5);
}
