//! Job handlers for open-re workers

use crate::AppState;
use openre_core::ids::FileId;
use openre_core::traits::JobType;
use openre_queue::{BoxedJobHandler, Job, JobHandler};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{error, info};

/// Analysis job handler
pub struct AnalysisJobHandler {
    state: Arc<AppState>,
}

impl AnalysisJobHandler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[async_trait::async_trait]
impl JobHandler for AnalysisJobHandler {
    fn job_type(&self) -> JobType {
        JobType::Analysis
    }

    async fn handle(&self, job: Job) -> openre_core::error::OpenreResult<serde_json::Value> {
        info!(job_id = %job.id, "Starting analysis job");

        // Extract payload
        let file_id_str = job.payload.get("file_id").and_then(|v| v.as_str());
        let stages = job.payload.get("stages").and_then(|v| v.as_array());
        let _config = job.payload.get("config");

        let file_id_str = match file_id_str {
            Some(id) => id,
            None => {
                error!(job_id = %job.id, "No file_id in job payload");
                return Err(openre_core::Error::InvalidInput("Missing file_id".into()));
            }
        };

        // Parse file ID
        let file_id = file_id_str.parse::<FileId>().map_err(|_| {
            openre_core::Error::InvalidInput(format!("Invalid file_id: {}", file_id_str))
        })?;

        // Download file from object storage using file_id directly
        // The object store generates paths from file IDs
        let file_data = self.state.object_store.get_object(file_id).await?;

        // Read file data (for now just verify it exists)
        let mut file_data = file_data;
        let mut buffer = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file_data, &mut buffer).await?;

        // For now, just return a mock result
        // Real implementation would run the analysis pipeline
        let result = serde_json::json!({
            "file_id": file_id_str,
            "status": "completed",
            "stages": stages.map(|s| s.len()).unwrap_or(0),
            "functions_found": 0,
            "analysis_duration_ms": 0,
            "file_size_bytes": buffer.len(),
        });

        info!(job_id = %job.id, "Analysis job completed");
        Ok(result)
    }
}

/// Get all job handlers for the worker
pub fn get_job_handlers(state: Arc<AppState>) -> Vec<BoxedJobHandler> {
    vec![Arc::new(AnalysisJobHandler::new(state))]
}
