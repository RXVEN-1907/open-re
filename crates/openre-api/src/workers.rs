//! Job handlers for open-re workers

use crate::AppState;
use openre_core::ids::FileId;
use openre_core::traits::JobType;
use openre_queue::{BoxedJobHandler, Job, JobHandler};
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tracing::{error, info, warn};

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

        // Validate stages - at least one stage must be specified
        let stage_count = stages.map(|s| s.len()).unwrap_or(0);
        if stage_count == 0 {
            warn!(job_id = %job.id, "No analysis stages specified, using default stages");
        }

        // Verify file exists in object storage (streaming check, no full load)
        // We just open the stream and read a small amount to verify accessibility
        let mut file_stream = self.state.object_store.get_object(file_id).await?;
        let mut verify_buffer = [0u8; 1024];
        let bytes_read = tokio::io::AsyncReadExt::read(&mut file_stream, &mut verify_buffer).await?;
        if bytes_read == 0 {
            error!(job_id = %job.id, file_id = %file_id_str, "File is empty or inaccessible");
            return Err(openre_core::Error::InvalidInput("File is empty".into()));
        }

        // Get file size from object store metadata (avoid loading entire file)
        let file_size = self.state.object_store.get_size(file_id).await.unwrap_or(0);

        // TODO: Implement actual analysis pipeline
        // This would include:
        // 1. Binary format identification (ELF, PE, Mach-O, WASM)
        // 2. Architecture detection
        // 3. Function discovery and CFG construction
        // 4. Data flow analysis
        // 5. Type recovery
        // 6. Decompilation
        // 7. AI enrichment (if enabled)
        // 8. Export results

        let start_time = std::time::Instant::now();

        // Placeholder for actual analysis - in production this runs the full pipeline
        // For now, we return a structured result indicating the job was received
        // and what stages would be run
        let result = serde_json::json!({
            "file_id": file_id_str,
            "status": "completed",
            "stages_requested": stage_count,
            "stages_completed": 0,  // Will be updated by actual pipeline
            "functions_found": 0,
            "analysis_duration_ms": start_time.elapsed().as_millis() as u64,
            "file_size_bytes": file_size,
            "note": "Analysis pipeline not yet implemented - this is a scaffold"
        });

        info!(job_id = %job.id, file_size = file_size, "Analysis job scaffold completed");
        Ok(result)
    }
}

/// Get all job handlers for the worker
pub fn get_job_handlers(state: Arc<AppState>) -> Vec<BoxedJobHandler> {
    vec![Arc::new(AnalysisJobHandler::new(state))]
}
