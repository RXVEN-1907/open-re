//! Metrics collection for analysis pipeline

use openre_core::ids::StageId;
use openre_telemetry::metrics;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::debug;

/// Pipeline metrics collector
pub struct PipelineMetrics {
    stage_durations: Arc<RwLock<HashMap<StageId, Vec<Duration>>>>,
    stage_memory: Arc<RwLock<HashMap<StageId, Vec<u64>>>>,
    stage_success_rate: Arc<RwLock<HashMap<StageId, (u64, u64)>>>,
    function_counts: Arc<RwLock<HashMap<StageId, Vec<u64>>>>,
    instruction_counts: Arc<RwLock<HashMap<StageId, Vec<u64>>>>,
}

impl PipelineMetrics {
    pub fn new() -> Self {
        Self {
            stage_durations: Arc::new(RwLock::new(HashMap::new())),
            stage_memory: Arc::new(RwLock::new(HashMap::new())),
            stage_success_rate: Arc::new(RwLock::new(HashMap::new())),
            function_counts: Arc::new(RwLock::new(HashMap::new())),
            instruction_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn record_stage(&self, stage_id: StageId, result: &StageResult) {
        // Record duration
        let duration = result.completed_at - result.started_at;
        self.stage_durations.write().await
            .entry(stage_id)
            .or_default()
            .push(duration);

        // Record memory
        self.stage_memory.write().await
            .entry(stage_id)
            .or_default()
            .push(result.metrics.memory_peak_mb);

        // Record success rate
        let (success, total) = self.stage_success_rate.write().await
            .entry(stage_id)
            .or_default();
        *total += 1;
        if result.status == StageStatus::Success {
            *success += 1;
        }

        // Record function count
        self.function_counts.write().await
            .entry(stage_id)
            .or_default()
            .push(result.metrics.functions_analyzed);

        // Record instruction count
        self.instruction_counts.write().await
            .entry(stage_id)
            .or_default()
            .push(result.metrics.instructions_processed);

        // Emit to global metrics
        metrics::record_stage_completed(&stage_id.to_string(), duration, result.metrics.memory_peak_mb);
    }

    pub async fn get_summary(&self) -> PipelineSummary {
        let durations = self.stage_durations.read().await;
        let memory = self.stage_memory.read().await;
        let success_rates = self.stage_success_rate.read().await;
        let functions = self.function_counts.read().await;
        let instructions = self.instruction_counts.read().await;

        PipelineSummary {
            avg_stage_duration: durations.iter()
                .map(|(k, v)| (*k, v.iter().sum::<Duration>() / v.len() as u32))
                .collect(),
            avg_memory_mb: memory.iter()
                .map(|(k, v)| (*k, v.iter().sum::<u64>() / v.len() as u64))
                .collect(),
            success_rates: success_rates.iter()
                .map(|(k, (s, t))| (*k, *s as f64 / *t as f64))
                .collect(),
            throughput: instructions.iter()
                .map(|(k, v)| {
                    let total_instructions: u64 = v.iter().sum();
                    let total_duration: f64 = durations.get(k)
                        .map(|d| d.iter().map(|dur| dur.as_secs_f64()).sum::<f64>())
                        .unwrap_or(1.0);
                    (*k, total_instructions as f64 / total_duration)
                })
                .collect(),
        }
    }
}

impl Default for PipelineMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Pipeline metrics summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSummary {
    pub avg_stage_duration: HashMap<StageId, Duration>,
    pub avg_memory_mb: HashMap<StageId, u64>,
    pub success_rates: HashMap<StageId, f64>,
    pub throughput: HashMap<StageId, f64>, // instructions per second
}