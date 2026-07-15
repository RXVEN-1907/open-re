//! Core traits for open-re services

use async_trait::async_trait;
use crate::{ids::*, error::Result, JobStatus, JobProgress, AnalysisJob, AnalysisResult, AnalysisConfig, CreateAnalysisRequest, RequestContext};

/// Trait for analysis service
#[async_trait]
pub trait AnalysisService: Send + Sync {
    async fn create_analysis(&self, ctx: RequestContext, req: CreateAnalysisRequest) -> Result<AnalysisJob>;
    async fn execute_analysis(&self, job: AnalysisJob) -> Result<AnalysisResult>;
    async fn get_progress(&self, job_id: JobId) -> Result<JobProgress>;
    async fn cancel_analysis(&self, job_id: JobId, reason: String) -> Result<()>;
}

/// Trait for plugin service
#[async_trait]
pub trait PluginService: Send + Sync {
    async fn discover_plugins(&self) -> Result<Vec<PluginInfo>>;
    async fn load_plugin(&self, plugin_id: &PluginId) -> Result<LoadedPlugin>;
    async fn execute_capability(&self, plugin_id: &PluginId, cap: &str, input: serde_json::Value) -> Result<serde_json::Value>;
    async fn hot_reload(&self, plugin_id: &PluginId) -> Result<()>;
}

/// Trait for AI service
#[async_trait]
pub trait AiService: Send + Sync {
    async fn infer(&self, request: InferenceRequest) -> Result<InferenceResponse>;
    async fn batch_infer(&self, requests: Vec<InferenceRequest>) -> Result<Vec<InferenceResponse>>;
}

/// Trait for file service
#[async_trait]
pub trait FileService: Send + Sync {
    async fn upload(&self, ctx: RequestContext, stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>, metadata: FileMetadata) -> Result<FileRecord>;
    async fn identify_format(&self, file_id: FileId) -> Result<FileFormat>;
    async fn get_binary(&self, file_id: FileId) -> Result<IsolatedBinary>;
}

/// Trait for workspace service
#[async_trait]
pub trait WorkspaceService: Send + Sync {
    async fn create_project(&self, ctx: RequestContext, request: CreateProjectRequest) -> Result<Project>;
    async fn invite_collaborator(&self, ctx: RequestContext, project_id: ProjectId, email: String, role: CollaboratorRole) -> Result<CollaboratorInvite>;
    async fn create_share_link(&self, ctx: RequestContext, project_id: ProjectId, analysis_id: Option<AnalysisId>, permissions: SharePermissions, expires_in: Option<std::time::Duration>) -> Result<ShareLink>;
}

/// Trait for queue manager
#[async_trait]
pub trait QueueManager: Send + Sync {
    async fn enqueue(&self, job: AnalysisJob) -> Result<JobId>;
    async fn dequeue(&self, worker_id: &WorkerId, count: usize) -> Result<Vec<DequeuedJob>>;
    async fn ack(&self, worker_id: &WorkerId, stream: &str, entry_id: &str) -> Result<()>;
    async fn requeue(&self, job: AnalysisJob, delay: Option<std::time::Duration>) -> Result<()>;
    async fn move_to_dlq(&self, job: AnalysisJob, error: String) -> Result<()>;
    async fn cancel_job(&self, job_id: JobId, reason: String) -> Result<()>;
    async fn update_progress(&self, progress: JobProgress) -> Result<()>;
    async fn get_progress(&self, job_id: JobId) -> Result<Option<JobProgress>>;
    async fn get_queue_metrics(&self) -> Result<QueueMetrics>;
}

/// Trait for global storage (PostgreSQL)
#[async_trait]
pub trait GlobalStore: Send + Sync {
    async fn create_job(&self, job: &AnalysisJob) -> Result<()>;
    async fn complete_job(&self, job_id: JobId, result: &AnalysisResult) -> Result<()>;
    async fn update_job_status(&self, job_id: JobId, status: JobStatus) -> Result<()>;
    async fn create_project(&self, project: &Project) -> Result<()>;
    async fn init_project_db(&self, project_id: ProjectId) -> Result<()>;
    async fn add_collaborator(&self, project_id: ProjectId, user_id: UserId, role: CollaboratorRole) -> Result<()>;
    async fn create_invite(&self, invite: &CollaboratorInvite) -> Result<()>;
    async fn create_share_link(&self, link: &ShareLink) -> Result<()>;
    async fn update_file(&self, file: &FileRecord) -> Result<()>;
    async fn update_file_format(&self, file_id: FileId, format: FileFormat) -> Result<()>;
}

/// Trait for project storage (SQLite)
#[async_trait]
pub trait ProjectStore: Send + Sync {
    async fn ensure_schema(&self, project_id: ProjectId) -> Result<()>;
    async fn finalize(&self, project_id: ProjectId) -> Result<()>;
    async fn write_identification(&self, output: &IdentificationOutput) -> Result<()>;
    async fn write_disassembly(&self, output: &DisassemblyOutput) -> Result<()>;
    async fn write_control_flow(&self, output: &ControlFlowOutput) -> Result<()>;
    async fn write_data_flow(&self, output: &DataFlowOutput) -> Result<()>;
    async fn write_type_recovery(&self, output: &TypeRecoveryOutput) -> Result<()>;
    async fn write_decompilation(&self, output: &DecompilationOutput) -> Result<()>;
    async fn write_annotation(&self, annotation: &Annotation) -> Result<()>;
    async fn query(&self, sql: &str, params: Vec<serde_json::Value>) -> Result<Vec<serde_json::Value>>;
}

/// Trait for object storage
#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put_stream(&self, file_id: FileId, stream: &mut (dyn tokio::io::AsyncRead + Unpin + Send)) -> Result<(u64, String)>;
    async fn get_object(&self, file_id: FileId) -> Result<Box<dyn tokio::io::AsyncRead + Unpin + Send>>;
    async fn put(&self, path: &str, data: Vec<u8>) -> Result<()>;
    async fn get(&self, path: &str) -> Result<Vec<u8>>;
    async fn delete(&self, path: &str) -> Result<()>;
    async fn delete_file(&self, file_id: FileId) -> Result<()>;
}

// Placeholder types - will be defined in respective crates
pub struct PluginInfo;
pub struct LoadedPlugin;
pub struct InferenceRequest;
pub struct InferenceResponse;
pub struct FileMetadata;
pub struct FileRecord;
pub struct IsolatedBinary;
pub struct FileFormat;
pub struct CreateProjectRequest;
pub struct Project;
pub struct CollaboratorInvite;
pub struct CollaboratorRole;
pub struct ShareLink;
pub struct SharePermissions;
pub struct IdentificationOutput;
pub struct DisassemblyOutput;
pub struct ControlFlowOutput;
pub struct DataFlowOutput;
pub struct TypeRecoveryOutput;
pub struct DecompilationOutput;
pub struct Annotation;
pub struct DequeuedJob;
pub struct QueueMetrics;
pub struct RequestContext;