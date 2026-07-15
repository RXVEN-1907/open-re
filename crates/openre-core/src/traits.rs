//! Core traits for open-re services

use async_trait::async_trait;
use crate::{ids::*, error::Result};

/// Trait for analysis service
#[async_trait]
pub trait AnalysisService: Send + Sync {
    async fn create_analysis(&self, job_id: JobId) -> Result<()>;
    async fn execute_analysis(&self, job_id: JobId) -> Result<()>;
    async fn get_progress(&self, job_id: JobId) -> Result<()>;
    async fn cancel_analysis(&self, job_id: JobId, reason: String) -> Result<()>;
}

/// Trait for plugin service
#[async_trait]
pub trait PluginService: Send + Sync {
    async fn discover_plugins(&self) -> Result<Vec<String>>;
    async fn load_plugin(&self, plugin_id: &PluginId) -> Result<()>;
    async fn execute_capability(&self, plugin_id: &PluginId, cap: &str, input: serde_json::Value) -> Result<serde_json::Value>;
    async fn hot_reload(&self, plugin_id: &PluginId) -> Result<()>;
}

/// Trait for AI service
#[async_trait]
pub trait AiService: Send + Sync {
    async fn infer(&self, request: String) -> Result<String>;
    async fn batch_infer(&self, requests: Vec<String>) -> Result<Vec<String>>;
}

/// Trait for file service
#[async_trait]
pub trait FileService: Send + Sync {
    async fn upload(&self, file_id: FileId, stream: Box<dyn tokio::io::AsyncRead + Unpin + Send>) -> Result<()>;
    async fn identify_format(&self, file_id: FileId) -> Result<String>;
    async fn get_binary(&self, file_id: FileId) -> Result<()>;
}

/// Trait for workspace service
#[async_trait]
pub trait WorkspaceService: Send + Sync {
    async fn create_project(&self, name: String) -> Result<ProjectId>;
    async fn invite_collaborator(&self, project_id: ProjectId, email: String) -> Result<()>;
    async fn create_share_link(&self, project_id: ProjectId) -> Result<String>;
}

/// Trait for queue manager
#[async_trait]
pub trait QueueManager: Send + Sync {
    async fn enqueue(&self, job_id: JobId) -> Result<()>;
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