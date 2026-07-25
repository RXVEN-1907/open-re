//! Core traits for open-re services

use async_trait::async_trait;
use crate::{ids::*, error::OpenreResult};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Result type alias for open-re operations
pub type Result<T> = OpenreResult<T>;

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

// Job types for the queue system
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobType {
    Analysis,
    Identification,
    Disassembly,
    ControlFlow,
    DataFlow,
    TypeRecovery,
    Decompilation,
    AiEnrichment,
    Export,
    Import,
    PluginExecution,
    Custom(String),
}

impl JobType {
    pub fn as_str(&self) -> &str {
        match self {
            JobType::Analysis => "analysis",
            JobType::Identification => "identification",
            JobType::Disassembly => "disassembly",
            JobType::ControlFlow => "control_flow",
            JobType::DataFlow => "data_flow",
            JobType::TypeRecovery => "type_recovery",
            JobType::Decompilation => "decompilation",
            JobType::AiEnrichment => "ai_enrichment",
            JobType::Export => "export",
            JobType::Import => "import",
            JobType::PluginExecution => "plugin_execution",
            JobType::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for JobType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for JobType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "analysis" => Ok(JobType::Analysis),
            "identification" => Ok(JobType::Identification),
            "disassembly" => Ok(JobType::Disassembly),
            "control_flow" => Ok(JobType::ControlFlow),
            "data_flow" => Ok(JobType::DataFlow),
            "type_recovery" => Ok(JobType::TypeRecovery),
            "decompilation" => Ok(JobType::Decompilation),
            "ai_enrichment" => Ok(JobType::AiEnrichment),
            "export" => Ok(JobType::Export),
            "import" => Ok(JobType::Import),
            "plugin_execution" => Ok(JobType::PluginExecution),
            _ => Ok(JobType::Custom(s.to_string())),
        }
    }
}

// Placeholder types - will be defined in respective crates
pub struct PluginInfo;
pub struct LoadedPlugin;
pub struct InferenceRequest;
pub struct InferenceResponse;
pub struct FileMetadata;

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub id: FileId,
    pub project_id: ProjectId,
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub format: Option<FileFormat>,
    pub architecture: Option<Architecture>,
    pub compiler_info: Option<serde_json::Value>,
    pub status: FileStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Uploading,
    Uploaded,
    Identifying,
    Ready,
    Failed,
    Deleted,
}

impl FileStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileStatus::Uploading => "uploading",
            FileStatus::Uploaded => "uploaded",
            FileStatus::Identifying => "identifying",
            FileStatus::Ready => "ready",
            FileStatus::Failed => "failed",
            FileStatus::Deleted => "deleted",
        }
    }
}

#[derive(Default)]
pub struct IsolatedBinary;

pub struct CreateProjectRequest;

#[derive(Debug, Clone)]
pub struct Project {
    pub id: ProjectId,
    pub name: String,
    pub description: String,
    pub owner_id: UserId,
    pub visibility: String,
    pub settings: serde_json::Value,
    pub sqlite_path: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct CollaboratorInvite {
    pub id: Uuid,
    pub project_id: ProjectId,
    pub email: String,
    pub role: CollaboratorRole,
    pub invited_by: UserId,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollaboratorRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl CollaboratorRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            CollaboratorRole::Owner => "owner",
            CollaboratorRole::Admin => "admin",
            CollaboratorRole::Member => "member",
            CollaboratorRole::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShareLink {
    pub id: ShareLinkId,
    pub project_id: ProjectId,
    pub analysis_id: Option<AnalysisId>,
    pub permissions: SharePermissions,
    pub token: String,
    pub created_by: UserId,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePermissions {
    pub can_view: bool,
    pub can_comment: bool,
    pub can_download: bool,
}

#[derive(Debug, Clone)]
pub struct IdentificationOutput {
    pub format: FileFormat,
    pub architecture: Architecture,
    pub compiler_info: serde_json::Value,
    pub confidence: f32,
}

pub struct DisassemblyOutput;
pub struct ControlFlowOutput;
pub struct DataFlowOutput;
pub struct TypeRecoveryOutput;
pub struct DecompilationOutput;

#[derive(Debug, Clone)]
pub struct Annotation {
    pub address: u64,
    pub annotation_type: AnnotationType,
    pub value: String,
    pub function_id: Option<FunctionId>,
    pub created_by: AnnotationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnotationType {
    Comment,
    Name,
    Type,
    Bookmark,
    Label,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnnotationSource {
    User,
    Ai,
    Plugin,
    Signature,
}

pub struct DequeuedJob;
pub struct QueueMetrics;
pub struct RequestContext;

#[derive(Debug, Clone)]
pub struct AnalysisJob {
    pub id: JobId,
    pub project_id: ProjectId,
    pub file_id: FileId,
    pub priority: i32,
    pub config: AnalysisConfig,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub retry_count: u32,
    pub max_retries: u32,
    pub idempotency_key: Option<String>,
    pub tags: Vec<String>,
    pub timeout_secs: u64,
    pub created_by: UserId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub stages: Vec<StageId>,
    pub priority: Priority,
    pub max_retries: u32,
    pub timeout_secs: u64,
    pub ai_enabled: bool,
    pub incremental: bool,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            stages: StageId::all_ordered(),
            priority: Priority::DEFAULT,
            max_retries: 3,
            timeout_secs: 3600,
            ai_enabled: true,
            incremental: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub job_id: JobId,
    pub status: JobStatus,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}