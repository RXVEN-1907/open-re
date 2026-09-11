//! Analysis pipeline for open-re

pub mod binary;
pub mod incremental;
pub mod metrics;
pub mod orchestrator;
pub mod progress;
pub mod stages;

// Explicit re-exports to avoid ambiguous glob re-exports
pub use binary::*;
pub use metrics::*;
pub use stages::*;

// Explicit re-exports from incremental (avoiding AnalysisResult conflict with orchestrator)
pub use incremental::{AnalysisChanges, IncrementalAnalyzer};

// Explicit re-exports from orchestrator (avoiding AnalysisResult, VariableInfo, StageStatus conflicts)
pub use orchestrator::{
    AnalysisConfig, AnalysisJob, AnalysisStatistics, AnalysisStatus, AnnotationInfo,
    BasicBlockInfo, CallEdgeInfo, CancellationToken, CfgEdgeInfo, ConstantInfo, ExecutorConfig,
    FunctionId, FunctionInfo, IdentificationOutput, InstructionInfo, IsolatedBinary, LoopInfo,
    Orchestrator, PipelineContext, PluginRegistry, ProjectStore, SpanGuard, StageContext, StageDag,
    StageExecutor, StringInfo, TelemetryHandle, TypeInfo, VariableInfo,
};

// Explicit re-exports from progress (avoiding StageStatus conflict with orchestrator)
pub use progress::{JobProgress, JobStatus, ProgressTracker, QueueManager, StageProgress};

// Re-export binary analysis types for use by other crates
pub use binary::common::{
    AnalysisSession, AnalysisStageStatus, Architecture, BasicBlock, BinaryFormat,
    BinaryIdentification, BinaryMetadata, BinaryUploadRequest, BinaryUploadResponse, Bitness,
    CallEdge, CallType, CfgEdge, CfgEdgeType, CompilerInfo, ControlFlowOutput, DataDependency,
    DataFlowOutput, DependencyType, DisassemblyOutput, Endianness, ExportInfo, ExtractedString,
    FileHashes, FunctionBoundary, ImportInfo, ImportedFunction, Instruction, LoopType, Operand,
    OperandKind, OperandType, OperatingSystem, RelroLevel, ResourceInfo, SectionCharacteristics,
    SectionInfo, SecurityFeatures, SegmentInfo, SegmentPermissions, StringEncoding, SymbolBinding,
    SymbolInfo, SymbolType, SymbolVisibility, TypeKind, TypeRecoveryOutput, TypeSource, Variable,
    VariableStorage, VersionInfo,
};

// Re-export AiService and NoopAiService from stages (not orchestrator) to avoid conflicts
pub use stages::{AiService, InferenceRequest, InferenceResponse, NoopAiService, TaskType};
