//! Analysis pipeline for open-re

pub mod binary;
pub mod incremental;
pub mod metrics;
pub mod orchestrator;
pub mod progress;
pub mod stages;

pub use binary::*;
pub use incremental::*;
pub use metrics::*;
pub use orchestrator::*;
pub use progress::*;
pub use stages::*;

// Re-export binary analysis types for use by other crates
pub use binary::common::{
    AnalysisSession, AnalysisStageStatus, AnalysisStatus, Architecture, BasicBlock, BinaryFormat,
    BinaryIdentification, BinaryMetadata, BinaryUploadRequest, BinaryUploadResponse, Bitness,
    CallEdge, CallType, CfgEdge, CfgEdgeType, CompilerInfo, ControlFlowOutput, DataDependency,
    DataFlowOutput, DependencyType, DisassemblyOutput, Endianness, ExportInfo, ExtractedString,
    FileHashes, FunctionBoundary, IdentificationOutput, ImportInfo, ImportedFunction, Instruction,
    LoopInfo, LoopType, Operand, OperandKind, OperandType, OperatingSystem, RelroLevel,
    ResourceInfo, SectionCharacteristics, SectionInfo, SecurityFeatures, SegmentInfo,
    SegmentPermissions, StringEncoding, SymbolBinding, SymbolInfo, SymbolType, SymbolVisibility,
    TypeInfo, TypeKind, TypeRecoveryOutput, TypeSource, Variable, VariableStorage, VersionInfo,
};

// Re-export AiService and NoopAiService from stages (not orchestrator) to avoid conflicts
pub use stages::{AiService, InferenceRequest, InferenceResponse, NoopAiService, TaskType};
