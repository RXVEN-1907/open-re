//! Analysis pipeline for open-re

pub mod orchestrator;
pub mod stages;
pub mod incremental;
pub mod progress;
pub mod metrics;
pub mod binary;

pub use orchestrator::*;
pub use stages::*;
pub use incremental::*;
pub use progress::*;
pub use metrics::*;
pub use binary::*;

// Re-export binary analysis types for use by other crates
pub use binary::common::{
    BinaryFormat, Architecture, Endianness, OperatingSystem, Bitness,
    SecurityFeatures, RelroLevel, BinaryIdentification, CompilerInfo,
    SectionInfo, SectionCharacteristics, SegmentInfo, SegmentPermissions,
    SymbolInfo, SymbolType, SymbolBinding, SymbolVisibility,
    ImportInfo, ImportedFunction, ExportInfo, ExtractedString, StringEncoding,
    ResourceInfo, VersionInfo, BinaryMetadata, FileHashes,
    AnalysisSession, AnalysisStatus, AnalysisStageStatus,
    BinaryUploadRequest, BinaryUploadResponse,
    IdentificationOutput, DisassemblyOutput, FunctionBoundary, BasicBlock, Instruction,
    Operand, OperandKind, OperandType, ControlFlowOutput, CfgEdge, CfgEdgeType,
    CallEdge, CallType, LoopInfo, LoopType, DataFlowOutput, Variable, VariableStorage,
    DataDependency, DependencyType, TypeRecoveryOutput, TypeInfo, TypeKind, TypeSource,
};