//! Binary analysis module for open-re

pub mod common;
pub mod elf;
pub mod macho;
pub mod metadata;
pub mod metrics;
pub mod pe;
pub mod static_analysis;
pub mod traits;
pub mod upload;
pub mod wasm;

// Re-export common types
pub use common::*;

// Explicit re-exports from traits (only non-conflicting types)
pub use traits::{
    BasicBlockInfo, BinaryIdentifier, BinaryMetadataExtractor, CallEdgeType, CallGraph,
    CallGraphEdge, CallGraphNode, CfgNode, ControlFlowGraph, ControlFlowInfo,
    DataDependency as TraitsDataDependency, DataDependencyType, FunctionInfo, InstructionInfo,
    InstructionType, StaticAnalyzer, VariableInfo as TraitsVariableInfo, VariableScope,
    VariableType,
};

pub use elf::{ElfIdentifier, ElfMetadataExtractor, ElfParser};
pub use macho::{MachoIdentifier, MachoMetadataExtractor, MachoParser};
pub use metadata::{MetadataExtractionService, ObjectStore as MetadataObjectStore};
pub use metrics::*;
pub use pe::{PeIdentifier, PeMetadataExtractor, PeParser};
pub use static_analysis::*;
pub use upload::{BinaryUploadService, ObjectStore as UploadObjectStore};
pub use wasm::{WasmIdentifier, WasmMetadataExtractor, WasmParser};
