//! Common types for binary analysis

use openre_core::ids::*;
use openre_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use chrono::{DateTime, Utc};

/// Binary file format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Unknown,
}

impl BinaryFormat {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        if bytes.len() >= 4 && &bytes[0..4] == b"\x7fELF" {
            BinaryFormat::Elf
        } else if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
            BinaryFormat::Pe
        } else if bytes.len() >= 4 && (&bytes[0..4] == b"\xfe\xed\xfa\xce" || &bytes[0..4] == b"\xce\xfa\xed\xfe") {
            BinaryFormat::MachO
        } else {
            BinaryFormat::Unknown
        }
    }
}

/// Architecture
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    PowerPc,
    PowerPc64,
    RiscV32,
    RiscV64,
    Unknown,
}

/// Endianness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Endianness {
    Little,
    Big,
}

/// Operating system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Linux,
    Windows,
    MacOS,
    FreeBSD,
    Android,
    IOS,
    Unknown,
}

/// Bitness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Bitness {
    Bit32,
    Bit64,
}

/// Security features
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityFeatures {
    pub aslr: bool,
    pub dep_nx: bool,
    pub pie: bool,
    pub relro: RelroLevel,
    pub stack_canary: bool,
    pub fortify_source: bool,
    pub cfi: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RelroLevel {
    None,
    Partial,
    Full,
}

impl Default for RelroLevel {
    fn default() -> Self {
        RelroLevel::None
    }
}

/// Binary identification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryIdentification {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub bitness: Bitness,
    pub endianness: Endianness,
    pub os: OperatingSystem,
    pub entry_point: Option<u64>,
    pub compiler_info: Option<CompilerInfo>,
    pub security_features: SecurityFeatures,
    pub confidence: f32,
}

/// Compiler information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    pub name: String,
    pub version: Option<String>,
    pub language: Option<String>,
}

/// Section information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub characteristics: SectionCharacteristics,
    pub entropy: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SectionCharacteristics {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub shared: bool,
    pub discardable: bool,
    pub not_cached: bool,
    pub not_paged: bool,
}

/// Segment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub permissions: SegmentPermissions,
    pub alignment: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SegmentPermissions {
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// Symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub symbol_type: SymbolType,
    pub binding: SymbolBinding,
    pub visibility: SymbolVisibility,
    pub section_index: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolType {
    Function,
    Object,
    Section,
    File,
    Common,
    Tls,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolBinding {
    Local,
    Global,
    Weak,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolVisibility {
    Default,
    Internal,
    Hidden,
    Protected,
    Unknown,
}

/// Import information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub library: String,
    pub functions: Vec<ImportedFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFunction {
    pub name: String,
    pub address: Option<u64>,
    pub ordinal: Option<u16>,
}

/// Export information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
    pub forwarder: Option<String>,
}

/// String extraction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub address: u64,
    pub length: usize,
    pub content: String,
    pub encoding: StringEncoding,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
    Utf16Be,
    Unknown,
}

/// Resource information (PE specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceInfo {
    pub resource_type: String,
    pub name: Option<String>,
    pub language: u16,
    pub size: u32,
    pub offset: u32,
}

/// Version information (PE specific)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub file_version: Option<String>,
    pub product_version: Option<String>,
    pub company_name: Option<String>,
    pub file_description: Option<String>,
    pub internal_name: Option<String>,
    pub legal_copyright: Option<String>,
    pub original_filename: Option<String>,
    pub product_name: Option<String>,
}

/// Binary metadata (complete extracted information)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub file_id: FileId,
    pub identification: BinaryIdentification,
    pub sections: Vec<SectionInfo>,
    pub segments: Vec<SegmentInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub strings: Vec<ExtractedString>,
    pub resources: Vec<ResourceInfo>,
    pub version_info: Option<VersionInfo>,
    pub hashes: FileHashes,
    pub analyzed_at: DateTime<Utc>,
}

/// File hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Analysis session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub id: AnalysisId,
    pub file_id: FileId,
    pub project_id: ProjectId,
    pub status: AnalysisStatus,
    pub stages: Vec<AnalysisStageStatus>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnalysisStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStageStatus {
    pub stage: String,
    pub status: AnalysisStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Binary upload request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryUploadRequest {
    pub project_id: ProjectId,
    pub file_name: String,
    pub file_data: Vec<u8>,
    pub description: Option<String>,
}

/// Binary upload response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryUploadResponse {
    pub file_id: FileId,
    pub analysis_id: AnalysisId,
    pub status: AnalysisStatus,
    pub message: String,
}

/// Identification output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentificationOutput {
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub compiler_info: Option<CompilerInfo>,
    pub confidence: f32,
}

/// Disassembly output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyOutput {
    pub function_boundaries: Vec<FunctionBoundary>,
    pub basic_blocks: Vec<BasicBlock>,
    pub instructions: Vec<Instruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionBoundary {
    pub id: FunctionId,
    pub address: u64,
    pub name: Option<String>,
    pub size: u64,
    pub start_block_id: Option<BasicBlockId>,
    pub end_block_id: Option<BasicBlockId>,
    pub is_entry: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BasicBlockId,
    pub function_id: FunctionId,
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
    pub instruction_count: u64,
    pub is_entry: bool,
    pub is_exit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub id: InstructionId,
    pub block_id: BasicBlockId,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub operand_types: Vec<OperandType>,
    pub groups: Vec<String>,
    pub size: u64,
    pub stack_change: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operand {
    pub kind: OperandKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperandKind {
    Register,
    Immediate,
    Memory,
    Expression,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperandType {
    Integer,
    Float,
    Address,
    Register,
    Unknown,
}

/// Control flow output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowOutput {
    pub cfg_edges: Vec<CfgEdge>,
    pub call_edges: Vec<CallEdge>,
    pub loops: Vec<LoopInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub id: CfgEdgeId,
    pub from_block_id: BasicBlockId,
    pub to_block_id: BasicBlockId,
    pub edge_type: CfgEdgeType,
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CfgEdgeType {
    Unconditional,
    Conditional,
    Call,
    Return,
    Indirect,
    Exception,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub id: CallEdgeId,
    pub from_function_id: FunctionId,
    pub to_function_id: FunctionId,
    pub call_site_address: u64,
    pub call_type: CallType,
    pub is_resolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallType {
    Direct,
    Indirect,
    Tail,
    Syscall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopInfo {
    pub id: LoopId,
    pub function_id: FunctionId,
    pub header_block_id: BasicBlockId,
    pub loop_type: LoopType,
    pub entry_edges: Vec<CfgEdgeId>,
    pub exit_edges: Vec<CfgEdgeId>,
    pub body_blocks: Vec<BasicBlockId>,
    pub depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoopType {
    While,
    DoWhile,
    For,
    Infinite,
    Unknown,
}

/// Data flow output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowOutput {
    pub variables: Vec<Variable>,
    pub data_dependencies: Vec<DataDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Variable {
    pub id: VariableId,
    pub function_id: FunctionId,
    pub name: String,
    pub type_id: Option<TypeId>,
    pub storage: VariableStorage,
    pub register: Option<String>,
    pub stack_offset: Option<i64>,
    pub size: u64,
    pub scope_start: Option<u64>,
    pub scope_end: Option<u64>,
    pub is_parameter: bool,
    pub is_return: bool,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariableStorage {
    Register,
    Stack,
    Global,
    Heap,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDependency {
    pub from: VariableId,
    pub to: VariableId,
    pub dependency_type: DependencyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DependencyType {
    Read,
    Write,
    ReadWrite,
}

/// Type recovery output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeRecoveryOutput {
    pub types: HashMap<TypeId, TypeInfo>,
    pub variables: Vec<Variable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeInfo {
    pub name: String,
    pub kind: TypeKind,
    pub size: Option<u64>,
    pub alignment: Option<u64>,
    pub definition: serde_json::Value,
    pub source: TypeSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeKind {
    Primitive,
    Pointer,
    Array,
    Struct,
    Union,
    Enum,
    Function,
    Void,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TypeSource {
    DebugInfo,
    Inferred,
    Manual,
    Imported,
}