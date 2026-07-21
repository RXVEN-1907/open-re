//! Traits for binary analysis

use crate::binary::common::*;
use openre_core::error::Result;
use async_trait::async_trait;

/// Trait for binary format identification
#[async_trait]
pub trait BinaryIdentifier: Send + Sync {
    fn format(&self) -> BinaryFormat;
    
    async fn identify(&self, data: &[u8]) -> Result<BinaryIdentification>;
    
    fn can_handle(&self, data: &[u8]) -> bool {
        BinaryFormat::from_bytes(data) == self.format()
    }
}

/// Trait for binary metadata extraction
#[async_trait]
pub trait BinaryMetadataExtractor: Send + Sync {
    fn format(&self) -> BinaryFormat;
    
    async fn extract_metadata(&self, data: &[u8]) -> Result<BinaryMetadata>;
    
    async fn extract_sections(&self, data: &[u8]) -> Result<Vec<SectionInfo>>;
    
    async fn extract_segments(&self, data: &[u8]) -> Result<Vec<SegmentInfo>>;
    
    async fn extract_symbols(&self, data: &[u8]) -> Result<Vec<SymbolInfo>>;
    
    async fn extract_imports(&self, data: &[u8]) -> Result<Vec<ImportInfo>>;
    
    async fn extract_exports(&self, data: &[u8]) -> Result<Vec<ExportInfo>>;
    
    async fn extract_strings(&self, data: &[u8]) -> Result<Vec<ExtractedString>>;
    
    async fn extract_resources(&self, data: &[u8]) -> Result<Vec<ResourceInfo>>;
    
    async fn extract_version_info(&self, data: &[u8]) -> Result<Option<VersionInfo>>;
}

/// Trait for static analysis
#[async_trait]
pub trait StaticAnalyzer: Send + Sync {
    async fn calculate_entropy(&self, data: &[u8]) -> Result<f64>;
    
    async fn find_functions(&self, data: &[u8], metadata: &BinaryMetadata) -> Result<Vec<FunctionInfo>>;
    
    async fn analyze_control_flow(&self, data: &[u8], metadata: &BinaryMetadata) -> Result<ControlFlowInfo>;
    
    async fn analyze_data_flow(&self, data: &[u8], metadata: &BinaryMetadata) -> Result<DataFlowInfo>;
}

/// Function information from static analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub size: u64,
    pub name: Option<String>,
    pub is_thunk: bool,
    pub is_import: bool,
    pub basic_blocks: Vec<BasicBlockInfo>,
    pub calls: Vec<u64>,
    pub called_by: Vec<u64>,
    pub complexity: u32,
}

/// Basic block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlockInfo {
    pub address: u64,
    pub size: u64,
    pub instructions: Vec<InstructionInfo>,
    pub predecessors: Vec<u64>,
    pub successors: Vec<u64>,
}

/// Instruction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionInfo {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub instruction_type: InstructionType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstructionType {
    Normal,
    Call,
    Jump,
    ConditionalJump,
    Return,
    Syscall,
    Unknown,
}

/// Control flow information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowInfo {
    pub functions: Vec<FunctionInfo>,
    pub call_graph: CallGraph,
    pub cfg: ControlFlowGraph,
}

/// Call graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: Vec<CallGraphNode>,
    pub edges: Vec<CallGraphEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphNode {
    pub address: u64,
    pub name: Option<String>,
    pub is_external: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphEdge {
    pub from: u64,
    pub to: u64,
    pub edge_type: CallEdgeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CallEdgeType {
    Direct,
    Indirect,
    Virtual,
}

/// Control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub nodes: Vec<CfgNode>,
    pub edges: Vec<CfgEdge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode {
    pub address: u64,
    pub function_address: u64,
    pub basic_block: BasicBlockInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: u64,
    pub to: u64,
    pub edge_type: CfgEdgeType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CfgEdgeType {
    Fallthrough,
    Branch,
    Call,
    Return,
    Indirect,
}

/// Data flow information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowInfo {
    pub variables: Vec<VariableInfo>,
    pub data_dependencies: Vec<DataDependency>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableInfo {
    pub address: u64,
    pub name: Option<String>,
    pub var_type: VariableType,
    pub size: u64,
    pub scope: VariableScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariableType {
    Integer,
    Float,
    Pointer,
    Array,
    Struct,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VariableScope {
    Global,
    Local,
    Parameter,
    Register,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataDependency {
    pub from: u64,
    pub to: u64,
    pub dependency_type: DataDependencyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataDependencyType {
    Read,
    Write,
    ReadWrite,
}