//! Static analysis implementation

use anyhow::{anyhow, Result as AnyResult};
use async_trait::async_trait;
use goblin::{elf::Elf, pe::PE};
use serde::{Deserialize, Serialize};

use crate::binary::common::*;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_telemetry::metrics;
use tracing::{info, warn};

/// Static analysis service (high-level)
pub struct StaticAnalysisService;

impl StaticAnalysisService {
    pub fn new() -> Self {
        Self
    }

    /// Run static analysis on a binary
    pub async fn analyze(
        &self,
        _file_id: FileId,
        metadata: &BinaryMetadata,
    ) -> Result<StaticAnalysisResult> {
        let start = std::time::Instant::now();

        // Calculate entropy for each section
        let section_entropies = self.calculate_section_entropies(metadata).await?;

        // Find functions
        let functions = self.find_functions(metadata).await?;

        // Analyze control flow
        let control_flow = self.analyze_control_flow(metadata).await?;

        // Analyze data flow
        let data_flow = self.analyze_data_flow(metadata).await?;

        metrics::record_http_request("POST", 200, start.elapsed());

        Ok(StaticAnalysisResult { section_entropies, functions, control_flow, data_flow })
    }

    /// Calculate entropy for each section
    async fn calculate_section_entropies(
        &self,
        metadata: &BinaryMetadata,
    ) -> Result<Vec<SectionEntropy>> {
        let mut entropies = Vec::new();

        for section in &metadata.sections {
            if section.raw_size > 0 {
                // In a real implementation, we'd fetch the section data from object storage
                // For now, we'll use the entropy already calculated during metadata extraction
                entropies.push(SectionEntropy {
                    section_name: section.name.clone(),
                    entropy: section.entropy,
                    size: section.raw_size,
                });
            }
        }

        Ok(entropies)
    }

    /// Find functions in the binary
    async fn find_functions(&self, metadata: &BinaryMetadata) -> Result<Vec<FunctionInfo>> {
        let mut functions = Vec::new();

        // Use symbols as function candidates
        for symbol in &metadata.symbols {
            if symbol.symbol_type == SymbolType::Function {
                functions.push(FunctionInfo {
                    address: symbol.address,
                    size: symbol.size,
                    name: Some(symbol.name.clone()),
                    is_thunk: false,
                    is_import: symbol.binding == SymbolBinding::Global
                        && symbol.visibility == SymbolVisibility::Default,
                    basic_blocks: Vec::new(), // Would need disassembly
                    calls: Vec::new(),
                    called_by: Vec::new(),
                    complexity: 0,
                });
            }
        }

        // Also check exports
        for export in &metadata.exports {
            functions.push(FunctionInfo {
                address: export.address,
                size: 0,
                name: Some(export.name.clone()),
                is_thunk: false,
                is_import: false,
                basic_blocks: Vec::new(),
                calls: Vec::new(),
                called_by: Vec::new(),
                complexity: 0,
            });
        }

        Ok(functions)
    }

    /// Analyze control flow
    async fn analyze_control_flow(&self, metadata: &BinaryMetadata) -> Result<ControlFlowInfo> {
        let functions = self.find_functions(metadata).await?;

        // Build call graph from imports/exports
        let mut call_graph = CallGraph { nodes: Vec::new(), edges: Vec::new() };

        // Add function nodes
        for func in &functions {
            call_graph.nodes.push(CallGraphNode {
                address: func.address,
                name: func.name.clone(),
                is_external: func.is_import,
            });
        }

        // Add import edges
        for import in &metadata.imports {
            for func in &import.functions {
                call_graph.nodes.push(CallGraphNode {
                    address: func.address.unwrap_or(0),
                    name: Some(format!("{}!{}", import.library, func.name)),
                    is_external: true,
                });
            }
        }

        // Build CFG (simplified)
        let cfg = ControlFlowGraph { nodes: Vec::new(), edges: Vec::new() };

        Ok(ControlFlowInfo { functions, call_graph, cfg })
    }

    /// Analyze data flow
    async fn analyze_data_flow(&self, metadata: &BinaryMetadata) -> Result<DataFlowInfo> {
        // Simplified data flow analysis
        Ok(DataFlowInfo { variables: Vec::new(), data_dependencies: Vec::new() })
    }
}

/// Static analyzer implementation (implements the StaticAnalyzer trait)
pub struct StaticAnalyzerImpl;

impl Default for StaticAnalyzerImpl {
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl StaticAnalyzer for StaticAnalyzerImpl {
    async fn calculate_entropy(&self, data: &[u8]) -> Result<f64> {
        if data.is_empty() {
            return Ok(0.0);
        }
        let mut counts = [0u64; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        Ok(entropy)
    }

    async fn find_functions(
        &self,
        data: &[u8],
        metadata: &BinaryMetadata,
    ) -> Result<Vec<FunctionInfo>> {
        let mut functions = Vec::new();

        // First, use symbols from metadata
        for symbol in &metadata.symbols {
            if symbol.symbol_type == SymbolType::Function {
                functions.push(FunctionInfo {
                    address: symbol.address,
                    size: symbol.size.max(1),
                    name: Some(symbol.name.clone()),
                    is_thunk: false,
                    is_import: symbol.binding == SymbolBinding::Global
                        && symbol.visibility == SymbolVisibility::Default,
                    basic_blocks: Vec::new(),
                    calls: Vec::new(),
                    called_by: Vec::new(),
                    complexity: 1,
                });
            }
        }

        // Also check exports
        for export in &metadata.exports {
            if !functions.iter().any(|f| f.address == export.address) {
                functions.push(FunctionInfo {
                    address: export.address,
                    size: 0,
                    name: Some(export.name.clone()),
                    is_thunk: false,
                    is_import: false,
                    basic_blocks: Vec::new(),
                    calls: Vec::new(),
                    called_by: Vec::new(),
                    complexity: 1,
                });
            }
        }

        // For ELF/PE, try to find additional functions via disassembly
        match metadata.identification.format {
            BinaryFormat::Elf => {
                if let Ok(elf) = Elf::parse(data) {
                    functions.extend(self.find_elf_functions(&elf, data)?);
                }
            }
            BinaryFormat::Pe => {
                if let Ok(pe) = PE::parse(data) {
                    functions.extend(self.find_pe_functions(&pe, data)?);
                }
            }
            _ => {}
        }

        // Sort and deduplicate
        functions.sort_by_key(|f| f.address);
        functions.dedup_by_key(|f| f.address);

        Ok(functions)
    }

    async fn analyze_control_flow(
        &self,
        data: &[u8],
        metadata: &BinaryMetadata,
    ) -> Result<ControlFlowInfo> {
        let functions = self.find_functions(data, metadata).await?;

        // Build call graph
        let mut call_graph = CallGraph { nodes: Vec::new(), edges: Vec::new() };

        // Add function nodes
        for func in &functions {
            call_graph.nodes.push(CallGraphNode {
                address: func.address,
                name: func.name.clone(),
                is_external: func.is_import,
            });
        }

        // Add import nodes
        for import in &metadata.imports {
            for func in &import.functions {
                call_graph.nodes.push(CallGraphNode {
                    address: func.address.unwrap_or(0),
                    name: Some(format!("{}!{}", import.library, func.name)),
                    is_external: true,
                });
            }
        }

        // Build basic CFG for each function (simplified)
        let mut cfg_nodes = Vec::new();
        let mut cfg_edges = Vec::new();

        for func in &functions {
            if func.size > 0 {
                // Create a basic block for the function
                cfg_nodes.push(CfgNode {
                    address: func.address,
                    function_address: func.address,
                    basic_block: BasicBlockInfo {
                        address: func.address,
                        size: func.size,
                        instructions: Vec::new(),
                        predecessors: Vec::new(),
                        successors: Vec::new(),
                    },
                });
            }
        }

        let cfg = ControlFlowGraph { nodes: cfg_nodes, edges: cfg_edges };

        Ok(ControlFlowInfo { functions, call_graph, cfg })
    }

    async fn analyze_data_flow(
        &self,
        data: &[u8],
        metadata: &BinaryMetadata,
    ) -> Result<DataFlowInfo> {
        // Simplified data flow analysis - would need full disassembly
        Ok(DataFlowInfo { variables: Vec::new(), data_dependencies: Vec::new() })
    }
}

impl StaticAnalyzerImpl {
    /// Find functions in ELF binary using disassembly
    fn find_elf_functions(&self, elf: &Elf, data: &[u8]) -> AnyResult<Vec<FunctionInfo>> {
        let mut functions = Vec::new();

        // Look for functions in .text section
        for section in &elf.section_headers {
            if section.sh_type == goblin::elf::section_header::SHT_PROGBITS {
                if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                    if name == ".text" || name.starts_with(".text.") {
                        // Would do actual disassembly here
                        // For now, just add entry point if in this section
                        if elf.entry >= section.sh_addr
                            && elf.entry < section.sh_addr + section.sh_size
                        {
                            functions.push(FunctionInfo {
                                address: elf.entry as u64,
                                size: section.sh_size,
                                name: Some("_start".to_string()),
                                is_thunk: false,
                                is_import: false,
                                basic_blocks: Vec::new(),
                                calls: Vec::new(),
                                called_by: Vec::new(),
                                complexity: 1,
                            });
                        }
                    }
                }
            }
        }

        Ok(functions)
    }

    /// Find functions in PE binary using disassembly
    fn find_pe_functions(&self, pe: &PE, data: &[u8]) -> AnyResult<Vec<FunctionInfo>> {
        let mut functions = Vec::new();

        // Add entry point
        functions.push(FunctionInfo {
            address: pe.entry as u64 + pe.image_base as u64,
            size: 0,
            name: Some("entry".to_string()),
            is_thunk: false,
            is_import: false,
            basic_blocks: Vec::new(),
            calls: Vec::new(),
            called_by: Vec::new(),
            complexity: 1,
        });

        Ok(functions)
    }
}

/// Section entropy information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub section_name: String,
    pub entropy: f64,
    pub size: u64,
}

/// Static analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisResult {
    pub section_entropies: Vec<SectionEntropy>,
    pub functions: Vec<FunctionInfo>,
    pub control_flow: ControlFlowInfo,
    pub data_flow: DataFlowInfo,
}
