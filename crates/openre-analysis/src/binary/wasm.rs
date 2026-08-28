//! WebAssembly Binary Parser

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use openre_core::ids::{FileId, VariableId};
use std::path::Path;
use wasmparser::{
    Export as WasmExport, ExternalKind, FuncType, Import as WasmImport, Parser, Payload, TypeRef,
};

use crate::binary::common::*;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as Result;
use openre_core::Error;

pub struct WasmParser;

impl WasmParser {
    pub fn parse(path: &Path) -> Result<BinaryInfo> {
        let bytes = std::fs::read(path)?;
        let parser = Parser::new(0);

        let mut info = BinaryInfo {
            format: BinaryFormat::Wasm,
            architecture: Architecture::Unknown,
            entry_point: 0,
            base_address: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
        };

        let mut function_names: Vec<String> = Vec::new();
        let mut export_names: Vec<(String, u32)> = Vec::new();

        for payload in parser.parse_all(&bytes) {
            match payload {
                Ok(Payload::Version { num, .. }) => {
                    info.sections.push(Section {
                        name: format!("WASM v{}", num),
                        address: 0,
                        size: 0,
                        flags: SectionFlags { readable: true, writable: false, executable: false },
                        data: None,
                    });
                }
                Ok(Payload::TypeSection(types)) => for _ in types {},
                Ok(Payload::FunctionSection(functions)) => {
                    for func in functions {
                        if let Ok(ty_idx) = func {
                            function_names.push(format!("func_{}", ty_idx));
                        }
                    }
                }
                Ok(Payload::ExportSection(exports_reader)) => {
                    for export in exports_reader {
                        if let Ok(WasmExport { name, kind, index }) = export {
                            if kind == ExternalKind::Func {
                                export_names.push((name.to_string(), index));
                            }
                            info.exports
                                .push(Export { name: name.to_string(), address: index as u64 });
                        }
                    }
                }
                Ok(Payload::ImportSection(imports_reader)) => {
                    for import in imports_reader {
                        if let Ok(WasmImport { module, name, ty }) = import {
                            if let TypeRef::Func(ty_index) = ty {
                                info.imports.push(Import {
                                    name: name.to_string(),
                                    library: Some(module.to_string()),
                                });
                            }
                        }
                    }
                }
                Ok(Payload::CodeSectionStart { count, range, .. }) => {
                    info.sections.push(Section {
                        name: "code".to_string(),
                        address: range.start as u64,
                        size: count as u64,
                        flags: SectionFlags { readable: true, writable: false, executable: true },
                        data: None,
                    });
                }
                Ok(Payload::DataSection(data_reader)) => {
                    for data in data_reader {
                        if let Ok(data) = data {
                            info.sections.push(Section {
                                name: format!("data_{}", data.range.start),
                                address: data.range.start as u64,
                                size: data.data.len() as u64,
                                flags: SectionFlags {
                                    readable: true,
                                    writable: true,
                                    executable: false,
                                },
                                data: Some(data.data.to_vec()),
                            });
                        }
                    }
                }
                Ok(Payload::CustomSection(custom)) => {
                    info.sections.push(Section {
                        name: custom.name().to_string(),
                        address: 0,
                        size: custom.data().len() as u64,
                        flags: SectionFlags { readable: true, writable: false, executable: false },
                        data: Some(custom.data().to_vec()),
                    });
                }
                Ok(Payload::ElementSection(_))
                | Ok(Payload::GlobalSection(_))
                | Ok(Payload::MemorySection(_))
                | Ok(Payload::TableSection(_)) => {}
                Ok(Payload::End(_)) => break,
                Err(e) => return Err(Error::Internal(anyhow!("WASM parse error: {}", e))),
                _ => {}
            }
        }

        for (idx, name) in function_names.iter().enumerate() {
            let is_export = export_names.iter().any(|(_, i)| *i == idx as u32);
            info.symbols.push(Symbol {
                name: name.clone(),
                address: idx as u64,
                size: 0,
                symbol_type: SymbolType::Function,
                binding: if is_export { SymbolBinding::Global } else { SymbolBinding::Local },
                section_index: 0,
            });
        }

        for section in &info.sections {
            if let Some(data) = &section.data {
                info.strings.extend(Self::extract_strings(data));
            }
        }

        Ok(info)
    }

    fn extract_strings(data: &[u8]) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current = String::new();

        for &b in data {
            if b == 0 {
                if current.len() >= 4 {
                    strings.push(current.clone());
                }
                current.clear();
            } else if b.is_ascii_graphic() || b == b' ' {
                current.push(b as char);
            } else {
                current.clear();
            }
        }

        strings
    }
}

/// WASM Binary Identifier
#[derive(Default)]
pub struct WasmIdentifier;

#[async_trait]
impl BinaryIdentifier for WasmIdentifier {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Wasm
    }

    async fn identify(&self, data: &[u8]) -> Result<BinaryIdentification> {
        if data.len() >= 8 && &data[0..4] == b"\x00asm" {
            let parser = Parser::new(0);
            let mut version = 0;

            for payload in parser.parse_all(data) {
                if let Ok(Payload::Version { num, .. }) = payload {
                    version = num;
                }
            }

            return Ok(BinaryIdentification {
                format: BinaryFormat::Wasm,
                architecture: Architecture::Unknown,
                bitness: Bitness::Bit32,
                endianness: Endianness::Little,
                os: OperatingSystem::Unknown,
                entry_point: None,
                compiler_info: Some(CompilerInfo {
                    name: "wasm".to_string(),
                    version: Some(version.to_string()),
                    language: Some("wasm".to_string()),
                }),
                security_features: SecurityFeatures::default(),
                confidence: 0.95,
            });
        }

        Err(openre_core::Error::Internal(anyhow::anyhow!("Not a WASM file")))
    }
}

/// WASM Metadata Extractor
#[derive(Default)]
pub struct WasmMetadataExtractor;

#[async_trait]
impl BinaryMetadataExtractor for WasmMetadataExtractor {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Wasm
    }

    async fn extract_metadata(&self, data: &[u8]) -> Result<BinaryMetadata> {
        let bytes = data.to_vec();
        let parser = Parser::new(0);

        let mut sections = Vec::new();
        let mut symbols = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        let mut function_names: Vec<String> = Vec::new();
        let mut export_names: Vec<(String, u32)> = Vec::new();

        for payload in parser.parse_all(&bytes) {
            match payload {
                Ok(Payload::TypeSection(_)) => {}
                Ok(Payload::FunctionSection(functions)) => {
                    for func in functions {
                        if let Ok(ty_idx) = func {
                            function_names.push(format!("func_{}", ty_idx));
                        }
                    }
                }
                Ok(Payload::ExportSection(exports_reader)) => {
                    for export in exports_reader {
                        if let Ok(WasmExport { name, kind, index }) = export {
                            if kind == ExternalKind::Func {
                                export_names.push((name.to_string(), index));
                            }
                            exports.push(ExportInfo {
                                name: name.to_string(),
                                address: index as u64,
                                ordinal: index as u16,
                                forwarder: None,
                            });
                        }
                    }
                }
                Ok(Payload::ImportSection(imports_reader)) => {
                    for import in imports_reader {
                        if let Ok(WasmImport { module, name, ty }) = import {
                            if let TypeRef::Func(ty_index) = ty {
                                imports.push(ImportInfo {
                                    library: module.to_string(),
                                    functions: vec![ImportedFunction {
                                        name: name.to_string(),
                                        address: None,
                                        ordinal: Some(ty_index as u16),
                                    }],
                                });
                            }
                        }
                    }
                }
                Ok(Payload::CodeSectionStart { count, range, .. }) => {
                    sections.push(SectionInfo {
                        name: "code".to_string(),
                        virtual_address: range.start as u64,
                        virtual_size: (range.end - range.start) as u64,
                        raw_offset: range.start as u64,
                        raw_size: (range.end - range.start) as u64,
                        characteristics: SectionCharacteristics {
                            readable: true,
                            writable: false,
                            executable: true,
                            shared: false,
                            discardable: false,
                            not_cached: false,
                            not_paged: false,
                        },
                        entropy: 0.0,
                    });
                }
                Ok(Payload::DataSection(data_reader)) => {
                    for data in data_reader {
                        if let Ok(data) = data {
                            let entropy = calculate_entropy(&data.data);
                            sections.push(SectionInfo {
                                name: format!("data_{}", data.range.start),
                                virtual_address: data.range.start as u64,
                                virtual_size: data.data.len() as u64,
                                raw_offset: data.range.start as u64,
                                raw_size: data.data.len() as u64,
                                characteristics: SectionCharacteristics {
                                    readable: true,
                                    writable: true,
                                    executable: false,
                                    shared: false,
                                    discardable: false,
                                    not_cached: false,
                                    not_paged: false,
                                },
                                entropy,
                            });
                        }
                    }
                }
                Ok(Payload::CustomSection(custom)) => {
                    let entropy = calculate_entropy(custom.data());
                    sections.push(SectionInfo {
                        name: custom.name().to_string(),
                        virtual_address: 0,
                        virtual_size: custom.data().len() as u64,
                        raw_offset: 0,
                        raw_size: custom.data().len() as u64,
                        characteristics: SectionCharacteristics {
                            readable: true,
                            writable: false,
                            executable: false,
                            shared: false,
                            discardable: false,
                            not_cached: false,
                            not_paged: false,
                        },
                        entropy,
                    });
                }
                _ => {}
            }
        }

        for (idx, name) in function_names.iter().enumerate() {
            let is_export = export_names.iter().any(|(_, i)| *i == idx as u32);
            symbols.push(SymbolInfo {
                name: name.clone(),
                address: idx as u64,
                size: 0,
                symbol_type: SymbolType::Function,
                binding: if is_export { SymbolBinding::Global } else { SymbolBinding::Local },
                visibility: if is_export {
                    SymbolVisibility::Default
                } else {
                    SymbolVisibility::Hidden
                },
                section_index: Some(0),
            });
        }

        let hashes = calculate_hashes(&bytes);

        Ok(BinaryMetadata {
            file_id: FileId::nil(),
            identification: BinaryIdentification {
                format: BinaryFormat::Wasm,
                architecture: Architecture::Unknown,
                bitness: Bitness::Bit32,
                endianness: Endianness::Little,
                os: OperatingSystem::Unknown,
                entry_point: None,
                compiler_info: None,
                security_features: SecurityFeatures::default(),
                confidence: 0.95,
            },
            sections,
            segments: Vec::new(),
            symbols,
            imports,
            exports,
            strings: Vec::new(),
            resources: Vec::new(),
            version_info: None,
            hashes,
            analyzed_at: chrono::Utc::now(),
        })
    }

    async fn extract_sections(&self, data: &[u8]) -> Result<Vec<SectionInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.sections)
    }

    async fn extract_segments(&self, _data: &[u8]) -> Result<Vec<SegmentInfo>> {
        Ok(Vec::new())
    }

    async fn extract_symbols(&self, data: &[u8]) -> Result<Vec<SymbolInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.symbols)
    }

    async fn extract_imports(&self, data: &[u8]) -> Result<Vec<ImportInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.imports)
    }

    async fn extract_exports(&self, data: &[u8]) -> Result<Vec<ExportInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.exports)
    }

    async fn extract_strings(&self, _data: &[u8]) -> Result<Vec<ExtractedString>> {
        Ok(Vec::new())
    }

    async fn extract_resources(&self, _data: &[u8]) -> Result<Vec<ResourceInfo>> {
        Ok(Vec::new())
    }

    async fn extract_version_info(&self, _data: &[u8]) -> Result<Option<VersionInfo>> {
        Ok(None)
    }
}

/// Calculate entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
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
    entropy
}

/// Calculate file hashes
fn calculate_hashes(data: &[u8]) -> FileHashes {
    use md5::{Digest, Md5};
    use sha1::Sha1;
    use sha2::Sha256;

    let md5_hash = format!("{:x}", Md5::digest(data));
    let sha1_hash = format!("{:x}", Sha1::digest(data));
    let sha256_hash = format!("{:x}", Sha256::digest(data));

    FileHashes { md5: md5_hash, sha1: sha1_hash, sha256: sha256_hash }
}

/// WASM Static Analyzer Implementation
#[async_trait]
impl StaticAnalyzer for WasmParser {
    async fn calculate_entropy(&self, data: &[u8]) -> Result<f64> {
        Ok(calculate_entropy(data))
    }

    async fn find_functions(
        &self,
        data: &[u8],
        metadata: &BinaryMetadata,
    ) -> Result<Vec<FunctionInfo>> {
        let mut functions = Vec::new();

        // Extract functions from symbols
        for symbol in &metadata.symbols {
            if symbol.symbol_type == SymbolType::Function {
                functions.push(FunctionInfo {
                    address: symbol.address,
                    size: symbol.size,
                    name: Some(symbol.name.clone()),
                    is_thunk: false,
                    is_import: symbol.binding != SymbolBinding::Global,
                    basic_blocks: Vec::new(),
                    calls: Vec::new(),
                    called_by: Vec::new(),
                    complexity: 1,
                });
            }
        }

        // Also find functions from exports
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

        Ok(functions)
    }

    async fn analyze_control_flow(
        &self,
        _data: &[u8],
        metadata: &BinaryMetadata,
    ) -> Result<ControlFlowInfo> {
        let mut functions = Vec::new();
        let mut call_graph_nodes = Vec::new();
        let mut call_graph_edges = Vec::new();
        let mut cfg_nodes = Vec::new();
        let mut cfg_edges = Vec::new();

        // Add functions from symbols
        for symbol in &metadata.symbols {
            if symbol.symbol_type == SymbolType::Function {
                let func = FunctionInfo {
                    address: symbol.address,
                    size: symbol.size,
                    name: Some(symbol.name.clone()),
                    is_thunk: false,
                    is_import: symbol.binding != SymbolBinding::Global,
                    basic_blocks: Vec::new(),
                    calls: Vec::new(),
                    called_by: Vec::new(),
                    complexity: 1,
                };
                functions.push(func.clone());

                call_graph_nodes.push(CallGraphNode {
                    address: symbol.address,
                    name: Some(symbol.name.clone()),
                    is_external: symbol.binding != SymbolBinding::Global,
                });
            }
        }

        // Add imports as external call targets
        for import in &metadata.imports {
            for func in &import.functions {
                call_graph_nodes.push(CallGraphNode {
                    address: func.address.unwrap_or(0),
                    name: Some(func.name.clone()),
                    is_external: true,
                });

                // Add edges from potential callers (simplified)
                for node in &call_graph_nodes {
                    if !node.is_external {
                        call_graph_edges.push(CallGraphEdge {
                            from: node.address,
                            to: func.address.unwrap_or(0),
                            edge_type: CallEdgeType::Direct,
                        });
                    }
                }
            }
        }

        // Add exports as entry points
        for export in &metadata.exports {
            call_graph_nodes.push(CallGraphNode {
                address: export.address,
                name: Some(export.name.clone()),
                is_external: false,
            });
        }

        Ok(ControlFlowInfo {
            functions,
            call_graph: CallGraph { nodes: call_graph_nodes, edges: call_graph_edges },
            cfg: ControlFlowGraph { nodes: cfg_nodes, edges: cfg_edges },
        })
    }

    async fn analyze_data_flow(
        &self,
        _data: &[u8],
        metadata: &BinaryMetadata,
    ) -> Result<DataFlowInfo> {
        let mut variables = Vec::new();
        let mut data_dependencies = Vec::new();
        let mut var_counter = 0u64;

        // Extract variables from data sections
        for section in &metadata.sections {
            if section.characteristics.writable && !section.characteristics.executable {
                // Potential data section
                var_counter += 1;
                variables.push(crate::binary::traits::VariableInfo {
                    address: section.virtual_address,
                    name: Some(section.name.clone()),
                    var_type: crate::binary::traits::VariableType::Unknown,
                    size: section.virtual_size,
                    scope: crate::binary::traits::VariableScope::Global,
                });
                // Add self-dependency for the variable
                data_dependencies.push(crate::binary::traits::DataDependency {
                    from: var_counter,
                    to: var_counter,
                    dependency_type: crate::binary::traits::DataDependencyType::ReadWrite,
                });
            }
        }

        // Add imports as data dependencies (simplified)
        for import in &metadata.imports {
            for func in &import.functions {
                var_counter += 1;
                data_dependencies.push(crate::binary::traits::DataDependency {
                    from: var_counter,
                    to: var_counter,
                    dependency_type: crate::binary::traits::DataDependencyType::Read,
                });
            }
        }

        Ok(DataFlowInfo { variables, data_dependencies })
    }
}
