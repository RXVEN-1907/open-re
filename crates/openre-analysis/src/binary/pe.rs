//! PE Binary Parser

use anyhow::{Context, Result};
use async_trait::async_trait;
use goblin::pe::PE;
use openre_core::ids::FileId;
use std::path::Path;

use crate::binary::common::*;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as ResultCore;

pub struct PeParser;

impl PeParser {
    pub fn parse(path: &Path) -> Result<BinaryInfo> {
        let bytes = std::fs::read(path)?;
        let pe = PE::parse(&bytes).context("Failed to parse PE")?;

        let mut info = BinaryInfo {
            format: BinaryFormat::Pe,
            architecture: Self::arch_from_pe(&pe),
            entry_point: pe.entry as u64,
            base_address: pe.image_base as u64,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
        };

        // Parse sections
        for section in &pe.sections {
            let name = std::str::from_utf8(&section.name)
                .unwrap_or("unknown")
                .trim_end_matches('\0')
                .to_string();

            // Get section data using the raw pointer and size
            let data = if section.pointer_to_raw_data > 0 && section.size_of_raw_data > 0 {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;
                if end <= bytes.len() {
                    Some(bytes[start..end].to_vec())
                } else {
                    None
                }
            } else {
                None
            };

            info.sections.push(Section {
                name,
                address: section.virtual_address as u64 + pe.image_base as u64,
                size: section.virtual_size as u64,
                flags: Self::section_flags(section.characteristics),
                data,
            });
        }

        // Parse imports
        for import in &pe.imports {
            let dll_name = import.dll.to_string();

            // Goblin 0.7: import.name is Cow<'_, str>
            let name_str: &str = import.name.as_ref();
            if !name_str.is_empty() {
                info.imports
                    .push(Import { name: name_str.to_string(), library: Some(dll_name.clone()) });
            }
        }

        // Parse exports
        for export in &pe.exports {
            if let Some(name) = export.name {
                let func_name = name.to_string();

                info.exports.push(Export {
                    name: func_name,
                    address: export.rva as u64 + pe.image_base as u64,
                });
            }
        }

        // Extract strings from all sections
        for section in &pe.sections {
            if section.pointer_to_raw_data > 0 && section.size_of_raw_data > 0 {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;
                if end <= bytes.len() {
                    let data = &bytes[start..end];
                    info.strings.extend(Self::extract_strings(data));
                }
            }
        }

        Ok(info)
    }

    fn arch_from_pe(pe: &PE) -> crate::Architecture {
        match pe.header.coff_header.machine {
            goblin::pe::header::COFF_MACHINE_X86_64 => crate::Architecture::X86_64,
            goblin::pe::header::COFF_MACHINE_X86 => crate::Architecture::X86,
            goblin::pe::header::COFF_MACHINE_ARM64 => crate::Architecture::Arm64,
            goblin::pe::header::COFF_MACHINE_ARM => crate::Architecture::Arm,
            _ => crate::Architecture::Unknown,
        }
    }

    fn section_flags(chars: u32) -> crate::SectionFlags {
        crate::SectionFlags {
            readable: chars & 0x40000000 != 0,   // IMAGE_SCN_MEM_READ
            writable: chars & 0x80000000 != 0,   // IMAGE_SCN_MEM_WRITE
            executable: chars & 0x20000000 != 0, // IMAGE_SCN_MEM_EXECUTE
        }
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

/// PE Binary Identifier
#[derive(Default)]
pub struct PeIdentifier;

#[async_trait]
impl BinaryIdentifier for PeIdentifier {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Pe
    }

    async fn identify(&self, data: &[u8]) -> ResultCore<BinaryIdentification> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("PE parse error: {}", e)))?;
        Ok(BinaryIdentification {
            format: BinaryFormat::Pe,
            architecture: PeParser::arch_from_pe(&pe),
            bitness: if pe.is_64 { Bitness::Bit64 } else { Bitness::Bit32 },
            endianness: Endianness::Little, // PE is always little-endian
            os: OperatingSystem::Windows,
            entry_point: Some(pe.entry as u64),
            compiler_info: None,
            security_features: SecurityFeatures::default(),
            confidence: 0.95,
        })
    }
}

/// PE Metadata Extractor
#[derive(Default)]
pub struct PeMetadataExtractor;

#[async_trait]
impl BinaryMetadataExtractor for PeMetadataExtractor {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Pe
    }

    async fn extract_metadata(&self, data: &[u8]) -> ResultCore<BinaryMetadata> {
        let bytes = data.to_vec();
        let pe = PE::parse(&bytes)
            .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("PE parse error: {}", e)))?;

        let mut sections = Vec::new();
        for section in &pe.sections {
            let name = std::str::from_utf8(&section.name)
                .unwrap_or("unknown")
                .trim_end_matches('\0')
                .to_string();

            let entropy = if section.pointer_to_raw_data > 0 && section.size_of_raw_data > 0 {
                let start = section.pointer_to_raw_data as usize;
                let end = start + section.size_of_raw_data as usize;
                if end <= bytes.len() {
                    calculate_entropy(&bytes[start..end])
                } else {
                    0.0
                }
            } else {
                0.0
            };

            sections.push(SectionInfo {
                name,
                virtual_address: section.virtual_address as u64 + pe.image_base as u64,
                virtual_size: section.virtual_size as u64,
                raw_offset: section.pointer_to_raw_data as u64,
                raw_size: section.size_of_raw_data as u64,
                characteristics: SectionCharacteristics {
                    readable: section.characteristics & 0x40000000 != 0,
                    writable: section.characteristics & 0x80000000 != 0,
                    executable: section.characteristics & 0x20000000 != 0,
                    shared: false,
                    discardable: false,
                    not_cached: false,
                    not_paged: false,
                },
                entropy,
            });
        }

        let mut segments = Vec::new();
        // PE doesn't have segments like ELF, use sections as segments
        for section in &pe.sections {
            segments.push(SegmentInfo {
                virtual_address: section.virtual_address as u64 + pe.image_base as u64,
                virtual_size: section.virtual_size as u64,
                raw_offset: section.pointer_to_raw_data as u64,
                raw_size: section.size_of_raw_data as u64,
                permissions: SegmentPermissions {
                    readable: section.characteristics & 0x40000000 != 0,
                    writable: section.characteristics & 0x80000000 != 0,
                    executable: section.characteristics & 0x20000000 != 0,
                },
                alignment: 0x1000,
            });
        }

        let mut symbols = Vec::new();
        // PE symbols would come from COFF symbol table or debug info
        // For now, use exports as symbols
        for export in &pe.exports {
            if let Some(name) = export.name {
                symbols.push(SymbolInfo {
                    name: name.to_string(),
                    address: export.rva as u64 + pe.image_base as u64,
                    size: 0,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: Some(0),
                });
            }
        }

        let mut imports = Vec::new();
        for import in &pe.imports {
            let dll_name = import.dll.to_string();
            // import.name is Cow<'_, str> in goblin 0.7
            let name_str: &str = import.name.as_ref();
            if !name_str.is_empty() {
                imports.push(ImportInfo {
                    library: dll_name,
                    functions: vec![ImportedFunction {
                        name: name_str.to_string(),
                        address: None,
                        ordinal: Some(import.ordinal),
                    }],
                });
            }
        }

        let mut exports = Vec::new();
        for export in &pe.exports {
            if let Some(name) = export.name {
                let forwarder = export.reexport.as_ref().map(|r| match r {
                    goblin::pe::export::Reexport::DLLName { export: exp, lib } => {
                        format!("{}.{}", lib, exp)
                    }
                    goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                        format!("{}#{}", lib, ordinal)
                    }
                });
                exports.push(ExportInfo {
                    name: name.to_string(),
                    address: export.rva as u64 + pe.image_base as u64,
                    ordinal: 0, // Ordinal not directly available in this struct
                    forwarder,
                });
            }
        }

        let strings = Vec::new(); // Simplified for now

        let hashes = calculate_hashes(&bytes);

        Ok(BinaryMetadata {
            file_id: FileId::nil(),
            identification: BinaryIdentification {
                format: BinaryFormat::Pe,
                architecture: PeParser::arch_from_pe(&pe),
                bitness: if pe.is_64 { Bitness::Bit64 } else { Bitness::Bit32 },
                endianness: Endianness::Little,
                os: OperatingSystem::Windows,
                entry_point: Some(pe.entry as u64),
                compiler_info: None,
                security_features: SecurityFeatures::default(),
                confidence: 0.95,
            },
            sections,
            segments,
            symbols,
            imports,
            exports,
            strings,
            resources: Vec::new(),
            version_info: None,
            hashes,
            analyzed_at: chrono::Utc::now(),
        })
    }

    async fn extract_sections(&self, data: &[u8]) -> ResultCore<Vec<SectionInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.sections)
    }

    async fn extract_segments(&self, data: &[u8]) -> ResultCore<Vec<SegmentInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.segments)
    }

    async fn extract_symbols(&self, data: &[u8]) -> ResultCore<Vec<SymbolInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.symbols)
    }

    async fn extract_imports(&self, data: &[u8]) -> ResultCore<Vec<ImportInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.imports)
    }

    async fn extract_exports(&self, data: &[u8]) -> ResultCore<Vec<ExportInfo>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.exports)
    }

    async fn extract_strings(&self, data: &[u8]) -> ResultCore<Vec<ExtractedString>> {
        let metadata = self.extract_metadata(data).await?;
        Ok(metadata.strings)
    }

    async fn extract_resources(&self, _data: &[u8]) -> ResultCore<Vec<ResourceInfo>> {
        Ok(Vec::new())
    }

    async fn extract_version_info(&self, _data: &[u8]) -> ResultCore<Option<VersionInfo>> {
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
    use sha1::{Digest as Sha1Digest, Sha1};
    use sha2::{Digest as Sha2Digest, Sha256};

    let md5_hash = {
        let mut hasher = Md5::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    let sha1_hash = {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };

    FileHashes { md5: md5_hash, sha1: sha1_hash, sha256: sha256_hash }
}
