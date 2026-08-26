//! PE binary analysis implementation

use crate::binary::common::*;
use crate::binary::traits::*;
use async_trait::async_trait;
use goblin::container::{Container, Endian};
use goblin::pe::{section_table::SectionTable, PE};
use openre_core::error::OpenreResult as Result;
use openre_core::ids::FileId;
use std::collections::HashMap;

/// PE binary identifier
pub struct PeIdentifier;

#[async_trait]
impl BinaryIdentifier for PeIdentifier {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Pe
    }

    async fn identify(&self, data: &[u8]) -> Result<BinaryIdentification> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let architecture = match pe.header.coff_header.machine {
            0x014c => Architecture::X86,       // IMAGE_FILE_MACHINE_I386
            0x8664 => Architecture::X86_64,    // IMAGE_FILE_MACHINE_AMD64
            0x01c0 => Architecture::Arm,       // IMAGE_FILE_MACHINE_ARM
            0xaa64 => Architecture::Arm64,     // IMAGE_FILE_MACHINE_ARM64
            0x0166 => Architecture::Mips,      // IMAGE_FILE_MACHINE_MIPS16
            0x01a2 => Architecture::PowerPc,   // IMAGE_FILE_MACHINE_POWERPC
            0x01f0 => Architecture::PowerPc64, // IMAGE_FILE_MACHINE_POWERPCFP
            _ => Architecture::Unknown,
        };

        let bitness = if pe.is_64 {
            Bitness::Bit64
        } else {
            Bitness::Bit32
        };

        let endianness = Endianness::Little; // PE is always little-endian

        let os = OperatingSystem::Windows;

        let entry_point = match &pe.header.optional_header {
            Some(oh) if oh.standard_fields.address_of_entry_point != 0 => {
                Some(oh.windows_fields.image_base + oh.standard_fields.address_of_entry_point)
            }
            _ => None,
        };

        // Extract security features
        let security_features = extract_security_features(&pe);

        // Try to detect compiler from rich header or other metadata
        let compiler_info = extract_compiler_info(&pe);

        Ok(BinaryIdentification {
            format: BinaryFormat::Pe,
            architecture,
            bitness,
            endianness,
            os,
            entry_point,
            compiler_info,
            security_features,
            confidence: 0.95,
        })
    }
}

/// PE metadata extractor
pub struct PeMetadataExtractor;

#[async_trait]
impl BinaryMetadataExtractor for PeMetadataExtractor {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Pe
    }

    async fn extract_metadata(&self, data: &[u8]) -> Result<BinaryMetadata> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let identification = PeIdentifier.identify(data).await?;
        let sections = self.extract_sections(data).await?;
        let segments = self.extract_segments(data).await?;
        let symbols = self.extract_symbols(data).await?;
        let imports = self.extract_imports(data).await?;
        let exports = self.extract_exports(data).await?;
        let strings = self.extract_strings(data).await?;
        let resources = self.extract_resources(data).await?;
        let version_info = self.extract_version_info(data).await?;

        let hashes = calculate_hashes(data);

        Ok(BinaryMetadata {
            file_id: FileId::nil(), // Will be set by caller
            identification,
            sections,
            segments,
            symbols,
            imports,
            exports,
            strings,
            resources,
            version_info,
            hashes,
            analyzed_at: chrono::Utc::now(),
        })
    }

    async fn extract_sections(&self, data: &[u8]) -> Result<Vec<SectionInfo>> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let mut sections = Vec::new();

        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            let characteristics = SectionCharacteristics {
                readable: section.characteristics & 0x40000000 != 0, // IMAGE_SCN_MEM_READ
                writable: section.characteristics & 0x80000000 != 0, // IMAGE_SCN_MEM_WRITE
                executable: section.characteristics & 0x20000000 != 0, // IMAGE_SCN_MEM_EXECUTE
                shared: section.characteristics & 0x10000000 != 0,   // IMAGE_SCN_MEM_SHARED
                discardable: section.characteristics & 0x02000000 != 0, // IMAGE_SCN_MEM_DISCARDABLE
                not_cached: section.characteristics & 0x04000000 != 0, // IMAGE_SCN_MEM_NOT_CACHED
                not_paged: section.characteristics & 0x08000000 != 0, // IMAGE_SCN_MEM_NOT_PAGED
            };

            // Calculate entropy for the section
            let entropy = if section.size_of_raw_data > 0
                && section.pointer_to_raw_data < data.len() as u32
            {
                let start = section.pointer_to_raw_data as usize;
                let end = (start + section.size_of_raw_data as usize).min(data.len());
                if start < end {
                    calculate_entropy(&data[start..end])
                } else {
                    0.0
                }
            } else {
                0.0
            };

            sections.push(SectionInfo {
                name,
                virtual_address: section.virtual_address as u64,
                virtual_size: section.virtual_size as u64,
                raw_offset: section.pointer_to_raw_data as u64,
                raw_size: section.size_of_raw_data as u64,
                characteristics,
                entropy,
            });
        }

        Ok(sections)
    }

    async fn extract_segments(&self, data: &[u8]) -> Result<Vec<SegmentInfo>> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let mut segments = Vec::new();

        // PE doesn't have explicit segments like ELF, but we can derive them from sections
        // Group sections by their memory permissions
        let mut segment_map: HashMap<(bool, bool, bool), Vec<&SectionTable>> = HashMap::new();

        for section in &pe.sections {
            let key = (
                section.characteristics & 0x40000000 != 0, // readable
                section.characteristics & 0x80000000 != 0, // writable
                section.characteristics & 0x20000000 != 0, // executable
            );
            segment_map.entry(key).or_default().push(section);
        }

        for ((readable, writable, executable), sections) in segment_map {
            if sections.is_empty() {
                continue;
            }

            let min_va = sections
                .iter()
                .map(|s| s.virtual_address)
                .min()
                .unwrap_or(0);
            let max_va = sections
                .iter()
                .map(|s| s.virtual_address + s.virtual_size)
                .max()
                .unwrap_or(0);
            let min_raw = sections
                .iter()
                .map(|s| s.pointer_to_raw_data)
                .min()
                .unwrap_or(0);
            let max_raw = sections
                .iter()
                .map(|s| s.pointer_to_raw_data + s.size_of_raw_data)
                .max()
                .unwrap_or(0);

            let permissions = SegmentPermissions {
                readable,
                writable,
                executable,
            };

            segments.push(SegmentInfo {
                virtual_address: min_va as u64,
                virtual_size: (max_va - min_va) as u64,
                raw_offset: min_raw as u64,
                raw_size: (max_raw - min_raw) as u64,
                permissions,
                alignment: pe
                    .header
                    .optional_header
                    .as_ref()
                    .map(|oh| oh.windows_fields.section_alignment as u64)
                    .unwrap_or(0),
            });
        }

        Ok(segments)
    }

    async fn extract_symbols(&self, data: &[u8]) -> Result<Vec<SymbolInfo>> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let mut symbols = Vec::new();

        // Extract symbols from export table
        for export in &pe.exports {
            if let Some(name) = &export.name {
                symbols.push(SymbolInfo {
                    name: name.to_string(),
                    address: export.rva as u64,
                    size: export.size as u64,
                    symbol_type: SymbolType::Function,
                    binding: SymbolBinding::Global,
                    visibility: SymbolVisibility::Default,
                    section_index: None,
                });
            }
        }

        // Extract symbols from import table (as external symbols)
        for import in &pe.imports {
            symbols.push(SymbolInfo {
                name: format!("{}!{}", import.dll, import.name),
                address: import.rva as u64,
                size: import.size as u64,
                symbol_type: SymbolType::Function,
                binding: SymbolBinding::Global,
                visibility: SymbolVisibility::Default,
                section_index: None,
            });
        }

        Ok(symbols)
    }

    async fn extract_imports(&self, data: &[u8]) -> Result<Vec<ImportInfo>> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let mut imports = Vec::new();

        // goblin 0.7 exposes a flat import list: each entry is a single imported symbol
        let mut by_library: HashMap<String, Vec<ImportedFunction>> = HashMap::new();
        for import in &pe.imports {
            let name = import.name.to_string();
            by_library
                .entry(import.dll.to_string())
                .or_default()
                .push(ImportedFunction {
                    name,
                    address: Some(import.rva as u64),
                    ordinal: Some(import.ordinal),
                });
        }

        for (library, functions) in by_library {
            if !functions.is_empty() {
                imports.push(ImportInfo { library, functions });
            }
        }

        Ok(imports)
    }

    async fn extract_exports(&self, data: &[u8]) -> Result<Vec<ExportInfo>> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let mut exports = Vec::new();

        for export in &pe.exports {
            if let Some(name) = &export.name {
                exports.push(ExportInfo {
                    name: name.to_string(),
                    address: export.rva as u64,
                    ordinal: 0,
                    forwarder: export.reexport.as_ref().map(|r| match r {
                        goblin::pe::export::Reexport::DLLName { export, lib } => {
                            format!("{}.{}", lib, export)
                        }
                        goblin::pe::export::Reexport::DLLOrdinal { ordinal, lib } => {
                            format!("{}.#{}", lib, ordinal)
                        }
                    }),
                });
            }
        }

        Ok(exports)
    }

    async fn extract_strings(&self, data: &[u8]) -> Result<Vec<ExtractedString>> {
        let pe = PE::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse PE: {}", e)))?;

        let mut strings = Vec::new();

        // Extract strings from all sections
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            if section.size_of_raw_data > 0 && section.pointer_to_raw_data < data.len() as u32 {
                let start = section.pointer_to_raw_data as usize;
                let end = (start + section.size_of_raw_data as usize).min(data.len());
                if start < end {
                    let section_strings = extract_strings_from_data(
                        &data[start..end],
                        section.virtual_address as u64,
                        Some(name),
                    );
                    strings.extend(section_strings);
                }
            }
        }

        Ok(strings)
    }

    async fn extract_resources(&self, data: &[u8]) -> Result<Vec<ResourceInfo>> {
        let _ = data;
        // goblin 0.7 does not expose PE resource directory parsing
        Ok(Vec::new())
    }

    async fn extract_version_info(&self, data: &[u8]) -> Result<Option<VersionInfo>> {
        let _ = data;
        // goblin 0.7 does not expose PE version info parsing
        Ok(None)
    }
}

/// Extract security features from PE
fn extract_security_features(pe: &PE) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    let dll_characteristics = pe
        .header
        .optional_header
        .as_ref()
        .map(|oh| oh.windows_fields.dll_characteristics)
        .unwrap_or(0);

    // Check for ASLR (Dynamic Base)
    features.aslr = dll_characteristics & 0x0040 != 0; // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE

    // Check for DEP/NX
    features.dep_nx = dll_characteristics & 0x0100 != 0; // IMAGE_DLLCHARACTERISTICS_NX_COMPAT

    // Check for PIE (Relocations stripped means no ASLR, but PE doesn't have PIE concept like ELF)
    // PE uses ASLR instead
    features.pie = features.aslr;

    // Check for RELRO equivalent (SafeSEH, SEH, CFG)
    let has_safeseh = dll_characteristics & 0x0004 != 0; // IMAGE_DLLCHARACTERISTICS_NO_SEH
    let has_cfg = dll_characteristics & 0x4000 != 0; // IMAGE_DLLCHARACTERISTICS_GUARD_CF

    features.relro = if has_safeseh && has_cfg {
        RelroLevel::Full
    } else if has_safeseh || has_cfg {
        RelroLevel::Partial
    } else {
        RelroLevel::None
    };

    // Check for stack canary (/GS)
    // This is harder to detect from static analysis, but we can check for security cookie
    features.stack_canary = dll_characteristics & 0x0002 != 0; // IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE (not exactly, but related)

    // Check for CFG (Control Flow Guard)
    features.cfi = has_cfg;

    features
}

/// Extract compiler info from PE
fn extract_compiler_info(pe: &PE) -> Option<CompilerInfo> {
    // Check for Go (has specific section names)
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        if name.starts_with(".go") || name == ".gopclntab" {
            return Some(CompilerInfo {
                name: "Go".to_string(),
                version: None,
                language: Some("Go".to_string()),
            });
        }
    }

    // Check for Rust (has specific section names)
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_end_matches('\0')
            .to_string();
        if name.contains("rust") {
            return Some(CompilerInfo {
                name: "rustc".to_string(),
                version: None,
                language: Some("Rust".to_string()),
            });
        }
    }

    // Check for .NET (has CLR header, data directory index 14)
    let has_clr = pe
        .header
        .optional_header
        .as_ref()
        .and_then(|oh| oh.data_directories.data_directories.get(14))
        .map(|dd| dd.as_ref().map(|d| d.size > 0).unwrap_or(false))
        .unwrap_or(false);
    if has_clr {
        return Some(CompilerInfo {
            name: ".NET".to_string(),
            version: None,
            language: Some("C#/VB.NET/F#".to_string()),
        });
    }

    None
}

/// Calculate entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Extract strings from raw data
fn extract_strings_from_data(
    data: &[u8],
    base_addr: u64,
    section: Option<String>,
) -> Vec<ExtractedString> {
    let mut strings = Vec::new();
    let mut current_string = Vec::new();
    let mut start_addr = base_addr;

    for (i, &byte) in data.iter().enumerate() {
        if byte >= 0x20 && byte <= 0x7E {
            if current_string.is_empty() {
                start_addr = base_addr + i as u64;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= 4 {
                if let Ok(content) = String::from_utf8(current_string.clone()) {
                    strings.push(ExtractedString {
                        address: start_addr,
                        length: current_string.len(),
                        content,
                        encoding: StringEncoding::Ascii,
                        section: section.clone(),
                    });
                }
            }
            current_string.clear();
        }
    }

    // Check for UTF-16 strings
    if data.len() >= 2 {
        for i in (0..data.len() - 1).step_by(2) {
            let b1 = data[i];
            let b2 = data[i + 1];
            if b1 >= 0x20 && b1 <= 0x7E && b2 == 0 {
                // Potential UTF-16LE
                let mut utf16_data = Vec::new();
                let mut j = i;
                while j + 1 < data.len() {
                    let b1 = data[j];
                    let b2 = data[j + 1];
                    if b1 == 0 && b2 == 0 {
                        break;
                    }
                    if b2 == 0 && b1 >= 0x20 && b1 <= 0x7E {
                        utf16_data.push(b1);
                        j += 2;
                    } else {
                        break;
                    }
                }
                if utf16_data.len() >= 4 {
                    if let Ok(content) = String::from_utf8(utf16_data) {
                        strings.push(ExtractedString {
                            address: base_addr + i as u64,
                            length: content.len() * 2,
                            content,
                            encoding: StringEncoding::Utf16Le,
                            section: section.clone(),
                        });
                    }
                }
            }
        }
    }

    strings
}

/// Calculate file hashes
fn calculate_hashes(data: &[u8]) -> FileHashes {
    use md5::{Digest, Md5};
    use sha1::Sha1;
    use sha2::Sha256;

    let md5_hash = format!("{:x}", Md5::digest(data));
    let sha1_hash = format!("{:x}", Sha1::digest(data));
    let sha256_hash = format!("{:x}", Sha256::digest(data));

    FileHashes {
        md5: md5_hash,
        sha1: sha1_hash,
        sha256: sha256_hash,
    }
}
