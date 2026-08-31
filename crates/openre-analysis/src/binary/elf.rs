//! ELF Binary Parser

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use goblin::elf::Elf;
use openre_core::ids::FileId;
use std::path::Path;

use crate::binary::common::*;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as ResultCore;

pub struct ElfParser;

impl ElfParser {
    pub fn parse(path: &Path) -> Result<BinaryInfo> {
        let bytes = std::fs::read(path)?;
        let elf = Elf::parse(&bytes).context("Failed to parse ELF")?;

        let mut info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: Self::arch_from_elf(&elf),
            entry_point: elf.entry as u64,
            base_address: elf
                .program_headers
                .iter()
                .find(|ph| {
                    ph.p_type == goblin::elf::program_header::PT_LOAD && ph.p_flags & 0x1 != 0
                }) // PF_X
                .map(|ph| ph.p_vaddr)
                .unwrap_or(0),
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
        };

        // Parse sections
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                info.sections.push(Section {
                    name: name.to_string(),
                    address: section.sh_addr,
                    size: section.sh_size,
                    flags: Self::section_flags(section.sh_flags),
                    data: if section.sh_type == goblin::elf::section_header::SHT_PROGBITS {
                        let start = section.sh_offset as usize;
                        let end = start + section.sh_size as usize;
                        if end <= bytes.len() {
                            Some(bytes[start..end].to_vec())
                        } else {
                            None
                        }
                    } else {
                        None
                    },
                });
            }
        }

        // Parse symbols
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    info.symbols.push(Symbol {
                        name: name.to_string(),
                        address: sym.st_value,
                        size: sym.st_size,
                        symbol_type: Self::symbol_type(sym.st_info),
                        binding: Self::symbol_binding(sym.st_info),
                        section_index: sym.st_shndx as u32,
                    });
                }
            }
        }

        // Parse dynamic symbols (imports/exports)
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let binding = Self::symbol_binding(sym.st_info);
                if binding == crate::SymbolBinding::Global && sym.st_shndx == 0 {
                    // Import
                    info.imports.push(Import {
                        name: name.to_string(),
                        library: None, // Would need DT_NEEDED parsing
                    });
                } else if binding == crate::SymbolBinding::Global && sym.st_shndx != 0 {
                    // Export
                    info.exports.push(Export { name: name.to_string(), address: sym.st_value });
                }
            }
        }

        // Extract strings from string tables
        for section in &elf.section_headers {
            if section.sh_type == goblin::elf::section_header::SHT_STRTAB {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                if end <= bytes.len() {
                    let data = &bytes[start..end];
                    // Extract null-terminated strings
                    let mut current = String::new();
                    for &b in data {
                        if b == 0 {
                            if current.len() >= 4 {
                                info.strings.push(current.clone());
                            }
                            current.clear();
                        } else if b.is_ascii_graphic() || b == b' ' {
                            current.push(b as char);
                        } else {
                            current.clear();
                        }
                    }
                }
            }
        }

        Ok(info)
    }

    fn arch_from_elf(elf: &Elf) -> crate::Architecture {
        match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => crate::Architecture::X86_64,
            goblin::elf::header::EM_386 => crate::Architecture::X86,
            goblin::elf::header::EM_AARCH64 => crate::Architecture::Arm64,
            goblin::elf::header::EM_ARM => crate::Architecture::Arm,
            goblin::elf::header::EM_MIPS => crate::Architecture::Mips,
            goblin::elf::header::EM_RISCV => crate::Architecture::RiscV64,
            _ => crate::Architecture::Unknown,
        }
    }

    fn section_flags(flags: u64) -> crate::SectionFlags {
        crate::SectionFlags {
            readable: flags & 0x4 != 0,   // PF_R
            writable: flags & 0x2 != 0,   // PF_W
            executable: flags & 0x1 != 0, // PF_X
        }
    }

    fn symbol_type(info: u8) -> crate::SymbolType {
        match goblin::elf::sym::st_type(info) {
            goblin::elf::sym::STT_FUNC => crate::SymbolType::Function,
            goblin::elf::sym::STT_OBJECT => crate::SymbolType::Object,
            goblin::elf::sym::STT_SECTION => crate::SymbolType::Section,
            goblin::elf::sym::STT_FILE => crate::SymbolType::File,
            _ => crate::SymbolType::Unknown,
        }
    }

    fn symbol_binding(info: u8) -> crate::SymbolBinding {
        match goblin::elf::sym::st_bind(info) {
            goblin::elf::sym::STB_LOCAL => crate::SymbolBinding::Local,
            goblin::elf::sym::STB_GLOBAL => crate::SymbolBinding::Global,
            goblin::elf::sym::STB_WEAK => crate::SymbolBinding::Weak,
            _ => crate::SymbolBinding::Unknown,
        }
    }
}

/// ELF Binary Identifier
#[derive(Default)]
pub struct ElfIdentifier;

#[async_trait]
impl BinaryIdentifier for ElfIdentifier {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }

    async fn identify(&self, data: &[u8]) -> ResultCore<BinaryIdentification> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("ELF parse error: {}", e)))?;
        Ok(BinaryIdentification {
            format: BinaryFormat::Elf,
            architecture: ElfParser::arch_from_elf(&elf),
            bitness: if elf.is_64 { Bitness::Bit64 } else { Bitness::Bit32 },
            endianness: if elf.header.e_ident[goblin::elf::header::EI_DATA]
                == goblin::elf::header::ELFDATA2LSB
            {
                Endianness::Little
            } else {
                Endianness::Big
            },
            os: OperatingSystem::Linux, // ELF is primarily Linux
            entry_point: Some(elf.entry as u64),
            compiler_info: None,
            security_features: SecurityFeatures::default(),
            confidence: 0.95,
        })
    }
}

/// ELF Metadata Extractor
#[derive(Default)]
pub struct ElfMetadataExtractor;

#[async_trait]
impl BinaryMetadataExtractor for ElfMetadataExtractor {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }

    async fn extract_metadata(&self, data: &[u8]) -> ResultCore<BinaryMetadata> {
        let bytes = data.to_vec();
        let elf = Elf::parse(&bytes)
            .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("ELF parse error: {}", e)))?;

        let mut sections = Vec::new();
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                let entropy = if section.sh_type == goblin::elf::section_header::SHT_PROGBITS
                    && section.sh_size > 0
                {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    if end <= bytes.len() {
                        calculate_entropy(&bytes[start..end])
                    } else {
                        0.0
                    }
                } else {
                    0.0
                };

                sections.push(SectionInfo {
                    name: name.to_string(),
                    virtual_address: section.sh_addr,
                    virtual_size: section.sh_size,
                    raw_offset: section.sh_offset,
                    raw_size: section.sh_size,
                    characteristics: SectionCharacteristics {
                        readable: section.sh_flags & 0x4 != 0,
                        writable: section.sh_flags & 0x2 != 0,
                        executable: section.sh_flags & 0x1 != 0,
                        shared: false,
                        discardable: false,
                        not_cached: false,
                        not_paged: false,
                    },
                    entropy,
                });
            }
        }

        let mut segments = Vec::new();
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                segments.push(SegmentInfo {
                    virtual_address: ph.p_vaddr,
                    virtual_size: ph.p_memsz,
                    raw_offset: ph.p_offset,
                    raw_size: ph.p_filesz,
                    permissions: SegmentPermissions {
                        readable: ph.p_flags & 0x4 != 0,
                        writable: ph.p_flags & 0x2 != 0,
                        executable: ph.p_flags & 0x1 != 0,
                    },
                    alignment: ph.p_align,
                });
            }
        }

        let mut symbols = Vec::new();
        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if !name.is_empty() {
                    symbols.push(SymbolInfo {
                        name: name.to_string(),
                        address: sym.st_value,
                        size: sym.st_size,
                        symbol_type: ElfParser::symbol_type(sym.st_info),
                        binding: ElfParser::symbol_binding(sym.st_info),
                        visibility: SymbolVisibility::Default,
                        section_index: Some(sym.st_shndx as u32),
                    });
                }
            }
        }

        let mut imports = Vec::new();
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let binding = ElfParser::symbol_binding(sym.st_info);
                if binding == crate::SymbolBinding::Global && sym.st_shndx == 0 {
                    imports.push(ImportInfo {
                        library: "unknown".to_string(),
                        functions: vec![ImportedFunction {
                            name: name.to_string(),
                            address: None,
                            ordinal: None,
                        }],
                    });
                }
            }
        }

        let mut exports = Vec::new();
        for sym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                let binding = ElfParser::symbol_binding(sym.st_info);
                if binding == crate::SymbolBinding::Global && sym.st_shndx != 0 {
                    exports.push(ExportInfo {
                        name: name.to_string(),
                        address: sym.st_value,
                        ordinal: 0,
                        forwarder: None,
                    });
                }
            }
        }

        let strings = Vec::new(); // Simplified for now

        // Calculate file hashes
        let hashes = calculate_hashes(&bytes);

        Ok(BinaryMetadata {
            file_id: FileId::nil(),
            identification: BinaryIdentification {
                format: BinaryFormat::Elf,
                architecture: ElfParser::arch_from_elf(&elf),
                bitness: if elf.is_64 { Bitness::Bit64 } else { Bitness::Bit32 },
                endianness: if elf.header.e_ident[goblin::elf::header::EI_DATA]
                    == goblin::elf::header::ELFDATA2LSB
                {
                    Endianness::Little
                } else {
                    Endianness::Big
                },
                os: OperatingSystem::Linux,
                entry_point: Some(elf.entry as u64),
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
    use sha1::Sha1;
    use sha2::Sha256;

    let md5_hash = format!("{:x}", Md5::digest(data));
    let sha1_hash = format!("{:x}", Sha1::digest(data));
    let sha256_hash = format!("{:x}", Sha256::digest(data));

    FileHashes { md5: md5_hash, sha1: sha1_hash, sha256: sha256_hash }
}
