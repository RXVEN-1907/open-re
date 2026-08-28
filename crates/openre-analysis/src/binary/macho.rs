//! MachO Binary Parser (simplified for goblin 0.7)

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use goblin::mach::MachO;
use openre_core::ids::FileId;
use std::path::Path;

use crate::binary::common::*;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as ResultCore;

pub struct MachoParser;

impl MachoParser {
    pub fn parse(path: &Path) -> Result<BinaryInfo> {
        let bytes = std::fs::read(path)?;
        let macho = MachO::parse(&bytes, 0)?;

        let mut info = BinaryInfo {
            format: BinaryFormat::MachO,
            architecture: Self::arch_from_macho(&macho),
            entry_point: macho.entry,
            base_address: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
        };

        // Parse segments/sections using macho.segments
        for segment in macho.segments.iter() {
            if let Ok(sections) = segment.sections() {
                for (section, _data) in sections {
                    let name = section.name().unwrap_or("unknown").to_string();
                    let data = if section.offset > 0 && section.size > 0 {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
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
                        address: section.addr,
                        size: section.size,
                        flags: Self::section_flags(section.flags),
                        data,
                    });
                }
            }
        }

        // Parse symbols
        if let Some(symbols) = &macho.symbols {
            for symbol in symbols.iter() {
                if let Ok((name, nlist)) = symbol {
                    if !name.is_empty() {
                        info.symbols.push(Symbol {
                            name: name.to_string(),
                            address: nlist.n_value,
                            size: 0,
                            symbol_type: crate::SymbolType::Unknown,
                            binding: crate::SymbolBinding::Global,
                            section_index: nlist.n_sect as u32,
                        });
                    }
                }
            }
        }

        // Extract strings from all sections
        for section in &info.sections {
            if let Some(data) = &section.data {
                info.strings.extend(Self::extract_strings(data));
            }
        }

        Ok(info)
    }

    fn arch_from_macho(macho: &MachO) -> crate::Architecture {
        match macho.header.cputype {
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => crate::Architecture::X86_64,
            goblin::mach::constants::cputype::CPU_TYPE_I386 => crate::Architecture::X86,
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => crate::Architecture::Arm64,
            goblin::mach::constants::cputype::CPU_TYPE_ARM => crate::Architecture::Arm,
            _ => crate::Architecture::Unknown,
        }
    }

    fn section_flags(flags: u32) -> crate::SectionFlags {
        crate::SectionFlags {
            readable: flags & 0x1 != 0,
            writable: flags & 0x2 != 0,
            executable: flags & 0x4 != 0,
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

/// MachO Binary Identifier
#[derive(Default)]
pub struct MachoIdentifier;

#[async_trait]
impl BinaryIdentifier for MachoIdentifier {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }

    async fn identify(&self, data: &[u8]) -> ResultCore<BinaryIdentification> {
        if data.len() < 4 {
            return Err(openre_core::Error::Internal(anyhow::anyhow!(
                "Data too small for MachO"
            )));
        }

        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let is_fat = magic == goblin::mach::fat::FAT_MAGIC || magic == goblin::mach::fat::FAT_CIGAM;

        let (architecture, bitness, is_64, entry_point) = if is_fat {
            (crate::Architecture::Unknown, Bitness::Bit64, true, None)
        } else {
            let macho = MachO::parse(data, 0)
                .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("MachO parse error: {}", e)))?;
            let arch = MachoParser::arch_from_macho(&macho);
            let is_64 = macho.is_64;
            (arch, if is_64 { Bitness::Bit64 } else { Bitness::Bit32 }, is_64, Some(macho.entry))
        };

        Ok(BinaryIdentification {
            format: BinaryFormat::MachO,
            architecture,
            bitness,
            endianness: Endianness::Little,
            os: OperatingSystem::MacOS,
            entry_point,
            compiler_info: None,
            security_features: SecurityFeatures::default(),
            confidence: 0.95,
        })
    }
}

/// MachO Metadata Extractor
#[derive(Default)]
pub struct MachoMetadataExtractor;

#[async_trait]
impl BinaryMetadataExtractor for MachoMetadataExtractor {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }

    async fn extract_metadata(&self, data: &[u8]) -> ResultCore<BinaryMetadata> {
        let bytes = data.to_vec();

        if bytes.len() >= 4 {
            let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            if magic == goblin::mach::fat::FAT_MAGIC || magic == goblin::mach::fat::FAT_CIGAM {
                return extract_fat_metadata(&bytes).await;
            }
        }

        let macho = MachO::parse(&bytes, 0)
            .map_err(|e| openre_core::Error::Internal(anyhow::anyhow!("MachO parse error: {}", e)))?;

        let arch = MachoParser::arch_from_macho(&macho);
        let is_64 = macho.is_64;
        let bitness = if is_64 { Bitness::Bit64 } else { Bitness::Bit32 };
        let entry_point = Some(macho.entry);

        let mut sections = Vec::new();
        let mut segments = Vec::new();
        let mut symbols = Vec::new();
        let mut imports = Vec::new();
        let mut exports = Vec::new();

        // Parse segments
        for segment in macho.segments.iter() {
            segments.push(SegmentInfo {
                virtual_address: segment.vmaddr,
                virtual_size: segment.vmsize,
                raw_offset: segment.fileoff,
                raw_size: segment.filesize,
                permissions: SegmentPermissions {
                    readable: segment.maxprot & 0x1 != 0,
                    writable: segment.maxprot & 0x2 != 0,
                    executable: segment.maxprot & 0x4 != 0,
                },
                alignment: 0x1000,
            });

            // Parse sections from this segment
            if let Ok(segment_sections) = segment.sections() {
                for (section, _data) in segment_sections {
                    let name = section.name().unwrap_or("unknown").to_string();
                    let entropy = if section.size > 0 && section.offset > 0 {
                        let start = section.offset as usize;
                        let end = start + section.size as usize;
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
                        virtual_address: section.addr,
                        virtual_size: section.size,
                        raw_offset: section.offset as u64,
                        raw_size: section.size,
                        characteristics: SectionCharacteristics {
                            readable: section.flags & 0x1 != 0,
                            writable: section.flags & 0x2 != 0,
                            executable: section.flags & 0x4 != 0,
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

        // Parse symbols
        if let Some(symtab) = &macho.symbols {
            for symbol in symtab.iter() {
                if let Ok((name, nlist)) = symbol {
                    if !name.is_empty() {
                        symbols.push(SymbolInfo {
                            name: name.to_string(),
                            address: nlist.n_value,
                            size: 0,
                            symbol_type: SymbolType::Unknown,
                            binding: SymbolBinding::Global,
                            visibility: SymbolVisibility::Default,
                            section_index: Some(nlist.n_sect as u32),
                        });
                    }
                }
            }
        }

        let hashes = calculate_hashes(&bytes);

        Ok(BinaryMetadata {
            file_id: FileId::nil(),
            identification: BinaryIdentification {
                format: BinaryFormat::MachO,
                architecture: arch,
                bitness,
                endianness: Endianness::Little,
                os: OperatingSystem::MacOS,
                entry_point,
                compiler_info: None,
                security_features: SecurityFeatures::default(),
                confidence: 0.95,
            },
            sections,
            segments,
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

    async fn extract_strings(&self, _data: &[u8]) -> ResultCore<Vec<ExtractedString>> {
        Ok(Vec::new())
    }

    async fn extract_resources(&self, _data: &[u8]) -> ResultCore<Vec<ResourceInfo>> {
        Ok(Vec::new())
    }

    async fn extract_version_info(&self, _data: &[u8]) -> ResultCore<Option<VersionInfo>> {
        Ok(None)
    }
}

/// Extract metadata from a fat MachO binary
async fn extract_fat_metadata(bytes: &[u8]) -> ResultCore<BinaryMetadata> {
    let hashes = calculate_hashes(bytes);
    Ok(BinaryMetadata {
        file_id: FileId::nil(),
        identification: BinaryIdentification {
            format: BinaryFormat::MachO,
            architecture: crate::Architecture::Unknown,
            bitness: Bitness::Bit64,
            endianness: Endianness::Little,
            os: OperatingSystem::MacOS,
            entry_point: None,
            compiler_info: None,
            security_features: SecurityFeatures::default(),
            confidence: 0.9,
        },
        sections: Vec::new(),
        segments: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        resources: Vec::new(),
        version_info: None,
        hashes,
        analyzed_at: chrono::Utc::now(),
    })
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

    FileHashes {
        md5: md5_hash,
        sha1: sha1_hash,
        sha256: sha256_hash,
    }
}