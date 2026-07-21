//! ELF binary analysis implementation

use crate::binary::common::*;
use crate::binary::traits::*;
use openre_core::error::Result;
use async_trait::async_trait;
use goblin::elf::{Elf, SectionHeader, Sym, Dynamic};
use goblin::container::{Container, Endian};
use std::collections::HashMap;

/// ELF binary identifier
pub struct ElfIdentifier;

#[async_trait]
impl BinaryIdentifier for ElfIdentifier {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }

    async fn identify(&self, data: &[u8]) -> Result<BinaryIdentification> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_ARM => Architecture::Arm,
            goblin::elf::header::EM_AARCH64 => Architecture::Arm64,
            goblin::elf::header::EM_MIPS => Architecture::Mips,
            goblin::elf::header::EM_MIPS_RS3_LE => Architecture::Mips64,
            goblin::elf::header::EM_PPC => Architecture::PowerPc,
            goblin::elf::header::EM_PPC64 => Architecture::PowerPc64,
            goblin::elf::header::EM_RISCV => {
                if elf.is_64 { Architecture::RiscV64 } else { Architecture::RiscV32 }
            }
            _ => Architecture::Unknown,
        };

        let bitness = if elf.is_64 { Bitness::Bit64 } else { Bitness::Bit32 };
        
        let endianness = match elf.container().endian() {
            Endian::Little => Endianness::Little,
            Endian::Big => Endianness::Big,
        };

        let os = match elf.header.e_ident[goblin::elf::header::EI_OSABI] {
            goblin::elf::header::ELFOSABI_LINUX => OperatingSystem::Linux,
            goblin::elf::header::ELFOSABI_FREEBSD => OperatingSystem::FreeBSD,
            goblin::elf::header::ELFOSABI_ANDROID => OperatingSystem::Android,
            _ => OperatingSystem::Unknown,
        };

        let entry_point = if elf.header.e_entry != 0 {
            Some(elf.header.e_entry)
        } else {
            None
        };

        // Extract security features
        let security_features = extract_security_features(&elf);

        // Try to detect compiler from .comment section
        let compiler_info = extract_compiler_info(&elf, data);

        Ok(BinaryIdentification {
            format: BinaryFormat::Elf,
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

/// ELF metadata extractor
pub struct ElfMetadataExtractor;

#[async_trait]
impl BinaryMetadataExtractor for ElfMetadataExtractor {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::Elf
    }

    async fn extract_metadata(&self, data: &[u8]) -> Result<BinaryMetadata> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let identification = ElfIdentifier.identify(data).await?;
        let sections = self.extract_sections(data).await?;
        let segments = self.extract_segments(data).await?;
        let symbols = self.extract_symbols(data).await?;
        let imports = self.extract_imports(data).await?;
        let exports = self.extract_exports(data).await?;
        let strings = self.extract_strings(data).await?;
        let resources = Vec::new(); // ELF doesn't have resources like PE
        let version_info = None; // ELF doesn't have version info like PE

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
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let mut sections = Vec::new();
        let strtab = elf.shdr_strtab;

        for section in &elf.section_headers {
            let name = strtab.get_at(section.sh_name).unwrap_or("").to_string();
            
            let characteristics = SectionCharacteristics {
                readable: section.sh_flags & goblin::elf::section_header::SHF_ALLOC != 0,
                writable: section.sh_flags & goblin::elf::section_header::SHF_WRITE != 0,
                executable: section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR != 0,
                shared: false,
                discardable: section.sh_flags & goblin::elf::section_header::SHF_EXCLUDE != 0,
                not_cached: false,
                not_paged: false,
            };

            // Calculate entropy for the section
            let entropy = if section.sh_size > 0 && section.sh_offset < data.len() as u64 {
                let start = section.sh_offset as usize;
                let end = (start + section.sh_size as usize).min(data.len());
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
                virtual_address: section.sh_addr,
                virtual_size: section.sh_size,
                raw_offset: section.sh_offset,
                raw_size: section.sh_size,
                characteristics,
                entropy,
            });
        }

        Ok(sections)
    }

    async fn extract_segments(&self, data: &[u8]) -> Result<Vec<SegmentInfo>> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let mut segments = Vec::new();

        for phdr in &elf.program_headers {
            if phdr.p_type == goblin::elf::program_header::PT_LOAD {
                let permissions = SegmentPermissions {
                    readable: phdr.p_flags & goblin::elf::program_header::PF_R != 0,
                    writable: phdr.p_flags & goblin::elf::program_header::PF_W != 0,
                    executable: phdr.p_flags & goblin::elf::program_header::PF_X != 0,
                };

                segments.push(SegmentInfo {
                    virtual_address: phdr.p_vaddr,
                    virtual_size: phdr.p_memsz,
                    raw_offset: phdr.p_offset,
                    raw_size: phdr.p_filesz,
                    permissions,
                    alignment: phdr.p_align,
                });
            }
        }

        Ok(segments)
    }

    async fn extract_symbols(&self, data: &[u8]) -> Result<Vec<SymbolInfo>> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let mut symbols = Vec::new();
        let strtab = elf.dynstrtab.as_deref().unwrap_or("");

        for sym in &elf.dynsyms {
            let name = strtab.get_at(sym.st_name).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }

            let symbol_type = match goblin::elf::sym::st_type(sym.st_info) {
                goblin::elf::sym::STT_FUNC => SymbolType::Function,
                goblin::elf::sym::STT_OBJECT => SymbolType::Object,
                goblin::elf::sym::STT_SECTION => SymbolType::Section,
                goblin::elf::sym::STT_FILE => SymbolType::File,
                goblin::elf::sym::STT_COMMON => SymbolType::Common,
                goblin::elf::sym::STT_TLS => SymbolType::Tls,
                _ => SymbolType::Unknown,
            };

            let binding = match goblin::elf::sym::st_bind(sym.st_info) {
                goblin::elf::sym::STB_LOCAL => SymbolBinding::Local,
                goblin::elf::sym::STB_GLOBAL => SymbolBinding::Global,
                goblin::elf::sym::STB_WEAK => SymbolBinding::Weak,
                _ => SymbolBinding::Unknown,
            };

            let visibility = match goblin::elf::sym::st_visibility(sym.st_other) {
                goblin::elf::sym::STV_DEFAULT => SymbolVisibility::Default,
                goblin::elf::sym::STV_INTERNAL => SymbolVisibility::Internal,
                goblin::elf::sym::STV_HIDDEN => SymbolVisibility::Hidden,
                goblin::elf::sym::STV_PROTECTED => SymbolVisibility::Protected,
                _ => SymbolVisibility::Unknown,
            };

            symbols.push(SymbolInfo {
                name,
                address: sym.st_value,
                size: sym.st_size,
                symbol_type,
                binding,
                visibility,
                section_index: if sym.st_shndx != 0 { Some(sym.st_shndx) } else { None },
            });
        }

        Ok(symbols)
    }

    async fn extract_imports(&self, data: &[u8]) -> Result<Vec<ImportInfo>> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let mut imports = Vec::new();
        let mut lib_map: HashMap<String, Vec<ImportedFunction>> = HashMap::new();

        // Extract needed libraries from dynamic section
        for dyn_entry in &elf.dynamic {
            if dyn_entry.d_tag == goblin::elf::dynamic::DT_NEEDED {
                if let Some(name) = elf.dynstrtab.as_deref().and_then(|s| s.get_at(dyn_entry.d_val as usize)) {
                    lib_map.entry(name.to_string()).or_default();
                }
            }
        }

        // Extract imported symbols
        for sym in &elf.dynsyms {
            if goblin::elf::sym::st_bind(sym.st_info) == goblin::elf::sym::STB_GLOBAL
                && sym.st_shndx == goblin::elf::sym::SHN_UNDEF
            {
                if let Some(name) = elf.dynstrtab.as_deref().and_then(|s| s.get_at(sym.st_name)) {
                    // Find which library this symbol comes from
                    // This is a simplification - in reality we'd need to check version info
                    for lib in lib_map.keys() {
                        lib_map.get_mut(lib).unwrap().push(ImportedFunction {
                            name: name.to_string(),
                            address: None,
                            ordinal: None,
                        });
                        break;
                    }
                }
            }
        }

        for (library, functions) in lib_map {
            if !functions.is_empty() {
                imports.push(ImportInfo { library, functions });
            }
        }

        Ok(imports)
    }

    async fn extract_exports(&self, data: &[u8]) -> Result<Vec<ExportInfo>> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let mut exports = Vec::new();
        let strtab = elf.dynstrtab.as_deref().unwrap_or("");

        for sym in &elf.dynsyms {
            if goblin::elf::sym::st_bind(sym.st_info) == goblin::elf::sym::STB_GLOBAL
                && sym.st_shndx != goblin::elf::sym::SHN_UNDEF
            {
                if let Some(name) = strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        exports.push(ExportInfo {
                            name: name.to_string(),
                            address: sym.st_value,
                            ordinal: 0, // ELF doesn't use ordinals
                            forwarder: None,
                        });
                    }
                }
            }
        }

        Ok(exports)
    }

    async fn extract_strings(&self, data: &[u8]) -> Result<Vec<ExtractedString>> {
        let elf = Elf::parse(data)
            .map_err(|e| openre_core::Error::Validation(format!("Failed to parse ELF: {}", e)))?;

        let mut strings = Vec::new();

        // Extract strings from .rodata, .data, .bss sections
        for section in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
            if name == ".rodata" || name == ".data" || name == ".bss" || name == ".sdata" {
                if section.sh_size > 0 && section.sh_offset < data.len() as u64 {
                    let start = section.sh_offset as usize;
                    let end = (start + section.sh_size as usize).min(data.len());
                    if start < end {
                        let section_strings = extract_strings_from_data(&data[start..end], section.sh_addr, Some(name.to_string()));
                        strings.extend(section_strings);
                    }
                }
            }
        }

        // Also extract from .strtab and .dynstr
        for section in &elf.section_headers {
            let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
            if name == ".strtab" || name == ".dynstr" {
                if section.sh_size > 0 && section.sh_offset < data.len() as u64 {
                    let start = section.sh_offset as usize;
                    let end = (start + section.sh_size as usize).min(data.len());
                    if start < end {
                        let section_strings = extract_strings_from_data(&data[start..end], section.sh_addr, Some(name.to_string()));
                        strings.extend(section_strings);
                    }
                }
            }
        }

        Ok(strings)
    }

    async fn extract_resources(&self, _data: &[u8]) -> Result<Vec<ResourceInfo>> {
        Ok(Vec::new()) // ELF doesn't have resources
    }

    async fn extract_version_info(&self, _data: &[u8]) -> Result<Option<VersionInfo>> {
        Ok(None) // ELF doesn't have version info like PE
    }
}

/// Extract security features from ELF
fn extract_security_features(elf: &Elf) -> SecurityFeatures {
    let mut features = SecurityFeatures::default();

    // Check for PIE (Position Independent Executable)
    features.pie = elf.header.e_type == goblin::elf::header::ET_DYN;

    // Check for RELRO
    let mut has_relro = false;
    let mut has_bind_now = false;
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_RELRO {
            has_relro = true;
        }
    }
    for dyn_entry in &elf.dynamic {
        if dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS_1 {
            if dyn_entry.d_val & goblin::elf::dynamic::DF_1_NOW != 0 {
                has_bind_now = true;
            }
        }
    }
    features.relro = if has_relro && has_bind_now {
        RelroLevel::Full
    } else if has_relro {
        RelroLevel::Partial
    } else {
        RelroLevel::None
    };

    // Check for stack canary (look for __stack_chk_fail symbol)
    let strtab = elf.dynstrtab.as_deref().unwrap_or("");
    for sym in &elf.dynsyms {
        if let Some(name) = strtab.get_at(sym.st_name) {
            if name.contains("stack_chk_fail") || name.contains("stack_smash") {
                features.stack_canary = true;
                break;
            }
        }
    }

    // Check for FORTIFY_SOURCE (look for __chk_fail or similar)
    for sym in &elf.dynsyms {
        if let Some(name) = strtab.get_at(sym.st_name) {
            if name.contains("_chk_fail") || name.contains("_fortify") {
                features.fortify_source = true;
                break;
            }
        }
    }

    // NX/DEP - check if stack is executable
    for phdr in &elf.program_headers {
        if phdr.p_type == goblin::elf::program_header::PT_GNU_STACK {
            features.dep_nx = (phdr.p_flags & goblin::elf::program_header::PF_X) == 0;
            break;
        }
    }

    // ASLR - if PIE is enabled, ASLR is likely enabled
    features.aslr = features.pie;

    features
}

/// Extract compiler info from .comment section
fn extract_compiler_info(elf: &Elf, data: &[u8]) -> Option<CompilerInfo> {
    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");
        if name == ".comment" {
            if section.sh_size > 0 && section.sh_offset < data.len() as u64 {
                let start = section.sh_offset as usize;
                let end = (start + section.sh_size as usize).min(data.len());
                if start < end {
                    let comment = String::from_utf8_lossy(&data[start..end]);
                    return parse_compiler_comment(&comment);
                }
            }
        }
    }
    None
}

fn parse_compiler_comment(comment: &str) -> Option<CompilerInfo> {
    // GCC: "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
    // Clang: "clang version 14.0.0-1ubuntu1"
    if comment.contains("GCC:") || comment.contains("gcc") {
        let version = comment.split_whitespace()
            .find(|s| s.chars().next().map_or(false, |c| c.is_ascii_digit()))
            .map(|s| s.to_string());
        Some(CompilerInfo {
            name: "GCC".to_string(),
            version,
            language: Some("C/C++".to_string()),
        })
    } else if comment.contains("clang") {
        let version = comment.split_whitespace()
            .find(|s| s.chars().next().map_or(false, |c| c.is_ascii_digit()))
            .map(|s| s.to_string());
        Some(CompilerInfo {
            name: "Clang".to_string(),
            version,
            language: Some("C/C++".to_string()),
        })
    } else if comment.contains("rustc") {
        let version = comment.split_whitespace()
            .find(|s| s.chars().next().map_or(false, |c| c.is_ascii_digit()))
            .map(|s| s.to_string());
        Some(CompilerInfo {
            name: "rustc".to_string(),
            version,
            language: Some("Rust".to_string()),
        })
    } else {
        None
    }
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
fn extract_strings_from_data(data: &[u8], base_addr: u64, section: Option<String>) -> Vec<ExtractedString> {
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