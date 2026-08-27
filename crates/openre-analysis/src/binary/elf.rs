//! ELF Binary Parser

use anyhow::Result;
use goblin::elf::Elf;
use std::path::Path;

use super::{BinaryFormat, BinaryInfo, Export, Import, Section, Symbol};

pub struct ElfParser;

impl ElfParser {
    pub fn parse(path: &Path) -> Result<BinaryInfo> {
        let bytes = std::fs::read(path)?;
        let elf = Elf::parse(&bytes)?;

        let mut info = BinaryInfo {
            format: BinaryFormat::Elf,
            architecture: Self::arch_from_elf(&elf),
            entry_point: elf.entry as u64,
            base_address: elf
                .header
                .pt_load
                .iter()
                .find(|ph| ph.p_flags & 0x1 != 0) // PF_X
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
                if binding == goblin::elf::sym::STB_GLOBAL && sym.st_shndx == 0 {
                    // Import
                    info.imports.push(Import {
                        name: name.to_string(),
                        library: None, // Would need DT_NEEDED parsing
                    });
                } else if binding == goblin::elf::sym::STB_GLOBAL && sym.st_shndx != 0 {
                    // Export
                    info.exports.push(Export {
                        name: name.to_string(),
                        address: sym.st_value,
                    });
                }
            }
        }

        // Extract strings
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

    fn symbol_binding(info: u8) -> u8 {
        goblin::elf::sym::st_bind(info)
    }
}
