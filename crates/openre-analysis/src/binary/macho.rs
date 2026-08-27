//! MachO Binary Parser

use anyhow::Result;
use goblin::mach::MachO;
use std::path::Path;

use super::{BinaryFormat, BinaryInfo, Symbol, Section, Import, Export};

pub struct MachoParser;

impl MachoParser {
    pub fn parse(path: &Path) -> Result<BinaryInfo> {
        let bytes = std::fs::read(path)?;
        let macho = MachO::parse(&bytes)?;

        let mut info = BinaryInfo {
            format: BinaryFormat::MachO,
            architecture: crate::Architecture::Unknown,
            entry_point: 0,
            base_address: 0,
            sections: Vec::new(),
            symbols: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
        };

        match macho {
            MachO::Binary(bin) => {
                info.architecture = Self::arch_from_macho(&bin);
                info.entry_point = bin.entry as u64;
                info.base_address = bin.base_address();

                // Parse segments/sections
                for segment in &bin.segments {
                    for section in &segment.sections() {
                        if let Ok(sect) = section {
                            let name = sect.name().unwrap_or("unknown").to_string();
                            info.sections.push(Section {
                                name,
                                address: sect.addr,
                                size: sect.size,
                                flags: Self::section_flags(sect.flags),
                                data: Some(sect.data(&bytes).to_vec()),
                            });
                        }
                    }
                }

                // Parse symbols
                if let Ok(symtab) = bin.symbols() {
                    for symbol in symtab {
                        info.symbols.push(Symbol {
                            name: symbol.name().unwrap_or("").to_string(),
                            address: symbol.value,
                            size: 0,
                            symbol_type: crate::SymbolType::Unknown,
                            binding: crate::SymbolBinding::Global,
                            section_index: symbol.sect as u32,
                        });
                    }
                }

                // Parse imports (dyld)
                for import in bin.imports() {
                    info.imports.push(Import {
                        name: import.name().to_string(),
                        library: import.library().map(|s| s.to_string()),
                    });
                }

                // Parse exports
                for export in bin.exports() {
                    info.exports.push(Export {
                        name: export.name().to_string(),
                        address: export.address(),
                    });
                }
            }
            MachO::Fat(multi) => {
                // Use first architecture (usually x86_64 or arm64)
                if let Some(arch) = multi.iter().next() {
                    return Self::parse_single(arch, &bytes);
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

    fn parse_single(arch: &goblin::mach::SingleArch, bytes: &[u8]) -> Result<BinaryInfo> {
        // Simplified - would need full implementation
        todo!("Implement fat binary single arch parsing")
    }

    fn arch_from_macho(bin: &goblin::mach::MachO) -> crate::Architecture {
        match bin.header.cputype {
            goblin::mach::constants::cputype::CPU_TYPE_X86_64 => crate::Architecture::X86_64,
            goblin::mach::constants::cputype::CPU_TYPE_I386 => crate::Architecture::X86,
            goblin::mach::constants::cputype::CPU_TYPE_ARM64 => crate::Architecture::Arm64,
            goblin::mach::constants::cputype::CPU_TYPE_ARM => crate::Architecture::Arm,
            _ => crate::Architecture::Unknown,
        }
    }

    fn section_flags(flags: u32) -> crate::SectionFlags {
        crate::SectionFlags {
            readable: flags & 0x1 != 0,  // S_ATTR_PURE_INSTRUCTIONS (readable)
            writable: flags & 0x2 != 0,  // Some writable flag
            executable: flags & 0x4 != 0, // S_ATTR_PURE_INSTRUCTIONS
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
