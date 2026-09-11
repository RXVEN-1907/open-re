//! Architecture definitions for multi-architecture support

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Supported CPU architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Architecture {
    /// 32-bit x86
    X86,
    /// 64-bit x86 (x86-64/AMD64)
    X86_64,
    /// 32-bit ARM
    Arm,
    /// 64-bit ARM (AArch64/ARM64)
    AArch64,
    /// 32-bit MIPS
    Mips,
    /// 64-bit MIPS
    Mips64,
    /// 32-bit RISC-V
    RiscV32,
    /// 64-bit RISC-V
    RiscV64,
    /// 32-bit PowerPC
    PowerPc,
    /// 64-bit PowerPC
    PowerPc64,
    /// 32-bit SPARC
    Sparc,
    /// 64-bit SPARC
    Sparc64,
    /// SystemZ (s390x)
    SystemZ,
    /// Berkeley Packet Filter
    Bpf,
    /// Ethereum Virtual Machine
    Evm,
    /// Unknown/unsupported architecture
    Unknown,
}

impl Architecture {
    pub fn capstone_arch(&self) -> capstone::Arch {
        match self {
            Architecture::X86 | Architecture::X86_64 => capstone::Arch::X86,
            Architecture::Arm => capstone::Arch::ARM,
            Architecture::AArch64 => capstone::Arch::ARM64,
            Architecture::Mips | Architecture::Mips64 => capstone::Arch::MIPS,
            Architecture::RiscV32 | Architecture::RiscV64 => capstone::Arch::RISCV,
            Architecture::PowerPc | Architecture::PowerPc64 => capstone::Arch::PPC,
            Architecture::Sparc | Architecture::Sparc64 => capstone::Arch::SPARC,
            Architecture::SystemZ => capstone::Arch::SYSZ,
            Architecture::Bpf => capstone::Arch::BPF,
            Architecture::Evm => capstone::Arch::EVM,
            Architecture::Unknown => capstone::Arch::X86,
        }
    }

    pub fn capstone_mode(&self, bitness: u8) -> capstone::Mode {
        match (self, bitness) {
            (Architecture::X86, 16) => capstone::Mode::Mode16,
            (Architecture::X86, 32) => capstone::Mode::Mode32,
            (Architecture::X86_64, 64) => capstone::Mode::Mode64,
            (Architecture::Arm, 32) => capstone::Mode::Arm,
            (Architecture::AArch64, 64) => capstone::Mode::Arm,
            (Architecture::Mips, 32) => capstone::Mode::Mips32,
            (Architecture::Mips64, 64) => capstone::Mode::Mips64,
            (Architecture::RiscV32, 32) => capstone::Mode::RiscV32,
            (Architecture::RiscV64, 64) => capstone::Mode::RiscV64,
            (Architecture::PowerPc, 32) => capstone::Mode::Mode32,
            (Architecture::PowerPc64, 64) => capstone::Mode::Mode64,
            _ => capstone::Mode::Default,
        }
    }

    pub fn default_endian(&self) -> Endianness {
        match self {
            Architecture::Mips
            | Architecture::Mips64
            | Architecture::Sparc
            | Architecture::Sparc64
            | Architecture::PowerPc
            | Architecture::PowerPc64 => Endianness::Big,
            _ => Endianness::Little,
        }
    }

    pub fn register_names(&self) -> &'static [&'static str] {
        match self {
            Architecture::X86_64 => &[
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15", "rip", "rflags", "cs", "ss", "ds", "es", "fs", "gs",
            ],
            Architecture::X86 => &[
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags", "cs",
                "ss", "ds", "es", "fs", "gs",
            ],
            Architecture::AArch64 => &[
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12",
                "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24",
                "x25", "x26", "x27", "x28", "x29", "x30", "sp", "pc",
            ],
            Architecture::Arm => &[
                "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
                "sp", "lr", "pc", "cpsr",
            ],
            Architecture::RiscV64 => &[
                "x0", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
                "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
                "s11", "t3", "t4", "t5", "t6", "pc",
            ],
            _ => &[],
        }
    }

    pub fn calling_convention(&self) -> CallingConvention {
        match self {
            Architecture::X86_64 => CallingConvention::SystemVAmd64,
            Architecture::X86 => CallingConvention::Cdecl,
            Architecture::AArch64 => CallingConvention::Aapcs64,
            Architecture::Arm => CallingConvention::Aapcs,
            Architecture::RiscV64 => CallingConvention::RiscV,
            Architecture::Mips64 => CallingConvention::MipsO32,
            _ => CallingConvention::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Syntax {
    Intel,
    Att,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    SystemVAmd64,
    MicrosoftX64,
    Cdecl,
    Stdcall,
    Fastcall,
    Aapcs,
    Aapcs64,
    RiscV,
    MipsO32,
    MipsN32,
    MipsN64,
    Unknown,
}

impl CallingConvention {
    pub fn argument_registers(&self) -> &'static [&'static str] {
        match self {
            CallingConvention::SystemVAmd64 => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            CallingConvention::MicrosoftX64 => &["rcx", "rdx", "r8", "r9"],
            CallingConvention::Aapcs64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            CallingConvention::Aapcs => &["r0", "r1", "r2", "r3"],
            CallingConvention::RiscV => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
            CallingConvention::MipsO32 => &["a0", "a1", "a2", "a3"],
            _ => &[],
        }
    }

    pub fn return_register(&self) -> &'static str {
        match self {
            CallingConvention::SystemVAmd64 | CallingConvention::MicrosoftX64 => "rax",
            CallingConvention::Aapcs64 => "x0",
            CallingConvention::Aapcs => "r0",
            CallingConvention::RiscV => "a0",
            CallingConvention::MipsO32 => "v0",
            _ => "rax",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSet {
    pub registers: HashMap<String, RegisterInfo>,
    pub flags_register: Option<String>,
    pub instruction_pointer: String,
    pub stack_pointer: String,
    pub frame_pointer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInfo {
    pub name: String,
    pub size: u8,
    pub alias: Option<String>,
    pub sub_registers: Vec<String>,
}

impl RegisterSet {
    pub fn for_architecture(arch: Architecture) -> Self {
        let mut registers = HashMap::new();
        for name in arch.register_names() {
            registers.insert(
                name.to_string(),
                RegisterInfo {
                    name: name.to_string(),
                    size: match arch {
                        Architecture::X86_64
                        | Architecture::AArch64
                        | Architecture::RiscV64
                        | Architecture::PowerPc64
                        | Architecture::Sparc64
                        | Architecture::Mips64 => 64,
                        _ => 32,
                    },
                    alias: None,
                    sub_registers: vec![],
                },
            );
        }
        Self {
            registers,
            flags_register: Some(match arch {
                Architecture::X86 | Architecture::X86_64 => "rflags".to_string(),
                Architecture::Arm | Architecture::AArch64 => "cpsr".to_string(),
                Architecture::RiscV64 => "pc".to_string(),
                _ => "flags".to_string(),
            }),
            instruction_pointer: match arch {
                Architecture::X86 | Architecture::X86_64 => "rip".to_string(),
                Architecture::Arm | Architecture::AArch64 => "pc".to_string(),
                Architecture::RiscV64 => "pc".to_string(),
                _ => "ip".to_string(),
            },
            stack_pointer: match arch {
                Architecture::X86_64 => "rsp".to_string(),
                Architecture::X86 => "esp".to_string(),
                Architecture::AArch64 => "sp".to_string(),
                Architecture::Arm => "sp".to_string(),
                Architecture::RiscV64 => "sp".to_string(),
                _ => "sp".to_string(),
            },
            frame_pointer: Some(match arch {
                Architecture::X86_64 => "rbp".to_string(),
                Architecture::X86 => "ebp".to_string(),
                Architecture::AArch64 => "x29".to_string(),
                Architecture::Arm => "r11".to_string(),
                Architecture::RiscV64 => "s0".to_string(),
                _ => "fp".to_string(),
            }),
        }
    }

    pub fn default_endian(arch: Architecture) -> Endianness {
        arch.default_endian()
    }

    pub fn register_names(arch: Architecture) -> Vec<String> {
        arch.register_names().iter().map(|s| s.to_string()).collect()
    }

    pub fn calling_convention(arch: Architecture) -> CallingConvention {
        arch.calling_convention()
    }

    pub fn argument_registers(conv: CallingConvention) -> Vec<String> {
        conv.argument_registers().iter().map(|s| s.to_string()).collect()
    }
}

/// Type of control flow edge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CfgEdgeType {
    Unconditional,
    ConditionalTrue,
    ConditionalFalse,
    Call,
    Return,
    Indirect,
    Exception,
    Fallthrough,
}

/// Edge in a control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub edge_type: CfgEdgeType,
    pub condition: Option<String>,
}

/// Basic block in a control flow graph
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: usize,
    pub start_address: u64,
    pub end_address: u64,
    pub instructions: Vec<u64>,
    pub predecessors: Vec<usize>,
    pub successors: Vec<usize>,
    pub is_entry: bool,
    pub is_exit: bool,
}

/// Control flow graph
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    #[serde(skip)]
    pub graph: petgraph::Graph<BasicBlock, CfgEdge>,
    pub entry: Option<usize>,
    pub exits: Vec<usize>,
}

/// Dominator tree for a control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DominatorTree {
    pub idoms: HashMap<usize, usize>,
    pub dominance_frontier: HashMap<usize, Vec<usize>>,
}

/// Loop information for a control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopInfo {
    pub headers: Vec<usize>,
    pub bodies: Vec<Vec<usize>>,
    pub depth: HashMap<usize, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x86_64_registers() {
        let regs = RegisterSet::for_architecture(Architecture::X86_64);
        assert!(regs.registers.contains_key("rax"));
        assert!(regs.registers.contains_key("rsp"));
        assert!(regs.registers.contains_key("rbp"));
        assert_eq!(regs.stack_pointer, "rsp");
        assert_eq!(regs.frame_pointer, Some("rbp".to_string()));
    }

    #[test]
    fn test_aarch64_calling_convention() {
        let cc = Architecture::AArch64.calling_convention();
        assert_eq!(cc.argument_registers(), &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]);
        assert_eq!(cc.return_register(), "x0");
    }

    #[test]
    fn test_systemv_amd64_calling_convention() {
        let cc = CallingConvention::SystemVAmd64;
        assert_eq!(cc.argument_registers(), &["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
        assert_eq!(cc.return_register(), "rax");
    }
}
