//! Capstone disassembler wrapper

use crate::architecture::{Architecture, Endianness, RegisterSet, Syntax};
use crate::error::{DisasmError, Result};
use capstone::prelude::*;
use capstone::Endian;
use serde::{Deserialize, Serialize};

/// Wrapper around Capstone disassembler engine
pub struct CapstoneWrapper {
    /// The underlying Capstone instance
    cs: Capstone,
    /// Architecture being disassembled
    arch: Architecture,
    /// Endianness of the target binary
    endian: Endianness,
    /// Register set for the architecture
    regs: RegisterSet,
}

impl CapstoneWrapper {
    /// Create a new Capstone wrapper for the given architecture
    pub fn new(arch: Architecture, endian: Endianness, syntax: Syntax) -> Result<Self> {
        let regs = RegisterSet::for_architecture(arch);
        let cs = Self::build_capstone(arch, endian, syntax)?;
        Ok(Self { cs, arch, endian, regs })
    }

    /// Build Capstone instance using the raw API for maximum compatibility
    fn build_capstone(arch: Architecture, endian: Endianness, syntax: Syntax) -> Result<Capstone> {
        // Convert syntax - only some architectures support syntax selection
        let cs_syntax = match syntax {
            Syntax::Intel => capstone::Syntax::Intel,
            Syntax::Att => capstone::Syntax::Att,
        };

        // Infer bitness from architecture
        let bitness = match arch {
            Architecture::X86_64
            | Architecture::AArch64
            | Architecture::Mips64
            | Architecture::RiscV64
            | Architecture::PowerPc64
            | Architecture::Sparc64 => 64,
            Architecture::X86
            | Architecture::Arm
            | Architecture::Mips
            | Architecture::RiscV32
            | Architecture::PowerPc
            | Architecture::Sparc => 32,
            Architecture::SystemZ => 64,
            Architecture::Bpf => 64,
            Architecture::Evm => 64,
            Architecture::Unknown => 64,
        };

        // Build based on architecture - use the raw API for maximum compatibility
        let cs_arch = arch.capstone_arch();
        let cs_mode = arch.capstone_mode(bitness);

        let cs_endian = match endian {
            Endianness::Little => Some(Endian::Little),
            Endianness::Big => Some(Endian::Big),
        };

        let mut cs = Capstone::new_raw(cs_arch, cs_mode, capstone::NO_EXTRA_MODE, cs_endian)
            .map_err(|e| DisasmError::CapstoneInit(e.to_string()))?;

        // Set syntax for architectures that support it
        let supports_syntax = matches!(
            arch,
            Architecture::X86
                | Architecture::X86_64
                | Architecture::Arm
                | Architecture::PowerPc
                | Architecture::PowerPc64
        );
        if supports_syntax {
            cs.set_syntax(cs_syntax).map_err(|e| DisasmError::CapstoneInit(e.to_string()))?;
        }

        // Enable detail
        cs.set_detail(true).map_err(|e| DisasmError::CapstoneInit(e.to_string()))?;

        Ok(cs)
    }

    /// Get the architecture
    pub fn architecture(&self) -> Architecture {
        self.arch
    }

    /// Get the endianness
    pub fn endianness(&self) -> Endianness {
        self.endian
    }

    /// Get the register set
    pub fn register_set(&self) -> &RegisterSet {
        &self.regs
    }

    /// Disassemble a single instruction at the given address
    pub fn disassemble_one(&self, code: &[u8], address: u64) -> Result<Option<Insn>> {
        let insns = self.cs.disasm_count(code, address, 1).map_err(|e| {
            DisasmError::DisassemblyFailed { offset: address, reason: e.to_string() }
        })?;
        Ok(insns.iter().next().map(|insn| Insn::from_capstone(&self.cs, insn)))
    }

    /// Disassemble multiple instructions
    pub fn disassemble(&self, code: &[u8], address: u64, count: usize) -> Result<Vec<Insn>> {
        let insns = self.cs.disasm_count(code, address, count).map_err(|e| {
            DisasmError::DisassemblyFailed { offset: address, reason: e.to_string() }
        })?;
        Ok(insns.iter().map(|insn| Insn::from_capstone(&self.cs, insn)).collect())
    }

    /// Disassemble all instructions in the given code
    pub fn disassemble_all(&self, code: &[u8], address: u64) -> Result<Vec<Insn>> {
        let insns = self.cs.disasm_all(code, address).map_err(|e| {
            DisasmError::DisassemblyFailed { offset: address, reason: e.to_string() }
        })?;
        Ok(insns.iter().map(|insn| Insn::from_capstone(&self.cs, insn)).collect())
    }
}

/// Instruction detail from Capstone
#[derive(Debug, Clone)]
pub struct Insn {
    /// Instruction address
    pub address: u64,
    /// Instruction bytes
    pub bytes: Vec<u8>,
    /// Mnemonic (e.g., "mov", "add")
    pub mnemonic: String,
    /// Operands string (e.g., "eax, 1")
    pub op_str: String,
    /// Instruction ID
    pub id: InsnId,
    /// Instruction groups
    pub groups: Vec<InsnGroup>,
    /// Detailed operand information
    pub operands: Vec<OpDetail>,
    /// Registers read
    pub regs_read: Vec<RegId>,
    /// Registers written
    pub regs_write: Vec<RegId>,
}

impl Insn {
    fn from_capstone(cs: &Capstone, insn: &capstone::Insn) -> Self {
        let detail = cs.insn_detail(insn).ok();

        let groups = detail
            .as_ref()
            .map(|d| d.groups().iter().map(InsnGroup::from_capstone).collect())
            .unwrap_or_default();

        // Note: operands require architecture-specific detail extraction
        // For now, we leave operands empty and rely on mnemonic/op_str
        let operands = Vec::new();

        let regs_read = detail
            .as_ref()
            .map(|d| d.regs_read().iter().map(|r| RegId(r.0 as u32)).collect())
            .unwrap_or_default();
        let regs_write = detail
            .as_ref()
            .map(|d| d.regs_write().iter().map(|r| RegId(r.0 as u32)).collect())
            .unwrap_or_default();

        Self {
            address: insn.address(),
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("").to_string(),
            op_str: insn.op_str().unwrap_or("").to_string(),
            id: InsnId(insn.id().0),
            groups,
            operands,
            regs_read,
            regs_write,
        }
    }
}

/// Instruction group classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InsnGroup {
    Invalid,
    Jump,
    Call,
    Ret,
    Int,
    Iret,
    Privilege,
    BranchRelative,
    BranchConditional,
    // Add more as needed
}

impl InsnGroup {
    fn from_capstone(g: &capstone::InsnGroupId) -> Self {
        // Capstone group type constants (from capstone_sys)
        // CS_GRP_INVALID = 0
        // CS_GRP_JUMP = 1
        // CS_GRP_CALL = 2
        // CS_GRP_RET = 3
        // CS_GRP_INT = 4
        // CS_GRP_IRET = 5
        // CS_GRP_PRIVILEGE = 6
        // CS_GRP_BRANCH_RELATIVE = 7
        // CS_GRP_CONDITIONAL_BRANCH = 8
        match g.0 {
            0 => InsnGroup::Invalid,
            1 => InsnGroup::Jump,
            2 => InsnGroup::Call,
            3 => InsnGroup::Ret,
            4 => InsnGroup::Int,
            5 => InsnGroup::Iret,
            6 => InsnGroup::Privilege,
            7 => InsnGroup::BranchRelative,
            8 => InsnGroup::BranchConditional,
            _ => InsnGroup::Invalid,
        }
    }
}

/// Operand detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpDetail {
    /// Operand type
    pub op_type: OpType,
    /// Register operand (if applicable)
    pub reg: Option<RegId>,
    /// Immediate value (if applicable)
    pub imm: Option<i64>,
    /// Memory operand details (if applicable)
    pub mem: Option<MemDetail>,
}

impl OpDetail {
    #[allow(dead_code)]
    fn from_capstone(_op: &()) -> Self {
        // Placeholder - detailed operand extraction requires architecture-specific code
        OpDetail { op_type: OpType::RegMem, reg: None, imm: None, mem: None }
    }
}

/// Operand type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpType {
    Reg,
    Imm,
    Mem,
    Fp,
    CImm,
    RegMem,
}

/// Memory operand detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemDetail {
    /// Base register
    pub base: Option<RegId>,
    /// Index register
    pub index: Option<RegId>,
    /// Scale factor
    pub scale: i32,
    /// Displacement
    pub disp: i64,
}

/// Register ID (architecture-specific)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegId(pub u32);

/// Instruction ID (architecture-specific)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InsnId(pub u32);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::architecture::{Architecture, Endianness, Syntax};

    #[test]
    fn test_x86_64_disasm() {
        let wrapper =
            CapstoneWrapper::new(Architecture::X86_64, Endianness::Little, Syntax::Intel).unwrap();

        // push rbp; mov rbp, rsp; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let insns = wrapper.disassemble_all(&code, 0x1000).unwrap();

        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[2].mnemonic, "pop");
        assert_eq!(insns[3].mnemonic, "ret");
    }

    #[test]
    fn test_aarch64_disasm() {
        let wrapper =
            CapstoneWrapper::new(Architecture::AArch64, Endianness::Little, Syntax::Intel).unwrap();

        // stp x29, x30, [sp, #-16]!; mov x29, sp; ldp x29, x30, [sp], #16; ret
        let code = [
            0xa9, 0xbf, 0x7f, 0xd2, 0xfd, 0x7b, 0xbf, 0xa9, 0xa8, 0xbf, 0x7f, 0xf2, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        let insns = wrapper.disassemble_all(&code, 0x1000).unwrap();

        assert!(insns.len() >= 3);
    }
}
