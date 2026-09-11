//! Disassembler core functionality

use crate::architecture::{Architecture, Endianness, Syntax};
use crate::capstone_wrapper::{CapstoneWrapper, Insn, InsnGroup};
use crate::error::{DisasmError, Result};
use serde::{Deserialize, Serialize};

/// Configuration for disassembly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyConfig {
    /// Target architecture
    pub architecture: Architecture,
    /// Endianness
    pub endianness: Endianness,
    /// Assembly syntax
    pub syntax: Syntax,
    /// Base address for disassembly
    pub base_address: u64,
    /// Bitness (32 or 64)
    pub bitness: u8,
    /// Maximum number of instructions to disassemble (0 = unlimited)
    pub max_instructions: usize,
    /// Whether to skip data sections
    pub skip_data: bool,
    /// Whether to enable detailed operand analysis
    pub detailed_operands: bool,
    /// Whether to track register definitions/uses
    pub track_registers: bool,
}

impl Default for DisassemblyConfig {
    fn default() -> Self {
        Self {
            architecture: Architecture::X86_64,
            endianness: Endianness::Little,
            syntax: Syntax::Intel,
            base_address: 0,
            bitness: 64,
            max_instructions: 0,
            skip_data: false,
            detailed_operands: true,
            track_registers: true,
        }
    }
}

/// Disassembled instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    /// Instruction address
    pub address: u64,
    /// Instruction size in bytes
    pub size: usize,
    /// Raw instruction bytes
    pub bytes: Vec<u8>,
    /// Mnemonic (e.g., "mov", "add", "jmp")
    pub mnemonic: String,
    /// Operand string (e.g., "rax, 1")
    pub op_str: String,
    /// Instruction groups (jump, call, ret, etc.)
    pub groups: Vec<InsnGroup>,
    /// Detailed operand information
    pub operands: Vec<Operand>,
    /// Registers read by this instruction
    pub regs_read: Vec<String>,
    /// Registers written by this instruction
    pub regs_write: Vec<String>,
    /// Instruction detail (optional, for advanced analysis)
    pub detail: Option<InstructionDetail>,
}

/// Instruction detail for advanced analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionDetail {
    /// Instruction ID (architecture-specific)
    pub id: u32,
    /// Operand details
    pub operands: Vec<OperandDetail>,
    /// Implicit registers read
    pub regs_read: Vec<u32>,
    /// Implicit registers written
    pub regs_write: Vec<u32>,
    /// Instruction groups
    pub groups: Vec<u32>,
}

/// Operand in an instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operand {
    /// Register operand
    Reg(String),
    /// Immediate value
    Imm(i64),
    /// Memory operand
    Mem { base: Option<String>, index: Option<String>, scale: i32, disp: i64 },
    /// Floating point immediate
    Fp(f64),
}

/// Detailed operand information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperandDetail {
    /// Operand type
    pub op_type: OperandType,
    /// Register index (if register)
    pub reg: Option<u32>,
    /// Immediate value (if immediate)
    pub imm: Option<i64>,
    /// Memory details (if memory)
    pub mem: Option<MemDetail>,
    /// Size in bytes
    pub size: u8,
    /// Access type (read/write/read-write)
    pub access: OperandAccess,
}

/// Operand type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandType {
    Register,
    Immediate,
    Memory,
    FloatingPoint,
    CImmediate,
    RegisterMemory,
}

/// Memory operand detail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemDetail {
    /// Base register index
    pub base: Option<u32>,
    /// Index register index
    pub index: Option<u32>,
    /// Scale factor (1, 2, 4, 8)
    pub scale: i32,
    /// Displacement
    pub disp: i64,
}

/// Operand access type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperandAccess {
    Read,
    Write,
    ReadWrite,
}

/// Main disassembler
pub struct Disassembler {
    /// Disassembly configuration
    pub config: DisassemblyConfig,
    /// Capstone wrapper
    pub wrapper: CapstoneWrapper,
}

impl Disassembler {
    /// Create a new disassembler with the given configuration
    pub fn new(config: DisassemblyConfig) -> Result<Self> {
        let wrapper = CapstoneWrapper::new(config.architecture, config.endianness, config.syntax)?;
        Ok(Self { config, wrapper })
    }

    /// Disassemble all instructions in the given code
    pub fn disassemble_all(&self, code: &[u8]) -> Result<Vec<Instruction>> {
        let insns = self.wrapper.disassemble_all(code, self.config.base_address)?;
        Ok(insns.into_iter().map(|i| self.convert_instruction(i)).collect())
    }

    /// Disassemble a specific range
    pub fn disassemble_range(&self, code: &[u8], start: u64, end: u64) -> Result<Vec<Instruction>> {
        let offset = (start.saturating_sub(self.config.base_address)) as usize;
        let size = (end - start) as usize;
        if offset + size > code.len() {
            return Err(DisasmError::DisassemblyFailed {
                offset: start,
                reason: "Range exceeds code buffer".to_string(),
            });
        }
        let insns =
            self.wrapper.disassemble(&code[offset..offset + size], start, (size / 4).max(1))?;
        Ok(insns.into_iter().map(|i| self.convert_instruction(i)).collect())
    }

    /// Get the architecture
    pub fn architecture(&self) -> Architecture {
        self.config.architecture
    }

    /// Get the endianness
    pub fn endianness(&self) -> Endianness {
        self.config.endianness
    }

    /// Get the syntax
    pub fn syntax(&self) -> Syntax {
        self.config.syntax
    }

    /// Convert Capstone instruction to our internal representation
    fn convert_instruction(&self, insn: Insn) -> Instruction {
        Instruction {
            address: insn.address,
            size: insn.bytes.len(),
            bytes: insn.bytes,
            mnemonic: insn.mnemonic,
            op_str: insn.op_str,
            groups: insn.groups,
            operands: Vec::new(), // Would need architecture-specific extraction
            regs_read: insn.regs_read.iter().map(|r| format!("reg_{}", r.0)).collect(),
            regs_write: insn.regs_write.iter().map(|r| format!("reg_{}", r.0)).collect(),
            detail: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembler_x86_64() {
        let config = DisassemblyConfig::default();
        let disasm = Disassembler::new(config).unwrap();

        // push rbp; mov rbp, rsp; pop rbp; ret
        let code = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        let insns = disasm.disassemble_all(&code).unwrap();

        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].mnemonic, "push");
        assert_eq!(insns[1].mnemonic, "mov");
        assert_eq!(insns[2].mnemonic, "pop");
        assert_eq!(insns[3].mnemonic, "ret");
    }
}
