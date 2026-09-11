//! Function detection and analysis

use crate::architecture::{Architecture, CallingConvention};
use crate::cfg::ControlFlowGraph;
use crate::disassembler::{Disassembler, DisassemblyConfig, Instruction};
use crate::error::{DisasmError, Result};
use std::collections::{HashMap, HashSet};

/// Detected function
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Function {
    /// Function start address
    pub start_address: u64,
    /// Function end address (exclusive)
    pub end_address: u64,
    /// Function name (if known)
    pub name: Option<String>,
    /// Function signature
    pub signature: Option<FunctionSignature>,
    /// Control flow graph
    pub cfg: ControlFlowGraph,
    /// Instructions in this function
    pub instructions: Vec<Instruction>,
    /// Stack frame info
    pub stack_frame: Option<StackFrame>,
    /// Calling convention
    pub calling_convention: CallingConvention,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
    /// Whether this is a thunk/trampoline
    pub is_thunk: bool,
    /// Whether this is a library function
    pub is_library: bool,
}

/// Function signature
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FunctionSignature {
    /// Return type
    pub return_type: Option<String>,
    /// Parameter types
    pub parameters: Vec<Parameter>,
    /// Calling convention
    pub calling_convention: CallingConvention,
    /// Whether function is variadic
    pub is_variadic: bool,
}

/// Function parameter
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Parameter {
    /// Parameter name
    pub name: Option<String>,
    /// Parameter type
    pub param_type: String,
    /// Register or stack location
    pub location: ParameterLocation,
}

/// Parameter location
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ParameterLocation {
    /// In register
    Register(String),
    /// On stack at offset
    Stack(i64),
    /// In register with stack spill
    RegisterStack(String, i64),
}

/// Stack frame information
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StackFrame {
    /// Stack frame size in bytes
    pub size: u64,
    /// Base pointer register
    pub base_pointer: Option<String>,
    /// Stack pointer offset at function entry
    pub sp_offset: i64,
    /// Saved registers
    pub saved_registers: Vec<SavedRegister>,
    /// Local variables
    pub locals: Vec<LocalVariable>,
    /// Function arguments on stack
    pub arguments: Vec<StackArgument>,
}

/// Saved register on stack
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SavedRegister {
    /// Register name
    pub register: String,
    /// Offset from base pointer
    pub offset: i64,
    /// Size in bytes
    pub size: u64,
}

/// Local variable
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalVariable {
    /// Variable name (if known)
    pub name: Option<String>,
    /// Type (if known)
    pub var_type: Option<String>,
    /// Offset from base pointer
    pub offset: i64,
    /// Size in bytes
    pub size: u64,
    /// Whether this is an array
    pub is_array: bool,
    /// Array element count
    pub array_count: Option<u64>,
}

/// Stack argument
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StackArgument {
    /// Argument index
    pub index: usize,
    /// Offset from stack pointer at call
    pub offset: i64,
    /// Size in bytes
    pub size: u64,
}

/// Function detector using various heuristics
#[allow(dead_code)]
pub struct FunctionDetector {
    /// Disassembler for instruction analysis
    disassembler: Disassembler,
    /// Architecture
    architecture: Architecture,
    /// Known function signatures (for library detection)
    known_signatures: HashMap<Vec<u8>, String>,
}

impl FunctionDetector {
    /// Create a new function detector
    pub fn new(architecture: Architecture) -> Result<Self> {
        let config = DisassemblyConfig { architecture, ..Default::default() };
        let disassembler = Disassembler::new(config)?;
        Ok(Self { disassembler, architecture, known_signatures: HashMap::new() })
    }

    /// Detect functions in a code section
    pub fn detect_functions(&mut self, code: &[u8], base_address: u64) -> Result<Vec<Function>> {
        let mut functions = Vec::new();
        let mut analyzed = HashSet::new();

        // Simple linear sweep with heuristic entry point detection
        let mut addr = base_address;
        while addr < base_address + code.len() as u64 {
            if analyzed.contains(&addr) {
                addr += 1;
                continue;
            }

            // Check if this looks like a function entry
            if self.is_function_entry(code, addr, base_address) {
                if let Ok(func) = self.analyze_function(code, addr, base_address) {
                    // Mark all instructions in this function as analyzed
                    for insn in &func.instructions {
                        analyzed.insert(insn.address);
                    }
                    functions.push(func);
                }
            }
            addr += 1
        }

        Ok(functions)
    }

    /// Check if an address looks like a function entry point
    fn is_function_entry(&mut self, code: &[u8], addr: u64, base_address: u64) -> bool {
        let offset = (addr.saturating_sub(base_address)) as usize;
        if offset >= code.len() {
            return false;
        }

        // Try to disassemble one instruction
        if let Ok(Some(insn)) = self.disassembler.wrapper.disassemble_one(&code[offset..], addr) {
            // Heuristics for function entry:
            // 1. Common prologue patterns
            // 2. Alignment (often 16-byte aligned on x86_64)
            // 3. Not in the middle of another instruction

            // Check for common prologue instructions
            let mnemonic = insn.mnemonic.to_lowercase();
            matches!(mnemonic.as_str(), "push" | "mov" | "sub" | "enter" | "endbr" | "nop")
        } else {
            false
        }
    }

    /// Analyze a function starting at the given address
    fn analyze_function(
        &mut self,
        code: &[u8],
        start_addr: u64,
        _base_address: u64,
    ) -> Result<Function> {
        let instructions = self.disassemble_function(code, start_addr)?;

        if instructions.is_empty() {
            return Err(DisasmError::FunctionDetection("No instructions found".to_string()));
        }

        let end_address =
            instructions.last().map(|i| i.address + i.size as u64).unwrap_or(start_addr);

        // Build CFG
        let cfg = crate::cfg::CfgBuilder::new(start_addr)
            .with_end_address(end_address)
            .add_instructions(instructions.clone())
            .build()?;

        // Detect calling convention
        let calling_convention =
            crate::architecture::RegisterSet::calling_convention(self.architecture);

        // Analyze stack frame
        let stack_frame = self.analyze_stack_frame(&instructions);

        // Try to detect function signature
        let signature = self.detect_signature(&instructions, &calling_convention);

        Ok(Function {
            start_address: start_addr,
            end_address,
            name: None,
            signature,
            cfg,
            instructions,
            stack_frame,
            calling_convention,
            confidence: 0.8,
            is_thunk: false,
            is_library: false,
        })
    }

    /// Disassemble a function starting at the given address
    fn disassemble_function(&mut self, code: &[u8], start_addr: u64) -> Result<Vec<Instruction>> {
        let mut instructions = Vec::new();
        let mut current_addr = start_addr;
        let mut seen_addresses = std::collections::HashSet::new();

        loop {
            if self.disassembler.config.max_instructions > 0
                && instructions.len() >= self.disassembler.config.max_instructions
            {
                break;
            }

            if seen_addresses.contains(&current_addr) {
                // Loop detected
                break;
            }

            // Find the code slice for current address
            let offset =
                (current_addr.saturating_sub(self.disassembler.config.base_address)) as usize;
            if offset >= code.len() {
                break;
            }

            let remaining = &code[offset..];
            match self.disassembler.wrapper.disassemble_one(remaining, current_addr)? {
                Some(insn) => {
                    let next_addr = current_addr + insn.bytes.len() as u64;
                    seen_addresses.insert(current_addr);
                    instructions.push(self.convert_insn(insn));
                    current_addr = next_addr;

                    // Check for function end (ret instruction)
                    if instructions.last().is_some_and(|i| {
                        i.groups.contains(&crate::capstone_wrapper::InsnGroup::Ret)
                    }) {
                        break;
                    }
                }
                None => break,
            }
        }

        Ok(instructions)
    }

    /// Convert capstone Insn to our Instruction type
    fn convert_insn(&self, insn: crate::capstone_wrapper::Insn) -> Instruction {
        Instruction {
            address: insn.address,
            size: insn.bytes.len(),
            bytes: insn.bytes,
            mnemonic: insn.mnemonic,
            op_str: insn.op_str,
            groups: insn.groups,
            operands: Vec::new(),
            regs_read: insn.regs_read.iter().map(|r| format!("reg_{}", r.0)).collect(),
            regs_write: insn.regs_write.iter().map(|r| format!("reg_{}", r.0)).collect(),
            detail: None,
        }
    }

    /// Analyze stack frame from instructions
    fn analyze_stack_frame(&self, instructions: &[Instruction]) -> Option<StackFrame> {
        // Simplified stack frame analysis
        // Look for stack pointer adjustments in prologue
        let mut sp_adjustment = 0i64;
        let mut base_pointer = None;

        for insn in instructions.iter().take(20) {
            // Only check first 20 instructions (prologue)
            let mnemonic = insn.mnemonic.to_lowercase();

            // Check for stack pointer modification
            if mnemonic == "sub" || mnemonic == "add" {
                if let Some(crate::disassembler::Operand::Reg(reg)) = insn.operands.first() {
                    if reg == "rsp" || reg == "esp" || reg == "sp" {
                        if let Some(crate::disassembler::Operand::Imm(imm)) = insn.operands.get(1) {
                            if mnemonic == "sub" {
                                sp_adjustment -= *imm;
                            } else {
                                sp_adjustment += *imm;
                            }
                        }
                    }
                }
            }

            // Check for base pointer setup
            if mnemonic == "mov" && insn.operands.len() == 2 {
                if let (
                    crate::disassembler::Operand::Reg(dst),
                    crate::disassembler::Operand::Reg(src),
                ) = (&insn.operands[0], &insn.operands[1])
                {
                    if (dst == "rbp" || dst == "ebp" || dst == "fp")
                        && (src == "rsp" || src == "esp" || src == "sp")
                    {
                        base_pointer = Some(dst.clone());
                    }
                }
            }

            // Stop at first non-prologue instruction
            if !matches!(
                mnemonic.as_str(),
                "push" | "mov" | "sub" | "add" | "enter" | "endbr" | "nop"
            ) {
                break;
            }
        }

        if sp_adjustment != 0 || base_pointer.is_some() {
            Some(StackFrame {
                size: sp_adjustment.unsigned_abs(),
                base_pointer,
                sp_offset: sp_adjustment,
                saved_registers: Vec::new(),
                locals: Vec::new(),
                arguments: Vec::new(),
            })
        } else {
            None
        }
    }

    /// Detect function signature from instructions and calling convention
    fn detect_signature(
        &self,
        instructions: &[Instruction],
        convention: &CallingConvention,
    ) -> Option<FunctionSignature> {
        let arg_regs = crate::architecture::RegisterSet::argument_registers(*convention);
        let mut parameters = Vec::new();

        // Look at first few instructions to see how argument registers are used
        for (i, reg) in arg_regs.iter().enumerate() {
            // Check if this register is used in the function
            let used = instructions.iter().any(|insn| {
                insn.regs_read.iter().any(|r| r == reg) || insn.regs_write.iter().any(|r| r == reg)
            });

            if used {
                parameters.push(Parameter {
                    name: Some(format!("arg{}", i)),
                    param_type: "unknown".to_string(),
                    location: ParameterLocation::Register(reg.clone()),
                });
            }
        }

        if !parameters.is_empty() {
            Some(FunctionSignature {
                return_type: Some("unknown".to_string()),
                parameters,
                calling_convention: *convention,
                is_variadic: false,
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::architecture::Architecture;

    #[test]
    fn test_function_detector_creation() {
        let detector = FunctionDetector::new(Architecture::X86_64);
        assert!(detector.is_ok());
    }

    #[test]
    fn test_register_set_for_x86_64() {
        let regs = crate::architecture::RegisterSet::for_architecture(Architecture::X86_64);
        assert_eq!(regs.instruction_pointer, "rip");
        assert_eq!(regs.stack_pointer, "rsp");
        assert_eq!(regs.frame_pointer, Some("rbp".to_string()));
    }

    #[test]
    fn test_calling_convention_args() {
        let args =
            crate::architecture::RegisterSet::argument_registers(CallingConvention::SystemVAmd64);
        assert_eq!(args, vec!["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);

        let args =
            crate::architecture::RegisterSet::argument_registers(CallingConvention::MicrosoftX64);
        assert_eq!(args, vec!["rcx", "rdx", "r8", "r9"]);
    }
}
