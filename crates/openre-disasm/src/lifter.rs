//! Instruction lifter to intermediate representation (IR)

use crate::architecture::Architecture;
use crate::disassembler::Instruction;
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Intermediate Representation instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrInstruction {
    pub id: usize,
    pub address: u64,
    pub op: IrOp,
    pub operands: Vec<IrOperand>,
    pub result: Option<IrOperand>,
    pub side_effects: Vec<IrSideEffect>,
    pub mnemonic: String,
}

/// IR operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrOp {
    // Data movement
    Mov,
    Movzx,
    Movsx,
    Lea,
    Push,
    Pop,
    Xchg,
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Idiv,
    Inc,
    Dec,
    Neg,
    // Logical
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Sar,
    Rol,
    Ror,
    Rcl,
    Rcr,
    // Comparison
    Cmp,
    Test,
    // Control flow
    Jmp,
    Jcc,
    Call,
    Ret,
    Int,
    Iret,
    Syscall,
    // Stack
    Enter,
    Leave,
    // String/block
    Movs,
    Stos,
    Lods,
    Scas,
    Cmps,
    // Flags
    Clc,
    Stc,
    Cmc,
    Cld,
    Std,
    // System
    Nop,
    Hlt,
    Pause,
    Cpuid,
    // Floating point/SIMD
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    Sqrt,
    // Vector
    Vadd,
    Vsub,
    Vmul,
    Vdiv,
    // Memory
    Load,
    Store,
    Fence,
    // Conversion
    Cvt,
    Ext,
    Trunc,
    // Unknown
    Unknown,
}

/// IR operand
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrOperand {
    pub op_type: IrOperandType,
    pub value: Option<u64>,
    pub register: Option<String>,
    pub memory: Option<IrMemory>,
    pub size: u32,
    pub is_temp: bool,
    pub ssa_version: Option<u32>,
}

/// IR operand types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrOperandType {
    Register,
    Immediate,
    Memory,
    Temporary,
    Flag,
    StackOffset,
}

/// Memory operand in IR
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrMemory {
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u32,
    pub displacement: i64,
    pub segment: Option<String>,
}

/// IR side effect
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IrSideEffect {
    RegWrite { register: String, size: u32 },
    MemWrite { address: IrOperand, size: u32 },
    FlagWrite { flags: Vec<String> },
    SpModify { offset: i64 },
    ControlFlow { target: Option<IrOperand>, is_call: bool },
}

/// Lifter: converts native instructions to IR
pub struct Lifter {
    #[allow(dead_code)]
    architecture: Architecture,
    temp_counter: usize,
}

impl Lifter {
    pub fn new(architecture: Architecture) -> Self {
        Self { architecture, temp_counter: 0 }
    }

    pub fn lift(&mut self, insn: &Instruction) -> Result<Vec<IrInstruction>> {
        let ir_op = self.mnemonic_to_ir_op(&insn.mnemonic)?;
        let ir_operands: Vec<IrOperand> = vec![];

        let result = if self.produces_result(ir_op) && !ir_operands.is_empty() {
            Some(ir_operands[0].clone())
        } else {
            None
        };

        let side_effects = vec![];

        let ir_insn = IrInstruction {
            id: self.temp_counter,
            address: insn.address,
            op: ir_op,
            operands: ir_operands,
            result,
            side_effects,
            mnemonic: insn.mnemonic.clone(),
        };

        self.temp_counter += 1;
        Ok(vec![ir_insn])
    }

    pub fn lift_all(&mut self, insns: &[Instruction]) -> Result<Vec<IrInstruction>> {
        let mut all_ir = Vec::new();
        for insn in insns {
            all_ir.extend(self.lift(insn)?);
        }
        Ok(all_ir)
    }

    #[allow(unreachable_patterns)]
    fn mnemonic_to_ir_op(&self, mnemonic: &str) -> Result<IrOp> {
        let mnem = mnemonic.to_lowercase();
        let ir_op = match mnem.as_str() {
            "mov" | "movabs" => IrOp::Mov,
            "movzx" => IrOp::Movzx,
            "movsx" | "movsxd" => IrOp::Movsx,
            "lea" => IrOp::Lea,
            "push" => IrOp::Push,
            "pop" => IrOp::Pop,
            "xchg" => IrOp::Xchg,
            "add" => IrOp::Add,
            "sub" => IrOp::Sub,
            "mul" | "imul" => IrOp::Mul,
            "div" | "idiv" => IrOp::Div,
            "inc" => IrOp::Inc,
            "dec" => IrOp::Dec,
            "neg" => IrOp::Neg,
            "and" => IrOp::And,
            "or" => IrOp::Or,
            "xor" => IrOp::Xor,
            "not" => IrOp::Not,
            "shl" | "sal" => IrOp::Shl,
            "shr" => IrOp::Shr,
            "sar" => IrOp::Sar,
            "rol" => IrOp::Rol,
            "ror" => IrOp::Ror,
            "rcl" => IrOp::Rcl,
            "rcr" => IrOp::Rcr,
            "cmp" => IrOp::Cmp,
            "test" => IrOp::Test,
            "jmp" => IrOp::Jmp,
            "ja" | "jae" | "jb" | "jbe" | "jc" | "jnc" | "je" | "jne" | "jg" | "jge" | "jl"
            | "jle" | "jna" | "jnae" | "jnb" | "jnbe" | "jnc" | "jne" | "jng" | "jnge" | "jnl"
            | "jnle" | "jno" | "jnp" | "jns" | "jnz" | "jo" | "jp" | "jpe" | "jpo" | "js"
            | "jz" => IrOp::Jcc,
            "call" => IrOp::Call,
            "ret" | "retn" | "retf" => IrOp::Ret,
            "int" | "int3" | "into" => IrOp::Int,
            "iret" | "iretd" | "iretq" => IrOp::Iret,
            "syscall" | "sysenter" | "sysexit" => IrOp::Syscall,
            "enter" => IrOp::Enter,
            "leave" => IrOp::Leave,
            "nop" => IrOp::Nop,
            "hlt" => IrOp::Hlt,
            "pause" | "rep" | "repne" => IrOp::Pause,
            "cpuid" => IrOp::Cpuid,
            _ => IrOp::Unknown,
        };
        Ok(ir_op)
    }

    fn produces_result(&self, op: IrOp) -> bool {
        !matches!(
            op,
            IrOp::Jmp
                | IrOp::Jcc
                | IrOp::Call
                | IrOp::Ret
                | IrOp::Int
                | IrOp::Iret
                | IrOp::Syscall
                | IrOp::Nop
                | IrOp::Hlt
                | IrOp::Pause
                | IrOp::Cpuid
                | IrOp::Clc
                | IrOp::Stc
                | IrOp::Cmc
                | IrOp::Cld
                | IrOp::Std
                | IrOp::Fence
                | IrOp::Unknown
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::architecture::Architecture;

    #[test]
    fn test_lifter_creation() {
        let lifter = Lifter::new(Architecture::X86_64);
        assert_eq!(lifter.architecture, Architecture::X86_64);
    }

    #[test]
    fn test_mnemonic_to_ir_op() {
        let lifter = Lifter::new(Architecture::X86_64);
        assert_eq!(lifter.mnemonic_to_ir_op("mov").unwrap(), IrOp::Mov);
        assert_eq!(lifter.mnemonic_to_ir_op("add").unwrap(), IrOp::Add);
        assert_eq!(lifter.mnemonic_to_ir_op("jmp").unwrap(), IrOp::Jmp);
        assert_eq!(lifter.mnemonic_to_ir_op("call").unwrap(), IrOp::Call);
        assert_eq!(lifter.mnemonic_to_ir_op("ret").unwrap(), IrOp::Ret);
        assert_eq!(lifter.mnemonic_to_ir_op("unknown").unwrap(), IrOp::Unknown);
    }
}
