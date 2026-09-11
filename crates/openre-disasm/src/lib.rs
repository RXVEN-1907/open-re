//! Multi-architecture disassembly engine for openre
//!
//! This crate provides Capstone-based disassembly with support for
//! x86, x86_64, ARM, AArch64, MIPS, RISC-V, PowerPC, SPARC, BPF, and EVM.

pub mod architecture;
pub mod capstone_wrapper;
pub mod cfg;
pub mod disassembler;
pub mod error;
pub mod function;
pub mod lifter;

pub use architecture::{Architecture, CallingConvention, Endianness, RegisterSet, Syntax};
pub use capstone_wrapper::CapstoneWrapper;
pub use cfg::{BasicBlock, CfgEdge, ControlFlowGraph, DominatorTree, LoopInfo};
pub use disassembler::{Disassembler, DisassemblyConfig, Instruction};
pub use error::{DisasmError, Result};
pub use function::{Function, FunctionSignature, StackFrame};
pub use lifter::{IrInstruction, IrOperand, IrOperandType, Lifter};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Architecture, Endianness, Syntax};

    #[test]
    fn test_crate_compiles() {
        let _ = Architecture::X86_64;
        let _ = Endianness::Little;
        let _ = Syntax::Intel;
        let _ = DisasmError::CapstoneInit("test".to_string());
    }
}
