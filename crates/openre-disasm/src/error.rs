//! Error types for the disassembly crate

use thiserror::Error;

/// Result type for disassembly operations
pub type Result<T> = std::result::Result<T, DisasmError>;

/// Errors that can occur during disassembly and binary analysis
#[derive(Error, Debug)]
pub enum DisasmError {
    /// Failed to initialize Capstone disassembler
    #[error("Capstone initialization failed: {0}")]
    CapstoneInit(String),

    /// Architecture is not supported
    #[error("Unsupported architecture: {0}")]
    UnsupportedArch(String),

    /// Architecture mode is not supported
    #[error("Unsupported mode: {0}")]
    UnsupportedMode(String),

    /// Disassembly failed at a specific offset
    #[error("Disassembly failed at offset 0x{offset:x}: {reason}")]
    DisassemblyFailed { offset: u64, reason: String },

    /// Function detection failed
    #[error("Function detection failed: {0}")]
    FunctionDetection(String),

    /// Control flow graph construction failed
    #[error("CFG construction failed: {0}")]
    CfgConstruction(String),

    /// Invalid instruction encountered
    #[error("Invalid instruction at address 0x{address:x}: {reason}")]
    InvalidInstruction { address: u64, reason: String },

    /// Lifter (IR translation) error
    #[error("Lifter error: {0}")]
    Lifter(String),
}

impl From<capstone::Error> for DisasmError {
    fn from(err: capstone::Error) -> Self {
        DisasmError::CapstoneInit(err.to_string())
    }
}
