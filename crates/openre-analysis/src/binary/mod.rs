//! Binary analysis module for open-re

pub mod common;
pub mod elf;
pub mod macho;
pub mod metadata;
pub mod pe;
pub mod static_analysis;
pub mod traits;
pub mod upload;
pub mod wasm;

pub use common::*;
pub use elf::{ElfIdentifier, ElfMetadataExtractor, ElfParser};
pub use macho::{MachoIdentifier, MachoMetadataExtractor, MachoParser};
pub use metadata::*;
pub use pe::{PeIdentifier, PeMetadataExtractor, PeParser};
pub use static_analysis::*;
pub use traits::*;
pub use upload::*;
pub use wasm::{WasmIdentifier, WasmMetadataExtractor, WasmParser};
