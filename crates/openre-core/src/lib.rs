//! Core types, errors, and traits for open-re

pub mod error;
pub mod ids;
pub mod traits;
pub mod result;
pub mod deduplication;
pub mod reporting;
pub mod history;

pub use error::*;
pub use ids::*;
pub use traits::*;
pub use result::*;
pub use deduplication::*;
pub use reporting::*;
pub use history::*;

// Re-export commonly used types
pub use ids::{PluginType, Capability, RiskLevel, FileFormat, Architecture, JobStatus, Priority};