//! Core types, errors, and traits for open-re

pub mod deduplication;
pub mod error;
pub mod history;
pub mod ids;
pub mod plugin;
pub mod reporting;
pub mod result;
pub mod traits;

pub use deduplication::*;
pub use error::*;
pub use history::*;
pub use ids::*;
pub use plugin::*;
pub use reporting::*;
pub use result::*;
pub use traits::*;

// Re-export commonly used types
pub use ids::{
    Architecture, Capability, FileFormat, JobStatus, PluginId, PluginType, Priority, RiskLevel,
    StageId,
};
pub use plugin::{
    CapabilityRequest, CapabilityResponse, CapabilitySet, CommandContext, CommandRegistration,
    CommandResult, Plugin, PluginInitInfo, PluginManifest, PluginMetadata, PluginRegistry,
    PluginSdkMetadata, PluginSource, PluginStatus, RegistryConfig, RegistryEntry,
};
