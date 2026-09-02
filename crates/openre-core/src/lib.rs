//! Core types, errors, and traits for open-re

pub mod app_map;
pub mod attack_path;
pub mod deduplication;
pub mod error;
pub mod evidence;
pub mod history;
pub mod ids;
pub mod plugin;
pub mod relationships;
pub mod remediation;
pub mod reporting;
pub mod result;
pub mod risk_knowledge;
pub mod traits;

pub use app_map::*;
pub use attack_path::*;
pub use deduplication::*;
pub use error::*;
pub use evidence::*;
pub use history::*;
pub use ids::*;
pub use plugin::*;
pub use relationships::*;
pub use remediation::*;
pub use reporting::*;
pub use result::*;
pub use risk_knowledge::*;
pub use traits::*;

pub use plugin::{
    CapabilityRequest, CapabilityResponse, CapabilitySet, CommandContext, CommandRegistration,
    CommandResult, Plugin, PluginInitInfo, PluginManifest, PluginMetadata, PluginRegistry,
    PluginSdkMetadata, PluginSource, PluginStatus, RegistryConfig, RegistryEntry,
};
