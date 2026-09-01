//! Plugin system for open-re

pub mod lifecycle;
pub mod manifest;
pub mod registry;
pub mod runtime;
pub mod sandbox;
pub mod sdk;
pub mod security;

pub use lifecycle::*;
pub use manifest::*;
pub use registry::*;
pub use runtime::*;
pub use sandbox::*;
pub use security::*;

// Re-export core types
pub use crate::manifest::{PluginSource, SimplePluginMetadata};
pub use openre_core::ids::{
    Capability, CapabilityRequest, CapabilityResponse, CapabilitySet, PluginId, PluginType,
    RiskLevel, StageId,
};
