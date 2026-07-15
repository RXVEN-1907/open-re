//! Capability system for plugins

use openre_core::ids::Capability;
use openre_core::error::Result;
use std::collections::HashSet;

/// Capability enforcer for runtime permission checking
pub struct CapabilityEnforcer {
    granted: HashSet<Capability>,
}

impl CapabilityEnforcer {
    pub fn new(granted: Vec<Capability>) -> Self {
        Self {
            granted: granted.into_iter().collect(),
        }
    }

    pub fn check(&self, capability: Capability) -> Result<()> {
        if self.granted.contains(&capability) {
            Ok(())
        } else {
            Err(openre_core::Error::Forbidden(format!(
                "Capability not granted: {:?}",
                capability
            )))
        }
    }

    pub fn has(&self, capability: Capability) -> bool {
        self.granted.contains(&capability)
    }
}

/// Validate that requested capabilities are allowed for a plugin type
pub fn validate_capabilities(
    plugin_type: openre_core::ids::PluginType,
    requested: &[Capability],
) -> Result<()> {
    let allowed = allowed_capabilities_for_type(plugin_type);
    
    for cap in requested {
        if !allowed.contains(cap) {
            return Err(openre_core::Error::Validation(format!(
                "Capability {:?} not allowed for plugin type {:?}",
                cap, plugin_type
            )));
        }
    }
    Ok(())
}

fn allowed_capabilities_for_type(
    plugin_type: openre_core::ids::PluginType,
) -> HashSet<Capability> {
    use openre_core::ids::{Capability, PluginType};
    
    match plugin_type {
        PluginType::Identifier => [
            Capability::ReadBinary,
            Capability::WriteAnnotations,
        ].into(),
        PluginType::Disassembler => [
            Capability::ReadBinary,
            Capability::WriteAnnotations,
            Capability::QueryDatabase,
        ].into(),
        PluginType::Decompiler => [
            Capability::ReadBinary,
            Capability::WriteAnnotations,
            Capability::QueryDatabase,
            Capability::ReadCfg,
        ].into(),
        PluginType::Analyzer => [
            Capability::ReadBinary,
            Capability::WriteAnnotations,
            Capability::QueryDatabase,
            Capability::ReadCfg,
            Capability::ReadDataFlow,
        ].into(),
        PluginType::AiEnricher => [
            Capability::ReadBinary,
            Capability::WriteAnnotations,
            Capability::QueryDatabase,
            Capability::CallAi,
        ].into(),
        PluginType::Exporter => [
            Capability::ReadBinary,
            Capability::QueryDatabase,
            Capability::ReadCfg,
            Capability::ReadPseudocode,
            Capability::ReadSymbols,
            Capability::ReadStrings,
            Capability::ReadXRefs,
        ].into(),
        PluginType::Importer => [
            Capability::WriteAnnotations,
            Capability::WriteBinary,
        ].into(),
        PluginType::UiExtension => [
            Capability::ReadUiState,
            Capability::WriteUiState,
            Capability::RegisterView,
            Capability::RegisterPanel,
            Capability::RegisterMenu,
            Capability::RegisterShortcut,
        ].into(),
        PluginType::Theme => [
            Capability::RegisterTheme,
        ].into(),
        PluginType::Language => [
            Capability::ReadBinary,
            Capability::WriteAnnotations,
            Capability::RegisterInstructionSet,
        ].into(),
    }
}