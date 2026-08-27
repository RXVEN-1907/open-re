//! Capability-based Permission System

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Fine-grained plugin capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // Binary access
    ReadBinary,
    WriteBinary,

    // Annotation access
    ReadAnnotations,
    WriteAnnotations,

    // Database access
    QueryDatabase,
    MutateDatabase,

    // Analysis access
    ReadCfg,
    ReadDataFlow,
    ReadPseudocode,
    ReadSymbols,
    ReadStrings,
    ReadXRefs,

    // AI access
    CallAi,

    // UI access
    ReadUiState,
    WriteUiState,
    RegisterView,
    RegisterPanel,
    RegisterMenu,
    RegisterShortcut,

    // Config access
    ReadConfig,
    WriteConfig,

    // System access
    SpawnProcess,
    NetworkAccess,

    // Extension registration
    RegisterInstructionSet,
    RegisterTheme,
}

impl Capability {
    /// Get the risk level of this capability
    pub fn risk_level(&self) -> RiskLevel {
        match self {
            Capability::ReadBinary
            | Capability::ReadAnnotations
            | Capability::QueryDatabase
            | Capability::ReadCfg
            | Capability::ReadDataFlow
            | Capability::ReadPseudocode
            | Capability::ReadSymbols
            | Capability::ReadStrings
            | Capability::ReadXRefs
            | Capability::ReadConfig => RiskLevel::Low,

            Capability::WriteAnnotations
            | Capability::MutateDatabase
            | Capability::WriteConfig
            | Capability::CallAi => RiskLevel::Medium,

            Capability::WriteBinary | Capability::SpawnProcess | Capability::NetworkAccess => {
                RiskLevel::High
            }

            Capability::ReadUiState
            | Capability::WriteUiState
            | Capability::RegisterView
            | Capability::RegisterPanel
            | Capability::RegisterMenu
            | Capability::RegisterShortcut
            | Capability::RegisterInstructionSet
            | Capability::RegisterTheme => RiskLevel::Low,
        }
    }

    /// Check if this capability requires explicit user consent
    pub fn requires_user_consent(&self) -> bool {
        matches!(
            self,
            Capability::WriteBinary
                | Capability::MutateDatabase
                | Capability::SpawnProcess
                | Capability::NetworkAccess
        )
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Capability::ReadBinary => "Read binary file contents",
            Capability::WriteBinary => "Write/modify binary files",
            Capability::ReadAnnotations => "Read code annotations",
            Capability::WriteAnnotations => "Write code annotations",
            Capability::QueryDatabase => "Query the analysis database",
            Capability::MutateDatabase => "Modify the analysis database",
            Capability::ReadCfg => "Read control flow graphs",
            Capability::ReadDataFlow => "Read data flow analysis",
            Capability::ReadPseudocode => "Read decompiled pseudocode",
            Capability::ReadSymbols => "Read symbol tables",
            Capability::ReadStrings => "Read extracted strings",
            Capability::ReadXRefs => "Read cross-references",
            Capability::CallAi => "Call AI/LLM models",
            Capability::ReadUiState => "Read UI state",
            Capability::WriteUiState => "Modify UI state",
            Capability::RegisterView => "Register custom views",
            Capability::RegisterPanel => "Register UI panels",
            Capability::RegisterMenu => "Register menu items",
            Capability::RegisterShortcut => "Register keyboard shortcuts",
            Capability::ReadConfig => "Read plugin configuration",
            Capability::WriteConfig => "Write plugin configuration",
            Capability::SpawnProcess => "Spawn subprocesses",
            Capability::NetworkAccess => "Make network requests",
            Capability::RegisterInstructionSet => "Register instruction set handlers",
            Capability::RegisterTheme => "Register UI themes",
        }
    }
}

/// Risk level for capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Capability set for a plugin
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    capabilities: HashSet<Capability>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_iter(caps: impl IntoIterator<Item = Capability>) -> Self {
        Self {
            capabilities: caps.into_iter().collect(),
        }
    }

    pub fn add(&mut self, cap: Capability) {
        self.capabilities.insert(cap);
    }

    pub fn remove(&mut self, cap: Capability) {
        self.capabilities.remove(&cap);
    }

    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    pub fn all(&self) -> impl Iterator<Item = Capability> + '_ {
        self.capabilities.iter().copied()
    }

    pub fn highest_risk(&self) -> RiskLevel {
        self.capabilities
            .iter()
            .map(|c| c.risk_level())
            .max()
            .unwrap_or(RiskLevel::Low)
    }

    pub fn requires_consent(&self) -> Vec<Capability> {
        self.capabilities
            .iter()
            .filter(|c| c.requires_user_consent())
            .copied()
            .collect()
    }
}

/// Capability request from plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    pub capability: Capability,
    pub justification: String,
    pub required: bool,
}

/// Capability response to plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResponse {
    pub granted: bool,
    pub reason: Option<String>,
}
