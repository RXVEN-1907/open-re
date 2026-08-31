//! Strongly-typed ID wrappers for open-re entities

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            pub fn as_uuid(&self) -> Uuid {
                self.0
            }

            pub fn nil() -> Self {
                Self(Uuid::nil())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::from_str(s)?))
            }
        }

        impl From<Uuid> for $name {
            fn from(uuid: Uuid) -> Self {
                Self(uuid)
            }
        }

        impl From<$name> for Uuid {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

define_id!(UserId);
define_id!(ProjectId);
define_id!(FileId);
define_id!(JobId);
define_id!(AnalysisId);
define_id!(PluginId);
define_id!(WorkerId);
define_id!(SessionId);
define_id!(ApiKeyId);
define_id!(InviteId);
define_id!(ShareLinkId);
define_id!(ExportId);
define_id!(FindingId);
define_id!(ScanId);
define_id!(TargetId);

/// Identifier for a pipeline stage (human-readable name)
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct StageId(String);

impl StageId {
    /// Create a stage id from its canonical name (e.g. "disassembly")
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn all_ordered() -> Vec<StageId> {
        vec![
            StageId::new("identification"),
            StageId::new("loading"),
            StageId::new("disassembly"),
            StageId::new("control_flow"),
            StageId::new("data_flow"),
            StageId::new("type_recovery"),
            StageId::new("decompilation"),
            StageId::new("ai_enrichment"),
            StageId::new("finalization"),
        ]
    }
}

impl fmt::Display for StageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for StageId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// Stage names for the analysis pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageName {
    Identification,
    Loading,
    Disassembly,
    ControlFlow,
    DataFlow,
    TypeRecovery,
    Decompilation,
    AiEnrichment,
    Finalization,
}

impl StageName {
    pub fn all() -> &'static [StageName] {
        &[
            StageName::Identification,
            StageName::Loading,
            StageName::Disassembly,
            StageName::ControlFlow,
            StageName::DataFlow,
            StageName::TypeRecovery,
            StageName::Decompilation,
            StageName::AiEnrichment,
            StageName::Finalization,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StageName::Identification => "identification",
            StageName::Loading => "loading",
            StageName::Disassembly => "disassembly",
            StageName::ControlFlow => "control_flow",
            StageName::DataFlow => "data_flow",
            StageName::TypeRecovery => "type_recovery",
            StageName::Decompilation => "decompilation",
            StageName::AiEnrichment => "ai_enrichment",
            StageName::Finalization => "finalization",
        }
    }
}

impl fmt::Display for StageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for StageName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identification" => Ok(StageName::Identification),
            "loading" => Ok(StageName::Loading),
            "disassembly" => Ok(StageName::Disassembly),
            "control_flow" => Ok(StageName::ControlFlow),
            "data_flow" => Ok(StageName::DataFlow),
            "type_recovery" => Ok(StageName::TypeRecovery),
            "decompilation" => Ok(StageName::Decompilation),
            "ai_enrichment" => Ok(StageName::AiEnrichment),
            "finalization" => Ok(StageName::Finalization),
            _ => Err(format!("Unknown stage name: {}", s)),
        }
    }
}

/// Plugin types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginType {
    Identifier,
    Disassembler,
    Decompiler,
    Analyzer,
    AiEnricher,
    Exporter,
    Importer,
    UiExtension,
    Theme,
    Language,
    Security,
}

impl PluginType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PluginType::Identifier => "identifier",
            PluginType::Disassembler => "disassembler",
            PluginType::Decompiler => "decompiler",
            PluginType::Analyzer => "analyzer",
            PluginType::AiEnricher => "ai-enricher",
            PluginType::Exporter => "exporter",
            PluginType::Importer => "importer",
            PluginType::UiExtension => "ui-extension",
            PluginType::Theme => "theme",
            PluginType::Language => "language",
            PluginType::Security => "security",
        }
    }
}

impl fmt::Display for PluginType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PluginType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "identifier" => Ok(PluginType::Identifier),
            "disassembler" => Ok(PluginType::Disassembler),
            "decompiler" => Ok(PluginType::Decompiler),
            "analyzer" => Ok(PluginType::Analyzer),
            "ai-enricher" => Ok(PluginType::AiEnricher),
            "exporter" => Ok(PluginType::Exporter),
            "importer" => Ok(PluginType::Importer),
            "ui-extension" => Ok(PluginType::UiExtension),
            "theme" => Ok(PluginType::Theme),
            "language" => Ok(PluginType::Language),
            "security" => Ok(PluginType::Security),
            _ => Err(format!("Unknown plugin type: {}", s)),
        }
    }
}

/// Plugin capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ReadBinary,
    WriteBinary,
    ReadAnnotations,
    WriteAnnotations,
    QueryDatabase,
    MutateDatabase,
    ReadCfg,
    ReadDataFlow,
    ReadPseudocode,
    ReadSymbols,
    ReadStrings,
    ReadXRefs,
    CallAi,
    ReadUiState,
    WriteUiState,
    RegisterView,
    RegisterPanel,
    RegisterMenu,
    RegisterShortcut,
    ReadConfig,
    WriteConfig,
    SpawnProcess,
    NetworkAccess,
    RegisterInstructionSet,
    RegisterTheme,
}

impl Capability {
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

    pub fn requires_user_consent(&self) -> bool {
        matches!(
            self,
            Capability::WriteBinary
                | Capability::MutateDatabase
                | Capability::SpawnProcess
                | Capability::NetworkAccess
        )
    }
}

/// Risk level for capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Capability set for a plugin
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    capabilities: std::collections::HashSet<Capability>,
}

impl CapabilitySet {
    pub fn new() -> Self {
        Self::default()
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
        self.capabilities.iter().map(|c| c.risk_level()).max().unwrap_or(RiskLevel::Low)
    }

    pub fn requires_consent(&self) -> Vec<Capability> {
        self.capabilities.iter().filter(|c| c.requires_user_consent()).copied().collect()
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

/// Validate capabilities for a plugin type
pub fn validate_capabilities(
    _plugin_type: PluginType,
    _capabilities: &[Capability],
) -> anyhow::Result<()> {
    // For now, accept any capability
    // In a real implementation, this would validate against plugin type restrictions
    Ok(())
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<T: IntoIterator<Item = Capability>>(iter: T) -> Self {
        Self {
            capabilities: iter.into_iter().collect(),
        }
    }
}

/// File formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileFormat {
    Pe,
    Elf,
    MachO,
    Wasm,
    Unknown,
}

impl FileFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            FileFormat::Pe => "pe",
            FileFormat::Elf => "elf",
            FileFormat::MachO => "macho",
            FileFormat::Wasm => "wasm",
            FileFormat::Unknown => "unknown",
        }
    }
}

/// Architectures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    X86,
    X86_64,
    Arm,
    Arm64,
    Mips,
    Mips64,
    RiscV32,
    RiscV64,
    Wasm32,
    Wasm64,
    Unknown,
}

impl Architecture {
    pub fn as_str(&self) -> &'static str {
        match self {
            Architecture::X86 => "x86",
            Architecture::X86_64 => "x86_64",
            Architecture::Arm => "arm",
            Architecture::Arm64 => "arm64",
            Architecture::Mips => "mips",
            Architecture::Mips64 => "mips64",
            Architecture::RiscV32 => "riscv32",
            Architecture::RiscV64 => "riscv64",
            Architecture::Wasm32 => "wasm32",
            Architecture::Wasm64 => "wasm64",
            Architecture::Unknown => "unknown",
        }
    }
}

/// Job status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum JobStatus {
    Queued { queued_at: chrono::DateTime<chrono::Utc> },
    Running { worker_id: WorkerId, started_at: chrono::DateTime<chrono::Utc>, stage: StageName },
    Completed { completed_at: chrono::DateTime<chrono::Utc> },
    Failed { error: String, failed_at: chrono::DateTime<chrono::Utc>, retryable: bool },
    Cancelled { cancelled_at: chrono::DateTime<chrono::Utc>, reason: String },
    Scheduled { run_at: chrono::DateTime<chrono::Utc> },
}

/// Job priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Priority(pub i32);

impl Priority {
    pub const LOW: Priority = Priority(-10);
    pub const DEFAULT: Priority = Priority(0);
    pub const HIGH: Priority = Priority(10);
    pub const CRITICAL: Priority = Priority(100);
}

define_id!(FunctionId);
define_id!(BasicBlockId);
define_id!(InstructionId);
define_id!(CfgEdgeId);
define_id!(CallEdgeId);
define_id!(LoopId);
define_id!(VariableId);
define_id!(TypeId);
define_id!(ObjectId);
define_id!(ReportId);

/// Alias for BasicBlockId for backwards compatibility
pub type BlockId = BasicBlockId;
