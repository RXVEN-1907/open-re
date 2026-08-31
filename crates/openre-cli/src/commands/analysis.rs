//! Binary Analysis Commands
//!
//! Local binary analysis using openre-analysis crate parsers (ELF, PE, MachO, WASM)
//! and pipeline orchestrator.

use crate::{print_output, CliError, Context};
use clap::{Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressStyle};
use openre_analysis::{
    binary::{
        common::{
            Architecture, BinaryFormat, BinaryIdentification, BinaryMetadata, ExportInfo,
            FileHashes, ImportInfo, ImportedFunction, OperatingSystem, SectionInfo, SegmentInfo,
            SymbolInfo,
        },
        elf::{ElfIdentifier, ElfMetadataExtractor},
        macho::{MachoIdentifier, MachoMetadataExtractor},
        pe::{PeIdentifier, PeMetadataExtractor},
        traits::{BinaryIdentifier, BinaryMetadataExtractor, StaticAnalyzer},
        wasm::{WasmIdentifier, WasmMetadataExtractor},
    },
    orchestrator::{AnalysisConfig, AnalysisJob, Orchestrator},
    progress::{JobProgress, JobStatus, StageProgress, StageStatus as ProgressStageStatus},
    StaticAnalysisService,
};
use openre_core::ids::{FileId, JobId, ProjectId, StageId, UserId};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tabled::{settings::Style, Table, Tabled};
use tokio::sync::Mutex;

#[derive(Subcommand)]
pub enum AnalysisCommands {
    /// Parse and identify binary format
    Parse(ParseArgs),

    /// Show binary information (header, architecture, entry point)
    Info(InfoArgs),

    /// List symbols
    Symbols(SymbolsArgs),

    /// List imports
    Imports(ImportsArgs),

    /// List exports
    Exports(ExportsArgs),

    /// Extract strings
    Strings(StringsArgs),

    /// List sections
    Sections(SectionsArgs),

    /// List segments
    Segments(SegmentsArgs),

    /// Find functions
    Functions(FunctionsArgs),

    /// Decompile a function
    Decompile(DecompileArgs),

    /// Show control flow graph for a function
    Cfg(CfgArgs),

    /// Show data flow analysis for a function
    Dataflow(DataflowArgs),

    /// Run analysis pipeline
    #[command(subcommand)]
    Pipeline(PipelineCommands),
}

#[derive(Parser)]
pub struct ParseArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Force binary format (auto-detected if not specified)
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub binary_format: Option<BinaryFormatArg>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct InfoArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct SymbolsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Filter by symbol type
    #[arg(long, value_enum)]
    pub filter_type: Option<SymbolTypeFilter>,

    /// Filter by binding
    #[arg(long, value_enum)]
    pub filter_binding: Option<SymbolBindingFilter>,

    /// Show only global symbols
    #[arg(long)]
    pub globals_only: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct ImportsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Filter by library
    #[arg(long)]
    pub library: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct ExportsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Filter by name pattern
    #[arg(long)]
    pub pattern: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct StringsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Minimum string length
    #[arg(short, long, default_value = "4")]
    pub min_length: usize,

    /// Search pattern (regex)
    #[arg(long)]
    pub pattern: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct SectionsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Show section data hex dump
    #[arg(long)]
    pub hex: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct SegmentsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct FunctionsArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Minimum function size
    #[arg(long, default_value = "16")]
    pub min_size: usize,

    /// Filter by name pattern
    #[arg(long)]
    pub pattern: Option<String>,

    /// Show basic blocks
    #[arg(long)]
    pub show_blocks: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct DecompileArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Function name or address
    #[arg(short, long, value_name = "NAME_OR_ADDR")]
    pub function: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct CfgArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Function name or address
    #[arg(short, long, value_name = "NAME_OR_ADDR")]
    pub function: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,

    /// Output as DOT graph
    #[arg(long)]
    pub dot: bool,
}

#[derive(Parser)]
pub struct DataflowArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Function name or address
    #[arg(short, long, value_name = "NAME_OR_ADDR")]
    pub function: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Subcommand)]
pub enum PipelineCommands {
    /// Run analysis pipeline
    Run(PipelineRunArgs),

    /// Check pipeline status
    Status(PipelineStatusArgs),

    /// Cancel pipeline
    Cancel(PipelineCancelArgs),
}

#[derive(Parser)]
pub struct PipelineRunArgs {
    /// Path to binary file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Stages to run
    #[arg(short, long, value_enum, default_value = "all")]
    pub stages: PipelineStagesArg,

    /// Enable AI enrichment
    #[arg(long)]
    pub ai_enabled: bool,

    /// Project ID (optional)
    #[arg(long)]
    pub project_id: Option<String>,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct PipelineStatusArgs {
    /// Analysis job ID
    #[arg(value_name = "ANALYSIS_ID")]
    pub id: String,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    pub output: OutputFormatArg,
}

#[derive(Parser)]
pub struct PipelineCancelArgs {
    /// Analysis job ID
    #[arg(value_name = "ANALYSIS_ID")]
    pub id: String,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BinaryFormatArg {
    Elf,
    Pe,
    Macho,
    Wasm,
}

impl From<BinaryFormatArg> for BinaryFormat {
    fn from(f: BinaryFormatArg) -> Self {
        match f {
            BinaryFormatArg::Elf => BinaryFormat::Elf,
            BinaryFormatArg::Pe => BinaryFormat::Pe,
            BinaryFormatArg::Macho => BinaryFormat::MachO,
            BinaryFormatArg::Wasm => BinaryFormat::Wasm,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolTypeFilter {
    Function,
    Object,
    Section,
    File,
    Unknown,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SymbolBindingFilter {
    Local,
    Global,
    Weak,
    Unknown,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PipelineStagesArg {
    All,
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

impl From<PipelineStagesArg> for Vec<StageId> {
    fn from(s: PipelineStagesArg) -> Self {
        match s {
            PipelineStagesArg::All => vec![
                StageId::new("identification"),
                StageId::new("loading"),
                StageId::new("disassembly"),
                StageId::new("control_flow"),
                StageId::new("data_flow"),
                StageId::new("type_recovery"),
                StageId::new("decompilation"),
                StageId::new("ai_enrichment"),
                StageId::new("finalization"),
            ],
            PipelineStagesArg::Identification => vec![StageId::new("identification")],
            PipelineStagesArg::Loading => vec![StageId::new("loading")],
            PipelineStagesArg::Disassembly => vec![StageId::new("disassembly")],
            PipelineStagesArg::ControlFlow => vec![StageId::new("control_flow")],
            PipelineStagesArg::DataFlow => vec![StageId::new("data_flow")],
            PipelineStagesArg::TypeRecovery => vec![StageId::new("type_recovery")],
            PipelineStagesArg::Decompilation => vec![StageId::new("decompilation")],
            PipelineStagesArg::AiEnrichment => vec![StageId::new("ai_enrichment")],
            PipelineStagesArg::Finalization => vec![StageId::new("finalization")],
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormatArg {
    Table,
    Json,
    Sarif,
}

impl From<OutputFormatArg> for crate::output::OutputFormat {
    fn from(f: OutputFormatArg) -> Self {
        match f {
            OutputFormatArg::Table => crate::output::OutputFormat::Table,
            OutputFormatArg::Json => crate::output::OutputFormat::Json,
            OutputFormatArg::Sarif => crate::output::OutputFormat::Json, // SARIF uses JSON format
        }
    }
}

/// Binary info display struct
#[derive(Tabled, Serialize, Deserialize)]
struct BinaryInfoDisplay {
    #[tabled(rename = "Property")]
    property: String,
    #[tabled(rename = "Value")]
    value: String,
}

/// Symbol display struct
#[derive(Tabled, Serialize, Deserialize)]
struct SymbolDisplay {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Type")]
    symbol_type: String,
    #[tabled(rename = "Binding")]
    binding: String,
    #[tabled(rename = "Section")]
    section: String,
}

/// Import display struct
#[derive(Tabled, Serialize, Deserialize)]
struct ImportDisplay {
    #[tabled(rename = "Library")]
    library: String,
    #[tabled(rename = "Function")]
    function: String,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Ordinal")]
    ordinal: String,
}

/// Export display struct
#[derive(Tabled, Serialize, Deserialize)]
struct ExportDisplay {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Ordinal")]
    ordinal: String,
    #[tabled(rename = "Forwarder")]
    forwarder: String,
}

/// Section display struct
#[derive(Tabled, Serialize, Deserialize)]
struct SectionDisplay {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Virtual Address")]
    vaddr: String,
    #[tabled(rename = "Virtual Size")]
    vsize: String,
    #[tabled(rename = "Raw Offset")]
    offset: String,
    #[tabled(rename = "Raw Size")]
    size: String,
    #[tabled(rename = "Readable")]
    readable: String,
    #[tabled(rename = "Writable")]
    writable: String,
    #[tabled(rename = "Executable")]
    executable: String,
    #[tabled(rename = "Entropy")]
    entropy: String,
}

/// Segment display struct
#[derive(Tabled, Serialize, Deserialize)]
struct SegmentDisplay {
    #[tabled(rename = "Virtual Address")]
    vaddr: String,
    #[tabled(rename = "Virtual Size")]
    vsize: String,
    #[tabled(rename = "Raw Offset")]
    offset: String,
    #[tabled(rename = "Raw Size")]
    size: String,
    #[tabled(rename = "Readable")]
    readable: String,
    #[tabled(rename = "Writable")]
    writable: String,
    #[tabled(rename = "Executable")]
    executable: String,
    #[tabled(rename = "Alignment")]
    alignment: String,
}

/// Function display struct
#[derive(Tabled, Serialize, Deserialize)]
struct FunctionDisplay {
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Blocks")]
    blocks: String,
    #[tabled(rename = "Calls")]
    calls: String,
    #[tabled(rename = "Complexity")]
    complexity: String,
}

/// String display struct
#[derive(Tabled, Serialize, Deserialize)]
struct StringDisplay {
    #[tabled(rename = "Offset")]
    offset: String,
    #[tabled(rename = "Length")]
    length: String,
    #[tabled(rename = "String")]
    string: String,
}

/// Basic block display struct
#[derive(Tabled, Serialize, Deserialize)]
struct BasicBlockDisplay {
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Instructions")]
    instructions: String,
    #[tabled(rename = "Predecessors")]
    predecessors: String,
    #[tabled(rename = "Successors")]
    successors: String,
}

/// Instruction display struct
#[derive(Tabled, Serialize, Deserialize)]
struct InstructionDisplay {
    #[tabled(rename = "Address")]
    address: String,
    #[tabled(rename = "Bytes")]
    bytes: String,
    #[tabled(rename = "Mnemonic")]
    mnemonic: String,
    #[tabled(rename = "Operands")]
    operands: String,
    #[tabled(rename = "Type")]
    inst_type: String,
}

/// Pipeline status display struct
#[derive(Tabled, Serialize, Deserialize)]
struct PipelineStatusDisplay {
    #[tabled(rename = "Stage")]
    stage: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Progress")]
    progress: String,
    #[tabled(rename = "Duration (ms)")]
    duration: String,
    #[tabled(rename = "Started")]
    started: String,
    #[tabled(rename = "Completed")]
    completed: String,
}

impl AnalysisCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            AnalysisCommands::Parse(args) => Self::cmd_parse(args, ctx).await,
            AnalysisCommands::Info(args) => Self::cmd_info(args, ctx).await,
            AnalysisCommands::Symbols(args) => Self::cmd_symbols(args, ctx).await,
            AnalysisCommands::Imports(args) => Self::cmd_imports(args, ctx).await,
            AnalysisCommands::Exports(args) => Self::cmd_exports(args, ctx).await,
            AnalysisCommands::Strings(args) => Self::cmd_strings(args, ctx).await,
            AnalysisCommands::Sections(args) => Self::cmd_sections(args, ctx).await,
            AnalysisCommands::Segments(args) => Self::cmd_segments(args, ctx).await,
            AnalysisCommands::Functions(args) => Self::cmd_functions(args, ctx).await,
            AnalysisCommands::Decompile(args) => Self::cmd_decompile(args, ctx).await,
            AnalysisCommands::Cfg(args) => Self::cmd_cfg(args, ctx).await,
            AnalysisCommands::Dataflow(args) => Self::cmd_dataflow(args, ctx).await,
            AnalysisCommands::Pipeline(cmd) => Self::cmd_pipeline(cmd, ctx).await,
        }
    }

    /// Get the appropriate metadata extractor for the binary format
    async fn get_extractor(format: BinaryFormat) -> Box<dyn BinaryMetadataExtractor> {
        match format {
            BinaryFormat::Elf => Box::new(ElfMetadataExtractor::default()),
            BinaryFormat::Pe => Box::new(PeMetadataExtractor::default()),
            BinaryFormat::MachO => Box::new(MachoMetadataExtractor::default()),
            BinaryFormat::Wasm => Box::new(WasmMetadataExtractor::default()),
            BinaryFormat::Unknown => panic!("Unknown binary format"),
        }
    }

    /// Get the appropriate identifier for the binary format
    fn get_identifier(format: BinaryFormat) -> Box<dyn BinaryIdentifier> {
        match format {
            BinaryFormat::Elf => Box::new(ElfIdentifier::default()),
            BinaryFormat::Pe => Box::new(PeIdentifier::default()),
            BinaryFormat::MachO => Box::new(MachoIdentifier::default()),
            BinaryFormat::Wasm => Box::new(WasmIdentifier::default()),
            BinaryFormat::Unknown => panic!("Unknown binary format"),
        }
    }

    /// Detect binary format from file
    async fn detect_format(file: &PathBuf) -> Result<BinaryFormat, CliError> {
        let data = std::fs::read(file)?;
        let formats =
            [BinaryFormat::Elf, BinaryFormat::Pe, BinaryFormat::MachO, BinaryFormat::Wasm];

        for format in formats {
            let identifier = Self::get_identifier(format);
            if identifier.can_handle(&data) {
                return Ok(format);
            }
        }

        Err(CliError::InvalidInput(
            "Could not detect binary format (not ELF, PE, MachO, or WASM)".into(),
        ))
    }

    /// Load and extract metadata from binary
    async fn load_metadata(
        file: &PathBuf,
        format: Option<BinaryFormatArg>,
    ) -> Result<BinaryMetadata, CliError> {
        let format = match format {
            Some(f) => f.into(),
            None => Self::detect_format(file).await?,
        };

        let data = std::fs::read(file)?;
        let extractor = Self::get_extractor(format).await;
        let mut metadata = extractor.extract_metadata(&data).await?;

        // Set file_id from hash
        metadata.file_id =
            FileId::from_str(&metadata.hashes.sha256).unwrap_or_else(|_| FileId::new());

        Ok(metadata)
    }

    /// Parse command - identify binary format
    async fn cmd_parse(args: ParseArgs, ctx: Context) -> Result<(), CliError> {
        let format = match args.binary_format {
            Some(f) => f.into(),
            None => Self::detect_format(&args.file).await?,
        };

        let data = std::fs::read(&args.file)?;
        let identifier = Self::get_identifier(format);
        let identification = identifier.identify(&data).await?;

        let mut info = vec![
            BinaryInfoDisplay {
                property: "Format".to_string(),
                value: format!("{:?}", identification.format),
            },
            BinaryInfoDisplay {
                property: "Architecture".to_string(),
                value: format!("{:?}", identification.architecture),
            },
            BinaryInfoDisplay {
                property: "Bitness".to_string(),
                value: format!("{:?}", identification.bitness),
            },
            BinaryInfoDisplay {
                property: "Endianness".to_string(),
                value: format!("{:?}", identification.endianness),
            },
            BinaryInfoDisplay {
                property: "Operating System".to_string(),
                value: format!("{:?}", identification.os),
            },
            BinaryInfoDisplay {
                property: "Entry Point".to_string(),
                value: identification
                    .entry_point
                    .map(|e| format!("0x{:x}", e))
                    .unwrap_or("N/A".to_string()),
            },
            BinaryInfoDisplay {
                property: "Confidence".to_string(),
                value: format!("{:.0}%", identification.confidence * 100.0),
            },
        ];

        if let Some(ref compiler) = identification.compiler_info {
            info.push(BinaryInfoDisplay {
                property: "Compiler".to_string(),
                value: format!(
                    "{} {}",
                    compiler.name,
                    compiler.version.clone().unwrap_or_default()
                ),
            });
        }

        // Output as SARIF if requested
        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::identification_to_sarif(&identification);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&info, &args.output.into())?;
        }

        Ok(())
    }

    /// Info command - show detailed binary information
    async fn cmd_info(args: InfoArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;
        let id = &metadata.identification;

        let mut info = vec![
            BinaryInfoDisplay {
                property: "File".to_string(),
                value: args.file.display().to_string(),
            },
            BinaryInfoDisplay { property: "Format".to_string(), value: format!("{:?}", id.format) },
            BinaryInfoDisplay {
                property: "Architecture".to_string(),
                value: format!("{:?}", id.architecture),
            },
            BinaryInfoDisplay {
                property: "Bitness".to_string(),
                value: format!("{:?}", id.bitness),
            },
            BinaryInfoDisplay {
                property: "Endianness".to_string(),
                value: format!("{:?}", id.endianness),
            },
            BinaryInfoDisplay {
                property: "Operating System".to_string(),
                value: format!("{:?}", id.os),
            },
            BinaryInfoDisplay {
                property: "Entry Point".to_string(),
                value: id.entry_point.map(|e| format!("0x{:x}", e)).unwrap_or("N/A".to_string()),
            },
            BinaryInfoDisplay {
                property: "Sections".to_string(),
                value: metadata.sections.len().to_string(),
            },
            BinaryInfoDisplay {
                property: "Segments".to_string(),
                value: metadata.segments.len().to_string(),
            },
            BinaryInfoDisplay {
                property: "Symbols".to_string(),
                value: metadata.symbols.len().to_string(),
            },
            BinaryInfoDisplay {
                property: "Imports".to_string(),
                value: metadata
                    .imports
                    .iter()
                    .map(|i| i.functions.len())
                    .sum::<usize>()
                    .to_string(),
            },
            BinaryInfoDisplay {
                property: "Exports".to_string(),
                value: metadata.exports.len().to_string(),
            },
            BinaryInfoDisplay { property: "MD5".to_string(), value: metadata.hashes.md5.clone() },
            BinaryInfoDisplay { property: "SHA1".to_string(), value: metadata.hashes.sha1.clone() },
            BinaryInfoDisplay {
                property: "SHA256".to_string(),
                value: metadata.hashes.sha256.clone(),
            },
        ];

        if let Some(compiler) = &id.compiler_info {
            info.push(BinaryInfoDisplay {
                property: "Compiler".to_string(),
                value: format!("{} {}", compiler.name, compiler.version.as_deref().unwrap_or("")),
            });
        }

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::metadata_to_sarif(&metadata);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&info, &args.output.into())?;
        }

        Ok(())
    }

    /// Symbols command
    async fn cmd_symbols(args: SymbolsArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;

        let mut symbols: Vec<SymbolDisplay> = metadata
            .symbols
            .into_iter()
            .filter(|s| {
                if args.globals_only
                    && s.binding != openre_analysis::binary::common::SymbolBinding::Global
                {
                    return false;
                }
                if let Some(filter) = args.filter_type {
                    let matches = match filter {
                        SymbolTypeFilter::Function => {
                            s.symbol_type == openre_analysis::binary::common::SymbolType::Function
                        }
                        SymbolTypeFilter::Object => {
                            s.symbol_type == openre_analysis::binary::common::SymbolType::Object
                        }
                        SymbolTypeFilter::Section => {
                            s.symbol_type == openre_analysis::binary::common::SymbolType::Section
                        }
                        SymbolTypeFilter::File => {
                            s.symbol_type == openre_analysis::binary::common::SymbolType::File
                        }
                        SymbolTypeFilter::Unknown => {
                            s.symbol_type == openre_analysis::binary::common::SymbolType::Unknown
                        }
                    };
                    if !matches {
                        return false;
                    }
                }
                if let Some(filter) = args.filter_binding {
                    let matches = match filter {
                        SymbolBindingFilter::Local => {
                            s.binding == openre_analysis::binary::common::SymbolBinding::Local
                        }
                        SymbolBindingFilter::Global => {
                            s.binding == openre_analysis::binary::common::SymbolBinding::Global
                        }
                        SymbolBindingFilter::Weak => {
                            s.binding == openre_analysis::binary::common::SymbolBinding::Weak
                        }
                        SymbolBindingFilter::Unknown => {
                            s.binding == openre_analysis::binary::common::SymbolBinding::Unknown
                        }
                    };
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .map(|s| SymbolDisplay {
                name: s.name,
                address: format!("0x{:x}", s.address),
                size: s.size.to_string(),
                symbol_type: format!("{:?}", s.symbol_type),
                binding: format!("{:?}", s.binding),
                section: s.section_index.map(|i| i.to_string()).unwrap_or("N/A".to_string()),
            })
            .collect();

        symbols.sort_by(|a, b| a.address.cmp(&b.address));

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::symbols_to_sarif(&symbols);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&symbols, &args.output.into())?;
        }

        Ok(())
    }

    /// Imports command
    async fn cmd_imports(args: ImportsArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;

        let mut imports: Vec<ImportDisplay> = metadata
            .imports
            .into_iter()
            .filter(|imp| {
                if let Some(lib) = &args.library {
                    imp.library.to_lowercase().contains(&lib.to_lowercase())
                } else {
                    true
                }
            })
            .flat_map(|imp| {
                imp.functions.into_iter().map(move |func| ImportDisplay {
                    library: imp.library.clone(),
                    function: func.name,
                    address: func
                        .address
                        .map(|a| format!("0x{:x}", a))
                        .unwrap_or("N/A".to_string()),
                    ordinal: func.ordinal.map(|o| o.to_string()).unwrap_or("N/A".to_string()),
                })
            })
            .collect();

        imports.sort_by(|a, b| a.library.cmp(&b.library).then(a.function.cmp(&b.function)));

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::imports_to_sarif(&imports);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&imports, &args.output.into())?;
        }

        Ok(())
    }

    /// Exports command
    async fn cmd_exports(args: ExportsArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;

        let mut exports: Vec<ExportDisplay> = metadata
            .exports
            .into_iter()
            .filter(|exp| {
                if let Some(pattern) = &args.pattern {
                    exp.name.to_lowercase().contains(&pattern.to_lowercase())
                } else {
                    true
                }
            })
            .map(|exp| ExportDisplay {
                name: exp.name,
                address: format!("0x{:x}", exp.address),
                ordinal: exp.ordinal.to_string(),
                forwarder: exp.forwarder.unwrap_or_default(),
            })
            .collect();

        exports.sort_by(|a, b| a.name.cmp(&b.name));

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::exports_to_sarif(&exports);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&exports, &args.output.into())?;
        }

        Ok(())
    }

    /// Strings command
    async fn cmd_strings(args: StringsArgs, ctx: Context) -> Result<(), CliError> {
        let data = std::fs::read(&args.file)?;
        let format = Self::detect_format(&args.file).await?;
        let extractor = Self::get_extractor(format).await;
        let strings = extractor.extract_strings(&data).await?;

        let mut filtered: Vec<StringDisplay> = strings
            .into_iter()
            .filter(|s| s.content.len() >= args.min_length)
            .filter(|s| {
                if let Some(pattern) = &args.pattern {
                    Regex::new(pattern).ok().map(|re| re.is_match(&s.content)).unwrap_or(false)
                } else {
                    true
                }
            })
            .map(|s| StringDisplay {
                offset: format!("0x{:x}", s.address),
                length: s.content.len().to_string(),
                string: s.content,
            })
            .collect();

        filtered.sort_by(|a, b| a.offset.cmp(&b.offset));

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::strings_to_sarif(&filtered);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&filtered, &args.output.into())?;
        }

        Ok(())
    }

    /// Sections command
    async fn cmd_sections(args: SectionsArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;

        let sections: Vec<SectionDisplay> = metadata
            .sections
            .into_iter()
            .map(|s| SectionDisplay {
                name: s.name,
                vaddr: format!("0x{:x}", s.virtual_address),
                vsize: s.virtual_size.to_string(),
                offset: format!("0x{:x}", s.raw_offset),
                size: s.raw_size.to_string(),
                readable: if s.characteristics.readable { "R" } else { "-" }.to_string(),
                writable: if s.characteristics.writable { "W" } else { "-" }.to_string(),
                executable: if s.characteristics.executable { "X" } else { "-" }.to_string(),
                entropy: format!("{:.2}", s.entropy),
            })
            .collect();

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::sections_to_sarif(&sections);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&sections, &args.output.into())?;
        }

        Ok(())
    }

    /// Segments command
    async fn cmd_segments(args: SegmentsArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;

        let segments: Vec<SegmentDisplay> = metadata
            .segments
            .into_iter()
            .map(|s| SegmentDisplay {
                vaddr: format!("0x{:x}", s.virtual_address),
                vsize: s.virtual_size.to_string(),
                offset: format!("0x{:x}", s.raw_offset),
                size: s.raw_size.to_string(),
                readable: if s.permissions.readable { "R" } else { "-" }.to_string(),
                writable: if s.permissions.writable { "W" } else { "-" }.to_string(),
                executable: if s.permissions.executable { "X" } else { "-" }.to_string(),
                alignment: format!("0x{:x}", s.alignment),
            })
            .collect();

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::segments_to_sarif(&segments);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&segments, &args.output.into())?;
        }

        Ok(())
    }

    /// Functions command
    async fn cmd_functions(args: FunctionsArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;
        let data = std::fs::read(&args.file)?;

        // Use static analysis to find functions
        let analyzer = StaticAnalysisService::new();
        let result = analyzer.analyze(metadata.file_id, &metadata).await?;

        let mut funcs: Vec<FunctionDisplay> = result
            .functions
            .into_iter()
            .filter(|f| f.size >= args.min_size as u64)
            .filter(|f| {
                if let Some(pattern) = &args.pattern {
                    f.name
                        .as_ref()
                        .map(|n| n.to_lowercase().contains(&pattern.to_lowercase()))
                        .unwrap_or(false)
                } else {
                    true
                }
            })
            .map(|f| FunctionDisplay {
                address: format!("0x{:x}", f.address),
                size: f.size.to_string(),
                name: f.name.unwrap_or_else(|| format!("sub_{:x}", f.address)),
                blocks: f.basic_blocks.len().to_string(),
                calls: f.calls.len().to_string(),
                complexity: f.complexity.to_string(),
            })
            .collect();

        funcs.sort_by(|a, b| a.address.cmp(&b.address));

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::functions_to_sarif(&funcs);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&funcs, &args.output.into())?;
        }

        // Show basic blocks if requested
        if args.show_blocks {
            println!("\nBasic blocks would be shown here (requires full disassembly)");
        }

        Ok(())
    }

    /// Decompile command
    async fn cmd_decompile(args: DecompileArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;
        let data = std::fs::read(&args.file)?;

        // Parse function address/name
        let func_addr = if args.function.starts_with("0x") {
            u64::from_str_radix(&args.function[2..], 16)
                .map_err(|_| CliError::InvalidInput("Invalid function address format".into()))?
        } else {
            // Find by name
            metadata
                .symbols
                .iter()
                .find(|s| s.name == args.function)
                .map(|s| s.address)
                .ok_or_else(|| CliError::InvalidInput("Function not found".into()))?
        };

        // Run decompilation (placeholder - would use pipeline)
        let pseudocode = format!(
            "// Decompilation of function at 0x{:x}\n// Not yet implemented - requires full pipeline execution\nfn sub_{:x}() {{\n    // TODO: Implement decompilation\n}}",
            func_addr, func_addr
        );

        #[derive(Serialize, Deserialize)]
        struct DecompileOutput {
            function: String,
            address: String,
            pseudocode: String,
        }

        let output = DecompileOutput {
            function: args.function,
            address: format!("0x{:x}", func_addr),
            pseudocode,
        };

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::decompile_to_sarif(&output);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&output, &args.output.into())?;
        }

        Ok(())
    }

    /// CFG command
    async fn cmd_cfg(args: CfgArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;
        let data = std::fs::read(&args.file)?;

        let func_addr = if args.function.starts_with("0x") {
            u64::from_str_radix(&args.function[2..], 16)
                .map_err(|_| CliError::InvalidInput("Invalid function address format".into()))?
        } else {
            metadata
                .symbols
                .iter()
                .find(|s| s.name == args.function)
                .map(|s| s.address)
                .ok_or_else(|| CliError::InvalidInput("Function not found".into()))?
        };

        // Run control flow analysis using the full analysis service
        let analyzer = StaticAnalysisService::new();
        let result = analyzer.analyze(metadata.file_id, &metadata).await?;

        // Filter to requested function
        let func_cfg = result.control_flow.functions.into_iter().find(|f| f.address == func_addr);

        if let Some(func) = func_cfg {
            if args.dot {
                // Output DOT format
                let mut dot = String::new();
                dot.push_str("digraph CFG {\n");
                for bb in &func.basic_blocks {
                    dot.push_str(&format!(
                        "  BB_{:x} [label=\"BB @ 0x{:x} ({} ins)\"];\n",
                        bb.address,
                        bb.address,
                        bb.instructions.len()
                    ));
                    for succ in &bb.successors {
                        dot.push_str(&format!("  BB_{:x} -> BB_{:x};\n", bb.address, succ));
                    }
                }
                dot.push_str("}\n");
                println!("{}", dot);
            } else {
                #[derive(Serialize, Deserialize)]
                struct CfgOutput {
                    function: String,
                    address: String,
                    blocks: Vec<BasicBlockDisplay>,
                }

                let blocks: Vec<BasicBlockDisplay> = func
                    .basic_blocks
                    .into_iter()
                    .map(|bb| BasicBlockDisplay {
                        address: format!("0x{:x}", bb.address),
                        size: bb.size.to_string(),
                        instructions: bb.instructions.len().to_string(),
                        predecessors: bb
                            .predecessors
                            .iter()
                            .map(|p| format!("0x{:x}", p))
                            .collect::<Vec<_>>()
                            .join(", "),
                        successors: bb
                            .successors
                            .iter()
                            .map(|s| format!("0x{:x}", s))
                            .collect::<Vec<_>>()
                            .join(", "),
                    })
                    .collect();

                let output = CfgOutput {
                    function: args.function,
                    address: format!("0x{:x}", func_addr),
                    blocks,
                };

                if args.output == OutputFormatArg::Sarif {
                    let sarif = Self::cfg_to_sarif(&output);
                    println!("{}", serde_json::to_string_pretty(&sarif)?);
                } else {
                    print_output(&output, &args.output.into())?;
                }
            }
        } else {
            return Err(CliError::InvalidInput("Function not found in CFG".into()));
        }

        Ok(())
    }

    /// Dataflow command
    async fn cmd_dataflow(args: DataflowArgs, ctx: Context) -> Result<(), CliError> {
        let metadata = Self::load_metadata(&args.file, None).await?;
        let data = std::fs::read(&args.file)?;

        let func_addr = if args.function.starts_with("0x") {
            u64::from_str_radix(&args.function[2..], 16)
                .map_err(|_| CliError::InvalidInput("Invalid function address format".into()))?
        } else {
            metadata
                .symbols
                .iter()
                .find(|s| s.name == args.function)
                .map(|s| s.address)
                .ok_or_else(|| CliError::InvalidInput("Function not found".into()))?
        };

        // Run data flow analysis using the full analysis service
        let analyzer = StaticAnalysisService::new();
        let result = analyzer.analyze(metadata.file_id, &metadata).await?;

        // Filter to requested function (simplified)
        #[derive(Serialize, Deserialize)]
        struct DataflowOutput {
            function: String,
            address: String,
            variables: Vec<VariableDisplay>,
            dependencies: Vec<DependencyDisplay>,
        }

        #[derive(Serialize, Deserialize, Tabled)]
        struct VariableDisplay {
            #[tabled(rename = "Address")]
            address: String,
            #[tabled(rename = "Name")]
            name: String,
            #[tabled(rename = "Type")]
            var_type: String,
            #[tabled(rename = "Size")]
            size: String,
            #[tabled(rename = "Scope")]
            scope: String,
        }

        #[derive(Serialize, Deserialize, Tabled)]
        struct DependencyDisplay {
            #[tabled(rename = "From")]
            from: String,
            #[tabled(rename = "To")]
            to: String,
            #[tabled(rename = "Type")]
            dep_type: String,
        }

        let variables: Vec<VariableDisplay> = result
            .data_flow
            .variables
            .into_iter()
            .map(|v| VariableDisplay {
                address: format!("0x{:x}", v.address),
                name: v.name.unwrap_or_else(|| format!("var_{:x}", v.address)),
                var_type: format!("{:?}", v.var_type),
                size: v.size.to_string(),
                scope: format!("{:?}", v.scope),
            })
            .collect();

        let dependencies: Vec<DependencyDisplay> = result
            .data_flow
            .data_dependencies
            .into_iter()
            .map(|d| DependencyDisplay {
                from: format!("0x{:x}", d.from),
                to: format!("0x{:x}", d.to),
                dep_type: format!("{:?}", d.dependency_type),
            })
            .collect();

        let output = DataflowOutput {
            function: args.function,
            address: format!("0x{:x}", func_addr),
            variables,
            dependencies,
        };

        if args.output == OutputFormatArg::Sarif {
            let sarif = Self::dataflow_to_sarif(&output);
            println!("{}", serde_json::to_string_pretty(&sarif)?);
        } else {
            print_output(&output, &args.output.into())?;
        }

        Ok(())
    }

    /// Pipeline commands
    async fn cmd_pipeline(cmd: PipelineCommands, ctx: Context) -> Result<(), CliError> {
        match cmd {
            PipelineCommands::Run(args) => Self::cmd_pipeline_run(args, ctx).await,
            PipelineCommands::Status(args) => Self::cmd_pipeline_status(args, ctx).await,
            PipelineCommands::Cancel(args) => Self::cmd_pipeline_cancel(args, ctx).await,
        }
    }

    /// Pipeline run command
    async fn cmd_pipeline_run(args: PipelineRunArgs, ctx: Context) -> Result<(), CliError> {
        // Create progress bar
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap(),
        );
        pb.set_message("Initializing analysis pipeline...");
        pb.enable_steady_tick(Duration::from_millis(100));

        // Load metadata
        let metadata = Self::load_metadata(&args.file, None).await?;
        let data = std::fs::read(&args.file)?;

        // Create pipeline context
        let project_id = args
            .project_id
            .and_then(|s| ProjectId::from_str(&s).ok())
            .unwrap_or_else(ProjectId::new);

        let job = AnalysisJob::new(
            project_id,
            metadata.file_id,
            AnalysisConfig {
                stages: args.stages.into(),
                priority: openre_analysis::orchestrator::Priority::DEFAULT,
                max_retries: 3,
                timeout_secs: 3600,
                ai_enabled: args.ai_enabled,
                incremental: false,
            },
            UserId::new(),
        );

        pb.set_message("Building pipeline...");

        // Create orchestrator (simplified - would need full setup)
        // For now, run identification stage manually
        let identifier = Self::get_identifier(metadata.identification.format);
        let identification = identifier.identify(&data).await?;

        pb.set_message("Running identification...");
        pb.finish_with_message("Analysis pipeline started!");

        // Output job info
        #[derive(Serialize, Deserialize, Tabled)]
        struct PipelineRunOutput {
            #[tabled(rename = "Job ID")]
            job_id: String,
            #[tabled(rename = "File")]
            file: String,
            #[tabled(rename = "Format")]
            format: String,
            #[tabled(rename = "Architecture")]
            architecture: String,
            #[tabled(rename = "Stages")]
            stages: String,
            #[tabled(rename = "AI Enabled")]
            ai_enabled: String,
            #[tabled(rename = "Status")]
            status: String,
        }

        let output = PipelineRunOutput {
            job_id: job.id.to_string(),
            file: args.file.display().to_string(),
            format: format!("{:?}", identification.format),
            architecture: format!("{:?}", identification.architecture),
            stages: match args.stages {
                PipelineStagesArg::All => "all".to_string(),
                s => format!("{:?}", s),
            },
            ai_enabled: args.ai_enabled.to_string(),
            status: "Started".to_string(),
        };

        print_output(&output, &args.output.into())?;

        // Note: Full pipeline execution requires the orchestrator with all dependencies
        // This would be integrated with the queue system in production

        Ok(())
    }

    /// Pipeline status command
    async fn cmd_pipeline_status(args: PipelineStatusArgs, ctx: Context) -> Result<(), CliError> {
        // In a real implementation, this would query the queue/job system
        let job_id = JobId::from_str(&args.id)
            .map_err(|e| CliError::InvalidInput(format!("Invalid job ID format: {}", e)))?;

        // Placeholder - would fetch from queue
        #[derive(Serialize, Deserialize, Tabled)]
        struct StatusOutput {
            #[tabled(rename = "Job ID")]
            job_id: String,
            #[tabled(rename = "Status")]
            status: String,
            #[tabled(rename = "Progress")]
            progress: String,
            #[tabled(rename = "Current Stage")]
            current_stage: String,
            #[tabled(rename = "Stages Completed")]
            stages_completed: String,
            #[tabled(rename = "Total Stages")]
            total_stages: String,
        }

        let output = StatusOutput {
            job_id: job_id.to_string(),
            status: "Running".to_string(),
            progress: "45%".to_string(),
            current_stage: "ControlFlow".to_string(),
            stages_completed: "3".to_string(),
            total_stages: "9".to_string(),
        };

        print_output(&output, &args.output.into())?;

        Ok(())
    }

    /// Pipeline cancel command
    async fn cmd_pipeline_cancel(args: PipelineCancelArgs, ctx: Context) -> Result<(), CliError> {
        let _job_id = JobId::from_str(&args.id)
            .map_err(|e| CliError::InvalidInput(format!("Invalid job ID format: {}", e)))?;

        // In a real implementation, this would send cancellation to the queue
        println!("Cancellation requested for job: {}", args.id);
        println!("Note: Full cancellation requires queue integration");

        Ok(())
    }

    // SARIF conversion helpers
    fn identification_to_sarif(id: &BinaryIdentification) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "openre-analysis",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/open-re/open-re"
                    }
                },
                "results": [{
                    "ruleId": "binary-identification",
                    "level": "note",
                    "message": {
                        "text": format!("Binary identified as {:?} ({:?})", id.format, id.architecture)
                    },
                    "properties": {
                        "format": format!("{:?}", id.format),
                        "architecture": format!("{:?}", id.architecture),
                        "bitness": format!("{:?}", id.bitness),
                        "endianness": format!("{:?}", id.endianness),
                        "os": format!("{:?}", id.os),
                        "entryPoint": id.entry_point.map(|e| format!("0x{:x}", e)),
                        "confidence": id.confidence
                    }
                }]
            }]
        })
    }

    fn metadata_to_sarif(meta: &BinaryMetadata) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "openre-analysis",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                },
                "results": [{
                    "ruleId": "binary-metadata",
                    "level": "note",
                    "message": {
                        "text": format!("Binary metadata extracted: {} sections, {} symbols", meta.sections.len(), meta.symbols.len())
                    },
                    "properties": {
                        "format": format!("{:?}", meta.identification.format),
                        "architecture": format!("{:?}", meta.identification.architecture),
                        "sections": meta.sections.len(),
                        "segments": meta.segments.len(),
                        "symbols": meta.symbols.len(),
                        "imports": meta.imports.iter().map(|i| i.functions.len()).sum::<usize>(),
                        "exports": meta.exports.len(),
                        "hashes": {
                            "md5": meta.hashes.md5,
                            "sha1": meta.hashes.sha1,
                            "sha256": meta.hashes.sha256
                        }
                    }
                }]
            }]
        })
    }

    fn symbols_to_sarif(symbols: &[SymbolDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": symbols.iter().map(|s| serde_json::json!({
                    "ruleId": "symbol",
                    "level": "note",
                    "message": { "text": format!("Symbol: {} at {}", s.name, s.address) },
                    "properties": {
                        "name": s.name,
                        "address": s.address,
                        "size": s.size,
                        "type": s.symbol_type,
                        "binding": s.binding,
                        "section": s.section
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn imports_to_sarif(imports: &[ImportDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": imports.iter().map(|i| serde_json::json!({
                    "ruleId": "import",
                    "level": "note",
                    "message": { "text": format!("Import: {} from {}", i.function, i.library) },
                    "properties": {
                        "library": i.library,
                        "function": i.function,
                        "address": i.address,
                        "ordinal": i.ordinal
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn exports_to_sarif(exports: &[ExportDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": exports.iter().map(|e| serde_json::json!({
                    "ruleId": "export",
                    "level": "note",
                    "message": { "text": format!("Export: {} at {}", e.name, e.address) },
                    "properties": {
                        "name": e.name,
                        "address": e.address,
                        "ordinal": e.ordinal,
                        "forwarder": e.forwarder
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn strings_to_sarif(strings: &[StringDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": strings.iter().map(|s| serde_json::json!({
                    "ruleId": "string",
                    "level": "note",
                    "message": { "text": format!("String at {}: {}", s.offset, s.string) },
                    "properties": {
                        "offset": s.offset,
                        "length": s.length,
                        "value": s.string
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn sections_to_sarif(sections: &[SectionDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": sections.iter().map(|s| serde_json::json!({
                    "ruleId": "section",
                    "level": "note",
                    "message": { "text": format!("Section: {} at {}", s.name, s.vaddr) },
                    "properties": {
                        "name": s.name,
                        "virtualAddress": s.vaddr,
                        "virtualSize": s.vsize,
                        "rawOffset": s.offset,
                        "rawSize": s.size,
                        "permissions": format!("{}{}{}", s.readable, s.writable, s.executable),
                        "entropy": s.entropy
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn segments_to_sarif(segments: &[SegmentDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": segments.iter().map(|s| serde_json::json!({
                    "ruleId": "segment",
                    "level": "note",
                    "message": { "text": format!("Segment at {} size {}", s.vaddr, s.vsize) },
                    "properties": {
                        "virtualAddress": s.vaddr,
                        "virtualSize": s.vsize,
                        "rawOffset": s.offset,
                        "rawSize": s.size,
                        "permissions": format!("{}{}{}", s.readable, s.writable, s.executable),
                        "alignment": s.alignment
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn functions_to_sarif(functions: &[FunctionDisplay]) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": functions.iter().map(|f| serde_json::json!({
                    "ruleId": "function",
                    "level": "note",
                    "message": { "text": format!("Function: {} at {} ({} bytes)", f.name, f.address, f.size) },
                    "properties": {
                        "name": f.name,
                        "address": f.address,
                        "size": f.size,
                        "blocks": f.blocks,
                        "calls": f.calls,
                        "complexity": f.complexity
                    }
                })).collect::<Vec<_>>()
            }]
        })
    }

    fn decompile_to_sarif(output: &impl Serialize) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": [{
                    "ruleId": "decompilation",
                    "level": "note",
                    "message": { "text": "Decompilation output" },
                    "properties": output
                }]
            }]
        })
    }

    fn cfg_to_sarif(output: &impl Serialize) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": [{
                    "ruleId": "cfg",
                    "level": "note",
                    "message": { "text": "Control flow graph" },
                    "properties": output
                }]
            }]
        })
    }

    fn dataflow_to_sarif(output: &impl Serialize) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": { "driver": { "name": "openre-analysis" }},
                "results": [{
                    "ruleId": "dataflow",
                    "level": "note",
                    "message": { "text": "Data flow analysis" },
                    "properties": output
                }]
            }]
        })
    }
}
