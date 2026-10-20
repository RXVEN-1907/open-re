//! Binary analysis commands

use crate::context::Context;
use crate::error::CliError;
use crate::output::{print_output, OutputFormat};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use openre_analysis::binary::common::{Architecture, BinaryFormat, Endianness};
use openre_analysis::binary::traits::{BinaryIdentifier, BinaryMetadataExtractor};
use openre_analysis::binary::{
    ElfIdentifier, ElfMetadataExtractor, MachoIdentifier, MachoMetadataExtractor, PeIdentifier,
    PeMetadataExtractor, WasmIdentifier, WasmMetadataExtractor,
};
use openre_disasm::{Disassembler, DisassemblyConfig};
use std::path::PathBuf;
use std::time::Instant;
use tabled::{Style, Table, Tabled};

#[derive(Subcommand, Debug)]
pub enum AnalyzeCommands {
    /// Parse and identify binary format
    Info(AnalyzeArgs),
    /// List symbols
    Symbols(AnalyzeArgs),
    /// List imports
    Imports(AnalyzeArgs),
    /// List exports
    Exports(AnalyzeArgs),
    /// Extract strings
    Strings(StringsArgs),
    /// List sections
    Sections(AnalyzeArgs),
    /// List segments
    Segments(AnalyzeArgs),
    /// List functions
    Functions(FunctionsArgs),
    /// Disassemble function or range
    Disasm(DisasmArgs),
    /// Decompile function
    Decompile(DecompileArgs),
    /// Run analysis pipeline stages
    Pipeline(PipelineArgs),
}

#[derive(Args, Debug)]
pub(crate) struct AnalyzeArgs {
    /// Binary file path
    file: PathBuf,

    /// Force binary format (auto-detected if not specified)
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Maximum number of rows to print (0 = unlimited)
    #[arg(long, default_value = "100")]
    limit: usize,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct StringsArgs {
    /// Binary file path
    file: PathBuf,

    /// Minimum string length
    #[arg(short, long, default_value = "4")]
    min_length: usize,

    /// Maximum number of strings to print (0 = unlimited)
    #[arg(long, default_value = "100")]
    limit: usize,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct FunctionsArgs {
    /// Binary file path
    file: PathBuf,

    /// Filter by name pattern
    #[arg(short, long)]
    filter: Option<String>,

    /// Show function details (type, binding, visibility)
    #[arg(long)]
    details: bool,

    /// Maximum number of rows to print (0 = unlimited)
    #[arg(long, default_value = "100")]
    limit: usize,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct DisasmArgs {
    /// Binary file path
    file: PathBuf,

    /// Function name or address to disassemble
    #[arg(short, long)]
    function: Option<String>,

    /// Start address (hex)
    #[arg(long)]
    start: Option<String>,

    /// End address (hex)
    #[arg(long)]
    end: Option<String>,

    /// Number of instructions
    #[arg(short, long, default_value = "50")]
    count: usize,

    /// Show byte representation
    #[arg(long)]
    bytes: bool,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct DecompileArgs {
    /// Binary file path
    file: PathBuf,

    /// Function name or address to decompile
    #[arg(short, long)]
    function: String,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct PipelineArgs {
    /// Binary file path
    file: PathBuf,

    /// Analysis stages to run
    #[arg(long, value_delimiter = ',', default_value = "all")]
    stages: Vec<PipelineStageArg>,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, ValueEnum)]
enum BinaryFormatArg {
    Elf,
    Pe,
    Macho,
    Wasm,
    Auto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum PipelineStageArg {
    All,
    Identify,
    Load,
    Disassemble,
    Cfg,
    Dataflow,
    Types,
    Decompile,
    AiEnrich,
}

const ALL_STAGES: [PipelineStageArg; 8] = [
    PipelineStageArg::Identify,
    PipelineStageArg::Load,
    PipelineStageArg::Disassemble,
    PipelineStageArg::Cfg,
    PipelineStageArg::Dataflow,
    PipelineStageArg::Types,
    PipelineStageArg::Decompile,
    PipelineStageArg::AiEnrich,
];

impl PipelineStageArg {
    fn name(self) -> &'static str {
        match self {
            PipelineStageArg::All => "all",
            PipelineStageArg::Identify => "identify",
            PipelineStageArg::Load => "load",
            PipelineStageArg::Disassemble => "disassemble",
            PipelineStageArg::Cfg => "cfg",
            PipelineStageArg::Dataflow => "dataflow",
            PipelineStageArg::Types => "types",
            PipelineStageArg::Decompile => "decompile",
            PipelineStageArg::AiEnrich => "ai_enrich",
        }
    }
}

impl AnalyzeCommands {
    pub async fn execute(self, ctx: Context) -> Result<(), CliError> {
        match self {
            AnalyzeCommands::Info(args) => run_info(ctx, args).await,
            AnalyzeCommands::Symbols(args) => run_symbols(ctx, args).await,
            AnalyzeCommands::Imports(args) => run_imports(ctx, args).await,
            AnalyzeCommands::Exports(args) => run_exports(ctx, args).await,
            AnalyzeCommands::Strings(args) => run_strings(ctx, args).await,
            AnalyzeCommands::Sections(args) => run_sections(ctx, args).await,
            AnalyzeCommands::Segments(args) => run_segments(ctx, args).await,
            AnalyzeCommands::Functions(args) => run_functions(ctx, args).await,
            AnalyzeCommands::Disasm(args) => run_disasm(ctx, args).await,
            AnalyzeCommands::Decompile(args) => run_decompile(ctx, args).await,
            AnalyzeCommands::Pipeline(args) => run_pipeline(ctx, args).await,
        }
    }
}

fn resolve_format(
    forced: Option<BinaryFormatArg>,
    data: &[u8],
    path: &std::path::Path,
) -> Result<BinaryFormat, CliError> {
    match forced {
        Some(BinaryFormatArg::Elf) => Ok(BinaryFormat::Elf),
        Some(BinaryFormatArg::Pe) => Ok(BinaryFormat::Pe),
        Some(BinaryFormatArg::Macho) => Ok(BinaryFormat::MachO),
        Some(BinaryFormatArg::Wasm) => Ok(BinaryFormat::Wasm),
        Some(BinaryFormatArg::Auto) | None => {
            let detected = BinaryFormat::from_bytes(data);
            if detected == BinaryFormat::Unknown {
                return Err(CliError::InvalidArgs(format!(
                    "Could not detect format of {} (use --binary-format to force)",
                    path.display()
                )));
            }
            Ok(detected)
        }
    }
}

fn truncate<T>(items: Vec<T>, limit: usize) -> Vec<T> {
    if limit == 0 {
        items
    } else {
        items.into_iter().take(limit).collect()
    }
}

/// Extract printable ASCII runs of at least `min_length` characters.
/// Runs made only of whitespace are dropped as noise.
fn extract_printable_strings(data: &[u8], min_length: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let printable = (0x20..0x7f).contains(&b);
        if printable && start.is_none() {
            start = Some(i);
        } else if !printable {
            if let Some(s) = start.take() {
                if i - s >= min_length && data[s..i].iter().any(|c| !c.is_ascii_whitespace()) {
                    out.push(String::from_utf8_lossy(&data[s..i]).into_owned());
                }
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_length && data[s..].iter().any(|c| !c.is_ascii_whitespace()) {
            out.push(String::from_utf8_lossy(&data[s..]).into_owned());
        }
    }
    out
}

fn extractor_for(format: BinaryFormat) -> Result<Box<dyn BinaryMetadataExtractor>, CliError> {
    match format {
        BinaryFormat::Elf => Ok(Box::new(ElfMetadataExtractor)),
        BinaryFormat::Pe => Ok(Box::new(PeMetadataExtractor)),
        BinaryFormat::MachO => Ok(Box::new(MachoMetadataExtractor)),
        BinaryFormat::Wasm => Ok(Box::new(WasmMetadataExtractor)),
        BinaryFormat::Unknown => Err(CliError::InvalidArgs("Binary format not supported".into())),
    }
}

fn identifier_for(format: BinaryFormat) -> Result<Box<dyn BinaryIdentifier>, CliError> {
    match format {
        BinaryFormat::Elf => Ok(Box::new(ElfIdentifier)),
        BinaryFormat::Pe => Ok(Box::new(PeIdentifier)),
        BinaryFormat::MachO => Ok(Box::new(MachoIdentifier)),
        BinaryFormat::Wasm => Ok(Box::new(WasmIdentifier)),
        BinaryFormat::Unknown => Err(CliError::InvalidArgs("Binary format not supported".into())),
    }
}

struct LoadedBinary {
    data: Vec<u8>,
    format: BinaryFormat,
}

fn load_binary(path: &PathBuf, forced: Option<BinaryFormatArg>) -> Result<LoadedBinary, CliError> {
    let data = std::fs::read(path)?;
    let format = resolve_format(forced, &data, path)?;
    Ok(LoadedBinary { data, format })
}

async fn run_info(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let metadata = extractor.extract_metadata(&loaded.data).await?;

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        let id = &metadata.identification;
        println!("{} {}", "Binary:".bold(), args.file.display());
        println!(
            "  {} {:?} {:?} {:?} {:?}",
            "Format:".bold(),
            id.format,
            id.architecture,
            id.bitness,
            id.endianness
        );
        println!("  {} {:?}  {} {:?}", "OS:".bold(), id.os, "Confidence:".bold(), id.confidence);
        println!(
            "  {} {}",
            "Entry point:".bold(),
            id.entry_point.map(|a| format!("0x{:x}", a)).unwrap_or_else(|| "-".to_string())
        );
        if let Some(compiler) = &id.compiler_info {
            println!(
                "  {} {} {}",
                "Compiler:".bold(),
                compiler.name,
                compiler.version.as_deref().unwrap_or("-")
            );
        }
        let sec = &id.security_features;
        println!(
            "  {} aslr={} dep/nx={} pie={} relro={:?} canary={} fortify={} cfi={}",
            "Hardening:".bold(),
            sec.aslr,
            sec.dep_nx,
            sec.pie,
            sec.relro,
            sec.stack_canary,
            sec.fortify_source,
            sec.cfi
        );
        println!(
            "  {} {} sections, {} symbols, {} imports, {} exports, {} strings",
            "Contents:".bold(),
            metadata.sections.len(),
            metadata.symbols.len(),
            metadata.imports.len(),
            metadata.exports.len(),
            metadata.strings.len()
        );
    } else {
        print_output(&metadata, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_symbols(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let symbols = truncate(extractor.extract_symbols(&loaded.data).await?, args.limit);

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        let rows: Vec<SymbolRow> = symbols
            .iter()
            .map(|s| SymbolRow {
                name: s.name.clone(),
                address: format!("0x{:x}", s.address),
                size: s.size as usize,
                symbol_type: format!("{:?}", s.symbol_type),
                binding: format!("{:?}", s.binding),
            })
            .collect();
        let mut table = Table::new(rows);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&symbols, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_imports(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let imports = truncate(extractor.extract_imports(&loaded.data).await?, args.limit);

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        let rows: Vec<ImportRow> = imports
            .iter()
            .flat_map(|i| {
                i.functions.iter().map(move |f| ImportRow {
                    library: i.library.clone(),
                    name: f.name.clone(),
                    address: f
                        .address
                        .map(|a| format!("0x{:x}", a))
                        .unwrap_or_else(|| "-".to_string()),
                })
            })
            .collect();
        let mut table = Table::new(rows);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&imports, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_exports(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let exports = truncate(extractor.extract_exports(&loaded.data).await?, args.limit);

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        let rows: Vec<ExportRow> = exports
            .iter()
            .map(|e| ExportRow {
                name: e.name.clone(),
                address: format!("0x{:x}", e.address),
                ordinal: e.ordinal.to_string(),
            })
            .collect();
        let mut table = Table::new(rows);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&exports, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_sections(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let sections = truncate(extractor.extract_sections(&loaded.data).await?, args.limit);

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        let rows: Vec<SectionRow> = sections
            .iter()
            .map(|s| SectionRow {
                name: s.name.clone(),
                address: format!("0x{:x}", s.virtual_address),
                size: s.virtual_size as usize,
                offset: format!("0x{:x}", s.raw_offset),
                entropy: format!("{:.2}", s.entropy),
            })
            .collect();
        let mut table = Table::new(rows);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&sections, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_segments(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let segments = truncate(extractor.extract_segments(&loaded.data).await?, args.limit);

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        let rows: Vec<SegmentRow> = segments
            .iter()
            .map(|s| SegmentRow {
                address: format!("0x{:x}", s.virtual_address),
                size: s.virtual_size as usize,
                offset: format!("0x{:x}", s.raw_offset),
                permissions: format!(
                    "{}{}{}",
                    if s.permissions.readable { "r" } else { "-" },
                    if s.permissions.writable { "w" } else { "-" },
                    if s.permissions.executable { "x" } else { "-" }
                ),
            })
            .collect();
        let mut table = Table::new(rows);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&segments, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_strings(ctx: Context, args: StringsArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Extracting strings from {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let _extractor = extractor_for(loaded.format)?;
    let mut strings: Vec<String> = extract_printable_strings(&loaded.data, args.min_length);

    spinner.finish_and_clear();

    strings.sort();
    strings.dedup();
    let strings = truncate(strings, args.limit);

    if ctx.format == OutputFormat::Table {
        for s in &strings {
            println!("{}", s);
        }
    } else {
        print_output(&strings, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_functions(ctx: Context, args: FunctionsArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Listing functions in {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let symbols = truncate(extractor.extract_symbols(&loaded.data).await?, args.limit);

    spinner.finish_and_clear();

    let functions: Vec<FunctionRow> = truncate(
        symbols
            .iter()
            .filter(|s| s.symbol_type == openre_analysis::SymbolType::Function)
            .filter(|s| match &args.filter {
                Some(pattern) => s.name.contains(pattern.as_str()),
                None => true,
            })
            .map(|s| FunctionRow {
                name: s.name.clone(),
                address: format!("0x{:x}", s.address),
                size: s.size as usize,
                complexity: "-".to_string(),
                symbol_type: if args.details {
                    format!("{:?}", s.symbol_type)
                } else {
                    "-".to_string()
                },
                binding: if args.details { format!("{:?}", s.binding) } else { "-".to_string() },
            })
            .collect(),
        args.limit,
    );

    if functions.is_empty() {
        println!("{} No functions found", "ℹ".blue());
        return Ok(());
    }

    if ctx.format == OutputFormat::Table {
        let mut table = Table::new(functions);
        table.with(Style::modern());
        println!("{}", table);
    } else {
        let rows: Vec<FunctionJsonRow> = functions
            .into_iter()
            .map(|f| FunctionJsonRow {
                name: f.name,
                address: f.address,
                size: f.size,
                symbol_type: f.symbol_type,
                binding: f.binding,
            })
            .collect();
        print_output(&rows, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

fn disasm_architecture(arch: Architecture) -> Option<openre_disasm::Architecture> {
    use openre_disasm::Architecture as DArch;
    Some(match arch {
        Architecture::X86 => DArch::X86,
        Architecture::X86_64 => DArch::X86_64,
        Architecture::Arm => DArch::Arm,
        Architecture::Arm64 => DArch::AArch64,
        Architecture::Mips => DArch::Mips,
        Architecture::Mips64 => DArch::Mips64,
        Architecture::PowerPc => DArch::PowerPc,
        Architecture::PowerPc64 => DArch::PowerPc64,
        Architecture::RiscV32 => DArch::RiscV32,
        Architecture::RiscV64 => DArch::RiscV64,
        Architecture::Unknown => return None,
    })
}

fn disasm_endianness(endian: Endianness) -> openre_disasm::Endianness {
    match endian {
        Endianness::Little => openre_disasm::Endianness::Little,
        Endianness::Big => openre_disasm::Endianness::Big,
    }
}

/// Locate a virtual address inside a mapped section and return its file offset.
fn file_offset_for(
    sections: &[openre_analysis::SectionInfo],
    address: u64,
) -> Option<(usize, u64)> {
    for section in sections {
        let start = section.virtual_address;
        let end = start.saturating_add(section.virtual_size);
        if address >= start && address < end {
            if section.raw_size == 0 || address - start >= section.raw_size {
                return None;
            }
            let remaining = section.raw_size - (address - start);
            return Some(((section.raw_offset + (address - start)) as usize, remaining));
        }
    }
    None
}

fn build_disassembler(
    identification: &openre_analysis::BinaryIdentification,
    base_address: u64,
    max_instructions: usize,
) -> Result<Disassembler, CliError> {
    let arch = disasm_architecture(identification.architecture)
        .ok_or_else(|| CliError::InvalidArgs("Unknown architecture, cannot disassemble".into()))?;
    let config = DisassemblyConfig {
        architecture: arch,
        endianness: disasm_endianness(identification.endianness),
        base_address,
        max_instructions,
        ..DisassemblyConfig::default()
    };
    Disassembler::new(config)
        .map_err(|e| CliError::InvalidArgs(format!("Disassembler setup failed: {}", e)))
}

async fn run_disasm(ctx: Context, args: DisasmArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Disassembling {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let metadata = extractor.extract_metadata(&loaded.data).await?;

    let (address, span) = if let Some(func) = &args.function {
        let symbol = metadata
            .symbols
            .iter()
            .find(|s| s.name == *func)
            .ok_or_else(|| CliError::NotFound(format!("Function '{}'", func)))?;
        let limit = if symbol.size > 0 { symbol.size } else { u64::MAX };
        (symbol.address, limit)
    } else if let (Some(start), Some(end)) = (&args.start, &args.end) {
        let start_addr = u64::from_str_radix(start.trim_start_matches("0x"), 16)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid start address: {}", e)))?;
        let end_addr = u64::from_str_radix(end.trim_start_matches("0x"), 16)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid end address: {}", e)))?;
        if end_addr <= start_addr {
            return Err(CliError::InvalidArgs("--end must be greater than --start".into()));
        }
        (start_addr, end_addr - start_addr)
    } else {
        return Err(CliError::InvalidArgs("Specify --function or --start/--end".into()));
    };

    let (offset, remaining) = file_offset_for(&metadata.sections, address)
        .ok_or_else(|| CliError::NotFound(format!("Section covering address 0x{:x}", address)))?;

    let span = span.min(remaining).min(loaded.data.len().saturating_sub(offset) as u64) as usize;
    if span == 0 {
        return Err(CliError::InvalidArgs("No bytes to disassemble at that address".into()));
    }

    let disassembler = build_disassembler(&metadata.identification, address, args.count)?;

    // Cap the byte window: worst-case instruction length bounds the bytes the
    // requested instruction count can consume.
    let budget = args.count.saturating_mul(16).min(span).max(1);
    let code = &loaded.data[offset..offset + budget];
    let instructions = disassembler
        .disassemble_all(code)
        .map_err(|e| CliError::InvalidArgs(format!("Disassembly failed: {}", e)))?;

    spinner.finish_and_clear();

    let rows: Vec<InstructionRow> = instructions
        .iter()
        .take(args.count)
        .map(|i| InstructionRow {
            address: i.address,
            bytes: i.bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" "),
            mnemonic: i.mnemonic.clone(),
            operands: i.op_str.clone(),
        })
        .collect();

    if rows.is_empty() {
        println!("{} No instructions decoded", "ℹ".blue());
        return Ok(());
    }

    if ctx.format == OutputFormat::Table {
        for insn in &rows {
            let text = if insn.operands.is_empty() {
                insn.mnemonic.clone()
            } else {
                format!("{} {}", insn.mnemonic, insn.operands)
            };
            println!("{:>16}  {}", format!("0x{:x}", insn.address).dimmed(), text);
            if args.bytes {
                println!("{:>16}  {}", "", insn.bytes.dimmed());
            }
        }
    } else {
        print_output(&rows, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_decompile(ctx: Context, args: DecompileArgs) -> Result<(), CliError> {
    let _spinner = ctx.spinner(format!("Decompiling function in {}...", args.file.display()));
    let _ = &args.function;
    Err(CliError::NotImplemented(
        "no decompiler backend is linked into this build; use `openre analyze disasm`".into(),
    ))
}

async fn run_pipeline(ctx: Context, args: PipelineArgs) -> Result<(), CliError> {
    let spinner = ctx.spinner(format!("Running analysis pipeline on {}...", args.file.display()));

    let loaded = load_binary(&args.file, args.binary_format)?;
    let extractor = extractor_for(loaded.format)?;
    let identifier = identifier_for(loaded.format)?;

    let requested: Vec<PipelineStageArg> = if args.stages.contains(&PipelineStageArg::All) {
        ALL_STAGES.to_vec()
    } else {
        args.stages.clone()
    };

    let mut stages: Vec<PipelineStageResult> = Vec::new();
    let mut metadata: Option<openre_analysis::BinaryMetadata> = None;
    let mut identification: Option<openre_analysis::BinaryIdentification> = None;
    let mut executed = 0usize;

    for stage in requested {
        let start = Instant::now();
        match stage {
            PipelineStageArg::All => {}
            PipelineStageArg::Identify => match identifier.identify(&loaded.data).await {
                Ok(result) => {
                    executed += 1;
                    stages.push(PipelineStageResult {
                        stage: stage.name().to_string(),
                        status: "success".to_string(),
                        detail: format!(
                            "{:?} {:?} {:?} {:?} on {:?}, confidence {:.2}",
                            result.format,
                            result.architecture,
                            result.bitness,
                            result.endianness,
                            result.os,
                            result.confidence
                        ),
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                    identification = Some(result);
                }
                Err(e) => stages.push(failed_stage(stage.name(), &e.to_string(), start)),
            },
            PipelineStageArg::Load => match extractor.extract_metadata(&loaded.data).await {
                Ok(m) => {
                    executed += 1;
                    stages.push(PipelineStageResult {
                        stage: stage.name().to_string(),
                        status: "success".to_string(),
                        detail: format!(
                            "parsed {} sections, {} symbols, {} imports, {} exports",
                            m.sections.len(),
                            m.symbols.len(),
                            m.imports.len(),
                            m.exports.len()
                        ),
                        duration_ms: start.elapsed().as_millis() as u64,
                    });
                    metadata = Some(m);
                }
                Err(e) => stages.push(failed_stage(stage.name(), &e.to_string(), start)),
            },
            PipelineStageArg::Disassemble => {
                let identification = match identification_or_loaded(&identification, &metadata) {
                    Some(id) => id,
                    None => {
                        stages.push(skipped_stage(
                            stage.name(),
                            "requires the identify or load stage to run first",
                        ));
                        continue;
                    }
                };
                match disassemble_text(&loaded.data, &metadata, &identification) {
                    Ok(count) => {
                        executed += 1;
                        stages.push(PipelineStageResult {
                            stage: stage.name().to_string(),
                            status: "success".to_string(),
                            detail: format!(
                                "decoded {} instructions from the entry section",
                                count
                            ),
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                    Err(reason) => {
                        stages.push(skipped_stage(stage.name(), &reason));
                    }
                }
            }
            PipelineStageArg::Cfg | PipelineStageArg::Dataflow => {
                let metadata = match &metadata {
                    Some(m) => m.clone(),
                    None => {
                        stages.push(skipped_stage(
                            stage.name(),
                            "requires the load stage to run first",
                        ));
                        continue;
                    }
                };
                let service = openre_analysis::StaticAnalysisService::new();
                match service.analyze(openre_core::ids::FileId::nil(), &metadata).await {
                    Ok(result) => {
                        executed += 1;
                        let detail = if stage == PipelineStageArg::Cfg {
                            format!(
                                "{} call-graph nodes, {} edges",
                                result.control_flow.call_graph.nodes.len(),
                                result.control_flow.call_graph.edges.len()
                            )
                        } else {
                            format!(
                                "{} variables, {} data dependencies",
                                result.data_flow.variables.len(),
                                result.data_flow.data_dependencies.len()
                            )
                        };
                        stages.push(PipelineStageResult {
                            stage: stage.name().to_string(),
                            status: "success".to_string(),
                            detail,
                            duration_ms: start.elapsed().as_millis() as u64,
                        });
                    }
                    Err(e) => stages.push(failed_stage(stage.name(), &e.to_string(), start)),
                }
            }
            PipelineStageArg::Types => {
                stages.push(skipped_stage(stage.name(), "no type-recovery backend linked"));
            }
            PipelineStageArg::Decompile => {
                stages.push(skipped_stage(stage.name(), "no decompiler backend linked"));
            }
            PipelineStageArg::AiEnrich => {
                stages
                    .push(skipped_stage(stage.name(), "run `openre ai analyze` for AI enrichment"));
            }
        }
    }

    spinner.finish_and_clear();

    let result = PipelineReport {
        file: args.file.display().to_string(),
        stages,
        summary: format!("{} stage(s) executed", executed),
    };

    if ctx.format == OutputFormat::Table {
        println!("\n{}", "Analysis Pipeline".bold().cyan());
        println!("{}", "═".repeat(50).dimmed());
        println!("File: {}", result.file);
        let mut table = Table::new(
            result
                .stages
                .iter()
                .map(|s| PipelineStageRow {
                    stage: s.stage.clone(),
                    status: s.status.clone(),
                    detail: s.detail.clone(),
                    duration: format!("{}ms", s.duration_ms),
                })
                .collect::<Vec<_>>(),
        );
        table.with(Style::modern());
        println!("{}", table);
        println!("\n{}", result.summary);
    } else {
        print_output(&result, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

fn identification_or_loaded(
    identification: &Option<openre_analysis::BinaryIdentification>,
    metadata: &Option<openre_analysis::BinaryMetadata>,
) -> Option<openre_analysis::BinaryIdentification> {
    if let Some(id) = identification {
        return Some(id.clone());
    }
    metadata.as_ref().map(|m| m.identification.clone())
}

/// Disassemble the first instructions of the executable section to bound pipeline cost.
fn disassemble_text(
    data: &[u8],
    metadata: &Option<openre_analysis::BinaryMetadata>,
    identification: &openre_analysis::BinaryIdentification,
) -> Result<usize, String> {
    let metadata = metadata.as_ref().ok_or("binary not loaded")?;
    let entry = if identification.entry_point.is_some() {
        identification.entry_point
    } else {
        metadata.identification.entry_point
    };
    let address = entry.unwrap_or_else(|| {
        metadata
            .sections
            .iter()
            .find(|s| s.characteristics.executable)
            .map(|s| s.virtual_address)
            .unwrap_or(0)
    });
    let (offset, remaining) = file_offset_for(&metadata.sections, address)
        .ok_or("no section covers the entry address")?;
    let span = remaining.min(data.len().saturating_sub(offset) as u64) as usize;
    if span == 0 {
        return Err("no bytes at the entry address".to_string());
    }
    let disassembler =
        build_disassembler(identification, address, 200).map_err(|e| e.to_string())?;
    let budget = 200usize.saturating_mul(16).min(span).max(1);
    let instructions =
        disassembler.disassemble_all(&data[offset..offset + budget]).map_err(|e| e.to_string())?;
    Ok(instructions.len())
}

fn failed_stage(stage: &str, error: &str, start: Instant) -> PipelineStageResult {
    PipelineStageResult {
        stage: stage.to_string(),
        status: "failed".to_string(),
        detail: error.to_string(),
        duration_ms: start.elapsed().as_millis() as u64,
    }
}

fn skipped_stage(stage: &str, reason: &str) -> PipelineStageResult {
    PipelineStageResult {
        stage: stage.to_string(),
        status: "skipped".to_string(),
        detail: reason.to_string(),
        duration_ms: 0,
    }
}

#[derive(tabled::Tabled)]
struct SymbolRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "ADDRESS")]
    address: String,
    #[tabled(rename = "SIZE")]
    size: usize,
    #[tabled(rename = "TYPE")]
    symbol_type: String,
    #[tabled(rename = "BINDING")]
    binding: String,
}

#[derive(tabled::Tabled)]
struct ImportRow {
    #[tabled(rename = "LIBRARY")]
    library: String,
    #[tabled(rename = "FUNCTION")]
    name: String,
    #[tabled(rename = "ADDRESS")]
    address: String,
}

#[derive(tabled::Tabled)]
struct ExportRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "ADDRESS")]
    address: String,
    #[tabled(rename = "ORDINAL")]
    ordinal: String,
}

#[derive(tabled::Tabled)]
struct SectionRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "ADDRESS")]
    address: String,
    #[tabled(rename = "SIZE")]
    size: usize,
    #[tabled(rename = "OFFSET")]
    offset: String,
    #[tabled(rename = "ENTROPY")]
    entropy: String,
}

#[derive(tabled::Tabled)]
struct SegmentRow {
    #[tabled(rename = "ADDRESS")]
    address: String,
    #[tabled(rename = "SIZE")]
    size: usize,
    #[tabled(rename = "OFFSET")]
    offset: String,
    #[tabled(rename = "PERMS")]
    permissions: String,
}

#[derive(tabled::Tabled)]
struct FunctionRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "ADDRESS")]
    address: String,
    #[tabled(rename = "SIZE")]
    size: usize,
    #[tabled(rename = "COMPLEXITY")]
    complexity: String,
    #[tabled(rename = "TYPE")]
    symbol_type: String,
    #[tabled(rename = "BINDING")]
    binding: String,
}

#[derive(serde::Serialize)]
struct FunctionJsonRow {
    name: String,
    address: String,
    size: usize,
    symbol_type: String,
    binding: String,
}

#[derive(serde::Serialize)]
struct InstructionRow {
    address: u64,
    bytes: String,
    mnemonic: String,
    operands: String,
}

#[derive(serde::Serialize)]
struct PipelineStageResult {
    stage: String,
    status: String,
    detail: String,
    duration_ms: u64,
}

#[derive(serde::Serialize)]
struct PipelineReport {
    file: String,
    stages: Vec<PipelineStageResult>,
    summary: String,
}

#[derive(tabled::Tabled)]
struct PipelineStageRow {
    #[tabled(rename = "STAGE")]
    stage: String,
    #[tabled(rename = "STATUS")]
    status: String,
    #[tabled(rename = "DETAIL")]
    detail: String,
    #[tabled(rename = "DURATION")]
    duration: String,
}
