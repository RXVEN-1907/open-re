//! Binary analysis commands

use crate::analysis_stubs::{
    BinaryAnalyzer, BinaryFormat, BinaryInfo, Disassembly, Function, PipelineResult, PipelineStage,
};
use crate::{print_output, CliError, Context, OutputFormat};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use std::path::PathBuf;
use tabled::{settings::Style, Table};

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
    /// Decompile function (stub)
    Decompile(DecompileArgs),
    /// Run full analysis pipeline
    Pipeline(PipelineArgs),
}

#[derive(Args, Debug)]
struct AnalyzeArgs {
    /// Binary file path
    file: PathBuf,

    /// Force binary format (auto-detected if not specified)
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct StringsArgs {
    /// Binary file path
    file: PathBuf,

    /// Minimum string length
    #[arg(short, long, default_value = "4")]
    min_length: usize,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct FunctionsArgs {
    /// Binary file path
    file: PathBuf,

    /// Filter by name pattern
    #[arg(short, long)]
    filter: Option<String>,

    /// Show function details (size, complexity, etc.)
    #[arg(long)]
    details: bool,

    /// Force binary format
    #[arg(long, value_enum)]
    binary_format: Option<BinaryFormatArg>,

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct DisasmArgs {
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
struct DecompileArgs {
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
struct PipelineArgs {
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

#[derive(Debug, Clone, ValueEnum)]
enum BinaryFormatArg {
    Elf,
    Pe,
    Macho,
    Wasm,
    Auto,
}

#[derive(Debug, Clone, ValueEnum)]
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

async fn run_info(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result = analyzer.info().await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_symbols(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result = analyzer.symbols().await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_imports(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result = analyzer.imports().await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_exports(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result = analyzer.exports().await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_sections(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result = analyzer.sections().await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_segments(ctx: Context, args: AnalyzeArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Analyzing {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result = analyzer.segments().await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_strings(ctx: Context, args: StringsArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Extracting strings from {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let strings: Vec<String> = analyzer.strings(args.min_length).await?;

    spinner.finish_and_clear();

    print_output(&strings, ctx.format, args.output.as_deref())?;
    Ok(())
}

async fn run_functions(ctx: Context, args: FunctionsArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Listing functions in {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let functions: Vec<crate::analysis_stubs::Function> =
        analyzer.functions(args.filter.as_deref(), args.details).await?;

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table && !functions.is_empty() {
        let mut table = Table::new(
            functions
                .iter()
                .map(|f| FunctionRow {
                    name: f.name.clone(),
                    address: format!("0x{:x}", f.address),
                    size: f.size as usize,
                    complexity: f
                        .complexity
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "-".to_string()),
                })
                .collect::<Vec<_>>(),
        );
        table.with(Style::modern());
        println!("{}", table);
    } else {
        print_output(&functions, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_disasm(ctx: Context, args: DisasmArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Disassembling {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let disasm = if let Some(func) = args.function {
        analyzer.disasm_function(&func, args.count, args.bytes).await?
    } else if let (Some(start), Some(end)) = (args.start, args.end) {
        let start_addr = u64::from_str_radix(&start.trim_start_matches("0x"), 16)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid start address: {}", e)))?;
        let end_addr = u64::from_str_radix(&end.trim_start_matches("0x"), 16)
            .map_err(|e| CliError::InvalidArgs(format!("Invalid end address: {}", e)))?;
        analyzer.disasm_range(start_addr, end_addr, args.bytes).await?
    } else {
        return Err(CliError::InvalidArgs("Specify --function or --start/--end".into()));
    };

    spinner.finish_and_clear();

    if ctx.format == OutputFormat::Table {
        for insn in &disasm.instructions {
            println!("{:>16}  {}", format!("0x{:x}", insn.address).dimmed(), insn.mnemonic);
            if args.bytes {
                if let Some(bytes) = &insn.bytes {
                    println!(
                        "{:>16}  {}",
                        "".dimmed(),
                        bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
                    );
                }
            }
        }
    } else {
        print_output(&disasm, ctx.format, args.output.as_deref())?;
    }
    Ok(())
}

async fn run_decompile(ctx: Context, args: DecompileArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let spinner = ctx.spinner(format!("Decompiling function in {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let decompiled = analyzer.decompile(&args.function).await?;

    spinner.finish_and_clear();

    println!("\n{}", decompiled);
    if let Some(path) = args.output {
        std::fs::write(&path, &decompiled)?;
        println!("\n{} Saved to {}", "✓".green().bold(), path.display());
    }
    Ok(())
}

async fn run_pipeline(ctx: Context, args: PipelineArgs) -> Result<(), CliError> {
    let format =
        args.binary_format.map(|f| f.into()).unwrap_or(crate::analysis_stubs::BinaryFormat::Auto);
    let stages: Vec<_> = args.stages.iter().cloned().map(|s| s.into()).collect();

    let spinner = ctx.spinner(format!("Running analysis pipeline on {}...", args.file.display()));

    let analyzer = BinaryAnalyzer::open(&args.file, format).await?;
    let result: crate::analysis_stubs::PipelineResult = analyzer.run_pipeline(stages).await?;

    spinner.finish_and_clear();

    print_output(&result, ctx.format, args.output.as_deref())?;
    Ok(())
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
}

impl From<BinaryFormatArg> for crate::analysis_stubs::BinaryFormat {
    fn from(f: BinaryFormatArg) -> Self {
        match f {
            BinaryFormatArg::Elf => crate::analysis_stubs::BinaryFormat::Elf,
            BinaryFormatArg::Pe => crate::analysis_stubs::BinaryFormat::Pe,
            BinaryFormatArg::Macho => crate::analysis_stubs::BinaryFormat::Macho,
            BinaryFormatArg::Wasm => crate::analysis_stubs::BinaryFormat::Wasm,
            BinaryFormatArg::Auto => crate::analysis_stubs::BinaryFormat::Auto,
        }
    }
}

impl From<PipelineStageArg> for crate::analysis_stubs::PipelineStage {
    fn from(s: PipelineStageArg) -> Self {
        match s {
            PipelineStageArg::All => crate::analysis_stubs::PipelineStage::All,
            PipelineStageArg::Identify => crate::analysis_stubs::PipelineStage::Identify,
            PipelineStageArg::Load => crate::analysis_stubs::PipelineStage::Load,
            PipelineStageArg::Disassemble => crate::analysis_stubs::PipelineStage::Disassemble,
            PipelineStageArg::Cfg => crate::analysis_stubs::PipelineStage::Cfg,
            PipelineStageArg::Dataflow => crate::analysis_stubs::PipelineStage::Dataflow,
            PipelineStageArg::Types => crate::analysis_stubs::PipelineStage::Types,
            PipelineStageArg::Decompile => crate::analysis_stubs::PipelineStage::Decompile,
            PipelineStageArg::AiEnrich => crate::analysis_stubs::PipelineStage::AiEnrich,
        }
    }
}
