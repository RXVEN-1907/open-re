# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Commands

### Building the Project
```bash
# Build all crates in release mode
cargo build --workspace --release

# Build specific crates
cargo build -p openre-cli
cargo build -p openre-scan
cargo build -p openre-analysis

# Build for cross-compilation (example)
cargo build --release --target x86_64-unknown-linux-musl

# Build with specific features enabled/disabled
cargo build --workspace --release --no-default-features --features="scan ai"  # Only scan and AI
```

### Running Tests
```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p openre-core
cargo test -p openre-scan
cargo test -p openre-analysis
cargo test -p openre-ai

# Run integration tests
cargo test --test integration_tests

# Run a single test function
cargo test test_full_analysis_pipeline -- --exact

# Run tests with nextest (faster)
cargo nextest run --workspace

# Run tests for a specific binary
cargo test -p openre-cli --bin openre-cli
```

### Code Quality
```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Fix clippy warnings automatically
cargo clippy --workspace --all-targets --all-features -- -D warnings --fix
```

### Running the Application
```bash
# Run the CLI with help
cargo run --bin openre-cli -- --help

# Web scanning examples
cargo run --bin openre-cli -- scan https://example.com --profile quick
cargo run --bin openre-cli -- scan https://example.com --profile standard --format json --output results.json
cargo run --bin openre-cli -- scan https://example.com --profile full --format sarif --output audit.sarif

# Binary analysis examples
cargo run --bin openre-cli -- analyze ./binary --format json
cargo run --bin openre-cli -- analyze ./binary --format sarif --output analysis.sarif

# Launch TUI
cargo run --bin openre-tui

# AI features (requires configuration via environment variables)
# Set API keys as environment variables before running:
#   export OPENAI_API_KEY="your-key-here"
#   export ANTHROPIC_API_KEY="your-key-here"
#   export VLLM_BASE_URL="http://localhost:8000"
#   export VLLM_API_KEY="optional-key"

cargo run --bin openre-cli -- ai chat "Explain SQL injection vulnerabilities"
cargo run --bin openre-cli -- ai analyze --finding ./findings.json
cargo run --bin openre-cli -- ai explain --finding ./finding.json --detail deep --audience developer
cargo run --bin openre-cli -- ai remediate --finding ./finding.json --fix-type code --language python
cargo run --bin openre-cli -- ai test --provider openai --model gpt-4

# Exploit generation and remediation (requires analysis feature)
cargo run --bin openre-cli -- exploit <finding-id>
cargo run --bin openre-cli -- remediate <finding-id>
```

### Configuration
```bash
# Show current configuration
cargo run --bin openre-cli -- config show

# Set configuration values
cargo run --bin openre-cli -- config set ai.enabled true
cargo run --bin openre-cli -- config set ai.local_first false
cargo run --bin openre-cli -- config set scanner.default_profile full

# Reset to defaults
cargo run --bin openre-cli -- config reset
```

### Development Workflow
```bash
# Watch for changes and rebuild
cargo watch -x "build --bin openre-cli"

# Generate documentation
cargo doc --workspace --open

# Check for unused dependencies
cargo machete

# Audit dependencies
cargo audit

# Update dependencies
cargo update

# Run specific examples from documentation
# Web scan with SARIF output for CI/CD
cargo run --bin openre-cli -- scan https://target.com --profile full --format sarif --output openre-results.sarif

# Binary analysis with function decompilation
cargo run --bin openre-cli -- analyze ./suspicious_binary --format json
cargo run --bin openre-cli -- ai explain --finding ./buffer_overflow.json --detail deep
```

## Project Architecture

### High-Level Structure
The open-re platform follows a modular architecture with multiple interconnected components:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              open-re Platform                               │
│  ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ CLI (openre) │  │ TUI (openre-tui) │  │ Library API  │  │   Plugins    │ │
│  └──────┬───────┘  └────────┬─────────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                   │                   │                 │         │
│         └───────────────────┴───────────────────┴─────────────────┘         │
│                             ▼                   ▼                           │
│              ┌─────────────────────────────────────────┐                    │
│              │               openre-core               │                    │
│              │   Types, Errors, Traits, Results, IDs   │                    │
│              └──────────────────┬──────────────────────┘                    │
│                                 │                                           │
│        ┌────────────────────────┼────────────────────────┐                  │
│        ▼                        ▼                        ▼                  │
│   ┌─────────────┐        ┌──────────────────┐       ┌─────────────┐         │
│   │ openre-scan │        │ openre-analysis  │       │  openre-ai  │         │
│   │ Web Scanner │        │ Binary Analyzer  │       │  AI Engine  │         │
│   │ 18+ checks  │        │ ELF/PE/Mach-O/   │       │ Local/Cloud │         │
│   │ SARIF/JSON  │        │  WASM + CFG/DFG  │       │  LLM + RAG  │         │
│   └──────┬──────┘        └──────┬─────────┘       └──────┬──────┘         │
│          │                        │                        │                │
│          └────────────────────────┼────────────────────────┘                │
│                                   ▼                                         │
│                      ┌────────────────────────┐                             │
│                      │  openre-intelligence   │                             │
│                      │  Coordinator Agent     │                             │
│                      │  Vuln Research → PoC   │                             │
│                      │ Exploit Gen → Remediate│                             │
│                      └────────────────────────┘                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Core Crates

1. **openre-core** - Fundamental types, traits, and interfaces shared across all components
   - Finding, Evidence, RemediationGuidance structs
   - Scanner, Analyzer, AiProvider traits
   - Error types and ID generation

2. **openre-config** - Layered configuration system (defaults → file → env → CLI)
   - TOML/JSON/YAML support via figment
   - Per-crate configuration sections
   - Environment variable prefix: `OPENRE_`

3. **openre-scan** - Web vulnerability scanner with 18 security checks
   - Three profiles: Quick (essential), Standard (recommended), Full (comprehensive)
   - Output formats: table (default), JSON, SARIF
   - Checks include: HTTP headers, security headers, cookie security, TLS, etc.
   - Configuration via environment variables:
     - `OPENRE_SCAN_TIMEOUT_SECS` (default: 10)
     - `OPENRE_SCAN_MAX_REDIRECTS` (default: 10)
     - `OPENRE_SCAN_USER_AGENT` (default: "openre-scan/0.1.0")

4. **openre-analysis** - Binary analysis engine
   - Supports ELF, PE, Mach-O, WASM formats via goblin crate
   - Analysis pipeline: Format detection → Parser → Metadata/CFG/DFG extraction → Pattern matching → AI enhancement
   - Output: AnalysisSession with findings, control flow graphs, data flow analysis
   - Feature flags: Enable with `--features="analysis"` or use default "full" features

5. **openre-ai** - AI/LLM integration layer
   - Multi-provider abstraction: Local (Ollama, llama.cpp, ONNX) and Cloud (OpenAI, Anthropic, vLLM)
   - Hybrid mode with local-first fallback
   - RAG pipeline for vulnerability research and PoC generation
   - **Requires environment variables for remote providers**:
     - `OPENAI_API_KEY` - OpenAI API key
     - `ANTHROPIC_API_KEY` - Anthropic API key
     - `VLLM_BASE_URL` - Base URL for vLLM server
     - `VLLM_API_KEY` - Optional API key for vLLM
   - Local providers work out-of-the-box (Ollama, llama.cpp, ONNX)
   - Controlled by `ai.enabled` config (default: true)

6. **openre-intelligence** - Coordinator agent workflow
   - Finding → Research Agent → Exploit Agent → Remediation Agent → Verification Agent
   - Generates IntelligenceReport with PoC exploits and remediation guidance
   - Depends on openre-analysis and openre-ai features

7. **openre-cli** - Unified command-line interface
   - Main entry point: `openre`
   - Subcommands: scan, analyze, ai, exploit, remediate, config, queue, version
   - Features: shell completion, verbose logging, offline mode, AI provider selection
   - Feature flags control optional functionality:
     - `analysis`: Binary analysis features
     - `scan`: Web scanning features
     - `ai`: AI-powered features
     - `sarif`: SARIF output support
     - `queue`: Job queue system
     - Default build includes all features (`full` feature set)

8. **openre-tui** - Full-screen terminal user interface
   - 10 functional panels: Projects, Jobs, Scans, Reverse Engineering, Findings, Workflows, AI, Plugins, Logs, Reports
   - Tab-based navigation, theme support, mouse support, real-time updates
   - Requires `tui` feature (included in default)

### Key Development Practices

- **Async/Await**: Heavy use of Tokio for asynchronous operations
- **Error Handling**: `anyhow::Result` for application errors, `thiserror` for library errors
- **Logging**: `tracing` and `tracing-subscriber` with configurable log levels
- **Environment Configuration**: 
  - Settings hierarchy: defaults → config files → environment variables → CLI args
  - Environment variables use `OPENRE_` prefix with double underscores for nesting
    - Example: `OPENRE_AI_ENABLED=false`
    - Example: `OPENRE_SCAN_TIMEOUT_SECS=30`
- **Testing**: Unit tests with `#[cfg(test)]`, integration tests in `tests/` directory
- **Code Formatting**: `rustfmt` with standard configuration
- **Linting**: `clippy` with warnings treated as errors in CI
- **Dependency Management**: Workspace-wide dependencies in root Cargo.toml
- **Feature Flags**: Optional functionality controlled via Cargo features

### Common Development Tasks

1. **Adding a new web scan check**:
   - Implement in `crates/openre-scan/src/checks/`
   - Register in the check registry (`ScannerProfilesConfig`)
   - Add to appropriate profiles (Quick/Standard/Full)
   - Write unit tests in `crates/openre-scan/src/checks/`

2. **Adding a new binary analysis feature**:
   - Implement in `crates/openre-analysis/src/stages/` or `src/pass/`
   - Add to the analysis pipeline (`PipelineStage` enum)
   - Update configuration options in `ScannerConfig`
   - Write unit tests

3. **Adding AI provider support**:
   - Implement in `crates/openre-ai/src/provider/` (for new providers)
   - Add to the `ProviderId` enum and `ModelProvider` trait
   - Configure in `AiConfig` and register in `register_providers` function
   - Add environment variable handling in `service.rs`
   - Write integration tests

4. **Creating a new CLI command**:
   - Add subcommand to `crates/openre-cli/src/commands/`
   - Implement execute function with `Context` parameter
   - Add to the `Commands` enum in `main.rs`
   - Ensure proper feature gating if the command requires optional features
   - Write tests for the command

5. **Developing a TUI panel**:
   - Implement in `crates/openre-tui/src/panel/`
   - Register in the panel manager (`TuiPanelsConfig`)
   - Add keybindings in `TuiKeybindingsConfig`
   - Add update logic for real-time data
   - Write unit tests for panel behavior

6. **Enabling/disabling features**:
   - Build with specific features: `cargo build --features="scan ai"`
   - Disable default features: `cargo build --no-default-features --features="scan"`
   - Check enabled features: `cargo config get features`

### Environment Variables for AI Features

To use remote AI providers, set these environment variables:

```bash
# OpenAI
export OPENAI_API_KEY="sk-your-openai-key-here"

# Anthropic
export ANTHROPIC_API_KEY="sk-ant-your-anthropic-key-here"

# vLLM
export VLLM_BASE_URL="http://localhost:8000/v1"
export VLLM_API_KEY="optional-vllm-key"  # Only if your vLLM server requires auth
```

Local AI providers (Ollama, llama.cpp, ONNX) work without additional configuration but require the respective software to be installed and running.

### Gotchas and Non-Obvious Patterns

1. **Feature Flag Dependencies**:
   - The `exploit` and `remediate` commands require the `analysis` feature
   - The `ai` command requires the `ai` feature
   - Building with `--no-default-features` requires explicitly enabling needed features

2. **Configuration Precedence**:
   - Command-line arguments override environment variables
   - Environment variables override config files
   - Config files override default values
   - Use `openre config show` to view effective configuration

3. **AI Provider Selection**:
   - When multiple providers are available, the router selects based on:
     1. Privacy settings (local-first preference)
     2. Provider capabilities (tools, vision, etc.)
     3. Model suitability for the task
     4. Availability and health status
   - Override selection with `--provider` and `--model` flags

4. **Testing Considerations**:
   - Integration tests may require external services (PostgreSQL, Redis)
   - Use `tempdir()` and in-memory databases for isolated unit tests
   - AI service tests should mock network calls to avoid real API requests
   - Run `cargo test --test integration_tests` for full integration suite

5. **Binary Analysis Limitations**:
   - Some advanced features (decompilation) require the `analysis` feature
   - Large binaries may consume significant memory during analysis
   - WASM analysis requires the `wasmparser` and `wasm-encoder` crates

6. **TUI Usage**:
   - The TUI requires a terminal that supports ANSI colors
   - Mouse support works in most modern terminals (iTerm2, GNOME Terminal, Windows Terminal)
   - Press `F1` or `?` for help within the TUI
   - Use `Tab`/`Shift+Tab` to navigate between panels

7. **Cross-Compilation**:
   - For musl targets: `rustup target add x86_64-unknown-linux-musl`
   - Static linking may require additional dependencies on some systems
   - macOS and Windows cross-compilation requires appropriate SDKs

## Getting Started

To begin working with this codebase:

1. **Clone the repository** (if not already done)
2. **Build the project**: `cargo build --workspace`
3. **Run tests**: `cargo test --workspace`
4. **Explore the CLI**: `cargo run --bin openre-cli -- --help`
5. **Configure AI providers** (optional): Set `OPENAI_API_KEY` or similar env vars
6. **Review architecture**: See `ARCHITECTURE.md` for detailed component interactions
7. **Check development guide**: See `docs/DEVELOPMENT.md` for workflow details

The platform is designed to be extensible, with clear separation of concerns between scanning, analysis, AI, and coordination layers. Most development work will involve adding features to specific crates while maintaining compatibility with the core interfaces defined in openre-core.