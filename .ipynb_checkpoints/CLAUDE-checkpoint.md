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
```

### Running Tests
```bash
# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p openre-core
cargo test -p openre-scan
cargo test -p openre-analysis

# Run integration tests
cargo test --test integration_tests

# Run with nextest (faster)
cargo nextest run --workspace
```

### Code Quality
```bash
# Format code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings
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

# AI features (requires configuration)
cargo run --bin openre-cli -- ai "analyze this function for vulnerabilities" --binary ./binary
cargo run --bin openre-cli -- exploit <finding-id>
cargo run --bin openre-cli -- remediate <finding-id>
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

3. **openre-scan** - Web vulnerability scanner with 18 security checks
   - Three profiles: Quick (essential), Standard (recommended), Full (comprehensive)
   - Output formats: table (default), JSON, SARIF
   - Checks include: HTTP headers, security headers, cookie security, TLS, etc.

4. **openre-analysis** - Binary analysis engine
   - Supports ELF, PE, Mach-O, WASM formats via goblin crate
   - Analysis pipeline: Format detection → Parser → Metadata/CFG/DFG extraction → Pattern matching → AI enhancement
   - Output: AnalysisSession with findings, control flow graphs, data flow analysis

5. **openre-ai** - AI/LLM integration layer
   - Multi-provider abstraction: Local (Ollama, llama.cpp, ONNX) and Cloud (OpenAI, Anthropic, vLLM)
   - Hybrid mode with local-first fallback
   - RAG pipeline for vulnerability research and PoC generation

6. **openre-intelligence** - Coordinator agent workflow
   - Finding → Research Agent → Exploit Agent → Remediation Agent → Verification Agent
   - Generates IntelligenceReport with PoC exploits and remediation guidance

7. **openre-cli** - Unified command-line interface
   - Main entry point: `openre`
   - Subcommands: scan, analyze, ai, exploit, remediate, config, queue, version
   - Features: shell completion, verbose logging, offline mode, AI provider selection

8. **openre-tui** - Full-screen terminal user interface
   - 10 functional panels: Projects, Jobs, Scans, Reverse Engineering, Findings, Workflows, AI, Plugins, Logs, Reports
   - Tab-based navigation, theme support, mouse support, real-time updates

### Key Development Practices

- **Async/Await**: Heavy use of Tokio for asynchronous operations
- **Error Handling**: `anyhow::Result` for application errors, `thiserror` for library errors
- **Logging**: `tracing` and `tracing-subscriber` with configurable log levels
- **Testing**: Unit tests with `#[cfg(test)]`, integration tests in `tests/` directory
- **Code Formatting**: `rustfmt` with standard configuration
- **Linting**: `clippy` with warnings treated as errors in CI
- **Dependency Management**: Workspace-wide dependencies in root Cargo.toml

### Common Development Tasks

1. **Adding a new web scan check**:
   - Implement in `crates/openre-scan/src/checks/`
   - Register in the check registry
   - Add to appropriate profiles (Quick/Standard/Full)
   - Write unit tests

2. **Adding a new binary analysis feature**:
   - Implement in `crates/openre-analysis/src/stages/` or `src/pass/` 
   - Add to the analysis pipeline
   - Update configuration options
   - Write unit tests

3. **Adding AI provider support**:
   - Implement in `crates/openre-ai/src/provider/`
   - Add to the AiProvider enum
   - Configure in the AI service layer
   - Write integration tests

4. **Creating a new CLI command**:
   - Add subcommand to `crates/openre-cli/src/commands/`
   - Implement execute function with Context parameter
   - Add to the Commands enum in main.rs
   - Write tests for the command

5. **Developing a TUI panel**:
   - Implement in `crates/openre-tui/src/panel/`
   - Register in the panel manager
   - Add keybindings and update logic
   - Write unit tests for panel behavior

## Getting Started

To begin working with this codebase:

1. **Clone the repository** (if not already done)
2. **Build the project**: `cargo build --workspace`
3. **Run tests**: `cargo test --workspace`
4. **Explore the CLI**: `cargo run --bin openre-cli -- --help`
5. **Review architecture**: See `ARCHITECTURE.md` for detailed component interactions
6. **Check development guide**: See `docs/DEVELOPMENT.md` for workflow details

The platform is designed to be extensible, with clear separation of concerns between scanning, analysis, AI, and coordination layers. Most development work will involve adding features to specific crates while maintaining compatibility with the core interfaces defined in openre-core.