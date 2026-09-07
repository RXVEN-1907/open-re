# open-re Platform Architecture

## Overview

```
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
```

**Open-source reverse engineering & offensive security platform**  
Modern security tools + LLMs for automated binary, web, API & app analysis  
Discover vulnerabilities • Generate PoC exploits • Actionable remediation

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              open-re Platform                               │
│  ┌──────────────┐  ┌────────────────┐  ┌───────────────┐  ┌──────────────┐  │
│  │CLI (openre)  │  │TUI (openre-tui)│  │  Library API  │  │  Plugins     │  │
│  └──────┬───────┘  └──────┬─────────┘  └──────┬────────┘  └──────┬───────┘  │
│         │                 │                 │                    │          │
│         └─────────────────┼─────────────────┼────────────────────┘          │
│                           ▼                 ▼                               │
│              ┌─────────────────────────────────────────┐                    │
│              │           openre-core                   │                    │
│              │  Types, Errors, Traits, Results, IDs   │                     │
│              └──────────────────┬──────────────────────┘                    │
│                                 │                                           │
│        ┌────────────────────────┼────────────────────────┐                  │
│        ▼                        ▼                        ▼                  │
│ ┌─────────────┐         ┌────────────────┐         ┌─────────────┐          │
│ │openre-scan  │         │openre-analysis │         │openre-ai    │          │
│ │ Web Scanner │         │ Binary Analyzer│         │ AI Engine   │          │
│ │ 18+ checks  │         │ ELF/PE/Mach-O/ │         │ Local/Cloud │          │
│ │ SARIF/JSON  │         │ WASM + CFG/DFG │         │ LLM + RAG   │          │
│ └──────┬──────┘         └──────┬─────────┘         └──────┬──────┘          │
│        │                       │                          │                 │
│        └───────────────────────┼──────────────────────────┘                 │
│                                ▼                                            │ 
│                 ┌─────────────────────────┐                                  │
│                 │  openre-intelligence    │                                  │
│                 │  Coordinator Agent      │                                  │
│                 │  Vuln Research → PoC    │                                  │
│                 │  Exploit Gen → Remediate│                                 │
│                 └─────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Cross-platform targets:**
- Linux: x86_64, aarch64, armv7
- macOS: x86_64, arm64
- Windows: x86_64
- FreeBSD: x86_64, aarch64

---

## Workspace Structure

### Crates (All Enabled in Workspace)

```toml
[workspace]
members = [
    "crates/openre-core",        # Core types, errors, traits
    "crates/openre-config",      # Configuration management
    "crates/openre-scan",        # Web vulnerability scanner
    "crates/openre-analysis",    # Binary analysis (ELF/PE/Mach-O/WASM)
    "crates/openre-ai",          # AI/LLM integration
    "crates/openre-intelligence", # Coordinator agent workflow
    "crates/openre-cli",         # Unified CLI
    "crates/openre-tui",         # Full-screen TUI
    "crates/openre-plugins",     # Plugin system
    "crates/openre-queue",       # Job queue
    "crates/openre-storage",     # SQLite/Redis storage
]
```

### Release Profile

```toml
[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"
strip = "debuginfo"
debug = false

[profile.release-lto]
inherits = "release"
lto = "fat"
```

---

## Component Details

### 1. openre-core
Core types shared across all crates:
- `Result` types: Finding, Evidence, RemediationGuidance, Severity, Confidence, Category
- `IDs`: ScanId, JobId, ProjectId, FindingId
- `Traits`: Scanner, Analyzer, AiProvider, Plugin
- `Error` types with `thiserror`
- Plugin system interfaces

### 2. openre-config
- Layered configuration: defaults → file → env → CLI
- TOML/JSON/YAML support via figment
- Per-crate config sections

### 3. openre-scan (Web Vulnerability Scanner)
**18 Security Checks across 3 Profiles:**

| Check | Quick | Standard | Full |
|-------|-------|----------|------|
| http-headers | ✅ | ✅ | ✅ |
| security-headers | ✅ | ✅ | ✅ |
| cookie-security | ✅ | ✅ | ✅ |
| tls-certificate | ✅ | ✅ | ✅ |
| information-disclosure | ✅ | ✅ | ✅ |
| technology-fingerprint | ✅ | ✅ | ✅ |
| content-security-policy | | ✅ | ✅ |
| cors-configuration | | ✅ | ✅ |
| robots-txt | | ✅ | ✅ |
| sitemap-xml | | ✅ | ✅ |
| directory-listing | | ✅ | ✅ |
| sensitive-files | | ✅ | ✅ |
| form-analysis | | ✅ | ✅ |
| link-analysis | | ✅ | ✅ |
| script-analysis | | ✅ | ✅ |
| meta-tags | | ✅ | ✅ |
| http-methods | | | ✅ |
| ssl-tls-configuration | | | ✅ |

**Output formats:** table (default), JSON, SARIF

### 4. openre-analysis (Binary Analysis)
**Using `goblin` crate for cross-format support:**

| Format | Platform | Arch Support |
|--------|----------|--------------|
| ELF | Linux, FreeBSD, Android | x86_64, aarch64, armv7, riscv64, mips, ppc64le, s390x |
| PE | Windows | x86_64, x86, aarch64, arm |
| Mach-O | macOS, iOS | x86_64, arm64, arm |
| WASM | Web, WASI | wasm32, wasm64 |

**Analysis Pipeline:**
```
Binary File → Format Detection → Parser →
  ├─ Metadata Extraction (headers, sections, symbols, imports/exports)
  ├─ Control Flow Graph (CFG) Recovery
  ├─ Data Flow Analysis (DFG)
  ├─ Function Boundary Detection
  ├─ String Extraction & Analysis
  ├─ Crypto Constant Detection
  ├─ Vulnerability Pattern Matching
  └─ AI-Enhanced Analysis (via openre-ai)
```

**Output:** `AnalysisSession` with findings, CFG, DFG, functions, strings, types

### 5. openre-ai (AI Integration)
**Multi-provider abstraction:**

```rust
enum AiProvider {
    Local(LocalRuntime),
    Cloud(CloudProvider),
    Hybrid { local, cloud },
}

enum LocalRuntime {
    Ollama { endpoint, model },
    LlamaCpp { model_path, n_ctx, n_gpu_layers },
    Onnx { model_path, execution_provider },  // CPU, CUDA, CoreML, DirectML
}

enum CloudProvider {
    OpenAI { api_key, model },
    Anthropic { api_key, model },
    Vllm { endpoint, model },
}
```

**RAG Pipeline for Vulnerability Research:**
1. **Index** - CVE database, exploit patterns, secure coding guides
2. **Retrieve** - Relevant context for discovered vulnerability
3. **Generate** - PoC exploit + remediation guidance
4. **Verify** - Static analysis of generated code

### 6. openre-intelligence (Coordinator Agent)
**Agent workflow:**
```
Finding → Coordinator →
  ├─ Research Agent: CVE lookup, exploit-db search, pattern matching
  ├─ Exploit Agent: PoC generation (Python/Rust/JS/Shell)
  ├─ Remediation Agent: Fix suggestions, code patches, config hardening
  └─ Verification Agent: Static analysis of PoC, exploit validation
```

**Output:** `IntelligenceReport` with:
- Vulnerability details + evidence
- Reproducible PoC exploit (with safety controls)
- Step-by-step remediation with code examples
- Risk score (CVSS + exploitability)

### 7. openre-cli (Unified CLI)
```
openre scan <url>              # Web vulnerability scanning
openre analyze <binary>        # Binary analysis (ELF/PE/Mach-O/WASM)
openre ai <prompt>             # AI-powered analysis
openre exploit <finding>       # Generate PoC exploit
openre remediate <finding>     # Get remediation guidance
openre config                  # Configuration management
openre tui                     # Launch TUI
openre version                 # Version info
```

### 8. openre-tui (Full-Screen TUI)
**10 Functional Panels:**

| Panel | Purpose |
|-------|---------|
| Projects | Manage analysis projects |
| Jobs | Queue management (scan, analyze, ai tasks) |
| Scans | Web scan results + progress |
| Reverse Engineering | Binary analysis (functions, CFG, strings, imports) |
| Findings | Unified findings view (web + binary + AI) |
| Workflows | Custom analysis pipelines |
| AI | Chat, model management, analysis history |
| Plugins | Load/manage community plugins |
| Logs | Real-time structured logs |
| Reports | Generate SARIF/HTML/PDF reports |

**Features:**
- Tab-based navigation (Tab/Shift+Tab)
- Theme support (Dark, Light, HighContrast, Solarized, Dracula, Nord, Gruvbox)
- Mouse support
- Real-time updates via event bus
- Configurable keybindings
- Help overlay (F1)

### 9. openre-plugins (Plugin System)
- Dynamic loading via `libloading`
- Capability-based permissions
- WASM plugin support (future)
- Plugin registry with versioning

### 10. openre-queue (Job Queue)
- Priority-based scheduling
- Persistent queue (SQLite/Redis)
- Worker pool with configurable concurrency
- Job dependencies and chaining

### 11. openre-storage (Persistence)
- SQLite for local development
- Redis for distributed deployments
- Schema migrations
- Encrypted sensitive data

---

## Cross-Platform Build & Distribution

### GitHub Actions Matrix

```yaml
strategy:
  matrix:
    include:
      - os: ubuntu-latest      target: x86_64-unknown-linux-gnu
      - os: ubuntu-latest      target: aarch64-unknown-linux-gnu
      - os: ubuntu-latest      target: armv7-unknown-linux-gnueabihf
      - os: macos-latest       target: x86_64-apple-darwin
      - os: macos-latest       target: aarch64-apple-darwin
      - os: windows-latest     target: x86_64-pc-windows-msvc
      - os: ubuntu-latest      target: x86_64-unknown-freebsd
      - os: ubuntu-latest      target: aarch64-unknown-freebsd
```

### Single Binary Output
- `openre` (~15-20MB stripped with all features)
- Statically linked where possible (musl on Linux)
- Code-signed on macOS/Windows

---

## Data Flow

### Web Scan Flow
```
Target URL → openre-scan → HTTP Client → 18 Checks → Findings
                                    ↓
                            openre-ai (enrichment)
                                    ↓
                            openre-intelligence (PoC + Remediation)
                                    ↓
                            Output: Table/JSON/SARIF
```

### Binary Analysis Flow
```
Binary File → openre-analysis → Format Detection (goblin)
                                    ↓
                            Parser → Metadata + CFG + DFG
                                    ↓
                            Pattern Matching → Findings
                                    ↓
                            openre-ai (vuln classification)
                                    ↓
                            openre-intelligence (PoC + Remediation)
                                    ↓
                            Output: JSON/SARIF + AnalysisSession
```

---

## Security Model

- **No telemetry** - Zero data collection
- **Offline-first** - All features work without network
- **Local AI preferred** - Cloud only when explicitly configured
- **Safety controls** - PoC exploits marked, require explicit confirmation
- **Authorization** - Only scan targets you own or have permission for

---

## Development Workflow

```bash
# Setup
rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu \
    x86_64-apple-darwin aarch64-apple-darwin \
    x86_64-pc-windows-msvc

# Build
cargo build --workspace --release

# Test
cargo test --workspace

# Lint
cargo fmt --check && cargo clippy --workspace

# Cross-compile (example)
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Future Extensibility

1. **WASM Plugins** - Sandbox plugins via Wasmtime
2. **Remote Scanning** - Distributed scan workers
3. **IDE Integration** - VS Code extension for inline findings
4. **CI/CD Templates** - GitHub Actions, GitLab CI, Jenkins
5. **Cloud Sync** - Optional project sync across machines
6. **Custom Check SDK** - Write checks in Rust, Python, JS