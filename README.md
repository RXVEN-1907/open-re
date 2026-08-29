# open-re

```text

 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
```
**Open-source Reverse Engineering & Offensive Security Platform**

Modern security tools + LLMs for automated binary, web, API & app analysis  
Discover vulnerabilities • Generate PoC exploits • Actionable remediation

[![CI](https://github.com/RXVEN-1907/open-re/workflows/CI/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/ci.yml)
[![Release](https://github.com/RXVEN-1907/open-re/workflows/Release/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/release.yml)
[![Security Audit](https://github.com/RXVEN-1907/open-re/workflows/Security%20Audit/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78+-orange.svg)](https://www.rust-lang.org)
[![Version](https://img.shields.io/badge/version-v0.1.0-blue.svg)](https://github.com/RXVEN-1907/open-re/releases)
[![Docs](https://img.shields.io/badge/docs-latest-green.svg)](https://rxven-1907.github.io/open-re)

**open-re** is a comprehensive reverse engineering and offensive security platform combining modern security tools and LLMs for automated analysis of binaries, websites, APIs, and applications — discovering vulnerabilities, generating reproducible PoC exploits, and providing actionable remediation guidance.

## 🎯 Platform Overview

| Component | Status | Description |
|-----------|--------|-------------|
| **openre-scan** | ✅ Stable | Lightweight standalone security scanner for web apps & APIs |
| **openre-core** | ✅ Stable | Core types, finding model, risk engine, ID system |
| **openre-intelligence** | 🚧 Beta | CVE matching, dependency analysis, finding correlation |
| **openre-security-ai** | 🚧 Beta | AI-enhanced analysis (LLM-powered vulnerability analysis) |
| **openre-plugins** | 🚧 Beta | WASM plugin system for extensibility |
| **openre-api** | 🚧 Alpha | REST/gRPC API server for platform integration |
| **openre-queue** | ✅ Stable | Distributed job queue with Redis backend |
| **openre-storage** | ✅ Stable | Object storage & persistence layer (SQLite) |
| **openre-telemetry** | ✅ Stable | Metrics, tracing, logging, audit logging |
| **openre-cli** | 🚧 Beta | Unified CLI for platform operations (requires API server) |
| **openre-analysis** | 🚧 Beta | Binary analysis pipeline (9-stage, incremental, ELF/PE/MachO/WASM) |
| **Frontend** | 🚧 Alpha | React 18 + TypeScript + Tailwind web UI |

> **Note**: Components marked 🚧 are under active development and may have incomplete features. ✅ Stable components are production-ready.

---

## ✨ Features

### 🔧 Architecture & Infrastructure

#### Plugin System (openre-plugins)

- **WASM-based Plugin Runtime** — Sandboxed execution with capability-based security
- **Capability System** — Fine-grained permissions (ReadBinary, WriteAnnotations, QueryDatabase, CallAI, NetworkAccess, etc.)
- **Plugin Registry** — Local and remote registry support with versioning
- **Plugin SDK** — Rust SDK with macros for rapid plugin development
- **Security Plugins** — Built-in plugins for access control, rate limiting, auth discovery, CORS, CSP, cookie security, path traversal, SQLi, XSS, GraphQL, REST API, session management, sensitive info, file upload
- **Lifecycle Management** — Install, enable/disable, configure, update, uninstall
- **Sandboxing** — Fuel metering, memory limits, syscall filtering

#### Analysis Pipeline (openre-analysis)

- **Multi-format Binary Support** — ELF, PE, MachO, WASM parsing and analysis
- **Incremental Analysis** — Change detection with fingerprint-based caching
- **Pipeline Stages** — Identification → Loading → Disassembly → Control Flow → Data Flow → Type Recovery → Decompilation → AI Enrichment → Finalization
- **Progress Tracking** — Real-time progress with stage-level granularity
- **Metrics Collection** — Per-stage timing, finding counts, resource usage
- **Static Analysis** — Symbol extraction, import/export analysis, section analysis, string extraction
- **Orchestrator** — Coordinates parallel stage execution with dependency management

#### AI/LLM Integration (openre-security-ai)

- **Multi-provider Support** — Ollama, OpenAI, Anthropic, ONNX Runtime, llama.cpp
- **Security Analyst** — Automated vulnerability analysis with context-aware prompts
- **Finding Provider** — Integrates with scan storage for contextual analysis
- **Prompt Compiler** — Template-based prompt engineering with variable injection
- **Safety Controls** — Output validation, PII filtering, confidence scoring
- **Remediation Generation** — Actionable fix suggestions with effort estimates
- **Correlation & Prioritization** — Cross-finding analysis and risk-based ordering
- **Context Management** — Conversation history with token budget management

#### Database & Storage Layer (openre-storage)

- **Object Storage Abstraction** — S3-compatible, local filesystem, in-memory backends
- **SQLite Persistence** — Embedded database with migrations (sqlx)
- **Project Management** — CRUD for projects, scans, findings, reports
- **File Storage** — Binary blob storage with SHA256 deduplication
- **Query Layer** — Flexible filtering, sorting, pagination for findings
- **Export Support** — JSON, SARIF, Markdown, HTML report generation

---

### 🚀 Features

#### Security Scanning (openre-scan)

- **Zero Dependencies** — Single ~7 MB binary, no runtime requirements
- **Three Scan Profiles** — Quick (6 checks), Standard (15 checks), Full (18 checks)
- **Multiple Output Formats** — Table (human-readable), JSON (machine-readable), SARIF 2.1.0 (CI/CD integration)
- **18+ Security Checks**:
  - **HTTP Headers** — Server disclosure, powered-by, custom headers
  - **Security Headers** — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP
  - **Cookie Security** — Secure, HttpOnly, SameSite flags
  - **TLS/SSL** — Certificate validation, chain verification, expiry, SANs
  - **Information Disclosure** — Debug headers, stack traces, version info
  - **Technology Fingerprinting** — Framework, CMS, server, library detection
  - **robots.txt / sitemap.xml** — Enumeration and analysis
  - **Directory Listing** — Index exposure detection
  - **Sensitive Files** — 20+ common paths (.git, .env, backup, config)
  - **Form Analysis** — GET passwords, autocomplete, CSRF tokens
  - **Link Analysis** — Mixed content, mailto, external redirects
  - **Script Analysis** — Inline scripts, external resources, integrity
  - **Meta Tags** — Security-relevant metadata
  - **Content Security Policy** — Directive analysis, nonce/hash usage
  - **CORS Configuration** — Origin reflection, credentials, wildcard
  - **HTTP Methods** — TRACE, PUT, DELETE, PATCH, OPTIONS
  - **SSL/TLS Deep Dive** — Cipher suites, protocol versions, renegotiation
- **Evidence-Based Findings** — Each finding includes supporting evidence (HTTP headers, response snippets, locations)
- **Risk Scoring** — Severity (Critical/High/Medium/Low/Info) + Confidence (Very High/High/Medium/Low)
- **Remediation Guidance** — Actionable steps with effort/priority estimates
- **Filtering** — `--checks` and `--exclude` for selective scanning
- **Custom Headers** — `--header` for authentication and custom requests
- **File Output** — `--output` to save results
- **Cross-Platform** — Linux, macOS, Windows
- **Privacy-Focused** — No telemetry, no data collection

#### TUI Improvements (openre-scan TUI)

- **Interactive Dashboard** — Real-time scan progress with live findings table
- **Keyboard Navigation** — Vim-style keybindings (j/k, g/G, /, ?)
- **Detail Panels** — Expandable finding details with evidence viewer
- **Filter & Search** — Real-time filtering by severity, category, check
- **Export from TUI** — Save results without leaving the interface
- **Theme Support** — Dark/light themes with custom color schemes
- **Multi-tab Layout** — Scans, Findings, Settings, Help tabs

#### API Endpoints (openre-api)

- **REST API** — OpenAPI 3.1 documented endpoints
- **gRPC API** — Protobuf definitions with tonic
- **WebSocket Support** — Real-time scan progress and notifications
- **Authentication** — JWT-based with API key support
- **Rate Limiting** — Token bucket per client
- **Versioning** — URL-based (v1, v2) with deprecation policy
- **Endpoints**:
  - `/api/v1/projects` — Project CRUD
  - `/api/v1/scans` — Scan management and results
  - `/api/v1/findings` — Finding queries with filtering
  - `/api/v1/ai/*` — Security analyst endpoints
  - `/api/v1/plugins` — Plugin registry and management
  - `/api/v1/exports` — Report generation and download
  - `/api/v1/auth` — Authentication and user management

#### Frontend/UI Features (React + TypeScript + Tailwind)

- **Dashboard** — Project overview, recent scans, severity trends
- **Scan Management** — Create, monitor, compare scans
- **Finding Browser** — Filterable, sortable finding table with detail drawer
- **AI Analyst Chat** — Conversational vulnerability analysis
- **Plugin Manager** — Browse, install, configure plugins
- **Settings** — User preferences, API keys, theme, notifications
- **Real-time Updates** — WebSocket-powered live data
- **Responsive Design** — Mobile-friendly with Tailwind
- **Accessibility** — WCAG 2.1 AA compliant

---

### ⚙️ CI/CD & DevOps

#### GitHub Actions Workflows

- **CI Pipeline** — Format, Clippy, Build, Test (core crates)
- **Security Audit** — cargo-audit, cargo-deny, dependency review
- **Release Automation** — Multi-platform builds (Linux/macOS/Windows), checksums, GitHub Releases
- **Docker Build** — Multi-arch images (API, Worker, Frontend) pushed to GHCR
- **Documentation** — markdownlint, cspell, link checking
- **Coverage** — cargo-llvm-cov with Codecov upload
- **Dependency Review** — PR dependency scanning with configurable policies

#### Release Management

- **Semantic Versioning** — Automated from conventional commits
- **Changelog Generation** — Auto-generated from commit history
- **Multi-platform Binaries** — x86_64 Linux/macOS/Windows + ARM64
- **Container Images** — GHCR with latest and versioned tags
- **SBOM Generation** — Software Bill of Materials (SPDX/CycloneDX)
- **Provenance** — SLSA Level 3 build attestations

#### Testing Infrastructure

- **Unit Tests** — Comprehensive coverage for core crates
- **Integration Tests** — End-to-end scan pipeline, API, storage
- **Property-based Tests** — Proptest for finding correlation, risk scoring
- **Benchmark Tests** — Criterion benchmarks for hot paths
- **Contract Tests** — API schema validation
- **E2E Tests** — Playwright for frontend, CLI scenario tests

#### Security Scanning

- **SAST** — cargo-audit, clippy, cargo-deny
- **Dependency Scanning** — GitHub Dependabot + custom policies
- **Container Scanning** — Trivy for Docker images
- **Secret Scanning** — GitHub secret scanning + pre-commit hooks
- **License Compliance** — cargo-deny license checking

---

### 🛠️ Developer Experience

#### CLI Improvements (openre-cli)

- **Unified Command Structure** — `openre <command> <subcommand>` for all operations
- **Rich Output** — Colored tables, JSON, YAML, SARIF with `--format`
- **Shell Completions** — Bash, Zsh, Fish, PowerShell, Elvish
- **Config File** — TOML configuration with profiles
- **Plugin Commands** — `openre plugin install/list/enable/disable/configure`
- **AI Commands** — `openre ai analyze/explain/remediate/correlate`
- **Project Commands** — `openre project create/list/show/delete`
- **Scan Commands** — `openre scan create/list/show/delete/run`
- **Context Management** — Multiple profiles with `openre config use`

#### Documentation

- **Architecture Docs** — 11 detailed architecture documents
- **API Reference** — OpenAPI specs with scalar/Redoc UI
- **Plugin Development Guide** — Tutorial + API reference
- **Security Plugin Guide** — Building security analysis plugins
- **Installation Guide** — Binary, Docker, source, package managers
- **Contributing Guide** — Code style, PR process, testing
- **Migration Guides** — Version upgrade instructions

#### Tooling

- **VS Code Config** — rust-analyzer, tasks, launch configs (planned)
- **Dev Container** — Full development environment with all tools (planned)
- **Pre-commit Hooks** — fmt, clippy, markdownlint, cspell (planned)
- **Makefile/Justfile** — Common development commands (planned)
- **Release Script** — Automated version bump, changelog, tag, push (planned)

> **Note**: Most tooling is planned for v0.2.0. Currently run checks manually: `cargo fmt --check && cargo clippy --workspace`.

---

## 📦 Quick Start

### Build from Source (Current Method)

```bash
# Clone repository
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re

# Build standalone scanner (works offline, no API server needed)
cargo build --release -p openre-scan
./target/release/openre-scan --help

# Build unified CLI (requires API server for most commands)
cargo build --release -p openre-cli
./target/release/openre --help
```

### Docker

```bash
# Build and run standalone scanner
docker build -t openre-scan -f docker/Dockerfile.scan .
docker run --rm openre-scan scan https://example.com --profile standard

# Full platform (API + Worker + Frontend) - requires docker-compose.yml
docker compose -f docker-compose.yml up -d
```

> **Note**: Pre-built binaries and Docker images are not yet published to GitHub Releases or GHCR. Build from source for now.

### Development Environment

```bash
# With Dev Container (VS Code / GitHub Codespaces)
# Or locally:
./scripts/setup-dev.sh

# Run tests
cargo test --workspace

# Run scanner
cargo run --package openre-scan -- scan https://example.com --profile quick
```

---

## 📖 Usage

### Standalone Scanner (openre-scan) — Works Offline

The `openre-scan` binary is a **standalone tool** that works completely offline — no API server, database, or network dependencies required (except the target being scanned).

```bash
# Quick scan (6 essential checks, ~2-3s)
openre-scan scan https://example.com --profile quick

# Standard scan (15 checks, ~10-15s) — Recommended for most use cases
openre-scan scan https://example.com --profile standard

# Full scan (18 checks, ~30-60s) — Comprehensive audit
openre-scan scan https://example.com --profile full

# JSON output for automation
openre-scan scan https://example.com --format json

# SARIF output for CI/CD (GitHub Code Scanning, Azure DevOps, etc.)
openre-scan scan https://example.com --format sarif --output results.sarif

# Save results to file
openre-scan scan https://example.com --output results.json

# Custom timeout and headers
openre-scan scan https://example.com --timeout 30 --header "Authorization=Bearer token"

# Filter specific checks (comma-separated)
openre-scan scan https://example.com --checks security-headers,csp,cors

# Exclude checks (comma-separated)
openre-scan scan https://example.com --exclude tech-fingerprint,robots-txt

# Follow redirects
openre-scan scan https://example.com --follow-redirects

# Disable progress bar (useful for CI/CD)
openre-scan scan https://example.com --no-progress

# Show version
openre-scan version

# Interactive TUI (experimental, requires --features tui)
openre-scan tui
```

### Unified CLI (openre) — Requires API Server

The `openre` CLI communicates with the **openre-api** server. Most commands require a running API server (start with `openre server start` or `docker compose up`).

```bash
# Start API server (in background)
openre server start &

# Project management
openre project create --name my-project --description "Security assessment"
openre project list
openre project get --id <project-id>

# Scan management
openre scan create --project my-project --target https://example.com --profile standard --run
openre scan run --id <scan-id>
openre scan list --project my-project
openre scan show --id <scan-id>
openre scan status --id <scan-id>  # Monitor progress
openre scan export --id <scan-id> --format sarif --output results.sarif

# Findings
openre finding list --project my-project --severity high,critical
openre finding show --id <finding-id> --evidence --remediation
openre finding stats --project my-project
openre finding verify --id <finding-id> --status true

# AI Analysis (requires AI provider configured in server)
openre ai analyze --finding-id <finding-id>
openre ai explain --finding-id <finding-id>
openre ai remediate --finding-id <finding-id>
openre ai correlate --project my-project

# AI Security Analyst (enhanced AI features)
openre analyst explain --scan-id <scan-id> --finding-id <finding-id>
openre analyst remediate --scan-id <scan-id> --finding-id <finding-id>
openre analyst correlate --scan-id <scan-id>
openre analyst prioritize --scan-id <scan-id>
openre analyst summarize --scan-id <scan-id> --audience developer

# Plugin management
openre plugin list
openre plugin install --source registry:plugin-name
openre plugin enable --id <plugin-id>
openre plugin configure --id <plugin-id> --config '{"key": "value"}'

# Reports
openre report generate --scan <scan-id> --format html --output report.html
openre report generate --scan <scan-id> --format sarif --output results.sarif
openre report list --project my-project
openre report download --id <report-id> --output report.html

# Configuration
openre config set server_url http://localhost:8080
openre config set api_key your-api-key
openre config get server_url
```

> **Key Difference**: `openre-scan` runs standalone and immediately scans targets. `openre` is a client for the platform API server — it manages projects, stores scans/findings, and enables AI analysis, but requires the server to be running.

### Scan Profiles

| Profile | Checks | Duration | Use Case |
|---------|--------|----------|----------|
| Quick | 6 | ~2-3s | Rapid assessment, CI/CD gates |
| Standard | 15 | ~10-15s | General purpose scanning |
| Full | 18 | ~30-60s | Comprehensive audit |

### Checks Included

**Quick Profile (6 checks):**

- `http-headers` — Server/X-Powered-By disclosure
- `security-headers` — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP (8 headers)
- `cookie-security` — Secure, HttpOnly, SameSite flags
- `tls-certificate` — HTTPS enforcement, certificate validation
- `info-disclosure` — Debug headers, server version disclosure
- `tech-fingerprint` — Framework/CMS/server/library detection

**Standard Profile (15 checks — includes Quick):**

- `csp` — Content Security Policy directive analysis (unsafe-inline, unsafe-eval, wildcards)
- `cors` — CORS misconfiguration (wildcard origin, credentials with wildcard)
- `robots-txt` — robots.txt enumeration and disallowed paths
- `sitemap` — sitemap.xml discovery
- `dir-listing` — Directory listing detection
- `sensitive-files` — 20+ common sensitive paths (.git, .env, config files, etc.)
- `forms` — GET password fields, autocomplete, missing CSRF tokens
- `links` — Mixed content (HTTP on HTTPS), mailto: links
- `scripts` — Inline scripts, external HTTP scripts on HTTPS page

**Full Profile (18 checks — includes Standard):**

- `http-methods` — TRACE, TRACK, PUT, DELETE, PATCH, OPTIONS
- `ssl-config` — SSL/TLS configuration placeholder (use testssl.sh/sslyze for deep analysis)
- `meta-tags` — Generator meta tag, meta refresh redirects

---

## 📊 Output Formats

### Table (Default)

Human-readable colorized table with severity indicators.

### JSON

Structured output for programmatic processing:

```json
{
  "scan_id": "uuid",
  "target": "https://example.com",
  "timestamp": "2024-01-01T00:00:00Z",
  "findings": [...],
  "findings_count": 10
}
```

### SARIF

Static Analysis Results Interchange Format 2.1.0 for CI/CD integration (GitHub Code Scanning, Azure DevOps, etc.).

### HTML Reports

Rich interactive reports with charts, finding details, and remediation guidance.

---

## 🔌 Plugin System

The WASM-based plugin system is **under active development** (🚧 Beta). The plugin runtime, capability system, and registry infrastructure are implemented, but built-in security plugins are not yet fully available.

### Plugin Infrastructure (Implemented)

- **WASM Runtime** — Sandboxed execution with fuel metering and memory limits
- **Capability System** — Fine-grained permissions (ReadBinary, WriteAnnotations, QueryDatabase, CallAI, NetworkAccess, etc.)
- **Plugin Registry** — Local registry with versioning support
- **Plugin SDK** — Rust SDK with macros for rapid plugin development
- **Lifecycle Management** — Install, enable/disable, configure, update, uninstall via CLI

### Built-in Security Plugins (Planned)

| Plugin | Category | Status |
|--------|----------|--------|
| access-control | AuthZ | 🚧 Planned |
| api-rate-limiting | DoS | 🚧 Planned |
| auth-discovery | AuthN | 🚧 Planned |
| cookie-security | Session | 🚧 Planned |
| cors-analysis | Config | 🚧 Planned |
| csp-analysis | Config | 🚧 Planned |
| file-upload | Input | 🚧 Planned |
| graphql-analysis | API | 🚧 Planned |
| information-disclosure | Info | 🚧 Planned |
| path-traversal | Input | 🚧 Planned |
| rate-limiting | DoS | 🚧 Planned |
| rest-api-analysis | API | 🚧 Planned |
| security-headers | Config | 🚧 Planned |
| sensitive-info | Info | 🚧 Planned |
| session-management | AuthN | 🚧 Planned |
| sql-injection | Input | 🚧 Planned |
| xss-analysis | Input | 🚧 Planned |

> **Note**: Security checks are currently implemented directly in `openre-scan` (see [Checks Included](#checks-included)). The plugin system will enable external developers to extend functionality.

### Developing Plugins

```bash
# Create new plugin project
cargo new --lib my-plugin
cd my-plugin

# Add dependencies (see openre-plugins crate for SDK)
# See docs/architecture/05-plugin-architecture.md

# Build WASM
cargo build --target wasm32-wasip1 --release

# Install (requires running API server)
openre plugin install --source local:./target/wasm32-wasip1/release/my_plugin.wasm
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        open-re Platform                         │
├─────────────────────────────────────────────────────────────────┤
│        ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│        │  Frontend   │  │   openre-   │  │  openre-    │        │
│        │  (React)    │◄─│    api      │◄─│   cli       │        │
│        └─────────────┘  └──────┬──────┘  └─────────────┘        │
│                                │                                │
│                ┌───────────────┼───────────────┐                │
│                ▼               ▼               ▼                │
│       ┌─────────────┐  ┌─────────────┐  ┌───────────────┐       │
│       │ openre-scan │  │openre-queue │  │ openre-storage│       │
│       └─────────────┘  └──────┬──────┘  └───────────────┘       │
│              │                │                                 │
│              ▼                ▼                                 │
│       ┌─────────────────────────────────────┐                   │
│       │      openre-core (shared types)     │                   │
│       ├─────────────────────────────────────┤                   │
│       │  Finding Model • Risk Engine • IDs  │                   │
│       └─────────────────────────────────────┘                   │
│              │                │                                 │
│              ▼                ▼                                 │
│       ┌─────────────┐  ┌─────────────┐  ┌──────────────┐        │
│       │openre-intel │  │openre-sec-ai│  │openre-plugins│        │
│       │ligence      │  │             │  │              │        │
│       └─────────────┘  └─────────────┘  └──────────────┘        │
│              │                │                │                │
│              └────────────────┴────────────────┘                │
│                               │                                 │
│              ┌────────────────┴────────────────┐                │
│              ▼                                 ▼                │
│       ┌─────────────┐                 ┌─────────────┐           │
│       │openre-analy-│                 │  openre-    │           │
│       │sis          │                 │  telemetry  │           │
│       └─────────────┘                 └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### Core Crates

| Crate | Status | Purpose | Key Types |
|-------|--------|---------|-----------|
| `openre-core` | ✅ Stable | Shared foundation | `Finding`, `RiskScore`, `StageId`, `PluginId`, `Capability` |
| `openre-config` | ✅ Stable | Configuration management | Layered config (file, env, CLI) |
| `openre-telemetry` | ✅ Stable | Observability | Metrics, Tracing, Logging, Audit |
| `openre-storage` | ✅ Stable | Persistence (SQLite) | `ScanStorage`, `ObjectStore`, Migrations |
| `openre-queue` | ✅ Stable | Job processing | `QueueManager`, `WorkerPool`, `Scheduler` |
| `openre-plugins` | 🚧 Beta | Extensibility | `PluginRegistry`, `Runtime`, `CapabilityEnforcer` |
| `openre-intelligence` | 🚧 Beta | Analysis enrichment | CVE matching, Correlation, Dependency analysis |
| `openre-security-ai` | 🚧 Beta | AI integration | `SecurityAnalyst`, `PromptCompiler`, Providers |
| `openre-analysis` | 🚧 Beta | Binary analysis | 9-stage pipeline, incremental analysis, ELF/PE/MachO/WASM parsers |
| `openre-api` | 🚧 Alpha | Platform API | REST, gRPC, WebSocket, Auth |
| `openre-cli` | 🚧 Beta | Unified CLI | All user-facing commands (requires API) |
| `openre-scan` | ✅ Stable | Standalone scanner | 18 security checks, 3 profiles |
| `openre-recon` | 🚧 Alpha | Reconnaissance | Subdomain enum, port scan, tech detect |
| `openre-scanner` | 🚧 Alpha | Scanner orchestration | Multi-target scanning coordination |
| `sentinel` | 🚧 Prototype | Security monitoring | Demo binary (hardcoded output) |

---

## ⚙️ Configuration

### Scanner Config (openre-scan)

Works without configuration. All options via command-line flags (see `openre-scan --help` or `openre-scan scan --help`).

No configuration file support yet (planned).

### Platform Config (openre-api, openre-cli)

The `openre` CLI stores its configuration in `~/.config/openre/config.toml`:

```toml
# ~/.config/openre/config.toml
server_url = "http://localhost:8080"
api_key = "your-api-key"  # or use OPENRE_API_KEY env var
output_format = "table"
verbose = false

# Profiles for different environments
[profiles.production]
server_url = "https://api.openre.example.com"
api_key = "prod-key"

[profiles.staging]
server_url = "https://staging-api.openre.example.com"
api_key = "staging-key"
```

The API server (`openre-api`) uses environment variables:

```bash
# Required (server will not start without these)
DATABASE_URL=sqlite://data/openre.db
REDIS_URL=redis://localhost:6379
JWT_SECRET=your-secret-key-min-32-chars

# Optional (defaults shown)
HOST=0.0.0.0
PORT=8080
WORKER_COUNT=4
AI_PROVIDER=ollama
AI_MODEL=codellama:13b
AI_BASE_URL=http://localhost:11434
METRICS_PORT=9090
LOG_LEVEL=info
```

---

## 🔒 Security & Legal

**Authorization Required**: Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

**No Telemetry**: open-re does not collect or transmit any usage data without explicit opt-in.

**Safe Design**:

- No shell command execution
- Path traversal prevention
- Network request validation (timeouts, redirect limits)
- Memory-safe Rust implementation
- Capability-based plugin sandboxing
- Input validation at all boundaries

**Vulnerability Reporting**: See [SECURITY.md](SECURITY.md) for responsible disclosure process.

---

## 📈 Performance

| Metric | Value |
|--------|-------|
| Binary Size (scanner) | ~7 MB (release, stripped) |
| Binary Size (CLI) | ~12 MB (release, stripped) |
| Startup Time | < 50ms cold start |
| Memory Usage (scanner) | 10-20 MB base footprint |
| Memory Usage (API) | 50-100 MB base footprint |
| Quick Scan | ~2-3 seconds |
| Standard Scan | ~10-15 seconds |
| Full Scan | ~30-60 seconds |
| API Throughput | 1000+ req/s (simple endpoints) |

---

## 🗺️ Roadmap

### v0.2.0 (Next Release)

- [ ] Configuration file support (TOML) for openre-scan
- [ ] Authentication handling (OAuth, JWT, API keys) in scanner
- [ ] Recursive crawling/spidering
- [ ] JavaScript rendering/analysis (headless)
- [ ] Plugin marketplace integration
- [ ] Multi-tenant API support
- [ ] ARM64 binary releases
- [ ] Homebrew tap and Cargo publish

### v0.3.0

- [ ] Distributed scanning (multi-worker)
- [ ] Custom check SDK for openre-scan
- [ ] Advanced correlation engine
- [ ] Compliance reporting (OWASP, PCI-DSS, HIPAA)
- [ ] IDE integrations (VS Code, IntelliJ)
- [ ] Pre-built binaries on GitHub Releases
- [ ] Docker images on GHCR

### v1.0.0

- [ ] Stable plugin API
- [ ] Full binary analysis pipeline
- [ ] Enterprise features (RBAC, SSO, Audit logs)
- [ ] Cloud-managed offering
- [ ] Professional support tiers

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test --workspace`
5. Run linters: `cargo fmt --check && cargo clippy --workspace`
6. Submit a pull request

### Development Setup

```bash
# Build all crates
cargo build --workspace

# Run all tests
cargo test --workspace

# Run linters
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings

# Build release binaries
cargo build --release -p openre-scan
cargo build --release -p openre-cli
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with:

- [Rust](https://www.rust-lang.org/) — Memory-safe systems programming
- [reqwest](https://github.com/seanmonstar/reqwest) — HTTP client
- [clap](https://github.com/clap-rs/clap) — CLI parsing
- [ratatui](https://ratatui.rs/) — TUI framework
- [select](https://github.com/utkarshkukreti/select.rs) — HTML parsing
- [tabled](https://github.com/nu11ptr/tabled) — Table formatting
- [tokio](https://tokio.rs/) — Async runtime
- [sqlx](https://github.com/launchbadge/sqlx) — Database toolkit
- [tonic](https://github.com/hyperium/tonic) — gRPC framework
- [axum](https://github.com/tokio-rs/axum) — Web framework
- [tracing](https://github.com/tokio-rs/tracing) — Observability

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture/01-system-overview.md) | System architecture and design principles |
| [Repository Structure](docs/architecture/02-repository-structure.md) | Codebase organization |
| [Backend Architecture](docs/architecture/03-backend-architecture.md) | Rust workspace design |
| [Frontend Architecture](docs/architecture/04-frontend-architecture.md) | React + TypeScript + Tailwind |
| [Plugin Architecture](docs/architecture/05-plugin-architecture.md) | WASM plugin system |
| [AI Architecture](docs/architecture/06-ai-architecture.md) | LLM integration design |
| [Analysis Pipeline](docs/architecture/07-analysis-pipeline.md) | Binary analysis stages |
| [Database Design](docs/architecture/08-database-design.md) | Schema and migrations |
| [Queue/Worker System](docs/architecture/09-queue-worker-system.md) | Job processing |
| [Security Model](docs/architecture/10-security-model.md) | Threat model and controls |
| [AI Security Analyst](docs/architecture/11-ai-security-analyst.md) | AI-powered analysis |

---

**Note**: This is the open-re platform repository. The standalone `openre-scan` tool can be used independently. The full platform with AI, plugins, web UI, and collaborative features is under active development.
