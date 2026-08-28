# open-re Development Tasks

Auto-generated task list for hourly automation. Each task represents an incremental implementation step toward the full platform.

## Task Format

- **Status**: `pending` | `in_progress` | `completed` | `blocked`
- **Priority**: `high` | `medium` | `low`
- **Crate**: Target crate(s) for the task

---

## Architecture/Infrastructure

### Plugin System (openre-plugins)

- [x] **task-001** - Implement WASM plugin runtime with wasmtime
  - Status: pending
  - Priority: high
  - Crate: openre-plugins
  - Details: Sandbox execution, fuel metering, memory limits

- [x] **task-002** - Build capability-based permission system
  - Status: pending
  - Priority: high
  - Crate: openre-plugins
  - Details: Fine-grained permissions (ReadBinary, WriteAnnotations, QueryDatabase, CallAI, NetworkAccess, etc.)

- [x] **task-003** - Create plugin registry (local + remote)
  - Status: pending
  - Priority: medium
  - Crate: openre-plugins
  - Details: Versioning, dependency resolution, signature verification

- [x] **task-004** - Develop Plugin SDK with macros
  - Status: pending
  - Priority: medium
  - Crate: openre-plugins
  - Details: `#[plugin]`, `#[capability]`, `#[command]` macros

- [x] **task-005** - Implement 17 built-in security plugins
  - Status: pending
  - Priority: high
  - Crate: openre-plugins
  - Details: access-control, api-rate-limiting, auth-discovery, cookie-security, cors-analysis, csp-analysis, file-upload, graphql-analysis, information-disclosure, path-traversal, rate-limiting, rest-api-analysis, security-headers, sensitive-info, session-management, sql-injection, xss-analysis

- [x] **task-006** - Build plugin lifecycle management
  - Status: pending
  - Priority: medium
  - Crate: openre-plugins
  - Details: Install, enable/disable, configure, update, uninstall

### Analysis Pipeline (openre-analysis)

- [x] **task-007** - Implement ELF binary parser
  - Status: pending
  - Priority: high
  - Crate: openre-analysis
  - Details: goblin-based parsing, section/symbol extraction

- [x] **task-008** - Implement PE binary parser
  - Status: pending
  - Priority: high
  - Crate: openre-analysis
  - Details: goblin-based PE parsing, import/export tables

- [x] **task-009** - Implement MachO binary parser
  - Status: pending
  - Priority: medium
  - Crate: openre-analysis
  - Details: MachO 64-bit support, dyld info

- [ ] **task-010** - Implement WASM binary parser
  - Status: pending
  - Priority: medium
  - Crate: openre-analysis
  - Details: wasmparser integration, section analysis

- [ ] **task-011** - Build incremental analysis with fingerprint caching
  - Status: pending
  - Priority: high
  - Crate: openre-analysis
  - Details: Change detection, cache invalidation, fingerprint-based

- [ ] **task-012** - Implement pipeline orchestrator
  - Status: pending
  - Priority: high
  - Crate: openre-analysis
  - Details: 9 stages: Identification → Loading → Disassembly → Control Flow → Data Flow → Type Recovery → Decompilation → AI Enrichment → Finalization

- [ ] **task-013** - Add progress tracking with stage granularity
  - Status: pending
  - Priority: medium
  - Crate: openre-analysis
  - Details: Real-time progress, ETA calculation, stage-level metrics

- [ ] **task-014** - Implement static analysis passes
  - Status: pending
  - Priority: medium
  - Crate: openre-analysis
  - Details: Symbol extraction, import/export analysis, section analysis, string extraction

### AI/LLM Integration (openre-security-ai)

- [ ] **task-015** - Build multi-provider abstraction layer
  - Status: pending
  - Priority: high
  - Crate: openre-security-ai
  - Details: Ollama, OpenAI, Anthropic, ONNX Runtime, llama.cpp

- [ ] **task-016** - Implement Security Analyst agent
  - Status: pending
  - Priority: high
  - Crate: openre-security-ai
  - Details: Context-aware vulnerability analysis, prompt templates

- [ ] **task-017** - Create Finding Provider integration
  - Status: pending
  - Priority: medium
  - Crate: openre-security-ai
  - Details: Integrate with scan storage for contextual analysis

- [ ] **task-018** - Build Prompt Compiler with variable injection
  - Status: pending
  - Priority: medium
  - Crate: openre-security-ai
  - Details: Template-based prompt engineering, variable substitution

- [ ] **task-018** - Implement safety controls
  - Status: pending
  - Priority: high
  - Crate: openre-security-ai
  - Details: Output validation, PII filtering, confidence scoring

- [ ] **task-020** - Add remediation generation
  - Status: pending
  - Priority: high
  - Crate: openre-security-ai
  - Details: Actionable fix suggestions with effort estimates

- [ ] **task-021** - Build correlation & prioritization engine
  - Status: pending
  - Priority: medium
  - Crate: openre-security-ai
  - Details: Cross-finding analysis, risk-based ordering

- [ ] **task-022** - Implement context management
  - Status: pending
  - Priority: medium
  - Crate: openre-security-ai
  - Details: Conversation history, token budget management

### Database & Storage Layer (openre-storage)

- [ ] **task-023** - Implement object storage abstraction
  - Status: pending
  - Priority: high
  - Crate: openre-storage
  - Details: S3-compatible, local filesystem, in-memory backends

- [ ] **task-024** - Build SQLite persistence with sqlx migrations
  - Status: pending
  - Priority: high
  - Crate: openre-storage
  - Details: Embedded DB, schema migrations, connection pooling

- [ ] **task-025** - Implement project/scans/findings/reports CRUD
  - Status: pending
  - Priority: high
  - Crate: openre-storage
  - Details: Full lifecycle management

- [ ] **task-026** - Add file storage with SHA256 deduplication
  - Status: pending
  - Priority: medium
  - Crate: openre-storage
  - Details: Binary blob storage, content-addressable

- [ ] **task-027** - Build flexible query layer
  - Status: pending
  - Priority: medium
  - Crate: openre-storage
  - Details: Filtering, sorting, pagination for findings

- [ ] **task-028** - Implement export support
  - Status: pending
  - Priority: medium
  - Crate: openre-storage
  - Details: JSON, SARIF, Markdown, HTML report generation

---

## Features

### Security Scanning (openre-scan)

- [ ] **task-029** - Enhance scanner with all 18+ checks
  - Status: pending
  - Priority: high
  - Crate: openre-scan
  - Details: HTTP headers, security headers, cookies, TLS, info disclosure, tech fingerprint, robots/sitemap, dir listing, sensitive files, forms, links, scripts, meta tags, CSP, CORS, HTTP methods, SSL/TLS deep dive

- [ ] **task-030** - Implement evidence-based findings
  - Status: pending
  - Priority: high
  - Crate: openre-scan
  - Details: HTTP headers, response snippets, locations per finding

- [ ] **task-031** - Build risk scoring system
  - Status: pending
  - Priority: high
  - Crate: openre-scan
  - Details: Severity (Critical/High/Medium/Low/Info) + Confidence (Very High/High/Medium/Low)

- [ ] **task-032** - Add remediation guidance
  - Status: pending
  - Priority: medium
  - Crate: openre-scan
  - Details: Actionable steps with effort/priority estimates

- [ ] **task-033** - Implement filtering (--checks, --exclude)
  - Status: pending
  - Priority: medium
  - Crate: openre-scan
  - Details: Selective scanning by check name/category

### TUI Improvements (openre-scan TUI)

- [ ] **task-034** - Build interactive dashboard
  - Status: pending
  - Priority: medium
  - Crate: openre-scan
  - Details: Real-time scan progress, live findings table

- [ ] **task-035** - Add vim-style keyboard navigation
  - Status: pending
  - Priority: low
  - Crate: openre-scan
  - Details: j/k, g/G, /, ? keybindings

- [ ] **task-036** - Implement detail panels with evidence viewer
  - Status: pending
  - Priority: medium
  - Crate: openre-scan
  - Details: Expandable finding details

- [ ] **task-037** - Add real-time filtering
  - Status: pending
  - Priority: low
  - Crate: openre-scan
  - Details: Filter by severity, category, check

- [ ] **task-038** - Implement export from TUI
  - Status: pending
  - Priority: low
  - Crate: openre-scan
  - Details: Save results without leaving interface

- [ ] **task-039** - Add theme support
  - Status: pending
  - Priority: low
  - Crate: openre-scan
  - Details: Dark/light themes, custom color schemes

- [ ] **task-040** - Build multi-tab layout
  - Status: pending
  - Priority: low
  - Crate: openre-scan
  - Details: Scans, Findings, Settings, Help tabs

### API Endpoints (openre-api)

- [ ] **task-041** - Implement REST API with OpenAPI 3.1
  - Status: pending
  - Priority: high
  - Crate: openre-api
  - Details: axum-based, documented endpoints

- [ ] **task-042** - Build gRPC API with tonic
  - Status: pending
  - Priority: medium
  - Crate: openre-api
  - Details: Protobuf definitions, code generation

- [ ] **task-043** - Add WebSocket support
  - Status: pending
  - Priority: medium
  - Crate: openre-api
  - Details: Real-time scan progress, notifications

- [ ] **task-044** - Implement JWT + API key authentication
  - Status: pending
  - Priority: high
  - Crate: openre-api
  - Details: Token validation, refresh, scopes

- [ ] **task-045** - Build rate limiting (token bucket)
  - Status: pending
  - Priority: medium
  - Crate: openre-api
  - Details: Per-client limits, burst handling

- [ ] **task-046** - Implement URL-based versioning
  - Status: pending
  - Priority: low
  - Crate: openre-api
  - Details: v1, v2 with deprecation policy

- [ ] **task-047** - Build all endpoint groups
  - Status: pending
  - Priority: high
  - Crate: openre-api
  - Details: projects, scans, findings, ai/*, plugins, exports, auth

### Frontend/UI (React + TypeScript + Tailwind)

- [ ] **task-048** - Build dashboard with project overview
  - Status: pending
  - Priority: medium
  - Crate: frontend
  - Details: Recent scans, severity trends, stats cards

- [ ] **task-049** - Implement scan management UI
  - Status: pending
  - Priority: high
  - Crate: frontend
  - Details: Create, monitor, compare scans

- [ ] **task-050** - Build finding browser
  - Status: pending
  - Priority: high
  - Crate: frontend
  - Details: Filterable, sortable table with detail drawer

- [ ] **task-051** - Create AI Analyst chat interface
  - Status: pending
  - Priority: high
  - Crate: frontend
  - Details: Conversational vulnerability analysis

- [ ] **task-052** - Build plugin manager
  - Status: pending
  - Priority: medium
  - Crate: frontend
  - Details: Browse, install, configure plugins

- [ ] **task-053** - Implement settings page
  - Status: pending
  - Priority: low
  - Crate: frontend
  - Details: User prefs, API keys, theme, notifications

- [ ] **task-054** - Add WebSocket real-time updates
  - Status: pending
  - Priority: medium
  - Crate: frontend
  - Details: Live data without polling

- [ ] **task-055** - Ensure responsive design + accessibility
  - Status: pending
  - Priority: medium
  - Crate: frontend
  - Details: Mobile-friendly, WCAG 2.1 AA

---

## CI/CD & DevOps

### GitHub Actions Workflows

- [ ] **task-056** - Enhance CI pipeline
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: Format, Clippy, Build, Test for core crates

- [ ] **task-057** - Build security audit workflow
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: cargo-audit, cargo-deny, dependency review

- [ ] **task-058** - Implement release automation
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: Multi-platform builds, checksums, GitHub Releases

- [ ] **task-059** - Add Docker build workflow
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: Multi-arch images (API, Worker, Frontend) to GHCR

- [ ] **task-060** - Build documentation workflow
  - Status: pending
  - Priority: medium
  - Crate: .github/workflows
  - Details: markdownlint, cspell, link checking

- [ ] **task-061** - Implement coverage workflow
  - Status: pending
  - Priority: medium
  - Crate: .github/workflows
  - Details: cargo-llvm-cov, Codecov upload

- [ ] **task-062** - Add dependency review workflow
  - Status: pending
  - Priority: medium
  - Crate: .github/workflows
  - Details: PR dependency scanning with policies

### Release Management

- [ ] **task-063** - Automate semantic versioning
  - Status: pending
  - Priority: medium
  - Crate: scripts
  - Details: From conventional commits

- [ ] **task-064** - Build changelog generation
  - Status: pending
  - Priority: medium
  - Crate: scripts
  - Details: Auto-generated from commit history

- [ ] **task-065** - Implement multi-platform binary builds
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: x86_64 Linux/macOS/Windows + ARM64

- [ ] **task-066** - Add container image publishing
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: GHCR with latest and versioned tags

- [ ] **task-067** - Build SBOM generation
  - Status: pending
  - Priority: medium
  - Crate: scripts
  - Details: SPDX/CycloneDX format

- [ ] **task-068** - Implement SLSA provenance
  - Status: pending
  - Priority: low
  - Crate: .github/workflows
  - Details: Level 3 build attestations

### Testing Infrastructure

- [ ] **task-069** - Expand unit test coverage
  - Status: pending
  - Priority: high
  - Crate: all
  - Details: Comprehensive coverage for core crates

- [ ] **task-070** - Build integration tests
  - Status: pending
  - Priority: high
  - Crate: all
  - Details: End-to-end scan pipeline, API, storage

- [ ] **task-071** - Add property-based tests
  - Status: pending
  - Priority: medium
  - Crate: openre-intelligence, openre-core
  - Details: Proptest for correlation, risk scoring

- [ ] **task-072** - Implement benchmark tests
  - Status: pending
  - Priority: low
  - Crate: all
  - Details: Criterion benchmarks for hot paths

- [ ] **task-073** - Add contract tests
  - Status: pending
  - Priority: medium
  - Crate: openre-api
  - Details: API schema validation

- [ ] **task-074** - Build E2E tests
  - Status: pending
  - Priority: medium
  - Crate: frontend, openre-cli
  - Details: Playwright for frontend, CLI scenarios

### Security Scanning

- [ ] **task-075** - Configure SAST pipeline
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: cargo-audit, clippy, cargo-deny

- [ ] **task-076** - Set up dependency scanning
  - Status: pending
  - Priority: high
  - Crate: .github/dependabot.yml
  - Details: GitHub Dependabot + custom policies

- [ ] **task-077** - Add container scanning
  - Status: pending
  - Priority: medium
  - Crate: .github/workflows
  - Details: Trivy for Docker images

- [ ] **task-078** - Implement secret scanning
  - Status: pending
  - Priority: high
  - Crate: .github/workflows
  - Details: GitHub secret scanning + pre-commit hooks

- [ ] **task-079** - Configure license compliance
  - Status: pending
  - Priority: medium
  - Crate: .github/workflows
  - Details: cargo-deny license checking

---

## Developer Experience

### CLI Improvements (openre-cli)

- [ ] **task-080** - Build unified command structure
  - Status: pending
  - Priority: high
  - Crate: openre-cli
  - Details: `openre <command> <subcommand>` for all operations

- [ ] **task-081** - Implement rich output formats
  - Status: pending
  - Priority: medium
  - Crate: openre-cli
  - Details: Colored tables, JSON, YAML, SARIF with `--format`

- [ ] **task-082** - Add shell completions
  - Status: pending
  - Priority: low
  - Crate: openre-cli
  - Details: Bash, Zsh, Fish, PowerShell, Elvish

- [ ] **task-083** - Build TOML config with profiles
  - Status: pending
  - Priority: medium
  - Crate: openre-cli
  - Details: Multiple profiles, `openre config use`

- [ ] **task-084** - Implement plugin commands
  - Status: pending
  - Priority: high
  - Crate: openre-cli
  - Details: install/list/enable/disable/configure

- [ ] **task-085** - Build AI commands
  - Status: pending
  - Priority: high
  - Crate: openre-cli
  - Details: analyze/explain/remediate/correlate

- [ ] **task-086** - Implement project commands
  - Status: pending
  - Priority: high
  - Crate: openre-cli
  - Details: create/list/show/delete

- [ ] **task-087** - Build scan commands
  - Status: pending
  - Priority: high
  - Crate: openre-cli
  - Details: create/list/show/delete/run

### Documentation

- [ ] **task-088** - Complete architecture docs (11 docs)
  - Status: pending
  - Priority: medium
  - Crate: docs/architecture
  - Details: System overview, repo structure, backend, frontend, plugin, AI, analysis, database, queue, security, AI analyst

- [ ] **task-089** - Build API reference with OpenAPI UI
  - Status: pending
  - Priority: medium
  - Crate: docs/api
  - Details: scalar/Redoc UI

- [ ] **task-090** - Write plugin development guide
  - Status: pending
  - Priority: medium
  - Crate: docs/injection
  - Details: Tutorial + API reference

- [ ] **task-091** - Create security plugin guide
  - Status: pending
  - Priority: medium
  - Crate: docs/security
  - Details: Building security analysis plugins

- [ ] **task-092** - Write installation guide
  - Status: pending
  - Priority: low
  - Crate: docs
  - Details: Binary, Docker, source, package managers

- [ ] **task-093** - Update contributing guide
  - Status: pending
  - Priority: low
  - Crate: CONTRIBUTING.md
  - Details: Code style, PR process, testing

- [ ] **task-094** - Write migration guides
  - Status: pending
  - Priority: low
  - Crate: docs
  - Details: Version upgrade instructions

### Tooling

- [ ] **task-095** - Set up pre-commit hooks
  - Status: pending
  - Priority: high
  - Crate: .pre-commit-config.yaml
  - Details: fmt, clippy, markdownlint, cspell

- [ ] **task-096** - Configure VS Code workspace
  - Status: pending
  - Priority: low
  - Crate: .vscode
  - Details: rust-analyzer, tasks, launch configs

- [ ] **task-097** - Build dev container
  - Status: pending
  - Priority: medium
  - Crate: .devcontainer
  - Details: Full development environment

- [ ] **task-098** - Create Makefile/Justfile
  - Status: pending
  - Priority: low
  - Crate: Justfile
  - Details: Common development commands

- [ ] **task-099** - Build release automation script
  - Status: pending
  - Priority: medium
  - Crate: scripts
  - Details: Version bump, changelog, tag, push

---

## Automation Instructions

This file is read by the hourly automation script. The script will:
1. Find the first `pending` task with `high` priority (then `medium`, then `low`)
2. Mark it `in_progress`
3. Implement the task
4. Run tests and linting
5. Commit and push
6. Mark task `completed`
7. Update this file

**Next task to execute**: task-001 (WASM plugin runtime)
