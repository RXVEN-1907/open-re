# Repository Size Audit

## Summary

**Current repository size: 13 MB** (after cleanup of build artifacts)

-   Source code: ~3.4 MB (crates/)
-   Git history: 6.7 MB (.git/)
-   Documentation: ~684 KB (docs/)
-   Frontend: ~632 KB (frontend/)
-   Plugins: ~224 KB (plugins/)
-   Python bindings: ~120 KB (Python/)
-   Tests: ~36 KB (tests/)
-   Configuration & scripts: ~1 MB (Cargo.lock, Docker, scripts, docs)

## Historical Issues (Now Resolved)

### 1. Build Artifacts (Previously 7.4 GB → Now Cleaned)

-   `target/` directory contained 7.4 GB of build artifacts (debug + release)
-   `.claude/worktrees/agent-*/target/` contained 1.1 GB of build artifacts from previous agent sessions
-   Both have been removed

### 2. Previously Committed Artifacts (Now in .gitignore)

-   `target/` - Rust build artifacts
-   `node_modules/` - JavaScript dependencies
-   `*.venv/` - Python virtual environments
-   `*.log` - Log files
-   `*.tmp` - Temporary files

## Current Repository Structure

```
13 MB total repository size
├── 6.7 MB .git/ (Git history)
├── 3.4 MB crates/ (Rust source code)
│   ├── 852 KB openre-plugins
│   ├── 428 KB openre-intelligence
│   ├── 332 KB openre-scanner
│   ├── 296 KB openre-api
│   ├── 220 KB openre-core
│   ├── 208 KB openre-security-ai
│   ├── 180 KB openre-analysis
│   ├── 180 KB openre-ai
│   ├── 164 KB openre-recon
│   ├── 140 KB openre-storage
│   ├── 140 KB openre-cli
│   ├── 120 KB openre-queue
│   ├──  52 KB openre-telemetry
│   ├──  48 KB openre-config
│   └──  20 KB sentinel
├── 684 KB docs/ (Documentation)
├── 632 KB frontend/ (Web interface code)
├── 224 KB plugins/ (Security plugin modules)
├── 184 KB Cargo.lock (Dependency lock file)
├── 120 KB Python/ (Python bindings)
└── Remaining: configs, scripts, tests, Docker files
```

## Source Code Breakdown

### Core Crates (Required for Scanner)

| Crate | Size | Purpose |
| ------- | ------ | --------- |
| openre-core | 220 KB | Core types, errors, finding model, deduplication |
| openre-config | 48 KB | Configuration management |
| openre-telemetry | 52 KB | Tracing, metrics, OpenTelemetry |
| openre-storage | 140 KB | PostgreSQL, SQLite, Redis abstractions |
| openre-queue | 120 KB | Job queue management |
| openre-plugins | 852 KB | Plugin system (WASM, native, registry) |
| openre-scanner | 332 KB | Scan engine, TUI, target management |
| **Subtotal** | **1.76 MB** | **Minimal scanner core** |

### Optional/Advanced Crates

| Crate | Size | Purpose | Optional? |
| ------- | ------ | --------- | ----------- |
| openre-recon | 164 KB | Reconnaissance plugins | Yes |
| openre-analysis | 180 KB | Binary analysis pipeline | Yes |
| openre-api | 296 KB | REST/gRPC API server | Yes |
| openre-cli | 140 KB | Full platform CLI | Yes |
| openre-intelligence | 428 KB | CVE matching, correlation | Yes |
| openre-ai | 180 KB | AI provider abstraction | **Yes** |
| openre-security-ai | 208 KB | AI Security Analyst | **Yes** |
| sentinel | 20 KB | Demo standalone scanner | Demo only |

### Total Optional: ~1.6 MB

## Build Artifacts (Excluded via .gitignore)

| Directory | Previous Size | Status |
| ----------- | -------------- | -------- |
| target/debug | 5.7 GB | Cleaned |
| target/release | 1.8 GB | Cleaned |
| .claude/worktrees/agent-*/target | 1.1 GB | Cleaned |
| **Total** | **8.6 GB** | **Removed** |

## Dependency Analysis

### Workspace Dependencies (Cargo.TOML)

#### Core Runtime (Required)

-   tokio, anyhow, thiserror, serde, uuid, chrono, tracing, dashmap, bytes, async-trait
-   **Estimated compile-time cost: Low-Medium**

#### Web/Network (Required for Scanner)

-   reqwest, hyper, rustls, tower, axum, utoipa
-   **Estimated compile-time cost: Medium**

#### Database (Required for Persistence)

-   sqlx, redis, rusqlite
-   **Estimated compile-time cost: Medium-High**

#### Binary Parsing (Required for Analysis)

-   goblin, object, scroll, xmas-ELF
-   **Estimated compile-time cost: Low**

#### Plugin System (Required)

-   wasmtime, wasmparser, libloading
-   **Estimated compile-time cost: High (wasmtime is large)**

#### AI/ML (COMMENTED OUT - Optional)

-   ort, llama-cpp-2, tokenizers, candle-* - All commented out
-   **Status: Not compiled by default ✓**

#### Heavy Dependencies (Only in Specific Crates)

-   wasmtime: Only in openre-plugins, openre-scanner, openre-recon
-   sqlx: Only in openre-core, openre-storage, openre-plugins
-   axum/tower: Only in openre-api, openre-scanner

## Recommendations

### ✅ Already Done

1.  Removed all build artifacts (8.6 GB saved)
2.  .gitignore properly excludes target/, node_modules/, venv/, logs, tmp
3.  AI/ML dependencies commented out in workspace
4.  Heavy dependencies (wasmtime, sqlx, axum) are crate-scoped

### 🔧 To Do

1.  **Make wasmtime optional** - Feature-gate WASM plugin support
2.  **Make sqlx optional** - Feature-gate database persistence
3.  **Create minimal "scanner" profile** - Only compile core scanner crates
4.  **Split workspace** - Consider separate Cargo.TOML for minimal scanner
5.  **Add .dockerignore** - Exclude target, .git, .claude, docs, tests from Docker builds

## Expected Minimal Installation Size

| Component | Estimated Size |
| ----------- | --------------- |
| Statically linked binary (release) | 8-15 MB |
| Configuration files | < 100 KB |
| Plugin directory (WASM plugins) | 1-5 MB (optional) |
| **Total minimal install** | **~10-20 MB** |

## Build Time Estimates

| Profile | Crates | Est. Build Time |
| --------- | -------- | ----------------- |
| Full workspace | 18 crates | 5-10 min |
| Scanner core only | 7 crates | 2-3 min |
| Minimal (no WASM, no DB) | 5 crates | 1-2 min |

---

_Last updated: 2026-08-15_
_Audit performed by: Phase 9 productionization_
