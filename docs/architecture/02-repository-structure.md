# Repository Structure

## Overview

This document defines the production-ready monorepo layout for open-re. The structure follows Rust workspace conventions with clear separation of concerns, enabling independent development, testing, and deployment of each component.

---

## Top-Level Structure

```
open-re/
├── .github/                    # GitHub workflows, templates, configs
├── .vscode/                    # VS Code workspace settings
├── docs/                       # All documentation (architecture, ADRs, guides)
│   ├── architecture/           # This directory
│   ├── adr/                    # Architecture Decision Records
│   └── ...
├── crates/                     # Rust crates (core backend)
│   ├── openre-core/            # Core domain types, traits, errors
│   ├── openre-api/             # HTTP/gRPC API layer
│   ├── openre-analysis/        # Analysis pipeline orchestration
│   ├── openre-plugins/         # Plugin system (loader, runtime, SDK)
│   ├── openre-ai/              # AI abstraction layer
│   ├── openre-storage/         # Storage abstractions (SQLite, PG, S3)
│   ├── openre-queue/           # Queue worker framework
│   ├── openre-config/          # Configuration management
│   ├── openre-telemetry/       # Logging, metrics, tracing
│   ├── openre-binary/          # Binary parsing (ELF, PE, Mach-O)
│   ├── openre-disasm/          # Disassembly engine abstraction
│   ├── openre-cfg/             # Control flow graph construction
│   ├── openre-decompiler/      # Decompilation pipeline
│   ├── openre-types/           # Type system
│   └── openre-python/          # Python bindings (pyo3)
├── plugins/                    # Built-in plugins (shipped with core)
│   ├── loader-elf/             # ELF loader plugin
│   ├── loader-pe/              # PE loader plugin
│   ├── loader-macho/           # Mach-O loader plugin
│   ├── disasm-capstone/        # Capstone-based disassembler
│   ├── disasm-llvm/            # LLVM-based disassembler
│   ├── cfg-standard/           # Standard CFG builder
│   ├── decompiler-standard/    # Standard decompiler (LLIL/MLIL/HLIL)
│   ├── ai-naming/              # AI function/variable naming
│   ├── ai-classification/      # AI function classification
│   ├── ai-crypto/              # AI crypto detection
│   ├── yara-scanner/           # YARA rule scanner
│   ├── capa-runner/            # Capa capability detection
│   └── exporter-c/             # C pseudo-code exporter
├── python/                     # Python packages
│   ├── openre/                 # Main Python package (pip installable)
│   │   ├── api/                # High-level async API
│   │   ├── scripting/          # Jupyter integration, REPL
│   │   ├── headless/           # Headless/CLI entry points
│   │   └── plugins/            # Python plugin SDK
│   └── openre-jupyter/         # Jupyter kernel extension
├── frontend/                   # Web frontend (React + TypeScript)
│   ├── packages/
│   │   ├── app/                # Main application
│   │   ├── components/         # Shared UI components
│   │   ├── core/               # Core hooks, state, API client
│   │   ├── views/              # View components (disasm, decomp, graph)
│   │   ├── plugins/            # Plugin UI extensions
│   │   └── ai/                 # AI chat, suggestions UI
│   ├── public/                 # Static assets
│   └── tests/                  # E2E, component tests
├── cli/                        # CLI tools
│   ├── openre-cli/             # Main CLI (Rust)
│   └── openre-headless/        # Headless analysis runner
├── docker/                     # Docker configurations
│   ├── docker-compose.yml      # Local development stack
│   ├── docker-compose.prod.yml # Production stack
│   ├── Dockerfile.api          # API service
│   ├── Dockerfile.worker       # Worker service
│   ├── Dockerfile.frontend     # Frontend build
│   └── .dockerignore
├── k8s/                        # Kubernetes manifests (optional)
│   ├── base/                   # Base resources
│   ├── overlays/
│   │   ├── dev/
│   │   ├── staging/
│   │   └── prod/
│   └── helm/                   # Helm charts
├── scripts/                    # Build, dev, release scripts
│   ├── build.sh
│   ├── test.sh
│   ├── lint.sh
│   ├── fmt.sh
│   ├── release.sh
│   └── dev-setup.sh
├── tests/                      # Integration tests (cross-crate)
│   ├── integration/
│   ├── fixtures/               # Test binaries, fixtures
│   └── snapshots/              # Snapshot tests
├── benchmarks/                 # Performance benchmarks
│   ├── disasm/
│   ├── decompiler/
│   └── ai/
├── Cargo.toml                  # Workspace root
├── Cargo.lock
├── pyproject.toml              # Python workspace config
├── package.json                # Frontend workspace config
├── turbo.json                  # Turborepo config (if using)
├── .rustfmt.toml
├── .clippy.toml
├── .gitignore
├── .editorconfig
├── LICENSE
├── README.md
├── CHANGELOG.md
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

---

## Directory Rationale

### `/crates` — Rust Workspace (Core Backend)

**Why separate crates?**
- **Compile-time boundaries**: Enforces clean architecture; circular dependencies caught early
- **Independent versioning**: Each crate can evolve at its own pace
- **Parallel compilation**: Cargo builds independent crates in parallel
- **Selective compilation**: `cargo build -p openre-api` only builds what's needed
- **Team ownership**: Different teams can own different crates

**Crate Categories:**

| Category | Crates | Purpose |
|----------|--------|---------|
| **Foundation** | `openre-core`, `openre-config`, `openre-telemetry` | Shared types, config, observability |
| **API Layer** | `openre-api` | HTTP/gRPC endpoints, request/response types |
| **Orchestration** | `openre-analysis`, `openre-queue` | Pipeline, workers, job management |
| **Extensibility** | `openre-plugins`, `openre-python` | Plugin system, Python bindings |
| **AI** | `openre-ai` | Model abstraction, prompt management |
| **Storage** | `openre-storage` | SQLite, PostgreSQL, S3 abstractions |
| **Binary Analysis** | `openre-binary`, `openre-disasm`, `openre-cfg`, `openre-decompiler`, `openre-types` | Core RE functionality |

**Dependency Rules:**
```
openre-core (no deps)
    ↑
openre-config, openre-telemetry
    ↑
openre-storage, openre-queue, openre-plugins, openre-ai
    ↑
openre-binary, openre-disasm, openre-cfg, openre-decompiler, openre-types
    ↑
openre-analysis
    ↑
openre-api, openre-python
```

### `/plugins` — Built-in Plugins

**Why separate from crates?**
- **Plugin boundary enforcement**: Plugins use only the public Plugin SDK API
- **Independent deployment**: Can be updated without rebuilding core
- **Third-party parity**: External plugins have same capabilities as built-in
- **Clear ownership**: Plugin authors work in their own directory

**Plugin Structure:**
```
plugins/
├── loader-elf/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs          # Plugin entry point
│   │   ├── parser.rs       # ELF parsing logic
│   │   └── metadata.rs     # Metadata extraction
│   ├── tests/
│   └── README.md
```

### `/python` — Python Packages

**Why separate Python workspace?**
- **PyPI publishing**: `openre` package published independently
- **Virtualenv isolation**: Users `pip install openre` without Rust toolchain
- **Jupyter integration**: Separate kernel package
- **Async-first API**: Designed for Python async/await patterns

### `/frontend` — Web Frontend (Monorepo)

**Why pnpm workspaces / Turborepo?**
- **Shared components**: `components`, `core` packages shared across views
- **Independent builds**: Each package builds independently
- **Type safety**: TypeScript project references for cross-package types
- **Plugin UI extensions**: Plugins can contribute React components

### `/cli` — Command Line Tools

**Why separate CLI crates?**
- **Binary size**: CLI doesn't need web framework deps
- **Distribution**: Single static binary for `openre-cli`
- **Headless CI**: `openre-headless` optimized for CI/CD (no UI deps)

### `/docker` — Container Definitions

**Why separate docker directory?**
- **Multi-service**: API, worker, frontend, DB, Redis, MinIO
- **Environment parity**: Same images for dev, staging, prod
- **Compose for dev**: `docker-compose.yml` spins up full stack locally

### `/k8s` — Kubernetes (Optional)

**Why include if optional?**
- **Production ready**: Teams deploying to K8s have starting point
- **GitOps friendly**: ArgoCD/Flux compatible structure
- **Helm charts**: Standard packaging for K8s

### `/scripts` — Automation

**Why separate scripts?**
- **CI/CD parity**: Same scripts run locally and in CI
- **Discoverability**: `scripts/` is obvious place to look
- **Language agnostic**: Bash for portability, can call cargo/pnpm/python

### `/tests` — Integration Tests

**Why separate from crates?**
- **Cross-crate scenarios**: Test full pipeline (upload → analysis → AI)
- **Fixtures management**: Shared test binaries, expected outputs
- **Snapshot testing**: Golden files for regression detection

### `/benchmarks` — Performance Benchmarks

**Why separate?**
- **Criterion.rs integration**: Proper benchmark harness
- **CI gating**: Fail if performance regresses >5%
- **Historical tracking**: Store results for trend analysis

---

## Configuration Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace root: members, profiles, patch, lints |
| `pyproject.toml` | Python workspace: dependencies, build-system, tools |
| `package.json` | Frontend workspace: workspaces, scripts, engines |
| `turbo.json` | Turborepo: pipeline, cache, dependsOn |
| `.rustfmt.toml` | Rust formatting (enforced in CI) |
| `.clippy.toml` | Clippy lints (deny warnings in CI) |
| `.editorconfig` | Cross-editor consistency (indent, charset) |

---

## Cargo Workspace Configuration

```toml
# Cargo.toml (root)
[workspace]
resolver = "2"
members = [
    "crates/*",
    "plugins/*",
    "cli/*",
]
exclude = [
    # Exclude crates not ready for publishing
]

[workspace.dependencies]
# Shared dependencies with versions
tokio = { version = "1.38", features = ["full", "rt-multi-thread"] }
axum = "0.7"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "sqlite", "uuid", "chrono", "json"] }
redis = { version = "0.24", features = ["tokio-comp", "connection-manager"] }
wasmtime = "20.0"
pyo3 = { version = "0.21", features = ["extension-module", "abi3"] }
# ... more shared deps

[workspace.lints.rust]
unused_crate_dependencies = "warn"
unused_imports = "warn"
missing_docs = "warn"
# ... more lints

[profile.release]
lto = "thin"
codegen-units = 1
strip = "symbols"
opt-level = 3
panic = "abort"

[profile.bench]
debug = true
```

---

## Python Workspace Configuration

```toml
# pyproject.toml (root)
[build-system]
requires = ["maturin>=1.6,<2.0"]
build-backend = "maturin"

[project]
name = "openre"
version = "0.1.0"
description = "AI-native reverse engineering platform"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "open-re contributors"}]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Rust",
    "Topic :: Security",
    "Topic :: Software Development :: Disassemblers",
]
requires-python = ">=3.11"
dependencies = [
    "pydantic>=2.6",
    "pydantic-settings>=2.2",
    "httpx>=0.26",
    "rich>=13.7",
    "typer>=0.9",
    "numpy>=1.26",
    "onnxruntime>=1.17",
]

[project.optional-dependencies]
jupyter = ["jupyter-client>=8.6", "ipykernel>=6.28"]
dev = ["pytest>=8.0", "pytest-asyncio>=0.23", "ruff>=0.3", "mypy>=1.8"]

[tool.maturin]
features = ["pyo3/extension-module", "pyo3/abi3-py311"]

[tool.ruff]
target-version = "py311"
line-length = 100
select = ["E", "F", "I", "W", "UP", "B", "C4", "PT", "PTH", "RUF", "SIM", "T20", "TRY", "ARG", "PTH", "ERA", "PD", "PGH", "PL", "TRY", "NPY", "RSE", "RET", "FLY", "TCH", "INT", "PERF", "ASYNC", "LOG", "PIE", "TID", "QF", "DTZ", "EXE", "ISC", "ICN", "BLE", "FUR", "NPY", "RSE", "RET", "FLY", "TCH", "INT", "PERF", "ASYNC", "LOG", "PIE", "TID", "QF", "DTZ", "EXE", "ISC", "ICN", "BLE", "FUR"]

[tool.mypy]
python_version = "3.11"
strict = true
warn_unused_ignores = true
disallow_untyped_defs = true
```

---

## Frontend Workspace Configuration

```json
// package.json (root)
{
  "name": "openre-frontend",
  "private": true,
  "workspaces": [
    "packages/*"
  ],
  "scripts": {
    "dev": "turbo run dev",
    "build": "turbo run build",
    "test": "turbo run test",
    "lint": "turbo run lint",
    "typecheck": "turbo run typecheck",
    "format": "prettier --write \"**/*.{ts,tsx,json,md}\""
  },
  "devDependencies": {
    "turbo": "^2.0",
    "typescript": "^5.5",
    "prettier": "^3.3",
    "eslint": "^9.0",
    "@typescript-eslint/eslint-plugin": "^8.0",
    "@typescript-eslint/parser": "^8.0",
    "vitest": "^2.0",
    "@vitest/ui": "^2.0"
  },
  "engines": {
    "node": ">=20.11",
    "pnpm": ">=9.0"
  },
  "packageManager": "pnpm@9.0"
}
```

```json
// turbo.json
{
  "$schema": "https://turbo.build/schema.json",
  "pipeline": {
    "build": {
      "dependsOn": ["^build"],
      "outputs": ["dist/**", "build/**"]
    },
    "test": {
      "dependsOn": ["build"],
      "outputs": ["coverage/**"]
    },
    "lint": {},
    "typecheck": {
      "dependsOn": ["^build"]
    },
    "dev": {
      "cache": false,
      "persistent": true
    }
  },
  "globalEnv": ["NODE_ENV", "VITE_API_URL"]
}
```

---

## Git Ignore Strategy

```gitignore
# .gitignore (root)
# Rust
/target/
**/*.rs.bk
Cargo.lock

# Python
__pycache__/
*.py[cod]
*$py.class
.pytest_cache/
.coverage
htmlcov/
.tox/
.venv/
venv/
env/
*.egg-info/
dist/
build/

# Node.js
node_modules/
.pnpm-store/
dist/
build/
.next/
*.tsbuildinfo

# IDE
.vscode/*
!.vscode/extensions.json
!.vscode/settings.json
.idea/
*.swp
*.swo
*~
.DS_Store

# Docker
.docker/

# Build artifacts
*.o
*.so
*.dylib
*.dll
*.lib
*.a
*.exe

# Environment
.env
.env.local
.env.*.local
*.pem
*.key

# Test artifacts
test-results/
coverage/
*.profraw

# OS
Thumbs.db
ehthumbs.db
Desktop.ini
```

---

## Development Workflow

```bash
# Initial setup
./scripts/dev-setup.sh

# Start full stack locally
docker-compose up -d

# Run API server (with hot reload)
cargo watch -x "run -p openre-api"

# Run frontend dev server
pnpm --filter @openre/app dev

# Run tests
./scripts/test.sh

# Run linters
./scripts/lint.sh

# Format code
./scripts/fmt.sh

# Build release
./scripts/release.sh
```

---

## Publishing Strategy

| Artifact | Registry | Trigger |
|----------|----------|---------|
| Rust crates | crates.io | Git tag `v*` |
| Python package | PyPI | Git tag `v*` |
| Docker images | GHCR | Git tag `v*` / main branch |
| Frontend | Static hosting | Git tag `v*` |
| CLI binaries | GitHub Releases | Git tag `v*` |

---

*This structure scales from solo developer to 50+ person team. Adjust crate granularity as team grows.*