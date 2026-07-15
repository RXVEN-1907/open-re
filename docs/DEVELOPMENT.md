# Development Guide

This guide covers setting up a development environment for open-re, coding standards, and contribution workflows.

## Prerequisites

### System Requirements

- **Rust**: 1.78+ (install via [rustup](https://rustup.rs/))
- **Node.js**: 20+ (for frontend)
- **pnpm**: 9+ (for frontend package management)
- **Python**: 3.11+ (for Python bindings)
- **PostgreSQL**: 16+ (for database)
- **Redis**: 7+ (for queue system)
- **Docker**: 24+ (for containerized development)

### Optional Tools

- **cargo-watch**: For auto-rebuilding
- **cargo-nextest**: For faster test runs
- **sqlx-cli**: For database migrations
- **protoc**: For gRPC protobuf compilation

## Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re

# Install Rust dependencies
cargo build --workspace

# Install frontend dependencies
cd frontend && pnpm install && cd ..

# Install Python dependencies
cd python && pip install -e . && cd ..
```

### 2. Start Development Services

```bash
# Start PostgreSQL, Redis, MinIO
docker compose up -d postgres redis minio

# Run database migrations
cargo run --bin openre-cli -- db migrate

# Start API server
cargo run --bin openre-api

# In another terminal, start frontend
cd frontend && pnpm dev
```

### 3. Verify Installation

- API: http://localhost:8080/health
- Frontend: http://localhost:3000
- API Docs: http://localhost:8080/docs

## Project Structure

```
open-re/
├── crates/                 # Rust workspace crates
│   ├── openre-core/        # Core types, errors, traits
│   ├── openre-config/      # Configuration management
│   ├── openre-telemetry/   # Logging, metrics, tracing, audit
│   ├── openre-storage/     # Database (PostgreSQL/SQLite) & object storage
│   ├── openre-queue/       # Redis Streams queue system
│   ├── openre-plugins/     # Plugin system (WASM + native)
│   ├── openre-analysis/    # Analysis pipeline & stages
│   ├── openre-ai/          # AI service (providers, prompts, tools)
│   ├── openre-api/         # HTTP/gRPC API server
│   └── openre-cli/         # Command-line interface
├── frontend/               # React/TypeScript frontend
│   ├── apps/web/           # Main web application
│   └── packages/           # Shared packages (ui, api-client, state, utils)
├── python/                 # Python bindings
│   ├── openre/             # Pure Python client
│   └── openre-bindings/    # PyO3 Rust bindings
├── docker/                 # Dockerfiles & compose files
├── tests/                  # Integration & unit tests
└── docs/                   # Documentation
```

## Development Workflow

### Running Tests

```bash
# Run all Rust tests
cargo test --workspace

# Run with nextest (faster)
cargo nextest run --workspace

# Run specific crate tests
cargo test -p openre-core

# Run integration tests
cargo test --test integration_tests

# Run frontend tests
cd frontend && pnpm test

# Run Python tests
cd python && pytest
```

### Code Quality

```bash
# Format Rust code
cargo fmt --all

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Frontend linting
cd frontend && pnpm lint

# Frontend type checking
cd frontend && pnpm typecheck
```

### Database Migrations

```bash
# Create new migration
sqlx migrate add -r "description_of_change"

# Run migrations
cargo run --bin openre-cli -- db migrate

# Revert last migration
sqlx migrate revert
```

### Adding a New Crate

1. Create directory under `crates/`
2. Add `Cargo.toml` with workspace dependencies
3. Add to workspace `Cargo.toml` members
4. Implement `lib.rs` with public API
5. Add tests in `tests/` directory

### Adding a New API Endpoint

1. Add route in `crates/openre-api/src/routes/`
2. Define request/response models with `utoipa` for OpenAPI
3. Add validation in `crates/openre-api/src/validation.rs`
4. Add authentication/authorization middleware
5. Write integration test

### Adding a New Analysis Stage

1. Implement `Stage` trait in `crates/openre-analysis/src/stages.rs`
2. Add to `StageName` enum
3. Register in `StageDag` with dependencies
4. Add configuration options
5. Write unit tests

### Adding a New Plugin Type

1. Add `PluginType` variant in `crates/openre-plugins/src/capability.rs`
2. Define capabilities in `Capability` enum
3. Implement host functions in `crates/openre-plugins/src/sdk.rs`
4. Update manifest schema
5. Add SDK documentation

## Coding Standards

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `clippy` and `rustfmt` defaults
- Prefer `anyhow::Result` for application errors
- Use `thiserror` for library error types
- Document public APIs with `///` comments
- Use `#[must_use]` for functions returning important values
- Prefer `async`/`await` over blocking calls

### TypeScript/React

- Use functional components with hooks
- Follow [React TypeScript Cheatsheet](https://react-typescript-cheatsheet.netlify.app/)
- Use `zod` for runtime validation
- Prefer `tanstack-query` for server state
- Use `zustand` for client state
- Follow Tailwind CSS conventions

### Python

- Follow [PEP 8](https://pep8.org/)
- Use type hints everywhere
- Use `pydantic` for data validation
- Follow [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

### Git Conventions

- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`
- Keep commits atomic and focused
- Write descriptive commit messages
- Reference issues: `fixes #123`

## Debugging

### API Server

```bash
# Run with debug logging
RUST_LOG=debug cargo run --bin openre-api

# Attach debugger (VS Code)
# Launch configuration: "Debug openre-api"
```

### Frontend

```bash
# Start with source maps
cd frontend && pnpm dev

# Debug in browser DevTools
# React DevTools extension recommended
```

### Database

```bash
# Connect to PostgreSQL
psql postgresql://openre:password@localhost:5432/openre

# Inspect SQLite
sqlite3 data/project.db
```

## Performance Profiling

```bash
# CPU profiling
cargo build --release --bin openre-api
perf record --call-graph=dwarf ./target/release/openre-api
perf report

# Memory profiling
valgrind --tool=massif ./target/release/openre-api
ms_print massif.out.*

# Benchmark
cargo bench --workspace
```

## Common Issues

### Port Conflicts

```bash
# Check what's using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>
```

### Database Connection Issues

```bash
# Check PostgreSQL status
docker compose logs postgres

# Reset database
docker compose down -v
docker compose up -d postgres
cargo run --bin openre-cli -- db migrate
```

### Frontend Build Errors

```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules pnpm-lock.yaml
pnpm install
```

### Rust Compilation Errors

```bash
# Clean and rebuild
cargo clean
cargo build --workspace

# Update toolchain
rustup update
```

## Useful Commands

```bash
# Watch for changes and rebuild
cargo watch -x "build --bin openre-api"

# Run specific test with output
cargo test test_name -- --nocapture

# Generate documentation
cargo doc --workspace --open

# Check for unused dependencies
cargo machete

# Audit dependencies
cargo audit

# Check for outdated dependencies
cargo outdated
```

## Resources

- [Architecture Documentation](../architecture/)
- [API Reference](http://localhost:8080/docs)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)