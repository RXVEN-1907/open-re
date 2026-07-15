# open-re

[![CI](https://github.com/RXVEN-1907/open-re/workflows/CI/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/ci.yml)
[![Release](https://github.com/RXVEN-1907/open-re/workflows/Release/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78+-orange.svg)](https://www.rust-lang.org)
[![Node.js](https://img.shields.io/badge/node-20+-green.svg)](https://nodejs.org)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)

**open-re** is an open-source reverse engineering platform designed for malware analysis, vulnerability research, and binary analysis. Built with modern technologies and AI-powered capabilities.

## Features

- **Multi-architecture Support**: x86_64, ARM64, MIPS, and more
- **AI-Powered Analysis**: Local (ONNX, llama.cpp) and remote (OpenAI, vLLM) LLM integration
- **Plugin System**: WASM sandboxed plugins with native opt-in
- **Collaborative Analysis**: Real-time collaboration with CRDT-based sync
- **Modern Web UI**: React 18 + TypeScript + Tailwind CSS
- **REST + gRPC API**: Full programmatic access
- **CLI Tool**: Complete command-line interface
- **Python Bindings**: Native Python client and PyO3 bindings

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
docker compose up -d
```

Access the web UI at **http://localhost:3000** and API at **http://localhost:8080**.

### Manual Installation

See [INSTALLATION.md](docs/INSTALLATION.md) for detailed instructions.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React)                        │
├─────────────────────────────────────────────────────────────┤
│                    API Gateway (Axum)                        │
├──────────────┬──────────────┬──────────────┬────────────────┤
│   Analysis   │    Plugin    │     AI       │   Storage      │
│  Pipeline    │   Registry   │  Service     │  (PostgreSQL/  │
│              │              │              │   SQLite/S3)   │
└──────────────┴──────────────┴──────────────┴────────────────┘
```

## Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Architecture Overview](docs/architecture/01-system-overview.md)
- [API Reference](http://localhost:8080/docs) (when running)

## Project Structure

```
open-re/
├── crates/                 # Rust workspace
│   ├── openre-core/        # Core types, errors, traits
│   ├── openre-config/      # Configuration management
│   ├── openre-telemetry/   # Logging, metrics, tracing, audit
│   ├── openre-storage/     # Database & object storage
│   ├── openre-queue/       # Redis Streams queue system
│   ├── openre-plugins/     # Plugin system (WASM + native)
│   ├── openre-analysis/    # Analysis pipeline & stages
│   ├── openre-ai/          # AI service (providers, prompts, tools)
│   ├── openre-api/         # HTTP/gRPC API server
│   └── openre-cli/         # Command-line interface
├── frontend/               # React/TypeScript frontend
│   ├── apps/web/           # Main web application
│   └── packages/           # Shared packages
├── python/                 # Python bindings
│   ├── openre/             # Pure Python client
│   └── openre-bindings/    # PyO3 Rust bindings
├── docker/                 # Dockerfiles & compose files
├── tests/                  # Integration & unit tests
└── docs/                   # Documentation
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `cargo test --workspace && cd frontend && pnpm test`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Community

- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Questions and ideas
- **Discord**: Real-time chat (link coming soon)

## Acknowledgments

Built with amazing open-source projects:
- [Ghidra](https://ghidra-sre.org/) - Inspiration for analysis pipeline
- [Binary Ninja](https://binary.ninja/) - Plugin architecture ideas
- [radare2](https://radare.org/) - Cross-platform support
- [ONNX Runtime](https://onnxruntime.ai/) - Local AI inference
- [llama.cpp](https://github.com/ggerganov/llama.cpp) - Local LLM inference
- [wasmtime](https://wasmtime.dev/) - WASM plugin runtime
- **Discord/Matrix**: Real-time chat (coming soon)

## License

[MIT License](LICENSE) - See LICENSE file for details.