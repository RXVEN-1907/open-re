# Installation Guide

## openre-scan — Lightweight Web Security Scanner

Single binary (~7 MB), zero dependencies, runs anywhere.

> **Note**: Pre-built binaries, Cargo package, Homebrew tap, and Docker images are **not yet published**. Build from source for now (see [Build from Source](#build-from-source)).

---

## Quick Install (Not Yet Available)

The following installation methods are **planned for v0.2.0**:

### Linux (x86_64) — *Coming Soon*

```bash
# Not yet available
# curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-linux-x86_64
# chmod +x openre-scan
# ./openre-scan --help
```

### macOS (x86_64 / Apple Silicon) — *Coming Soon*

```bash
# Not yet available
# curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-macos-x86_64
# chmod +x openre-scan
```

### Windows (x86_64) — *Coming Soon*

```powershell
# Not yet available
# Invoke-WebRequest -Uri "https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-windows-x86_64.exe" -OutFile "openre-scan.exe"
# .\openre-scan.exe --help
```

---

## Package Managers — *Coming Soon*

### Cargo (Rust)

```bash
# Not yet published to crates.io
# cargo install openre-scan
```

### Homebrew (macOS / Linux)

```bash
# Not yet available
# brew tap rxven-1907/tap
# brew install openre-scan
```

### Docker

```bash
# Not yet published to GHCR
# docker pull ghcr.io/rxven-1907/openre-scan:latest
```

---

## Build from Source (Current Method)

### Prerequisites

-   **Rust 1.78+** (install via `rustup.rs`)
-   **Git**

### Build Steps

```bash
# Clone repository
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re

# Build release binary (standalone scanner, works offline)
cargo build --release -p openre-scan

# Binary at ./target/release/openre-scan
./target/release/openre-scan --help

# Build unified CLI (requires API server for most commands)
cargo build --release -p openre-cli

# Binary at ./target/release/openre
./target/release/openre --help
```

### With TUI (Experimental, enabled by default)

```bash
# TUI is enabled by default in openre-scan
cargo build --release -p openre-scan
./target/release/openre-scan tui
```

### Minimal Build (No TUI)

```bash
cargo build --release -p openre-scan --no-default-features
```

---

## Platform-Specific Notes

### Linux (Ubuntu/Debian)

```bash
# Install Rust
curl --proto '=HTTPS' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install build dependencies
sudo apt update && sudo apt install -y build-essential pkg-config libssl-dev

# Build
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
cargo build --release -p openre-scan
```

### macOS

```bash
# Install Rust
curl --proto '=HTTPS' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Or via Homebrew
# brew install rust

# Build
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
cargo build --release -p openre-scan
```

### Windows

**Option 1: WSL2 (Recommended)**

1.  Install WSL2 + Ubuntu from Microsoft Store
2.  Follow Linux instructions above

**Option 2: Native (MSVC)**

1.  Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with "C++ build tools"
2.  Install Rust via [rustup-init.exe](https://rustup.rs)
3.  Build in Developer Command Prompt

```cmd
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
cargo build --release -p openre-scan
```

---

## First Scan

```bash
# Quick scan (6 checks, ~2-3s)
./target/release/openre-scan scan https://example.com --profile quick

# Standard scan (15 checks, ~10-15s) — Recommended
./target/release/openre-scan scan https://example.com --profile standard

# Full scan (18 checks, ~30-60s)
./target/release/openre-scan scan https://example.com --profile full

# JSON output for automation
./target/release/openre-scan scan https://example.com --format json

# SARIF for GitHub Code Scanning / CI/CD
./target/release/openre-scan scan https://example.com --format sarif --output results.sarif

# Save to file
./target/release/openre-scan scan https://example.com --output results.json
```

---

## Configuration

No config file needed. All options via CLI:

```bash
# Custom timeout (default: 10s)
openre-scan scan https://example.com --timeout 30

# Follow redirects (default: no)
openre-scan scan https://example.com --follow-redirects

# Custom headers (e.g., auth)
openre-scan scan https://example.com --header "Authorization=Bearer token"

# Select specific checks (comma-separated)
openre-scan scan https://example.com --checks security-headers,csp,cors

# Exclude checks (comma-separated)
openre-scan scan https://example.com --exclude tech-fingerprint,robots-txt

# Disable progress bar
openre-scan scan https://example.com --no-progress

# Verbose logging
openre-scan -v scan https://example.com
```

---

## AI Features

**Not available in openre-scan standalone binary.**

AI-powered analysis (explain, remediate, correlate) requires:
1. Running the full platform (`openre-api` server with AI provider configured)
2. Using the `openre` CLI or `openre analyst` commands

See [README.md](../README.md#unified-cli-openre--requires-api-server) for platform AI usage.

> **The scanner works fully without any API keys.** AI is an optional platform feature.

---

## Verifying Installation

```bash
# Check version
./target/release/openre-scan --version
# openre-scan 0.1.0

# Show help
./target/release/openre-scan --help

# Test scan (safe public target)
./target/release/openre-scan scan https://httpbin.org --profile quick
```

---

## Updating

### Source Build

```bash
cd open-re
git pull origin main
cargo build --release -p openre-scan
cargo build --release -p openre-cli
```

### Binary Download — *Coming Soon*

```bash
# Not yet available
# curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-linux-x86_64
# chmod +x openre-scan
```

---

## Uninstalling

### Binary

```bash
rm openre-scan  # or openre-scan.exe
```

### Cargo (when published)

```bash
# cargo uninstall openre-scan
```

### Source

```bash
cd ..
rm -rf open-re/
```

---

## Troubleshooting

### Build Errors

| Error | Fix |
| ------- | ----- |
| `linker 'cc' not found` | Install build tools: `sudo apt install build-essential` (Debian/Ubuntu), `xcode-select --install` (macOS) |
| `openssl` missing | `sudo apt install libssl-dev pkg-config` (Debian/Ubuntu) |
| Rust version too old | `rustup update` |

### Runtime Issues

| Issue | Fix |
| ------- | ----- |
| `Permission denied` | `chmod +x openre-scan` |
| `Certificate verification failed` | Target uses self-signed cert — use `--timeout` and verify manually |
| `Connection timeout` | Increase `--timeout` or check network/firewall |
| `Too many redirects` | Use `--max-redirects 0` to disable |

### Getting Help

```bash
openre-scan --help
openre-scan scan --help
```

-   **GitHub Issues**: Bug reports and feature requests
-   **GitHub Discussions**: Questions and ideas
-   **Security**: <security@open-re.org>

---

## Requirements Summary

| Component | Minimum | Recommended |
| ----------- | --------- | ------------- |
| Rust | 1.78 | Latest stable |
| OS | Linux/macOS/Windows | Any |
| Arch | x86_64 | x86_64 (ARM64 coming in v0.2.0) |
| Memory | 10 MB | 20 MB |
| Disk | 7 MB | 10 MB |