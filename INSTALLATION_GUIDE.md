# Installation Guide

## openre-scan — Lightweight Web Security Scanner

Single binary (~7 MB), zero dependencies, runs anywhere.

---

## Quick Install (Recommended)

### Linux (x86_64)

```bash
curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-linux-x86_64
chmod +x openre-scan
./openre-scan --help
```

### macOS (x86_64 / Apple Silicon)

```bash
# Intel Mac
curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-macos-x86_64
chmod +x openre-scan

# Apple Silicon (coming soon)
# curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-macos-aarch64
chmod +x openre-scan
```

### Windows (x86_64)

```powershell
# PowerShell
Invoke-WebRequest -Uri "https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-windows-x86_64.exe" -OutFile "openre-scan.exe"
.\openre-scan.exe --help
```

### Verify Download

```bash
# Download checksum
curl -L -o openre-scan.sha256 https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-linux-x86_64.sha256

# Verify
sha256sum -C openre-scan.sha256
```

---

## Package Managers

### Cargo (Rust)

```bash
Cargo install openre-scan
openre-scan --help
```

### Homebrew (macOS / Linux)

```bash
brew tap rxven-1907/tap
brew install openre-scan
```

### Docker

```bash
# Pull image
Docker pull ghcr.io/rxven-1907/openre-scan:latest

# Run scan
Docker run --rm ghcr.io/rxven-1907/openre-scan:latest scan https://example.com --profile standard

# With output file
Docker run --rm -v $(pwd):/data ghcr.io/rxven-1907/openre-scan:latest \
  scan https://example.com --format sarif --output /data/results.sarif
```

---

## Build from Source

### Prerequisites

-   **Rust 1.78+** (install via `rustup.rs`)
-   **Git**

### Build Steps

```bash
# Clone repository
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re

# Build release binary (CLI only)
Cargo build --release -p openre-scan

# Binary at ./target/release/openre-scan
./target/release/openre-scan --help
```

### With TUI (Experimental)

```bash
Cargo build --release -p openre-scan --features tui
./target/release/openre-scan tui
```

### Minimal Build (No Default Features)

```bash
Cargo build --release -p openre-scan --no-default-features
```

---

## Platform-Specific Notes

### Linux (Ubuntu/Debian)

```bash
# Install Rust
curl --proto '=HTTPS' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.Cargo/env

# Build
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
Cargo build --release -p openre-scan
```

### macOS

```bash
# Install Rust
brew install Rust

# Or via rustup
curl --proto '=HTTPS' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.Cargo/env

# Build
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
Cargo build --release -p openre-scan
```

### Windows

**Option 1: WSL2 (Recommended)**

1.  Install WSL2 + Ubuntu from Microsoft Store
2.  Follow Linux instructions above

**Option 2: Native (MSVC)**

1.  Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) with "C++ build tools"
2.  Install Rust via [rustup-init.exe](https://rustup.rs)
3.  Build in Developer Command Prompt

---

## First Scan

```bash
# Quick scan (6 checks, ~2-3s)
openre-scan scan https://example.com --profile quick

# Standard scan (15 checks, ~10-15s) — Recommended
openre-scan scan https://example.com --profile standard

# Full scan (18 checks, ~30-60s)
openre-scan scan https://example.com --profile full

# JSON output for automation
openre-scan scan https://example.com --format json

# SARIF for GitHub Code Scanning / CI/CD
openre-scan scan https://example.com --format sarif --output results.sarif

# Save to file
openre-scan scan https://example.com --output results.json
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

# Select specific checks
openre-scan scan https://example.com --checks http-headers,security-headers

# Exclude slow checks
openre-scan scan https://example.com --exclude sensitive-files

# Disable progress bar
openre-scan scan https://example.com --no-progress

# Verbose logging
openre-scan -v scan https://example.com
```

---

## AI Features (Optional)

Requires API key for OpenAI, Anthropic, or vLLM:

```bash
export OPENAI_API_KEY=sk-...

# Explain findings
openre-scan scan https://example.com --profile standard --ai explain

# Generate remediation
openre-scan scan https://example.com --profile standard --ai remediate

# Correlate findings
openre-scan scan https://example.com --profile standard --ai correlate
```

> **AI is optional**. The scanner works fully without any API keys.

---

## Verifying Installation

```bash
# Check version
openre-scan --version
# openre-scan 0.1.0

# Show help
openre-scan --help

# Test scan (safe public target)
openre-scan scan https://httpbin.org --profile quick
```

---

## Updating

### Binary Download

```bash
# Re-download latest release
curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-linux-x86_64
chmod +x openre-scan
```

### Cargo

```bash
Cargo install --force openre-scan
```

### Homebrew

```bash
brew upgrade openre-scan
```

### Source

```bash
cd open-re
git pull origin main
Cargo build --release -p openre-scan
```

---

## Uninstalling

### Binary

```bash
rm openre-scan  # or openre-scan.exe
```

### Cargo

```bash
Cargo uninstall openre-scan
```

### Homebrew

```bash
brew uninstall openre-scan
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
| `openssl` missing | `sudo apt install libssl-dev pkg-config` |
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
| Arch | x86_64 | x86_64 (ARM64 coming) |
| Memory | 10 MB | 20 MB |
| Disk | 7 MB | 10 MB |
