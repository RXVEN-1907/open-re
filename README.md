# openre

```
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚══════╝╚══════╝╚════════╝         ╚══════╝╚══════╝
```

**Open-source Reverse Engineering & Security Platform**

Modern security tools + LLMs for automated analysis of binaries, websites, APIs, and applications — discover vulnerabilities, generate reproducible PoC exploits, and get actionable remediation guidance.

All in a single cross-platform binary. No database, no server, no Docker, no external dependencies. Works like `nmap`.

---

## Quick Start

### Install (Pre-built Binaries)

```bash
# Linux / macOS / FreeBSD
curl -L https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-$(uname -s)-$(uname -m) -o openre
chmod +x openre

# Windows (PowerShell)
irm https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-windows-x86_64.exe -o openre.exe
```

### Build from Source

```bash
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
cargo build --release --package openre --package openre-scan --package openre-tui
# Binaries at ./target/release/
```

---

## What is it?

**openre** is a unified platform combining:
- **Web vulnerability scanning** (18+ security checks)
- **Binary analysis** (ELF, PE, Mach-O, WASM with CFG/DFG recovery)
- **AI-powered vulnerability research** (local: Ollama, llama.cpp, ONNX | cloud: OpenAI, Anthropic)
- **PoC exploit generation** & **actionable remediation guidance**

All in a single cross-platform binary (~15-20MB). No database, no server, no Docker required.

---

## Usage

### Web Security Scanning

```bash
# Quick scan (~2-3s) — essential checks for CI/CD
openre scan https://example.com --profile quick

# Standard scan (~10-15s) — recommended for general use
openre scan https://example.com --profile standard

# Full audit (~30-60s) — comprehensive
openre scan https://example.com --profile full --format sarif --output audit.sarif
```

### Binary Analysis

```bash
# Analyze any binary (ELF, PE, Mach-O, WASM)
openre analyze ./binary --format json

# With AI-enhanced analysis
openre ai "analyze this function for vulnerabilities" --binary ./binary
```

### AI-Powered Features

```bash
# Generate PoC exploit for a finding
openre exploit <finding-id>

# Get actionable remediation guidance
openre remediate <finding-id>

# Chat with AI about vulnerabilities
openre ai "explain this buffer overflow" --binary ./vulnerable_binary
```

### Interactive TUI

```bash
# Full-screen terminal UI with 10 panels
openre tui
```

**TUI Panels:** Projects, Jobs, Scans, Reverse Engineering, Findings, Workflows, AI, Plugins, Logs, Reports

---

## 18 Security Checks (Web Scanner)

| Check | Quick | Standard | Full |
|-------|-------|----------|------|
| HTTP Headers | ✅ | ✅ | ✅ |
| Security Headers (HSTS, CSP, etc.) | ✅ | ✅ | ✅ |
| Cookie Security | ✅ | ✅ | ✅ |
| TLS Certificate | ✅ | ✅ | ✅ |
| Information Disclosure | ✅ | ✅ | ✅ |
| Technology Fingerprinting | ✅ | ✅ | ✅ |
| CSP Analysis | | ✅ | ✅ |
| CORS Configuration | | ✅ | ✅ |
| robots.txt | | ✅ | ✅ |
| sitemap.xml | | ✅ | ✅ |
| Directory Listing | | ✅ | ✅ |
| Sensitive Files (20+ paths) | | ✅ | ✅ |
| Form Analysis | | ✅ | ✅ |
| Link Analysis | | ✅ | ✅ |
| Script Analysis | | ✅ | ✅ |
| Meta Tags | | ✅ | ✅ |
| HTTP Methods | | | ✅ |
| SSL/TLS Configuration | | | ✅ |

---

## Cross-Platform Support

| OS | Architectures |
|----|---------------|
| Linux | x86_64, aarch64, armv7 |
| macOS | x86_64, arm64 |
| Windows | x86_64 |
| FreeBSD | x86_64, aarch64 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              open-re Platform                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   CLI (openre)   │  │  TUI (openre-tui)  │  │  Library API  │  │  Plugins     │    │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │
│         │                 │                 │                 │             │
│         └─────────────────┼─────────────────┼─────────────────┘             │
│                           ▼                 ▼                               │
│              ┌─────────────────────────────────────────┐                   │
│              │           openre-core                   │                   │
│              │  Types, Errors, Traits, Results, IDs   │                   │
│              └──────────────────┬──────────────────────┘                   │
│                                 │                                         │
│        ┌────────────────────────┼────────────────────────┐                │
│        ▼                        ▼                        ▼                │
│ ┌─────────────┐         ┌─────────────┐         ┌─────────────┐          │
│ │openre-scan  │         │openre-analysis│        │openre-ai    │          │
│ │ Web Scanner │         │ Binary Analyzer│        │ AI Engine   │          │
│ │ 18+ checks  │         │ ELF/PE/Mach-O/│        │ Local/Cloud │          │
│ │ SARIF/JSON  │         │ WASM + CFG/DFG│        │ LLM + RAG   │          │
│ └──────┬──────┘         └──────┬──────┘         └──────┬──────┘          │
│        │                       │                       │                  │
│        └───────────────────────┼───────────────────────┘                  │
│                                ▼                                         │
│                 ┌────────────────────────┐                               │
│                 │  openre-intelligence   │                               │
│                 │  Coordinator Agent     │                               │
│                 │  Vuln Research → PoC   │                               │
│                 │  Exploit Gen → Remediate│                              │
│                 └────────────────────────┘                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## AI Providers

| Type | Providers |
|------|-----------|
| **Local** | Ollama, llama.cpp, ONNX Runtime (CPU/CUDA/CoreML) |
| **Cloud** | OpenAI, Anthropic, vLLM |
| **Hybrid** | Local-first with cloud fallback |

---

## Output Formats

- **table** (default) — Human-readable colored tables
- **json** — For automation and scripting
- **sarif** — CI/CD integration (GitHub Code Scanning, Azure DevOps)
- **yaml** — For configuration

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    ./openre scan https://staging.example.com --profile quick --format sarif --output results.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Security

Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

No telemetry. No data collection. Ever.
