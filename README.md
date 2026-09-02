# open-re

```text

 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
```
**Open-source Reverse Engineering & Security Platform**

[![CI](https://github.com/RXVEN-1907/open-re/workflows/CI/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org)

**open-re** is a reverse engineering and security platform. The currently working component is **openre-scan** — a lightweight standalone web security scanner. The full platform (API server, CLI, binary analysis, AI analysis, plugin system, web UI) is under active development.

---

## Current Features

### openre-scan — Standalone Web Security Scanner (Working)

A minimal, fast security assessment tool for web applications and APIs. Single binary (~7 MB), no runtime dependencies.

| Profile | Checks | Est. Duration | Use Case |
|---------|--------|---------------|----------|
| **Quick** | 6 | ~2-3s | Rapid assessment, CI/CD gates |
| **Standard** | 15 | ~10-15s | General purpose scanning |
| **Full** | 18 | ~30-60s | Comprehensive audit |

**18 Security Checks:**

| Check | Profile | Description |
|-------|---------|-------------|
| `http-headers` | Quick, Standard, Full | Server disclosure, powered-by, custom headers |
| `security-headers` | Quick, Standard, Full | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP |
| `cookie-security` | Quick, Standard, Full | Secure, HttpOnly, SameSite flags |
| `tls-certificate` | Quick, Standard, Full | Certificate validation, chain, expiry, SANs |
| `info-disclosure` | Quick, Standard, Full | Debug headers, stack traces, version info |
| `tech-fingerprint` | Quick, Standard, Full | Framework, CMS, server, library detection |
| `csp` | Standard, Full | Content Security Policy directive analysis |
| `cors` | Standard, Full | CORS misconfiguration (wildcard origin, credentials) |
| `robots-txt` | Standard, Full | robots.txt enumeration and analysis |
| `sitemap` | Standard, Full | sitemap.xml discovery |
| `dir-listing` | Standard, Full | Directory listing detection |
| `sensitive-files` | Standard, Full | 20+ common sensitive paths (.git, .env, configs, etc.) |
| `forms` | Standard, Full | GET passwords, autocomplete, CSRF tokens |
| `links` | Standard, Full | Mixed content, mailto links, external redirects |
| `scripts` | Standard, Full | Inline scripts, external resources, integrity |
| `meta-tags` | Standard, Full | Security-relevant meta tags (generator, refresh) |
| `http-methods` | Full | TRACE, PUT, DELETE, PATCH, OPTIONS |
| `ssl-config` | Full | SSL/TLS configuration placeholder (use testssl.sh/sslyze for deep analysis) |

**Output Formats:**
- **Table** (default) — Human-readable colorized table with severity indicators
- **JSON** — Structured output for automation
- **SARIF 2.1.0** — CI/CD integration (GitHub Code Scanning, Azure DevOps)

**Features:**
- Evidence-based findings (HTTP headers, response snippets, locations)
- Risk scoring: Severity (Critical/High/Medium/Low/Info) + Confidence (Very High/High/Medium/Low)
- Remediation guidance with effort/priority estimates
- Selective scanning: `--checks` and `--exclude` for custom check sets
- Custom headers: `--header` for authentication
- File output: `--output` to save results
- Cross-platform: Linux, macOS, Windows
- Privacy-focused: No telemetry, no data collection

**Interactive TUI (Experimental):**
```bash
openre-scan tui
```
- Real-time scan progress with live findings table
- Vim-style keybindings (j/k, g/G, /, ?)
- Expandable finding details with evidence viewer
- Real-time filtering by severity, category, check
- Theme support (dark/light)

---

### Core Library Crates (Working)

| Crate | Purpose |
|-------|---------|
| `openre-core` | Shared types: Finding, RiskScore, Evidence, Category, Severity, IDs |
| `openre-config` | Layered configuration (file, env, CLI) with hot-reload |
| `openre-telemetry` | Metrics, tracing, logging, audit logging |
| `openre-storage` | SQLite persistence, object storage abstraction, migrations |

---

## Roadmap (Not Yet Working)

The following components exist in the codebase but **do not currently compile or function**:

| Component | Status | Notes |
|-----------|--------|-------|
| `openre-api` | 🚧 Broken | REST/gRPC server — depends on openre-ai/openre-security-ai which have compilation errors |
| `openre-cli` | 🚧 Partial | Unified CLI — builds only with broken deps disabled; most commands require API server |
| `openre-ai` | 🚧 Broken | AI provider abstraction (OpenAI, Anthropic, vLLM, ONNX, llama.cpp) — compilation errors |
| `openre-security-ai` | 🚧 Broken | AI security analyst, grounded LLM service — compilation errors |
| `openre-plugins` | 🚧 Partial | WASM plugin runtime — crate compiles but not integrated with scanner/CLI |
| `openre-analysis` | 🚧 Not integrated | Binary analysis pipeline (ELF/PE/MachO/WASM) — exists but not wired up |
| `openre-intelligence` | 🚧 Not integrated | CVE matching, dependency analysis, finding correlation |
| `openre-queue` | 🚧 Not integrated | Distributed job queue with Redis backend |
| `openre-recon` | 🚧 Not integrated | Reconnaissance module |
| `openre-scanner` | 🚧 Not integrated | Scanner orchestration layer |
| `openre-tui` | 🚧 Not integrated | Full-screen platform TUI (separate from openre-scan TUI) |
| Frontend (React) | 🚧 Not functional | Web UI — requires API server to function |

**Target Versions:**
- **v0.2.0** — Fix AI crates, enable openre-api and openre-cli
- **v0.3.0** — Integrate binary analysis, plugin system, queue/worker
- **v0.4.0** — Web UI functional, distributed scanning
- **v1.0.0** — Stable plugin API, enterprise features

---

## Installation

### openre-scan (Working)

```bash
# Build from source
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
cargo build --release --package openre-scan
./target/release/openre-scan --help

# Or download from GitHub Releases (when published)
```

### Full Platform (Not Yet Working)

```bash
# This will NOT work until v0.2.0+
# docker compose -f docker-compose.yml up -d
```

---

## Usage

### Standalone Scanner (openre-scan)

```bash
# Quick scan (essential checks only, ~2-3s)
openre-scan scan https://example.com --profile quick

# Standard scan (recommended, ~10-15s)
openre-scan scan https://example.com --profile standard

# Full scan (all checks, ~30-60s)
openre-scan scan https://example.com --profile full

# JSON output for automation
openre-scan scan https://example.com --format json

# SARIF output for CI/CD
openre-scan scan https://example.com --format sarif --output results.sarif

# Save results to file
openre-scan scan https://example.com --output results.json

# Custom timeout and headers
openre-scan scan https://example.com --timeout 30 --header "Authorization=Bearer token"

# Filter specific checks
openre-scan scan https://example.com --checks security-headers,csp,cors

# Exclude checks
openre-scan scan https://example.com --exclude tech-fingerprint,robots-txt

# Show version
openre-scan version

# Interactive TUI (experimental)
openre-scan tui
```

### Example Output (Table Format)

```
┌────────────────────────────────────────────────────────────────────────────────┐
│ 🔍 openre-scan — Security Scan                                                 │
├────────────────────────────────────────────────────────────────────────────────┤
│ Target:           https://example.com                                          │
│ Profile:          Standard (15 checks)                                         │
└────────────────────────────────────────────────────────────────────────────────┘

📋 Checks to run:
  1. http-headers HTTP header analysis
  2. security-headers Security headers (HSTS, CSP, etc.)
  3. cookie-security Cookie security flags
  4. tls-certificate TLS certificate validation
  5. info-disclosure Debug info & version disclosure
  6. tech-fingerprint Tech stack detection
  7. csp CSP directive analysis
  8. cors CORS misconfiguration
  9. robots-txt robots.txt enumeration
 10. sitemap sitemap.xml discovery
 11. dir-listing Directory listing detection
 12. sensitive-files Sensitive file exposure (20+ paths)
 13. forms Form security (GET passwords, CSRF)
 14. links Mixed content & external links
 15. scripts Inline/external script analysis

✓ Server Header Disclosure (Info) [http-headers]
✓ Missing X-Frame-Options Header (Medium) [security-headers]
✓ Missing Content-Security-Policy (High) [security-headers]
...

┌────────────────────────────────────────────────────────────────────────────────┐
│ 📋 Scan Results                                                                │
├────────────────────────────────────────────────────────────────────────────────┤
│ Scan ID:        abc123...                                                      │
│ Duration:       2.34s                                                          │
│ Checks Run:     15                                                             │
│ Findings:       7                                                              │
└────────────────────────────────────────────────────────────────────────────────┘

📊 Findings by Severity:
  🔴 HIGH:     2
  🟡 MEDIUM:   3
  🔵 INFO:     2
```

---

## Workflows

### Web Scan Workflow (Working)

```bash
# 1. Quick reconnaissance
openre-scan scan https://target.com --profile quick --format json > quick.json

# 2. Standard assessment
openre-scan scan https://target.com --profile standard --output standard.json

# 3. Full audit for compliance
openre-scan scan https://target.com --profile full --format sarif --output audit.sarif

# 4. CI/CD integration
openre-scan scan https://staging.example.com --profile quick --format sarif --output results.sarif
# Upload results.sarif to GitHub Code Scanning / SARIF viewer
```

### Binary Analysis Workflow (Not Yet Working — Roadmap v0.3.0)

```bash
# Planned commands (do not work yet):
# openre analysis create my-project --file ./binary --type elf
# openre analysis run <analysis-id>
# openre analysis show <analysis-id> --format json
```

### AI-Assisted Analysis Workflow (Not Yet Working — Roadmap v0.2.0)

```bash
# Planned commands (do not work yet):
# openre ai analyze <finding-id>
# openre ai explain <finding-id>
# openre ai remediate <finding-id>
# openre ai correlate --project my-project
```

### Investigation Workflow (Not Yet Working — Roadmap v0.3.0)

```bash
# Planned commands (do not work yet):
# openre investigate start --finding <finding-id>
# openre map generate --project my-project
# openre attack-paths find --project my-project
```

---

## Configuration

### openre-scan

Works without configuration. Options via CLI flags (see `--help`).

No config file support yet (planned).

### Platform Config (Not Yet Functional)

When the API server works, configuration will be at `~/.config/openre/config.toml`:

```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "sqlite://data/openre.db"

[redis]
url = "redis://localhost:6379"

[queue]
worker_count = 4
max_retries = 3

[plugins]
enabled = true
registry_url = "https://plugins.openre.dev"
auto_update = false

[ai]
provider = "ollama"
model = "codellama:13b"
base_url = "http://localhost:11434"

[telemetry]
metrics_port = 9090
log_level = "info"
```

---

## Security & Legal

**Authorization Required**: Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

**No Telemetry**: open-re does not collect or transmit any usage data without explicit opt-in.

**Safe Design**:
- No shell command execution
- Path traversal prevention
- Network request validation (timeouts, redirect limits)
- Memory-safe Rust implementation
- Input validation at all boundaries

**Vulnerability Reporting**: See [SECURITY.md](SECURITY.md) for responsible disclosure process.

---

## Performance (openre-scan)

| Metric | Value |
|--------|-------|
| Binary Size | ~7 MB (release, stripped) |
| Startup Time | < 50ms cold start |
| Memory Usage | 10-20 MB base footprint |
| Quick Scan | ~2-3 seconds |
| Standard Scan | ~10-15 seconds |
| Full Scan | ~30-60 seconds |

---

## Project Structure

```
open-re/
├── crates/
│   ├── openre-core/         # Shared types (WORKING)
│   ├── openre-config/       # Configuration (WORKING)
│   ├── openre-telemetry/    # Observability (WORKING)
│   ├── openre-storage/      # Persistence (WORKING)
│   ├── openre-queue/        # Job queue (NOT INTEGRATED)
│   ├── openre-scan/         # Standalone scanner (WORKING)
│   ├── openre-scanner/      # Scanner orchestration (NOT INTEGRATED)
│   ├── openre-recon/        # Reconnaissance (NOT INTEGRATED)
│   ├── openre-analysis/     # Binary analysis (NOT INTEGRATED)
│   ├── openre-ai/           # AI providers (BROKEN)
│   ├── openre-security-ai/  # AI analyst (BROKEN)
│   ├── openre-intelligence/ # CVE/correlation (NOT INTEGRATED)
│   ├── openre-plugins/      # WASM plugins (PARTIAL)
│   ├── openre-api/          # API server (BROKEN)
│   ├── openre-cli/          # Unified CLI (PARTIAL)
│   ├── openre-tui/          # Platform TUI (NOT INTEGRATED)
│   └── sentinel/            # Security utilities
├── frontend/                # React web UI (REQUIRES API)
├── plugins/
│   └── security/            # 18 security plugins (WASM source)
├── docker/                  # Dockerfiles
├── docker-compose.yml       # Full stack (REQUIRES API)
└── docs/                    # Architecture docs
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
# Install pre-commit hooks
cargo install pre-commit
pre-commit install

# Run checks locally
cargo fmt --check && cargo clippy --workspace
cargo test --workspace  # Note: some crates have failing tests
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with:
- [Rust](https://www.rust-lang.org/) — Memory-safe systems programming
- [reqwest](https://github.com/seanmonstar/reqwest) — HTTP client
- [clap](https://github.com/clap-rs/clap) — CLI parsing
- [ratatui](https://ratatui.rs/) — TUI framework
- [select](https://github.com/utkarshkukreti/select.rs) — HTML parsing
- [tabled](https://github.com/nu11ptr/tabled) — Table formatting
- [tokio](https://tokio.rs/) — Async runtime
- [sqlx](https://github.com/launchbadge/sqlx) — Database toolkit
- [tracing](https://github.com/tokio-rs/tracing) — Observability

---

**Note**: This is the open-re platform repository. The standalone `openre-scan` tool works independently. The full platform with AI, plugins, web UI, API server, and binary analysis is under active development — see the Roadmap above for what's coming.