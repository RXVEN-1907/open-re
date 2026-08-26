# openre-scan

[![CI](https://github.com/RXVEN-1907/open-re/workflows/CI/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/ci.yml)
[![Release](https://github.com/RXVEN-1907/open-re/workflows/Release/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.78+-orange.svg)](https://www.rust-lang.org)

**openre-scan** is a lightweight, fast security assessment tool for web applications and APIs. It performs comprehensive security scanning with zero external dependencies and optional AI-enhanced analysis.

## Features

-   **Zero Dependencies**: Single ~7 MB binary, no runtime requirements
-   **Three Scan Profiles**: Quick (6 checks), Standard (15 checks), Full (18 checks)
-   **Multiple Output Formats**: Table (human-readable), JSON (machine-readable), SARIF (CI/CD integration)
-   **18 Security Checks**: HTTP headers, TLS/SSL, cookies, CSP, CORS, information disclosure, technology fingerprinting, robots.txt, sitemap, directory listing, sensitive files, forms, links, scripts, meta tags, HTTP methods, SSL/TLS configuration
-   **Evidence-Based Findings**: Each finding includes supporting evidence (HTTP headers, response snippets, locations)
-   **Risk Scoring**: Severity (Critical/High/Medium/Low/Info) and Confidence (Very High/High/Medium/Low) ratings
-   **Remediation Guidance**: Actionable steps with effort/priority estimates
-   **Cross-Platform**: Linux, macOS, Windows
-   **Privacy-Focused**: No telemetry, no data collection
-   **AI-Optional**: Works fully without AI; AI enhancement available via open-re platform

## Quick Start

### Install Binary (Recommended)

```bash
# Download latest release from GitHub Releases
# Or build from source:
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
Cargo build --release --package openre-scan
./target/release/openre-scan --help
```

### Docker

```bash
Docker run --rm ghcr.io/rxven-1907/openre-scan:latest scan https://example.com --profile standard
```

## Usage

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

# Show version
openre-scan version
```

### Scan Profiles

| Profile | Checks | Duration | Use Case |
| --------- | -------- | ---------- | ---------- |
| Quick | 6 | ~2-3s | Rapid assessment, CI/CD gates |
| Standard | 15 | ~10-15s | General purpose scanning |
| Full | 18 | ~30-60s | Comprehensive audit |

### Checks Included

**Quick Profile:**

-   HTTP Headers analysis
-   Security Headers (8 headers checked)
-   Cookie Security (Secure, HttpOnly, SameSite)
-   TLS Certificate validation
-   Information Disclosure (debug headers, server version)
-   Technology Fingerprinting

**Standard Profile (includes Quick):**

-   Content Security Policy analysis
-   CORS Configuration
-   Robots.txt enumeration
-   Sitemap.XML discovery
-   Directory Listing detection
-   Sensitive File exposure (20+ common paths)
-   Form Analysis (GET passwords, autocomplete, CSRF)
-   Link Analysis (mixed content, mailto)
-   Script Analysis (inline scripts, external resources)
-   Meta Tags analysis

**Full Profile (includes Standard):**

-   HTTP Methods (TRACE, PUT, DELETE, etc.)
-   SSL/TLS Configuration deep dive

## Output Formats

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

Static Analysis Results Interchange Format for CI/CD integration (GitHub Code Scanning, Azure DevOps, etc.).

## Example Output

```
🔍 openre-scan - Lightweight Security Scanner
Target: https://example.com
Profile: Standard

▶ Running 15 checks
  → HTTP-headers
  → security-headers
  → cookie-security
  → TLS-certificate
  → info-disclosure
  → tech-fingerprint
  → robots-txt
  → sitemap
  → dir-listing
  → sensitive-files
  → forms
  → links
  → scripts
  → meta-tags
  → CSP
  → CORS

📋 Scan Results
═══════════════════════════════════════════════════════════════════════════════
Scan ID: 5c56afdb-c9a0-4cb0-aad8-9f09ee9da45c | Duration: 0.26s | Checks: 15 | Findings: 10
════════════════════════════════════════════════════════════════════════════════
+----------+------------+--------------------------+---------------------------------------------+------------------+
| Severity | Confidence | Category                 | Title                                       | Check            |
+----------+------------+--------------------------+---------------------------------------------+------------------+
| HIGH     | High       | SecurityMisconfiguration | Missing Content-Security-Policy Header      | security-headers |
| HIGH     | High       | SecurityMisconfiguration | Missing Strict-Transport-Security Header    | security-headers |
| MEDIUM   | High       | SecurityMisconfiguration | Missing X-Frame-Options Header              | security-headers |
| MEDIUM   | High       | SecurityMisconfiguration | Missing X-Content-Type-Options Header       | security-headers |
| INFO     | High       | InformationDisclosure    | Server Header Disclosure                    | HTTP-headers     |
+----------+------------+--------------------------+---------------------------------------------+------------------+

📊 Summary by Severity
  High: 2
  Medium: 2
  Low: 0
  Info: 1
```

## Installation

### Requirements

-   Rust 1.78+ (for building from source)
-   No runtime dependencies for the binary

### Download Release Binary (Recommended)

Download the latest release from [GitHub Releases](https://github.com/RXVEN-1907/open-re/releases):

```bash
# Linux x86_64
curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-linux-x86_64
chmod +x openre-scan

# macOS x86_64
curl -L -o openre-scan https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-macos-x86_64
chmod +x openre-scan
```

### Build from Source

```bash
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
Cargo build --release --package openre-scan
# Binary at ./target/release/openre-scan (~7 MB)
```

### Minimal Build (CLI Only)

```bash
Cargo build --release --package openre-scan --no-default-features
```

### With TUI (Experimental)

```bash
Cargo build --release --package openre-scan --features tui
./target/release/openre-scan tui
```

## Configuration

openre-scan works without configuration. Optional configuration via:

-   Command-line flags (see `--help`)
-   Future: TOML config file (planned)

## Supported Targets

-   **Web Applications**: HTTP/HTTPS endpoints
-   **APIs**: REST, GraphQL endpoints
-   **Local Development**: localhost, private networks
-   **Any HTTP-speaking service**

## Vulnerability Categories Detected

| Category | Examples |
| ---------- | ---------- |
| Security Misconfiguration | Missing security headers, open CORS, directory listing |
| Information Disclosure | Server version, debug headers, sensitive files, technology stack |
| Injection Risks | Form analysis (GET passwords), missing CSRF |
| Cryptographic Issues | Missing HSTS, weak TLS configuration |
| Content Security | Missing/weak CSP, inline scripts |

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    curl -L -o openre-scan HTTPS://GitHub.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-Linux-x86_64
    chmod +x openre-scan
    ./openre-scan scan HTTPS://staging.example.com --format sarif --output results.sarif
- name: Upload SARIF
  uses: GitHub/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Performance

| Metric | Value |
| -------- | ------- |
| Binary Size | ~7 MB (release, stripped) |
| Startup Time | < 50ms cold start |
| Memory Usage | 10-20 MB base footprint |
| Quick Scan | ~2-3 seconds |
| Standard Scan | ~10-15 seconds |
| Full Scan | ~30-60 seconds |

## Security & Legal

**Authorization Required**: Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

**No Telemetry**: openre-scan does not collect or transmit any usage data.

**Safe Design**:

-   No Shell command execution
-   Path traversal prevention
-   Network request validation (timeouts, redirect limits)
-   Memory-safe Rust implementation

## Architecture

openre-scan is the standalone CLI component of the larger **open-re** platform. The platform includes:

-   **openre-scan** (this tool) - Lightweight standalone scanner
-   **openre-core** - Core types, finding model, risk engine
-   **openre-intelligence** - CVE matching, dependency analysis, correlation
-   **openre-security-ai** - AI-enhanced analysis (optional)
-   **openre-plugins** - WASM plugin system (planned)
-   **openre-api** - REST/gRPC API server (planned)
-   **Frontend** - Web UI (planned)

## Contributing

## Current Status (v0.1.0)

### ✅ Working Features

-   **CLI Scanner**: Fully functional with quick/standard/full profiles
-   **18 Security Checks**: HTTP headers, TLS, cookies, security headers, CSP, CORS, info disclosure, tech fingerprint, robots.txt, sitemap, directory listing, sensitive files, forms, links, scripts, meta tags, HTTP methods, SSL/TLS config
-   **Output Formats**: Table (human-readable), JSON (machine-readable), SARIF 2.1.0 (CI/CD)
-   **Filtering**: `--checks` and `--exclude` for selective scanning
-   **Custom Headers**: `--header` for authentication and custom requests
-   **File Output**: `--output` to save results
-   **Clean Installation**: Single ~7 MB binary, no runtime dependencies

### ⚠️ Experimental Features

-   **TUI Mode**: Interactive terminal UI (`--features tui`, then `openre-scan tui`) - functional but not extensively tested

### 🚧 Known Limitations

-   No configuration file support yet (planned for v0.2.0)
-   No authentication handling beyond custom headers
-   No recursive crawling/spidering
-   No JavaScript rendering/analysis
-   AI-enhanced analysis not included in standalone binary (part of open-re platform)
-   Some dependency vulnerabilities in transitive dependencies (documented in SECURITY.md)

### 🔒 Security Notice

**Authorization Required**: Only scan targets you own or have explicit written permission to test. Unauthorized scanning may violate laws and terms of service.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

1.  Fork the repository
2.  Create a feature branch
3.  Make your changes
4.  Run tests: `Cargo test --package openre-scan`
5.  Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

Built with:

-   [Rust](https://www.rust-lang.org/) - Memory-safe systems programming
-   [reqwest](https://github.com/seanmonstar/reqwest) - HTTP client
-   [clap](https://github.com/clap-rs/clap) - CLI parsing
-   [ratatui](https://ratatui.rs/) - TUI framework (experimental)
-   [select](https://github.com/utkarshkukreti/select.rs) - HTML parsing
-   [tabled](https://github.com/nu11ptr/tabled) - Table formatting

---

**Note**: This is the standalone `openre-scan` tool. The full `open-re` platform with AI, plugins, web UI, and collaborative features is under active development. See the [open-re repository](https://github.com/RXVEN-1907/open-re) for the complete platform roadmap.
