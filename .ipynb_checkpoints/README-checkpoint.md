# openre-scan

```
 ██████╗ ██████╗ ███████╗███╗   ██╗         ██████╗ ███████╗
██╔═══██╗██╔══██╗██╔════╝████╗  ██║         ██╔══██╗██╔════╝
██║   ██║██████╔╝█████╗  ██╔██╗ ██║ ██████╗ ██████╔╝█████╗
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║ ╚═════╝ ██╔══██╗██╔══╝
╚██████╔╝██║     ███████╗██║ ╚████║         ██║  ██║███████╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝         ╚═╝  ╚═╝╚══════╝
```

**Lightning-fast web security scanner for developers and security professionals**

[![CI](https://github.com/RXVEN-1907/open-re/actions/workflows/ci.yml/badge.svg)](https://github.com/RXVEN-1907/open-re/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org)

---

## What is it?

**openre-scan** is a standalone, zero-dependency web security scanner. Single binary (~7 MB), no runtime dependencies, no database, no server, no Docker. Runs everywhere: Linux, macOS, Windows, FreeBSD — on x86_64, aarch64, armv7.

Designed for:
- **Developers** — Quick security checks in CI/CD pipelines
- **Security professionals** — Rapid reconnaissance and auditing
- **Anyone** who needs to know if their web app has basic security headers

---

## Install

```bash
# Download release (recommended)
curl -L https://github.com/RXVEN-1907/open-re/releases/latest/download/openre-scan-$(uname -s)-$(uname -m) -o openre-scan
chmod +x openre-scan

# Or build from source
git clone https://github.com/RXVEN-1907/open-re.git
cd open-re
cargo build --release --package openre-scan
# Binary at ./target/release/openre-scan
```

---

## Quick Start

```bash
# Quick scan (~2-3s) — essential checks for CI/CD
openre-scan scan https://example.com --profile quick

# Standard scan (~10-15s) — recommended for general use
openre-scan scan https://example.com --profile standard

# Full audit (~30-60s) — comprehensive
openre-scan scan https://example.com --profile full --format sarif --output audit.sarif
```

---

## Scan Profiles

| Profile | Checks | Time | Use Case |
|---------|--------|------|----------|
| **Quick** | 6 | ~2-3s | CI/CD gates, rapid assessment |
| **Standard** | 15 | ~10-15s | General purpose (recommended) |
| **Full** | 18 | ~30-60s | Comprehensive audit |

---

## 18 Security Checks

```
http-headers        → Server disclosure, powered-by, custom headers
security-headers    → HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
                      Referrer-Policy, Permissions-Policy, COOP, CORP
cookie-security     → Secure, HttpOnly, SameSite flags
tls-certificate     → Certificate validation, chain, expiry, SANs
info-disclosure     → Debug headers, stack traces, version info
tech-fingerprint    → Framework, CMS, server, library detection
csp                 → Content Security Policy directive analysis
cors                → CORS misconfiguration (wildcard origin, credentials)
robots-txt          → robots.txt enumeration and analysis
sitemap             → sitemap.xml discovery
dir-listing         → Directory listing detection
sensitive-files     → 20+ common sensitive paths (.git, .env, configs, etc.)
forms               → GET passwords, autocomplete, CSRF tokens
links               → Mixed content, mailto links, external redirects
scripts             → Inline scripts, external resources, integrity
meta-tags           → Security-relevant meta tags (generator, refresh)
http-methods        → TRACE, PUT, DELETE, PATCH, OPTIONS (Full only)
ssl-config          → SSL/TLS configuration placeholder (Full only)
```

---

## Output Formats

| Format | Use Case |
|--------|----------|
| **table** (default) | Human-readable colorized table |
| **json** | Automation, scripting |
| **sarif** | CI/CD integration (GitHub Code Scanning, Azure DevOps) |

```bash
# SARIF for GitHub Code Scanning
openre-scan scan https://example.com --format sarif --output results.sarif

# JSON for automation
openre-scan scan https://example.com --format json > results.json
```

---

## Example Output

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 🔍 openre-scan — Security Scan                                              │
├────────────────────────────────────────────────────────────────────────────┤
│ Target:              https://example.com                                    │
│ Profile:             Standard (15 checks)                                   │
└────────────────────────────────────────────────────────────────────────────┘

  ✓ Server Header Disclosure (Info) [http-headers]
  ✓ Missing X-Frame-Options Header (Medium) [security-headers]
  ✓ Missing Content-Security-Policy (High) [security-headers]
  ...

┌────────────────────────────────────────────────────────────────────────────┐
│ 📋 Scan Results                                                              │
├────────────────────────────────────────────────────────────────────────────┤
│ Scan ID:        abc123...                                                    │
│ Duration:       2.34s                                                        │
│ Checks Run:     15                                                           │
│ Findings:       7                                                            │
└────────────────────────────────────────────────────────────────────────────┘

📊 Findings by Severity:
  🔴 HIGH:     2
  🟡 MEDIUM:   3
  🔵 LOW:      1
  ⚪ INFO:     1
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     openre-scan                              │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ HTTP Client  │  │ Check Engine │  │ Output Formatter │   │
│  │ (reqwest)    │──▶│ (18 checks)  │──▶│ (table/json/sarif)│   │
│  └──────────────┘  └──────────────┘  └──────────────────┘   │
│         │                  │                   │             │
│         ▼                  ▼                   ▼             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              18 Security Checks                      │    │
│  │  http-headers │ security-headers │ cookie-security  │    │
│  │  tls-cert     │ info-disclosure  │ tech-fingerprint │    │
│  │  csp          │ cors             │ robots-txt       │    │
│  │  sitemap      │ dir-listing      │ sensitive-files  │    │
│  │  forms        │ links            │ scripts          │    │
│  │  meta-tags    │ http-methods*    │ ssl-config*      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

* Single binary (~7 MB stripped)
* Zero runtime dependencies
* Cross-platform: Linux, macOS, Windows, FreeBSD
* Architectures: x86_64, aarch64, armv7

---

## CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    ./openre-scan scan https://staging.example.com --profile quick --format sarif --output results.sarif
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

---

## Contributing

```bash
# Run checks locally
cargo fmt --check && cargo clippy --workspace
cargo test --workspace
cargo build --workspace --release
```