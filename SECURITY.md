# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

**Do not** open a public GitHub issue for security vulnerabilities.

### How to Report

Email: **<security@open-re.org>**

Or use **GitHub Security Advisories** (preferred):

1.  Go to the repository's **Security** tab
2.  Click **Report a vulnerability**
3.  Fill in the details

### What to Include

-   Description of the vulnerability
-   Steps to reproduce
-   Affected versions (e.g., `openre-scan 0.1.0`)
-   Potential impact
-   Suggested fix or mitigation (if known)
-   Your contact info for follow-up

### Response Timeline

| Phase | Timeline |
| ------- | ---------- |
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Varies by severity |
| Coordinated disclosure | Typically 90 days |

We will credit you in the security advisory (unless you request anonymity).

---

## Security Model

### Threat Model

`openre-scan` is a **network security scanner** that:

-   Makes HTTP/HTTPS requests to user-specified targets
-   Parses HTTP responses and HTML content
-   Does **not** execute code from targets
-   Does **not** follow redirects by default (configurable)
-   Enforces timeouts and redirect limits

### Attack Surface

| Component | Risk | Mitigation |
| ----------- | ------ | ------------ |
| HTTP client | Response parsing | `reqwest` with strict limits, no auto-redirect |
| HTML parser | Malformed HTML | `select`/`html5ever` — memory-safe, no code execution |
| TLS | Certificate validation | `rustls` with `webpki-roots` — validates by default |
| File output | Path traversal | Output paths validated, no Shell expansion |
| User input | Injection | URL parsing via `url` crate, header validation |

### Security Guarantees

-   **No code execution** from scanned targets
-   **No Shell commands** — pure Rust HTTP client
-   **Memory safe** — no `unsafe` in scanner code
-   **No telemetry** — zero network calls except to target
-   **No auto-update** — user controls binary replacement
-   **Path traversal prevention** — output paths resolved safely

---

## Secure Usage

### Authorization

> **Only scan targets you own or have explicit written permission to test.**

Unauthorized scanning may violate:

-   Computer Fraud and Abuse Act (US)
-   Computer Misuse Act (UK)
-   GDPR (EU)
-   Terms of service of hosting providers

### Safe Defaults

```bash
# Default: no redirects, 10s timeout, 10 max redirects
openre-scan scan https://example.com

# Explicit limits for untrusted targets
openre-scan scan https://target.com --timeout 5 --max-redirects 0
```

### Network Isolation

For scanning untrusted targets in production:

```bash
# Run in network namespace (Linux)
sudo ip netns add scan-ns
sudo ip netns exec scan-ns openre-scan scan https://target.com

# Or use Docker with restricted network
Docker run --rm --network none \
  -v $(pwd):/data \
  ghcr.io/rxven-1907/openre-scan:latest \
  scan https://target.com --output /data/results.sarif
```

---

## Dependency Security

### Automated Scanning

-   **GitHub Dependabot** — weekly dependency updates
-   **Cargo-audit** — runs in CI on every PR
-   **Cargo-deny** — license and maintenance checks

### Current Advisories (as of v0.1.0)

| Crate | Version | Advisory | Status |
| ------- | --------- | ---------- | -------- |
| `time` | 0.1.45 | RUSTSEC-2020-0071 | Transitive via `xml5ever` (HTML parser) — **not directly reachable** |
| `Protobuf` | 2.28.0 | RUSTSEC-2024-0437 | Transitive via `opentelemetry-prometheus` — **telemetry only** |
| `ring` | 0.16.20 | RUSTSEC-2025-0009 | Transitive via `rustls` 0.20.9 — **TLS stack** |
| `rustls` | 0.20.9 | RUSTSEC-2024-0336 | **Direct dependency** — tracked for upgrade |

> **Note**: The core scanner (`openre-scan`) does not directly depend on `sqlx`, `wasmtime`, or `axum` — those are in optional platform crates. Vulnerabilities in those crates do not affect the shipped binary.

### Upgrading

```bash
# Check for vulnerabilities
Cargo audit

# Update dependencies
Cargo update
Cargo audit  # Verify fixes
```

---

## Release Security

### Binary Verification

Each release includes SHA256 checksums:

```bash
# Verify download
sha256sum -C openre-scan-Linux-x86_64.sha256
```

### Supply Chain

-   Built on GitHub Actions (ephemeral runners)
-   No external build dependencies
-   Static linking — no runtime library loading
-   Reproducible builds via locked `Cargo.lock`

---

## Vulnerability Disclosure History

| Date | Version | CVE/Advisory | Description |
|------|---------|--------------|-------------|
| — | — | — | No public vulnerabilities reported yet |

---

## Contact

-   **Security Email**: <security@open-re.org>
-   **GitHub Security Advisories**: [Report here](https://github.com/RXVEN-1907/open-re/security/advisories/new)
-   **PGP Key**: Available on request

---

_Last updated: 2026-08-16 for v0.1.0 release_
