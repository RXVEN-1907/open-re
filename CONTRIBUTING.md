# Contributing to open-re

Thank you for contributing to **open-re** — an open-source reverse engineering and offensive security platform.

We welcome:

-   **Security checks** (new vulnerability detections for openre-scan)
-   **Bug fixes** and **improvements** across all crates
-   **Documentation** updates
-   **Tests** and **CI** improvements
-   **AI integration** enhancements
-   **Plugin system** development
-   **Binary analysis** pipeline improvements

---

## Quick Start for Contributors

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/open-re.git
cd open-re

# 2. Build the scanner (standalone, works offline)
cargo build --release -p openre-scan

# 3. Build the CLI (requires API server for most commands)
cargo build --release -p openre-cli

# 4. Run tests
cargo test --workspace

# 5. Try the scanner
./target/release/openre-scan scan https://example.com --profile standard
```

---

## Adding a Security Check (openre-scan)

This is the most common contribution. A check is a self-contained async function that detects a specific vulnerability or misconfiguration.

### Current Structure

All checks are implemented directly in `crates/openre-scan/src/main.rs` (not separate files yet). The `Check` enum defines all available checks.

### 1. Add the Check Function

Add a new async function in `main.rs` following the existing pattern:

```rust
// In crates/openre-scan/src/main.rs
async fn check_my_new_check(client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;

    // Your detection logic here
    if some_vulnerable_condition {
        let finding = Finding::new(FindingConfig {
            title: "Descriptive Title".to_string(),
            description: "Human-readable explanation with context".to_string(),
            severity: Severity::Medium,        // Critical/High/Medium/Low/Info
            confidence: Confidence::High,       // VeryHigh/High/Medium/Low
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "my-new-check".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "Description of evidence".to_string(),
        )
        .with_data(serde_json::json!({"key": "value"}))
        .with_location(target.to_string());
        let remediation = RemediationGuidance::new(
            "Fix summary".to_string(),
            vec!["Step 1".to_string(), "Step 2".to_string()],
            RemediationEffort::Low,
            RemediationPriority::High,
        );
        findings.push(finding.with_evidence(evidence).with_remediation(remediation));
    }

    Ok(findings)
}
```

### 2. Register the Check

Add to the `Check` enum and implement the `run` match arm:

```rust
// In the Check enum
#[derive(Debug, Clone)]
pub enum Check {
    // ... existing checks
    MyNewCheck,
}

impl Check {
    pub async fn run(&self, client: &Client, target: &Url) -> anyhow::Result<Vec<Finding>> {
        match self {
            // ... existing arms
            Check::MyNewCheck => check_my_new_check(client, target).await,
        }
    }
}
```

### 3. Add to Scan Profiles

Add to `get_all_checks()` for the desired profiles:

```rust
pub fn get_all_checks(profile: &ScanProfile) -> Vec<Check> {
    match profile {
        ScanProfile::Quick => vec![
            // ... existing
        ],
        ScanProfile::Standard => vec![
            // ... existing
            Check::MyNewCheck,  // Add here for Standard profile
        ],
        ScanProfile::Full => vec![
            // ... existing
            Check::MyNewCheck,  // Add to Full profile
        ],
    }
}
```

### 4. Add Check Description

Add to `get_check_description()` for the help output (must handle all Check variants):

```rust
fn get_check_description(check: &Check) -> &'static str {
    match check {
        Check::HttpHeaders => "HTTP header analysis",
        Check::TlsCertificate => "TLS certificate validation",
        Check::CookieSecurity => "Cookie security flags",
        Check::SecurityHeaders => "Security headers (HSTS, CSP, etc.)",
        Check::ContentSecurityPolicy => "CSP directive analysis",
        Check::CorsConfiguration => "CORS misconfiguration",
        Check::InformationDisclosure => "Debug info & version disclosure",
        Check::TechnologyFingerprint => "Tech stack detection",
        Check::RobotsTxt => "robots.txt enumeration",
        Check::SitemapXml => "sitemap.xml discovery",
        Check::DirectoryListing => "Directory listing detection",
        Check::SensitiveFiles => "Sensitive file exposure (20+ paths)",
        Check::FormAnalysis => "Form security (GET passwords, CSRF)",
        Check::LinkAnalysis => "Mixed content & external links",
        Check::ScriptAnalysis => "Inline/external script analysis",
        Check::MetaTags => "Security-relevant meta tags",
        Check::HttpMethods => "Dangerous HTTP methods (TRACE, PUT, etc.)",
        Check::SslTlsConfiguration => "SSL/TLS deep configuration",
        Check::MyNewCheck => "Brief description of what this check does",
    }
}
```

### 5. Add a Test

```rust
// In crates/openre-scan/tests/integration.rs
#[tokio::test]
async fn test_my_new_check() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);
    let client = build_client(10, 10, false, "test".to_string(), None).unwrap();
    let target_url = target.parse::<Url>().unwrap();

    let findings = check_my_new_check(&client, &target_url).await.unwrap();
    assert!(findings.iter().any(|f| f.title.contains("Expected Title")));
    stop_test_server(server).await;
}
```

### 6. Run Tests

```bash
cargo test -p openre-scan --test integration test_my_new_check
```

### 7. Submit PR

```bash
git checkout -b feat/my-new-check
git add .
git commit -m "feat: add my-new-check for detecting X vulnerability"
git push origin feat/my-new-check
# Open PR on GitHub
```

---

## Check Design Guidelines

| Principle | Details |
| ----------- | --------- |
| **Single responsibility** | One check = one vulnerability class |
| **Evidence required** | Every finding must include `Evidence` (HTTP headers, body snippets, locations) |
| **Remediation included** | Provide actionable steps with effort/priority |
| **Severity accuracy** | Critical = immediate exploit, High = likely exploit, Medium = config issue, Low = info leak, Info = fingerprint |
| **Confidence honesty** | VeryHigh = deterministic, High = strong signal, Medium = heuristic, Low = speculative |
| **Performance** | Checks must complete in < 5s; use timeouts |
| **No false positives** | Prefer missing a finding over reporting a false one |

---

## Running Tests

```bash
# All workspace tests
cargo test --workspace

# Just openre-scan tests (unit + integration)
cargo test -p openre-scan

# Just integration tests
cargo test -p openre-scan --test integration

# With output
cargo test -p openre-scan --test integration -- --nocapture

# Core crate tests
cargo test -p openre-core -p openre-config -p openre-telemetry -p openre-storage
```

---

## Code Quality

```bash
# Format (must pass)
cargo fmt --all -- --check

# Lint (must pass with zero warnings)
cargo clippy --workspace -- -D warnings

# Build release (all crates)
cargo build --release --workspace
```

---

## Pull Request Process

### PR Title Format

Use conventional commits:

```
feat: add check for X vulnerability
fix: resolve false positive in security-headers check
docs: update installation guide for Windows
refactor: extract check trait for pluggable architecture
test: add integration test for CORS check
chore: update dependencies
```

### PR Requirements

-   [ ] All tests pass (`cargo test --workspace`)
-   [ ] Code formatted (`cargo fmt --all -- --check`)
-   [ ] Zero clippy warnings (`cargo clippy --workspace -- -D warnings`)
-   [ ] Release build succeeds (`cargo build --release --workspace`)
-   [ ] Documentation updated if CLI changes
-   [ ] CHANGELOG.md updated for user-facing changes
-   [ ] Linked to relevant issue

### Review Process

1.  Automated CI checks must pass
2.  At least one maintainer review
3.  Address review comments
4.  Maintainer merges after approval

---

## Architecture Overview (for contributors)

```
open-re/
├── crates/
│   ├── openre-core/           # Shared types: Finding, RiskScore, IDs, Capabilities
│   ├── openre-config/         # Configuration management
│   ├── openre-telemetry/      # Metrics, tracing, logging, audit
│   ├── openre-storage/        # SQLite persistence, object storage
│   ├── openre-queue/          # Redis job queue, worker pool
│   ├── openre-plugins/        # WASM plugin runtime, registry, capabilities
│   ├── openre-intelligence/   # CVE matching, correlation, dependency analysis
│   ├── openre-security-ai/    # AI providers, prompt compiler, safety
│   ├── openre-analysis/       # Binary analysis: ELF/PE/MachO/WASM parsers
│   ├── openre-api/            # REST/gRPC/WebSocket API server
│   ├── openre-cli/            # Unified CLI (requires API server)
│   ├── openre-scan/           # Standalone scanner (18 checks, 3 profiles)
│   ├── openre-recon/          # Reconnaissance (subdomain, port, tech)
│   ├── openre-scanner/        # Scanner orchestration
│   └── sentinel/              # Continuous monitoring
├── frontend/                  # React 18 + TypeScript + Tailwind
├── docker/                    # Dockerfiles
├── docs/                      # Architecture docs
└── plugins/                   # Plugin examples
```

### Key Types (from `openre-core`)

-   `Finding` — Core finding with severity, confidence, category, evidence, remediation
-   `Evidence` — Proof: HTTP request/response, location, timing, payload
-   `Severity` — Critical, High, Medium, Low, Info
-   `Confidence` — VeryHigh, High, Medium, Low
-   `Category` — SecurityMisconfiguration, InformationDisclosure, etc.
-   `RemediationGuidance` — Summary, steps, effort (Low/Medium/High), priority (Immediate/High/Medium/Low)
-   `Capability` — Plugin permissions (ReadBinary, WriteAnnotations, CallAI, etc.)
-   `PluginId`, `ScanId`, `ProjectId`, `FindingId` — Typed ID wrappers

---

## Reporting Bugs

Use the **Bug Report** template and include:

-   Clear description
-   Steps to reproduce
-   Expected vs actual behavior
-   Target URL (if safe to share)
-   Scanner version (`openre-scan --version`)
-   OS/Rust version

---

## Feature Requests

Use the **Feature Request** template:

-   Problem statement
-   Proposed solution
-   User value / use cases
-   Technical considerations

---

## Security Issues

**Do not** open public issues for security vulnerabilities.

Email: **<security@open-re.org>** (or use GitHub Security Advisories)

Include:

-   Description and impact
-   Reproduction steps
-   Affected versions
-   Suggested fix (if any)

---

## Recognition

Contributors are recognized in:

-   `CONTRIBUTORS.md`
-   Release notes
-   GitHub contributor graphs

---

## Questions

-   **GitHub Discussions** for questions and ideas
-   **GitHub Issues** for bugs and feature requests
-   **Pull Requests** for code reviews

---

## License

By contributing, you agree your contributions are licensed under the project's [MIT License](LICENSE).