# Contributing to openre-scan

Thank you for contributing to **openre-scan** — a lightweight, standalone web security scanner.

We welcome:

-   **Security checks** (new vulnerability detections)
-   **Bug fixes** and **improvements**
-   **Documentation** updates
-   **Tests** and **CI** improvements
-   **AI integration** enhancements

---

## Quick Start for Contributors

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/open-re.git
cd open-re

# 2. Build the scanner
Cargo build --release -p openre-scan

# 3. Run tests
Cargo test -p openre-scan

# 4. Try it
./target/release/openre-scan scan https://example.com --profile standard
```

---

## Adding a Security Check

This is the most common contribution. A check is a self-contained module that detects a specific vulnerability or misconfiguration.

### 1. Create the Check File

```bash
# Create new check module
touch crates/openre-scan/src/checks/my_new_check.rs
```

### 2. Implement the Check

```rust
// crates/openre-scan/src/checks/my_new_check.rs
use crate::{Check, Finding, Severity, Confidence, Category};
use reqwest::Client;
use url::Url;
use anyhow::Result;

pub struct MyNewCheck;

impl Check for MyNewCheck {
    fn name(&self) -> &'static str {
        "my-new-check"
    }

    async fn run(&self, client: &Client, target: &Url) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Your detection logic here
        let response = client.get(target.as_str()).send().await?;

        if some_vulnerable_condition {
            findings.push(Finding::new(
                "Descriptive Title".to_string(),
                "Human-readable explanation with context".to_string(),
                Severity::Medium,        // Critical/High/Medium/Low/Info
                Confidence::High,        // VeryHigh/High/Medium/Low
                Category::SecurityMisconfiguration,
                target.to_string(),
                "web".to_string(),
                self.name().to_string(),
                "1.0".to_string(),
                crate::scan_id(),
            ).with_evidence(evidence).with_remediation(remediation));
        }

        Ok(findings)
    }
}
```

### 3. Register the Check

Add to `crates/openre-scan/src/checks/mod.rs`:

```rust
pub mod my_new_check;
```

Add to `get_all_checks()` in `main.rs`:

```rust
ScanProfile::Standard => vec![
    // ... existing checks
    Check::MyNewCheck,  // Add here for Standard profile
    // or
    Check::MyNewCheck,  // Add to Full profile only
],
```

### 4. Add a Test

```rust
// crates/openre-scan/tests/integration.rs
#[tokio::test]
async fn test_my_new_check() {
    let (base_url, server) = start_test_server().await;
    let target = format!("{}/", base_url);
    let client = build_client(10, 10, false, "test".to_string(), None).unwrap();
    let target_url = target.parse::<Url>().unwrap();

    let findings = Check::MyNewCheck.run(&client, &target_url).await.unwrap();
    assert!(findings.iter().any(|f| f.title.contains("Expected Title")));
    stop_test_server(server).await;
}
```

### 5. Run Tests

```bash
Cargo test -p openre-scan --test integration test_my_new_check
```

### 6. Submit PR

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
# All openre-scan tests (unit + integration)
Cargo test -p openre-scan

# Just integration tests
Cargo test -p openre-scan --test integration

# With output
Cargo test -p openre-scan --test integration -- --nocapture

# Core crate tests
Cargo test -p openre-core -p openre-config -p openre-telemetry -p openre-storage
```

---

## Code Quality

```bash
# Format
Cargo fmt --all -- --check

# Lint (must pass with zero warnings)
Cargo clippy -p openre-scan -- -D warnings

# Build release
Cargo build --release -p openre-scan
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

-   [ ] All tests pass (`Cargo test -p openre-scan`)
-   [ ] Code formatted (`Cargo fmt --all -- --check`)
-   [ ] Zero clippy warnings (`Cargo clippy -p openre-scan -- -D warnings`)
-   [ ] Release build succeeds (`Cargo build --release -p openre-scan`)
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
openre-scan/
├── src/
│   ├── main.rs           # CLI entry point, check orchestration, output formats
│   ├── checks/           # Security check implementations (one file per check)
│   │   ├── mod.rs        # Check registration
│   │   ├── http_headers.rs
│   │   ├── security_headers.rs
│   │   └── ...           # Add new checks here
│   └── tui/              # Experimental terminal UI
├── tests/
│   └── integration.rs    # End-to-end tests against test_server.py
```

### Key Types (from `openre-core`)

-   `Finding` — Core finding with severity, confidence, category, evidence, remediation
-   `Evidence` — Proof: HTTP request/response, location, timing, payload
-   `Severity` — Critical, High, Medium, Low, Info
-   `Confidence` — VeryHigh, High, Medium, Low
-   `Category` — SecurityMisconfiguration, InformationDisclosure, etc.
-   `RemediationGuidance` — Summary, steps, effort (Low/Medium/High), priority (Immediate/High/Medium/Low)

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
