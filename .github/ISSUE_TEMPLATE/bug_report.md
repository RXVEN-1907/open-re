---
name: Bug Report
about: Report a bug in openre-scan
title: '[BUG] '
labels: ['bug', 'needs-triage']
assignees: ''
---

## Bug Description

A clear and concise description of what the bug is.

## Environment

- **openre-scan version**: (run `openre-scan --version`)
- **OS**: (e.g., Ubuntu 22.04, macOS 14, Windows 11)
- **Rust version** (if building from source): (run `rustc --version`)
- **Installation method**: (binary download / cargo install / homebrew / docker / source)

## Steps to Reproduce

1. Run command: `openre-scan scan <target> --profile <profile> ...`
2. Observe behavior
3. Expected vs actual

## Expected Behavior

What should happen?

## Actual Behavior

What actually happens? Include error messages, stack traces, or screenshots.

## Target Information (if applicable)

- Target URL: (sanitized if sensitive)
- Target type: (web app / API / localhost / etc.)
- Profile used: (quick / standard / full)

## Additional Context

- Logs (run with `-v` for verbose)
- Configuration (if any)
- Related issues or PRs

## Severity

- [ ] Critical — Crash, data loss, security issue
- [ ] High — Major feature broken, incorrect findings
- [ ] Medium — Minor feature broken, usability issue
- [ ] Low — Cosmetic, documentation, minor annoyance