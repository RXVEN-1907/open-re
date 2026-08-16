---
name: Security Check Contribution
about: Propose or contribute a new security check
title: '[CHECK] '
labels: ['enhancement', 'security-check', 'needs-triage']
assignees: ''
---

## Check Summary

**Name**: (e.g., `cors-misconfiguration`, `jwt-in-url`, `sensitive-api-keys`)

**Category**: (SecurityMisconfiguration / InformationDisclosure / InjectionRisk / CryptoIssue / ContentSecurity)

**Severity**: (Critical / High / Medium / Low / Info)

**Confidence**: (VeryHigh / High / Medium / Low)

## Vulnerability Description

What vulnerability or misconfiguration does this check detect?

## Detection Logic

How should the check detect this issue?
- HTTP headers to inspect
- HTML patterns to match
- Response codes to check
- Cookie attributes to validate
- TLS/certificate properties

## Evidence

What evidence should the finding include?
- HTTP headers
- Response body snippets
- Location (URL, header name, etc.)
- Timing information

## Remediation

What are the actionable steps to fix this?
- Summary
- Step-by-step instructions
- Effort: (Low / Medium / High)
- Priority: (Immediate / High / Medium / Low)

## References

- CVE IDs (if applicable)
- CWE IDs
- OWASP category
- External references (blog posts, specs, etc.)

## Test Case

Provide a test target or mock response that should trigger this check.

## Implementation Checklist

- [ ] Check module created in `crates/openre-scan/src/checks/`
- [ ] Implements `Check` trait
- [ ] Registered in `checks/mod.rs`
- [ ] Added to appropriate scan profile(s)
- [ ] Integration test added
- [ ] Documentation updated (if CLI changes)