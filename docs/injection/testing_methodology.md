# Injection Testing Methodology

## Overview

This document describes the testing methodology used by the injection testing framework to safely and reliably detect injection vulnerabilities with minimal false positives.

## Testing Principles

### 1. Evidence-Based Detection

Every finding must be backed by concrete evidence:
- **HTTP Request/Response**: Full request and response captured
- **Baseline Comparison**: Test response compared to clean baseline
- **Pattern Matching**: Specific vulnerability indicators identified
- **Reproducible Request**: Exact request that triggered the finding

### 2. Safe Testing Only

- **No Destructive Payloads**: Default payloads are non-destructive (`is_safe: true`)
- **No Exploit Chaining**: Single vulnerability detection only
- **No Post-Exploitation**: No privilege escalation, lateral movement, data exfiltration
- **Rate Limited**: Configurable RPS to prevent DoS
- **Scope Enforced**: Only authorized targets tested

### 3. Multi-Method Verification

Each vulnerability type is tested using multiple detection methods:

| Vulnerability | Primary Methods | Secondary Methods |
|---------------|-----------------|-------------------|
| SQL Injection | Error-Based, Boolean-Based | Time-Based, Union-Based, Pattern Match |
| NoSQL Injection | Error-Based, Pattern Match | Boolean-Based |
| XSS | Reflection, Pattern Match | Differential |
| SSTI | Pattern Match, Error-Based | Reflection |
| Command Injection | Pattern Match, Error-Based | Time-Based |
| XXE | Pattern Match, Error-Based | Out-of-Band |
| LDAP Injection | Error-Based, Pattern Match | Boolean-Based |
| XPath Injection | Error-Based, Pattern Match | Boolean-Based |
| Header Injection | Reflection, Pattern Match | Differential |

## Testing Process

### Phase 1: Reconnaissance & Parameter Discovery

1. **Target Analysis**: Identify input vectors (query params, body params, headers, cookies)
2. **Parameter Classification**: Categorize by type (ID, search, auth, file upload, etc.)
3. **Technology Detection**: Identify backend (database, template engine, OS, framework)
4. **Baseline Capture**: Record normal responses for each parameter

### Phase 2: Payload Generation

1. **Context-Aware Selection**: Filter payloads by:
   - Database type (MySQL, PostgreSQL, SQL Server, Oracle)
   - Template engine (Jinja2, Twig, Freemarker, Velocity)
   - OS type (Linux, Windows)
   - Technology hints (MongoDB, LDAP, XPath)
2. **Encoding Variants**: Apply multiple encodings:
   - None, URL, Double URL, HTML Entity, Unicode, Base64, Hex, SQL Comment, XML, JSON
3. **Safety Filtering**: Block dangerous patterns (DROP TABLE, rm -rf, etc.)
4. **Limit Enforcement**: Respect `max_payloads_per_param`

### Phase 3: Request Execution

For each parameter × payload × encoding combination:

1. **Scope Check**: Verify target within allowed scopes
2. **Payload Validation**: Check against blocked patterns
3. **Rate Limiting**: Token bucket algorithm
4. **Concurrency Control**: Semaphore-based limiting
5. **Request Mutation**: Inject payload into parameter
6. **HTTP Request**: Send with configured timeout, redirects, user agent
7. **Response Capture**: Full response (status, headers, body, timing)

### Phase 4: Response Analysis

Multiple analyzers run in parallel:

#### Error-Based Detection
- Match known error patterns for each technology
- High confidence when specific errors detected
- Examples: "SQL syntax", "MySQL error", "ORA-XXXXX", "LDAP error"

#### Reflection Detection
- Check if payload appears in response body
- Very high confidence for XSS, Header Injection
- Context-aware (HTML, JS, attribute, CSS)

#### Time-Based Detection
- Measure response time vs baseline
- Significant if `test_time - baseline_time > threshold` (default 3s)
- Used for blind SQLi, Command Injection, LDAP, XPath

#### Pattern Matching
- Category-specific regex patterns
- SQL: UNION SELECT, information_schema, WAITFOR DELAY
- XSS: `<script>`, `onerror=`, `javascript:`
- SSTI: `49`, `__class__`, `java.lang.Runtime`
- Command: `uid=`, `root:`, `C:\Windows`
- XXE: `/etc/passwd`, AWS metadata IP

#### Differential Analysis
- Compare test response to baseline
- Status code changes (500 errors)
- Length changes (>10% difference)
- Header changes
- New/removed patterns

#### Out-of-Band Detection
- For XXE (external DTD), SSRF
- Requires external listener (not implemented in core)

### Phase 5: Confidence Scoring

Each finding scored using multi-factor algorithm:

```
Score = Base × Method × Severity × Category × Evidence + Bonus
```

**Factors:**
- Base confidence from analyzer (0.6-0.95)
- Method weight (0.5-0.95)
- Severity weight (0.3-1.0)
- Category weight (0.85-1.0)
- Evidence quality multiplier (1.0-1.2)
- Multi-method bonus (0.1 per additional method)

**Labels:**
- Very High: ≥0.9
- High: ≥0.75
- Medium: ≥0.6
- Low: ≥0.4
- Very Low: <0.4

### Phase 6: Finding Generation

Convert `InjectionTestResult` to `Finding`:

```rust
Finding {
    title: "SQL Injection in parameter 'id'",
    description: "Detected SQL Injection... Payload: ' OR '1'='1\nConfidence: 85%\nVerification steps:\n1. Verify...\n2. Check...\n3. Attempt...",
    severity: High,
    confidence: High,
    category: Injection,
    evidence: [
        Evidence {
            type: HttpResponse,
            description: "Injection test response for parameter 'id'",
            data: { parameter, location, payload, detection_method, confidence, evidence }
        }
    ],
    references: [CWE-89, OWASP A03:2021],
    tags: ["error-based", "sql-injection"],
    reproducible_request: { method, url, headers, body, parameter, payload, location }
}
```

## Verification Steps

Each finding includes recommended verification steps:

### SQL Injection
1. Verify error is reproducible with same payload
2. Check if error reveals database structure
3. Attempt data extraction using UNION/boolean techniques
4. Test with different payloads to confirm

### XSS
1. Verify payload executes in browser context
2. Check if CSP or other mitigations prevent execution
3. Test with harmless payload (`<test>`) to confirm reflection
4. Identify reflection context (HTML, attribute, JS, CSS)

### SSTI
1. Verify template engine identified correctly
2. Test with non-destructive payloads first (`{{7*7}}`)
3. Check for RCE potential via template features
4. Identify template engine version

### Command Injection
1. Verify command output reproducible
2. Test with different commands (`id`, `whoami`, `ls`)
3. Check for privilege escalation possibilities
4. Identify OS and shell type

### XXE
1. Verify file read reproducible
2. Test for SSRF via XXE (internal network access)
3. Check for blind XXE (out-of-band)
4. Identify XML parser library

### LDAP Injection
1. Verify LDAP data exposure reproducible
2. Check for authentication bypass
3. Test for directory enumeration
4. Identify LDAP server type

### XPath Injection
1. Verify XML data exposure reproducible
2. Check for authentication bypass
3. Test for XML structure enumeration
4. Identify XPath processor

### Header Injection
1. Verify header injection reproducible
2. Check for response splitting
3. Test for cache poisoning
4. Identify affected headers

## False Positive Reduction

### Techniques Used

1. **Baseline Comparison**: Every test has clean baseline
2. **Multi-Method Confirmation**: Require multiple detection methods for high confidence
3. **Context Validation**: Verify finding makes sense for parameter type
4. **Pattern Specificity**: Use specific patterns, not generic ones
5. **Reproducibility**: Findings must be reproducible
6. **Confidence Thresholds**: Filter by confidence level

### Confidence Thresholds by Method

| Method | Min Confidence | Notes |
|--------|----------------|-------|
| Reflection | 0.9 | Very reliable |
| Error-Based | 0.8 | High reliability |
| Pattern Match | 0.85 | High with specific patterns |
| Time-Based | 0.85 | Requires consistent timing |
| Boolean-Based | 0.8 | Requires clear true/false diff |
| Differential | 0.7 | Lower, needs correlation |
| Heuristic | 0.5 | Lowest, needs manual review |

## Testing Against Vulnerable Applications

### Recommended Test Targets

| Application | Vulnerabilities | URL |
|-------------|-----------------|-----|
| OWASP Juice Shop | SQLi, XSS, XXE, SSTI | https://juice-shop.herokuapp.com |
| DVWA | SQLi, XSS, Command, Header | https://github.com/digininja/DVWA |
| bWAPP | All injection types | https://github.com/raesene/bWAPP |
| WebGoat | SQLi, XSS, XXE | https://github.com/WebGoat/WebGoat |
| Mutillidae | SQLi, XSS, Command | https://github.com/webpwnized/mutillidae |

### Test Procedure

1. **Deploy Target**: Run vulnerable app in isolated environment
2. **Configure Scan**: Create target with base URL, auth if needed
3. **Run Injection Plugins**: Execute all or specific injection plugins
4. **Verify Findings**: Compare with known vulnerabilities in target
5. **Measure Metrics**: True positives, false positives, false negatives
6. **Tune Payloads**: Adjust payloads based on results

### Expected Results

| Target | SQLi | XSS | Command | XXE | SSTI | LDAP | XPath | Header |
|--------|------|-----|---------|-----|------|------|-------|--------|
| Juice Shop | ✓ | ✓ | | ✓ | ✓ | | | |
| DVWA | ✓ | ✓ | ✓ | | | | | ✓ |
| bWAPP | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| WebGoat | ✓ | ✓ | | ✓ | | | | |
| Mutillidae | ✓ | ✓ | ✓ | | | | | |

## Regression Testing

### Automated Tests

Run after every change:

```bash
# Unit tests
cargo test -p openre-plugins injection_unit_tests

# Integration tests
cargo test -p openre-plugins injection_integration_tests

# All plugin tests
cargo test -p openre-plugins
```

### Test Coverage

- Payload generation for all categories
- Encoding/decoding correctness
- Parameter mutation for all locations
- Response analysis for all detection methods
- Confidence scoring accuracy
- Safety controls enforcement
- Context-aware payload filtering

### False Positive Tracking

Maintain registry of known false positives:
- Parameter names that trigger false alerts
- Response patterns that mimic vulnerabilities
- Technology-specific quirks

## Performance Considerations

### Optimization Strategies

1. **Payload Prioritization**: Test high-confidence payloads first
2. **Early Termination**: Stop testing parameter after confirmed finding
3. **Caching**: Cache baseline responses
4. **Parallel Execution**: Test multiple parameters concurrently
5. **Smart Filtering**: Skip irrelevant payloads based on context

### Resource Limits

Default limits (configurable):
- Max 100 requests per parameter test
- Max 10,000 total requests per scan
- 10 RPS rate limit
- 5 concurrent requests
- 30 second request timeout
- 50 payloads per parameter

## Reporting

### Finding Report Includes

1. **Vulnerability Details**: Category, parameter, location, payload
2. **Detection Method**: How it was detected
3. **Confidence Score**: Numerical and label
4. **Severity**: Critical/High/Medium/Low/Info
5. **Evidence**: Request/response, patterns, timing, diff
6. **Reproducible Request**: Exact request to reproduce
7. **Verification Steps**: Manual verification guide
8. **References**: CWE, OWASP, CVE links
9. **Tags**: For filtering and categorization

### Statistics Available

- Total findings by category
- Findings by detection method
- Findings by severity/confidence
- Verified vs false positive counts
- Average confidence per category
- Scan execution time and request count

## Continuous Improvement

### Feedback Loop

1. **Test Results** → **Payload Tuning** → **Better Detection**
2. **False Positives** → **Pattern Refinement** → **Reduced Noise**
3. **New Vulnerabilities** → **New Payloads/Patterns** → **Extended Coverage**
4. **Performance Data** → **Optimization** → **Faster Scans**

### Versioning

- Payload library versioned separately
- Detection patterns versioned
- Breaking changes require major version bump
- Backward compatibility maintained for configs