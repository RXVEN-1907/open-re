# Security Plugins Documentation

This document describes the security assessment plugins available in open-re for authentication, session management, and common web security misconfigurations.

## Overview

The security plugins are modular, independent components that integrate with the open-re scan engine. Each plugin focuses on a specific security domain and returns findings using the standardized finding schema.

## Plugin Categories

### 1. Authentication Discovery (`auth_discovery`)

**Purpose**: Detects authentication endpoints and mechanisms without attempting credential attacks.

**Checks Performed**:

-   Login forms (password fields, submit buttons, CSRF tokens)
-   Registration endpoints (password confirmation, email/username fields)
-   Password reset flows (forgot password, reset password pages)
-   Multi-factor authentication indicators (TOTP, authenticator apps, WebAuthn, SMS, backup codes)
-   Single Sign-On providers (Google, GitHub, GitLab, Microsoft, Okta, Auth0, Keycloak, SAML, OIDC)
-   OAuth/OpenID Connect indicators (authorization endpoints, token endpoints, client_id, redirect_uri, PKCE)

**Configuration**:

```json
{
  "enabled_checks": ["login_forms", "registration", "password_reset", "mfa", "sso", "OAuth", "OIDC"],
  "request_timeout": 30,
  "max_concurrent_requests": 10,
  "user_agent": "open-re-security-scanner/1.0",
  "follow_redirects": true,
  "max_redirects": 10
}
```

**References**: OWASP A07:2021, CWE-306, CWE-287

---

### 2. Session Management (`session_management`)

**Purpose**: Evaluates session cookie generation, expiration, invalidation, rotation, and fixation indicators.

**Checks Performed**:

-   Session cookie identification (naming patterns, attributes)
-   Session fixation testing (same session ID across requests)
-   Cookie security attributes (Secure, HttpOnly, SameSite, Domain, Path, Expiration)
-   Weak/predictable cookie value detection

**Configuration**:

```json
{
  "enabled_checks": ["session_cookies", "session_expiration", "session_invalidation", "session_rotation", "session_fixation", "cookie_security"],
  "request_timeout": 30,
  "max_concurrent_requests": 10
}
```

**References**: OWASP A07:2021, CWE-384, CWE-613, CWE-614

---

### 3. Cookie Security (`cookie_security`)

**Purpose**: Validates cookie security attributes comprehensively.

**Checks Performed**:

-   **Secure flag**: Cookie only transmitted over HTTPS
-   **HttpOnly flag**: Cookie inaccessible to JavaScript
-   **SameSite policy**: Lax, Strict, or None (with Secure)
-   **Domain scope**: Overly broad domain settings
-   **Path scope**: Root path vs. restricted paths
-   **Expiration**: Session cookies vs. persistent cookies with long lifetimes
-   **Weak/predictable values**: Short length, common patterns, low entropy
-   **Cookie prefixes**: `__Secure-` and `__Host-` prefix compliance

**Configuration**:

```json
{
  "enabled_checks": ["secure_flag", "httponly_flag", "samesite", "domain_scope", "path_scope", "expiration", "weak_values", "cookie_prefixes"],
  "request_timeout": 30,
  "max_concurrent_requests": 10
}
```

**References**: OWASP A05:2021, CWE-614, CWE-1004, CWE-1275, CWE-613, CWE-330

---

### 4. Security Headers (`security_headers`)

**Purpose**: Checks for presence and proper configuration of security headers.

**Headers Analyzed**:

-   **Content-Security-Policy (CSP)**: Directive analysis, unsafe-inline/eval detection, missing directives, frame-ancestors, reporting
-   **Strict-Transport-Security (HSTS)**: max-age, includeSubDomains, preload
-   **X-Frame-Options**: DENY, SAMEORIGIN, ALLOW-FROM (deprecated)
-   **Referrer-Policy**: Secure vs. insecure policies
-   **Permissions-Policy**: Dangerous permissions, wildcard usage
-   **X-Content-Type-Options**: nosniff
-   **Cache-Control**: no-store, no-cache, must-revalidate, public/private
-   **X-XSS-Protection**: Legacy header (informational)
-   **X-Permitted-Cross-Domain-Policies**: Legacy Flash header (informational)
-   **Cross-Origin headers**: COOP, COEP, CORP for cross-origin isolation

**Configuration**:

```json
{
  "enabled_checks": ["CSP", "HSTS", "xfo", "referrer_policy", "permissions_policy", "xcto", "cache_control", "x_xss_protection", "x_permitted_cross_domain", "cross_origin_isolation"],
  "request_timeout": 30,
  "max_concurrent_requests": 10
}
```

**References**: OWASP A05:2021, CWE-693, CWE-16

---

### 5. CORS Analysis (`cors_analysis`)

**Purpose**: Evaluates Cross-Origin Resource Sharing configuration for misconfigurations.

**Checks Performed**:

-   **Wildcard origins**: `Access-Control-Allow-Origin: *` with/without credentials
-   **Credential handling**: `Access-Control-Allow-Credentials: true` with specific origins
-   **Origin reflection**: Dynamic reflection of Origin header in ACAO
-   **Null origin**: Allowing `null` origin
-   **Unsafe methods**: PUT, DELETE, PATCH, TRACE, CONNECT in ACAM
-   **Wildcard headers**: `Access-Control-Allow-Headers: *`
-   **Preflight analysis**: OPTIONS request handling
-   **Missing Vary header**: Cache poisoning prevention

**Configuration**:

```json
{
  "enabled_checks": ["wildcard_origin", "credentials", "origin_reflection", "unsafe_methods", "preflight", "allow_headers"],
  "test_origins": ["HTTPS://evil.com", "HTTPS://sub.evil.com", "null"],
  "test_methods": ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"],
  "request_timeout": 30,
  "max_concurrent_requests": 10
}
```

**References**: OWASP A05:2021, CWE-942, CWE-346

---

### 6. Rate Limiting (`rate_limiting`)

**Purpose**: Safely determines if request throttling exists on endpoints.

**Checks Performed**:

-   **General endpoints**: Home, health, API root
-   **Authentication endpoints**: Login, register, password reset, MFA
-   **API endpoints**: User data, search, GraphQL
-   **Rate limit headers**: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After
-   **Conservative testing**: Burst test (10 requests) + sustained test (20 requests at 2/sec)

**Configuration**:

```json
{
  "enabled_checks": ["general_endpoints", "auth_endpoints", "api_endpoints", "rate_limit_headers", "retry_after"],
  "burst_size": 10,
  "sustained_requests": 20,
  "sustained_delay_ms": 500,
  "request_timeout": 30,
  "max_concurrent_requests": 10
}
```

**References**: OWASP A07:2021, CWE-770, CWE-307

---

### 7. Information Disclosure (`information_disclosure`)

**Purpose**: Detects exposure of sensitive information in responses.

**Checks Performed**:

-   **Server headers**: Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, X-Runtime, Via, X-Forwarded-*
-   **Framework/technology detection**: Laravel, Symfony, Django, Flask, Express, Rails, Spring, ASP.NET, PHP, node.js, Nginx, Apache, IIS, Tomcat, Jetty, Webpack, React, Vue, Angular, jQuery, Bootstrap, WordPress, Drupal, Joomla, Magento, Shopify
-   **Debug pages**: Laravel Whoops, Symfony Debug, Django Debug Toolbar, Flask Debug, Express Error Handler, ASP.NET Yellow Screen of Death
-   **Stack traces**: Java, Python, Go, JavaScript, node.js, Rust patterns
-   **Version numbers**: Semantic versions, version patterns in body
-   **Sensitive data**: Passwords, API keys, secrets, tokens, private keys, connection strings
-   **Directory listings**: Index of /, directory listing
-   **Source code disclosure**: PHP, JSP, ASP markers
-   **Backup/config files**: .bak, .backup, .old, .orig, .env, config files
-   **Sensitive comments**: TODO, FIXME, HACK, PASSWORD, SECRET, KEY, TOKEN in comments

**Configuration**:

```json
{
  "enabled_checks": ["server_headers", "framework_versions", "debug_pages", "stack_traces", "sensitive_data", "directory_listing", "source_code", "backup_files", "comments", "technology_stack"],
  "request_timeout": 30,
  "max_concurrent_requests": 10
}
```

**References**: OWASP A01:2021, A05:2021, CWE-200, CWE-497, CWE-215

---

## Finding Schema

All plugins return findings using the standardized schema:

```json
{
  "id": "uuid",
  "title": "Finding title",
  "description": "Detailed description",
  "severity": "info|low|medium|high|critical",
  "confidence": "very_low|low|medium|high|very_high",
  "category": "broken_authentication|security_misconfiguration|information_disclosure|...",
  "target": "https://example.com",
  "target_type": "web_application",
  "evidence": [
    {
      "evidence_type": "http_response|http_request|code_snippet|...",
      "description": "Evidence description",
      "data": {},
      "location": "HTTPS://example.com/login",
      "metadata": {}
    }
  ],
  "references": [
    {
      "reference_type": "cwe|owasp|cve|...",
      "title": "CWE-384",
      "url": "HTTPS://cwe.mitre.org/data/definitions/384.HTML",
      "description": "Session Fixation"
    }
  ],
  "plugin_source": "auth_discovery",
  "plugin_version": "0.1.0",
  "timestamp": "2026-01-15T10:30:00Z",
  "scan_id": "uuid",
  "metadata": {},
  "tags": ["login_form", "sso:google"],
  "verified": false,
  "false_positive": false,
  "risk_score": 75,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
  "cvss_score": 6.5
}
```

## Severity Levels

| Level | Value | Description |
| ------- | ------- | ------------- |
| Info | 0 | Informational - no direct security impact |
| Low | 1 | Minor security issue |
| Medium | 2 | Moderate security issue |
| High | 3 | Significant security issue |
| Critical | 4 | Severe security issue |

## Confidence Levels

| Level | Value | Percentage |
| ------- | ------- | ------------ |
| Very Low | 0 | 10% - Speculative |
| Low | 1 | 30% - Weak evidence |
| Medium | 2 | 50% - Reasonable evidence |
| High | 3 | 80% - Strong evidence |
| Very High | 4 | 95% - Confirmed |

## Risk Score Calculation

Risk score (0-100) = (Severity × 20) + (Confidence × 5)

Example: High (3) + High (3) = 60 + 15 = 75

## API Endpoints

### List Findings

```
GET /api/security/findings
```

Query parameters:

-   `page`, `per_page` - Pagination
-   `severity` - Filter by severity (comma-separated)
-   `confidence` - Filter by confidence
-   `category` - Filter by category
-   `target` - Filter by target URL
-   `plugin_source` - Filter by plugin
-   `scan_id` - Filter by scan
-   `verified` - Filter by verified status
-   `false_positive` - Filter by false positive status
-   `tags` - Filter by tags
-   `date_from`, `date_to` - Date range
-   `search` - Search in title/description
-   `min_risk_score`, `max_risk_score` - Risk score range
-   `sort` - Sort order (severity_desc, severity_asc, confidence_desc, timestamp_desc, timestamp_asc, risk_score_desc, target_asc)

### Get Finding

```
GET /api/security/findings/{id}
```

### Get Finding Statistics

```
GET /api/security/findings/stats
```

### Get Scan Findings

```
GET /api/security/scans/{scan_id}/findings
```

### Get Scan Finding Statistics

```
GET /api/security/scans/{scan_id}/findings/stats
```

## CLI Commands

### Security Findings

```bash
# List authentication findings
sentinel finding security auth --scan-id <id> --severity high,critical

# List session management findings
sentinel finding security session --scan-id <id>

# List cookie security findings
sentinel finding security cookie --scan-id <id>

# List security header findings
sentinel finding security headers --scan-id <id>

# List CORS findings
sentinel finding security CORS --scan-id <id>

# List rate limiting findings
sentinel finding security rate-limit --scan-id <id>

# List information disclosure findings
sentinel finding security info-disclosure --scan-id <id>

# Get security summary
sentinel finding security summary --scan-id <id>
```

## Plugin Development Guide

### Creating a New Security Plugin

1.  Create a new module in `crates/openre-plugins/src/security/`
2.  Implement the `SecurityPlugin` trait
3.  Implement the `Plugin` trait from the SDK
4.  Add plugin entry point using `openre_plugins::plugin_entry!`
5.  Create plugin manifest (`plugin.TOML`) in `plugins/security/<name>/`
6.  Create configuration schema (`config_schema.JSON`)
7.  Add tests in `crates/openre-plugins/tests/`
8.  Update documentation

### Required Trait Methods

```rust
#[async_trait]
trait SecurityPlugin: Plugin {
    fn security_category(&self) -> &'static str;
    fn version(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn references(&self) -> Vec<SecurityReference>;
    fn validate_config(&self, config: &SecurityPluginConfig) -> Result<(), String>;
}
```

### Helper Functions

The `security` module provides common utilities:

-   `standard_references()` - Common OWASP/CWE references
-   `extract_cookies()` - Parse Set-Cookie headers
-   `is_auth_page()` - Detect authentication pages
-   `detect_sso_providers()` - Identify SSO providers
-   `detect_mfa_indicators()` - Identify MFA mechanisms

## Testing

Run security plugin tests:

```bash
Cargo test -p openre-plugins security_plugins_test
Cargo test -p openre-plugins security_integration_test
```

## Best Practices

1.  **Conservative Testing**: Rate limiting and active tests should be conservative to avoid DoS
2.  **Low False Positives**: Only report findings with high confidence
3.  **Standardized Output**: Use the finding schema consistently
4.  **References**: Include relevant CWE, OWASP, and CVE references
5.  **Remediation**: Provide actionable recommendations
6.  **Evidence**: Include HTTP request/response evidence
7.  **Tags**: Use consistent tagging for categorization

## Constraints

These plugins do NOT implement:

-   SQL Injection
-   XSS
-   SSRF
-   Command Injection
-   Template Injection
-   Path Traversal
-   File Upload attacks
-   AI analysis
-   Report generation

This phase focuses only on authentication, session management, and common security misconfigurations.
