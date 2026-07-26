# File Handling Security Plugin Guide

## Overview

The File Handling plugins provide comprehensive security assessment for file upload mechanisms, path traversal vulnerabilities, and sensitive information exposure.

## Plugins

### 1. File Upload Security (`file_upload`)

Evaluates file upload mechanisms for security issues.

#### Capabilities
- **Endpoint Discovery**: Discovers file upload endpoints via OPTIONS requests
- **Dangerous Extension Testing**: Tests upload of executable scripts (PHP, ASP, JSP, etc.)
- **Double Extension Testing**: Tests bypasses using double extensions (shell.php.jpg)
- **Null Byte Injection**: Tests null byte termination in filenames
- **Path Traversal in Filename**: Tests directory traversal via filename
- **MIME Type Bypass**: Tests MIME type validation bypasses
- **File Size Limits**: Tests for missing file size restrictions
- **Empty Filename**: Tests handling of empty filenames
- **Special Characters**: Tests special characters in filenames
- **Unicode/UTF-8 Filenames**: Tests Unicode bypasses including RTL override
- **Case Sensitivity**: Tests case sensitivity bypasses

#### Configuration
```json
{
  "request_timeout": 60,
  "max_concurrent_requests": 5,
  "user_agent": "open-re-file-upload-scanner/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true
}
```

#### Test Payloads
The plugin uses safe, non-destructive test content:
- PHP: `<?php system($_GET['cmd']); ?>`
- ASP: `<% eval request("cmd") %>`
- JSP: `<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`
- Shell: `#!/bin/bash\necho 'test'`
- HTML: `<script>alert('XSS')</script>`
- SVG: `<svg onload=alert('XSS')>`

#### Findings
- Dangerous File Upload Accepted (High)
- Path Traversal in File Upload (Critical)
- Missing File Size Limits (Medium)
- Missing File Type Validation (High)

#### API Endpoints
- `GET /api/security/file-upload/findings` - List file upload findings
- `GET /api/security/file-upload/findings/stats` - File upload statistics

#### CLI Commands
```bash
sentinel finding security file-upload --scan-id <scan_id>
sentinel finding security file-upload-stats --scan-id <scan_id>
```

---

### 2. Path Traversal / LFI (`path_traversal`)

Safely detects Path Traversal and Local File Inclusion vulnerabilities.

#### Capabilities
- **Endpoint Discovery**: Discovers parameters vulnerable to path traversal
- **Comprehensive Payload Testing**: 30+ traversal payloads including:
  - Basic traversal (`../../etc/passwd`)
  - URL encoded traversal
  - Double encoded traversal
  - Unicode/UTF-8 bypasses (RTL override, BOM)
  - Null byte injection
  - Path truncation
  - Windows-specific paths
  - PHP filter wrappers (LFI)
- **LFI-Specific Testing**: Tests common include parameters with absolute paths
- **PHP Error Detection**: Identifies PHP errors indicative of LFI

#### Configuration
```json
{
  "request_timeout": 30,
  "max_concurrent_requests": 10,
  "user_agent": "open-re-path-traversal/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true
}
```

#### Test Payloads (Safe, Non-Destructive)
- Linux: `../../etc/passwd`, `../../etc/hosts`, `../../proc/version`
- Windows: `..\..\..\windows\system32\drivers\etc\hosts`, `..\..\..\windows\win.ini`
- Encoded: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- PHP Wrappers: `php://filter/convert.base64-encode/resource=../../etc/passwd`
- LFI Paths: `/etc/passwd`, `/proc/self/environ`, `/var/log/apache2/access.log`

#### Detection Indicators
- `/etc/passwd` content: `root:x:0:0:`, `daemon:x:1:1:`
- Windows: `[fonts]`, `for 16-bit app support`
- Process env: `HTTP_USER_AGENT=`, `PATH=`
- PHP errors: `failed to open stream`, `include(): Failed opening`

#### Findings
- Path Traversal / LFI Vulnerability (Critical)
- Potential Local File Inclusion (High)

#### API Endpoints
- `GET /api/security/path-traversal/findings` - List path traversal findings
- `GET /api/security/path-traversal/findings/stats` - Path traversal statistics

#### CLI Commands
```bash
sentinel finding security path-traversal --scan-id <scan_id>
sentinel finding security path-traversal-stats --scan-id <scan_id>
```

---

### 3. Sensitive Information Disclosure (`sensitive_info`)

Detects exposure of sensitive files and endpoints.

#### Capabilities
- **Environment Files**: `.env`, `.env.local`, `.env.production`, etc.
- **Configuration Files**: `config.json`, `config.yaml`, `application.properties`, etc.
- **Backup Files**: `backup.zip`, `backup.sql`, `dump.sql`, `site.zip`
- **Version Control**: `.git/`, `.svn/`, `.hg/`, `.git/config`
- **IDE Files**: `.idea/`, `.vscode/`, `*.swp`, `.DS_Store`
- **Log Files**: `access.log`, `error.log`, `debug.log`, `php_errors.log`
- **Secret Files**: `id_rsa`, `server.key`, `keystore.jks`, `passwords.txt`
- **Debug Endpoints**: `/debug`, `/actuator`, `/phpinfo.php`, `/h2-console`
- **API Documentation**: `/swagger.json`, `/openapi.json`, `/swagger-ui`

#### Configuration
```json
{
  "request_timeout": 30,
  "max_concurrent_requests": 10,
  "user_agent": "open-re-sensitive-info/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true
}
```

#### Detection Patterns
- Environment: `DATABASE_URL`, `API_KEY`, `SECRET_KEY`, `JWT_SECRET`
- Config: `password`, `secret`, `key`, `token`, `credential`
- Backup: `INSERT INTO`, `CREATE TABLE`, `mysqldump`
- VCS: `[core]`, `repositoryformatversion`
- Secrets: `-----BEGIN`, `PRIVATE KEY`, `ssh-rsa`
- Debug: `DEBUG`, `TRACE`, `environment`, `config`
- API Docs: `swagger`, `openapi`, `paths`, `definitions`

#### Severity by Category
- **Critical**: Secrets, Environment files
- **High**: Backups, Version control, Configuration
- **Medium**: Logs, Debug endpoints
- **Low**: IDE files
- **Info**: API documentation

#### Findings
- Exposed Environment File with Sensitive Data (Critical)
- Exposed Configuration File (High)
- Exposed Backup File (High)
- Exposed Version Control Artifacts (High)
- Exposed Secret File (Critical)
- Exposed Debug Endpoint (Medium)
- Exposed API Documentation (Info)

#### API Endpoints
- `GET /api/security/sensitive-info/findings` - List sensitive info findings
- `GET /api/security/sensitive-info/findings/stats` - Sensitive info statistics

#### CLI Commands
```bash
sentinel finding security sensitive-info --scan-id <scan_id>
sentinel finding security sensitive-info-stats --scan-id <scan_id>
```

---

## Common Patterns

### Safe Testing
All file handling plugins use safe, non-destructive testing:
- No actual file execution
- No destructive commands
- Controlled payloads only
- Read-only operations where possible

### Rate Limiting
Conservative rate limits to avoid impacting target:
- File upload: 5 concurrent, 60s timeout
- Path traversal: 10 concurrent, 30s timeout
- Sensitive info: 10 concurrent, 30s timeout

### Scope Enforcement
All plugins respect configured allowed/blocked scopes.

---

## Integration

### Scan Configuration
```json
{
  "target_id": "target_123",
  "name": "File Handling Security Scan",
  "plugins": ["file_upload", "path_traversal", "sensitive_info"],
  "max_concurrent_plugins": 3
}
```

### Finding Correlation
Findings can be correlated by:
- Target URL
- Scan ID
- Endpoint path
- Shared tags (file-upload, path-traversal, sensitive-info)

---

## Testing

### Recommended Targets
- **File Upload**: DVWA, bWAPP, custom upload forms
- **Path Traversal**: DVWA, bWAPP, custom file parameters
- **Sensitive Info**: Any web application with potential misconfigurations

### Validation
Run integration tests:
```bash
cargo test -p openre-plugins file_upload
cargo test -p openre-plugins path_traversal
cargo test -p openre-plugins sensitive_info
```

---

## References

- OWASP Top 10 2021 - A01:2021 Broken Access Control
- OWASP Top 10 2021 - A05:2021 Security Misconfiguration
- CWE-22 (Path Traversal)
- CWE-23 (Relative Path Traversal)
- CWE-434 (Unrestricted Upload)
- CWE-98 (PHP File Inclusion)
- CWE-200 (Information Exposure)
- CWE-538 (File/Directory Exposure)
- CWE-540 (Source Code Exposure)