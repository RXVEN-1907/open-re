# Security API Documentation

This document describes the API endpoints for retrieving security assessment findings.

## Base URL

All endpoints are prefixed with `/api/security`.

## Authentication

All endpoints require authentication via Bearer token, API key, or session cookie.

```
Authorization: Bearer <token>
```

or

```
X-API-Key: <api_key>
```

or

```
Cookie: session=<session_id>
```

## Endpoints

### List Findings

Retrieve a paginated list of security findings with filtering options.

**Endpoint**: `GET /api/security/findings`

**Query Parameters**:

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `page` | integer | Page number (default: 1) |
| `per_page` | integer | Items per page (default: 50, max: 100) |
| `severity` | string | Comma-separated list: info,low,medium,high,critical |
| `confidence` | string | Comma-separated list: very_low,low,medium,high,very_high |
| `category` | string | Comma-separated list of categories |
| `target` | string | Filter by target URL (substring match) |
| `plugin_source` | string | Filter by plugin name |
| `scan_id` | string | Filter by scan UUID |
| `verified` | boolean | Filter by verified status |
| `false_positive` | boolean | Filter by false positive status |
| `tags` | string | Comma-separated list of tags |
| `date_from` | string | ISO 8601 date (inclusive) |
| `date_to` | string | ISO 8601 date (inclusive) |
| `search` | string | Search in title and description |
| `min_risk_score` | integer | Minimum risk score (0-100) |
| `max_risk_score` | integer | Maximum risk score (0-100) |
| `sort` | string | Sort order: severity_desc, severity_asc, confidence_desc, timestamp_desc, timestamp_asc, risk_score_desc, target_asc |

**Response** (200 OK):

```json
{
  "findings": [
    {
      "id": "uuid",
      "title": "Authentication Endpoint Discovered: /login",
      "description": "Discovered authentication endpoint at HTTPS://example.com/login with status 200. Login form: true, Registration form: false, Password reset: false. MFA indicators: [\"TOTP (Time-based One-Time Password)\"], SSO providers: [\"Google OAuth\", \"GitHub OAuth\"], OAuth indicators: [\"OAuth\", \"Authorization Code Flow\"]",
      "severity": "info",
      "confidence": "high",
      "category": "broken_authentication",
      "target": "HTTPS://example.com/login",
      "target_type": "web_application",
      "evidence": [
        {
          "evidence_type": "HttpResponse",
          "description": "Authentication endpoint response (status: 200)",
          "data": {
            "url": "HTTPS://example.com/login",
            "status": 200,
            "login_form": true,
            "registration_form": false,
            "password_reset_form": false,
            "mfa_indicators": ["TOTP (Time-based One-Time Password)"],
            "sso_providers": ["Google OAuth", "GitHub OAuth"],
            "oauth_indicators": ["OAuth", "Authorization Code Flow"],
            "csrf_tokens": ["csrf_token"],
            "form_fields": [{"name": "username", "field_type": "text"}, {"name": "password", "field_type": "password"}]
          },
          "location": "HTTPS://example.com/login",
          "metadata": {}
        }
      ],
      "references": [
        {
          "reference_type": "Cwe",
          "title": "CWE-306",
          "url": "HTTPS://cwe.mitre.org/data/definitions/306.HTML",
          "description": "Missing Authentication for Critical Function"
        },
        {
          "reference_type": "Owasp",
          "title": "A07:2021",
          "url": "HTTPS://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
          "description": "OWASP Top 10 2021 - Identification and Authentication Failures"
        }
      ],
      "plugin_source": "auth_discovery",
      "plugin_version": "0.1.0",
      "timestamp": "2026-01-15T10:30:00Z",
      "scan_id": "uuid",
      "metadata": {},
      "tags": ["login_form", "mfa:totp", "sso:google_oauth", "sso:github_oauth"],
      "verified": false,
      "false_positive": false,
      "risk_score": 15,
      "cvss_vector": null,
      "cvss_score": null
    }
  ],
  "total": 42,
  "page": 1,
  "per_page": 50
}
```

### Get Finding

Retrieve a specific finding by ID.

**Endpoint**: `GET /api/security/findings/{id}`

**Path Parameters**:

-   `id` (string, required): Finding UUID

**Response** (200 OK): Finding object (same as in list)

**Response** (404 Not Found):

```json
{
  "error": "Not Found",
  "message": "Finding not found"
}
```

### Get Finding Statistics

Retrieve aggregated statistics for findings matching the filter.

**Endpoint**: `GET /api/security/findings/stats`

**Query Parameters**: Same as list findings (except pagination)

**Response** (200 OK):

```json
{
  "total": 42,
  "by_severity": {
    "Critical": 2,
    "High": 5,
    "Medium": 12,
    "Low": 15,
    "Info": 8
  },
  "by_confidence": {
    "VeryHigh": 10,
    "High": 15,
    "Medium": 12,
    "Low": 5,
    "VeryLow": 0
  },
  "by_category": {
    "BrokenAuthentication": 15,
    "SecurityMisconfiguration": 20,
    "InformationDisclosure": 7
  },
  "by_plugin": {
    "auth_discovery": 8,
    "session_management": 5,
    "cookie_security": 10,
    "security_headers": 7,
    "cors_analysis": 6,
    "rate_limiting": 3,
    "information_disclosure": 3
  },
  "verified_count": 5,
  "false_positive_count": 2,
  "avg_risk_score": 42.5,
  "max_risk_score": 95
}
```

### Get Scan Findings

Retrieve findings for a specific scan.

**Endpoint**: `GET /api/security/scans/{scan_id}/findings`

**Path Parameters**:

-   `scan_id` (string, required): Scan UUID

**Query Parameters**: Same as list findings (except scan_id)

**Response** (200 OK): Same as list findings

**Response** (404 Not Found):

```json
{
  "error": "Not Found",
  "message": "Scan not found"
}
```

### Get Scan Finding Statistics

Retrieve statistics for findings in a specific scan.

**Endpoint**: `GET /api/security/scans/{scan_id}/findings/stats`

**Path Parameters**:

-   `scan_id` (string, required): Scan UUID

**Query Parameters**: Same as finding stats (except scan_id)

**Response** (200 OK): Same as finding stats

## Error Responses

All endpoints may return these error responses:

### 401 Unauthorized

```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication"
}
```

### 403 Forbidden

```json
{
  "error": "Forbidden",
  "message": "Insufficient permissions"
}
```

### 404 Not Found

```json
{
  "error": "Not Found",
  "message": "Resource not found"
}
```

### 500 Internal Server Error

```json
{
  "error": "Internal Server Error",
  "message": "An unexpected error occurred"
}
```

## Rate Limiting

API endpoints are rate limited to 60 requests per minute per user/IP.

Rate limit headers:

-   `X-RateLimit-Limit`: Maximum requests per window
-   `X-RateLimit-Remaining`: Remaining requests in current window
-   `X-RateLimit-Reset`: Unix timestamp when limit resets
-   `Retry-After`: Seconds until next request allowed (on 429)

## Examples

### List High/Critical Authentication Findings

```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/security/findings?severity=high,critical&plugin_source=auth_discovery&per_page=20"
```

### Get Statistics for a Scan

```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/security/scans/abc123/findings/stats"
```

### Search for Cookie-Related Findings

```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/security/findings?search=cookie&category=security_misconfiguration"
```

### Get Findings by Tag

```bash
curl -H "Authorization: Bearer <token>" \
  "https://api.example.com/api/security/findings?tags=session_fixation,cookie_secure_flag"
```

## WebSocket Support

Real-time finding updates are available via WebSocket:

```
WS /api/security/findings/stream?scan_id=<scan_id>
```

Messages:

```json
{
  "type": "finding_created",
  "data": { /* finding object */ }
}
```

```json
{
  "type": "finding_updated",
  "data": { /* finding object */ }
}
```

```json
{
  "type": "scan_progress",
  "data": {
    "scan_id": "uuid",
    "progress_percent": 45.5,
    "current_plugin": "security_headers",
    "findings_count": 12
  }
}
```

## SDK Usage

### Rust

```rust
use openre_api::client::ApiClient;

let client = ApiClient::new("https://api.example.com", "Bearer <token>");

// List findings
let findings = client.security().list_findings(
    Some(vec![Severity::High, Severity::Critical]),
    Some("auth_discovery".to_string()),
    None, None, None, None, None, None, None, None, None, None, None, None,
    Some(FindingSort::SeverityDesc),
    1, 50
).await?;

// Get statistics
let stats = client.security().get_finding_stats(None).await?;

// Get scan findings
let scan_findings = client.security().get_scan_findings(scan_id, None, None, None, None, None, None, None, None, None, None, None, None, None, Some(FindingSort::SeverityDesc), 1, 50).await?;
```

### Python

```python
from openre import OpenREClient

client = OpenREClient("https://api.example.com", token="<token>")

# List findings
findings = client.security.list_findings(
    severity=["high", "critical"],
    plugin_source="auth_discovery",
    page=1, per_page=20
)

# Get statistics
stats = client.security.get_finding_stats()

# Get scan findings
scan_findings = client.security.get_scan_findings(scan_id)
```

## Changelog

### v0.1.0 (2026-01-15)

-   Initial security findings API
-   Endpoints for listing, retrieving, and statistics
-   Scan-specific finding queries
-   Filtering by severity, confidence, category, plugin, tags
-   Full-text search in title/description
-   Risk score filtering
-   WebSocket streaming for real-time updates
