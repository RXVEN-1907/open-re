# Injection Testing API Documentation

## Overview

The injection testing framework exposes RESTful API endpoints for managing and retrieving injection vulnerability findings. All endpoints require authentication via Bearer token.

## Base URL

```
/api/security
```

## Authentication

All endpoints require a valid JWT Bearer token:

```
Authorization: Bearer <token>
```

## Injection-Specific Endpoints

### List Injection Findings

Retrieve injection findings with filtering and pagination.

**Endpoint:** `GET /injection/findings`

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | integer | Page number (default: 1) |
| `per_page` | integer | Items per page (default: 50, max: 100) |
| `severity` | array[string] | Filter by severity: `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | array[string] | Filter by confidence: `very_high`, `high`, `medium`, `low`, `very_low` |
| `injection_category` | array[string] | Filter by injection category |
| `detection_method` | array[string] | Filter by detection method |
| `target` | string | Filter by target URL |
| `scan_id` | string | Filter by scan ID |
| `verified` | boolean | Filter verified findings |
| `false_positive` | boolean | Filter false positives |
| `tags` | array[string] | Filter by tags |
| `date_from` | datetime | Filter findings after date (ISO 8601) |
| `date_to` | datetime | Filter findings before date (ISO 8601) |
| `search` | string | Search in title/description |
| `min_risk_score` | integer | Minimum risk score (0-100) |
| `max_risk_score` | integer | Maximum risk score (0-100) |
| `sort` | string | Sort order: `severity_desc`, `severity_asc`, `confidence_desc`, `confidence_asc`, `date_desc`, `date_asc` |

**Response:** `200 OK`

```json
{
  "findings": [
    {
      "id": "finding_abc123",
      "title": "SQL Injection in parameter 'id'",
      "description": "Detected SQL Injection in parameter 'id' at location query using error_based detection.\n\nPayload: ' OR '1'='1\n\nConfidence: 85%\n\nVerification steps:\n1. Verify the error is reproducible with the same payload\n2. Check if the error reveals database structure\n3. Attempt to extract data using UNION or boolean-based techniques",
      "severity": "high",
      "confidence": "high",
      "category": "injection",
      "target": "https://example.com/search",
      "target_type": "web_application",
      "evidence": [
        {
          "evidence_type": "HttpResponse",
          "description": "Injection test response for parameter 'id'",
          "data": {
            "parameter": "id",
            "location": "query",
            "payload": "' OR '1'='1",
            "detection_method": "error_based",
            "confidence": 0.85,
            "evidence": {
              "triggering_response": {
                "status": 500,
                "body": "You have an error in your SQL syntax...",
                "body_length": 1234,
                "response_time_ms": 150
              },
              "matched_patterns": ["(?i)sql syntax"],
              "timing_info": null
            }
          },
          "location": "https://example.com/search?id=' OR '1'='1"
        }
      ],
      "references": [
        {
          "reference_type": "Cwe",
          "title": "CWE-89",
          "url": "https://cwe.mitre.org/data/definitions/89.html",
          "description": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')"
        },
        {
          "reference_type": "Owasp",
          "title": "A03:2021",
          "url": "https://owasp.org/Top10/A03_2021-Injection/",
          "description": "OWASP Top 10 2021 - Injection"
        }
      ],
      "plugin_source": "injection_framework",
      "plugin_version": "1.0.0",
      "timestamp": "2024-01-15T10:30:00Z",
      "scan_id": "scan_xyz789",
      "metadata": {
        "injection_category": "sql_injection",
        "detection_method": "error_based",
        "parameter": "id",
        "location": "query",
        "payload": "' OR '1'='1"
      },
      "tags": ["error-based", "sql-injection"],
      "verified": false,
      "false_positive": false,
      "risk_score": 85,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "cvss_score": 7.5
    }
  ],
  "total": 42,
  "page": 1,
  "per_page": 50
}
```

### Get Injection Statistics

Retrieve aggregated statistics for injection findings.

**Endpoint:** `GET /injection/findings/stats`

**Parameters:** Same filter parameters as list endpoint (without pagination)

**Response:** `200 OK`

```json
{
  "total": 156,
  "by_category": {
    "sql_injection": 45,
    "xss": 38,
    "command_injection": 12,
    "xxe": 8,
    "ssti": 15,
    "nosql_injection": 10,
    "ldap_injection": 5,
    "xpath_injection": 3,
    "header_injection": 20
  },
  "by_detection_method": {
    "error_based": 52,
    "reflection": 48,
    "pattern_match": 35,
    "time_based": 12,
    "boolean_based": 8,
    "differential": 15,
    "out_of_band": 2,
    "heuristic": 4
  },
  "by_severity": {
    "critical": 18,
    "high": 56,
    "medium": 42,
    "low": 30,
    "info": 10
  },
  "by_confidence": {
    "very_high": 28,
    "high": 54,
    "medium": 40,
    "low": 24,
    "very_low": 10
  },
  "verified_count": 45,
  "false_positive_count": 8,
  "avg_confidence": 0.72
}
```

### Get Injection Categories

List all supported injection vulnerability categories with metadata.

**Endpoint:** `GET /injection/categories`

**Response:** `200 OK`

```json
[
  {
    "category": "sql_injection",
    "display_name": "SQL Injection",
    "description": "Injection of SQL commands through user input",
    "severity": "High",
    "cwe_ids": ["CWE-89"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "nosql_injection",
    "display_name": "NoSQL Injection",
    "description": "Injection of NoSQL query operators through user input",
    "severity": "High",
    "cwe_ids": ["CWE-943"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "xss",
    "display_name": "Cross-Site Scripting (XSS)",
    "description": "Injection of malicious scripts into web pages",
    "severity": "High",
    "cwe_ids": ["CWE-79", "CWE-80"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "ssti",
    "display_name": "Server-Side Template Injection (SSTI)",
    "description": "Injection of template expressions into server-side templates",
    "severity": "Critical",
    "cwe_ids": ["CWE-1336"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "command_injection",
    "display_name": "Command Injection",
    "description": "Injection of OS commands through user input",
    "severity": "Critical",
    "cwe_ids": ["CWE-78"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "xxe",
    "display_name": "XML External Entity (XXE)",
    "description": "Exploitation of unsafe XML parser configurations",
    "severity": "Critical",
    "cwe_ids": ["CWE-611"],
    "owasp_refs": ["A05:2021"]
  },
  {
    "category": "ldap_injection",
    "display_name": "LDAP Injection",
    "description": "Injection of LDAP filter expressions",
    "severity": "High",
    "cwe_ids": ["CWE-90"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "xpath_injection",
    "display_name": "XPath Injection",
    "description": "Injection of XPath query expressions",
    "severity": "High",
    "cwe_ids": ["CWE-643"],
    "owasp_refs": ["A03:2021"]
  },
  {
    "category": "header_injection",
    "display_name": "HTTP Header Injection",
    "description": "Injection of CRLF sequences into HTTP headers",
    "severity": "High",
    "cwe_ids": ["CWE-113"],
    "owasp_refs": ["A03:2021"]
  }
]
```

### Get Detection Methods

List all supported detection methods with reliability ratings.

**Endpoint:** `GET /injection/detection-methods`

**Response:** `200 OK`

```json
[
  {
    "method": "error_based",
    "display_name": "Error-Based",
    "description": "Detection through error messages in responses",
    "reliability": "High"
  },
  {
    "method": "boolean_based",
    "display_name": "Boolean-Based Blind",
    "description": "Detection through boolean condition responses",
    "reliability": "High"
  },
  {
    "method": "time_based",
    "display_name": "Time-Based Blind",
    "description": "Detection through response timing differences",
    "reliability": "Medium"
  },
  {
    "method": "reflection",
    "display_name": "Reflection-Based",
    "description": "Detection through payload reflection in response",
    "reliability": "Very High"
  },
  {
    "method": "pattern_match",
    "display_name": "Pattern Matching",
    "description": "Detection through known vulnerability patterns",
    "reliability": "High"
  },
  {
    "method": "differential",
    "display_name": "Differential Analysis",
    "description": "Detection through response comparison",
    "reliability": "Medium"
  },
  {
    "method": "out_of_band",
    "display_name": "Out-of-Band",
    "description": "Detection through external channel interactions",
    "reliability": "Very High"
  },
  {
    "method": "heuristic",
    "display_name": "Heuristic Analysis",
    "description": "Detection through behavioral heuristics",
    "reliability": "Low"
  }
]
```

## General Security Endpoints (Also Include Injection Findings)

### List All Findings

**Endpoint:** `GET /findings`

Includes injection findings when filtered by `plugin_source=injection_framework` or `category=injection`.

### Get Finding Details

**Endpoint:** `GET /findings/{id}`

Returns full finding details including injection-specific metadata.

### Get Finding Statistics

**Endpoint:** `GET /findings/stats`

Includes injection findings in aggregated statistics.

### Get Scan Findings

**Endpoint:** `GET /scans/{scan_id}/findings`

Returns all findings for a specific scan, including injection findings.

### Get Scan Finding Statistics

**Endpoint:** `GET /scans/{scan_id}/findings/stats`

Returns statistics for a specific scan.

## Data Models

### FindingResponse

```json
{
  "id": "string (FindingId)",
  "title": "string",
  "description": "string",
  "severity": "critical|high|medium|low|info",
  "confidence": "very_high|high|medium|low|very_low",
  "category": "injection|xss|broken_authentication|...",
  "target": "string",
  "target_type": "string",
  "evidence": "EvidenceResponse[]",
  "references": "ReferenceResponse[]",
  "plugin_source": "string",
  "plugin_version": "string",
  "timestamp": "datetime (ISO 8601)",
  "scan_id": "string (ScanId)",
  "metadata": "object",
  "tags": "string[]",
  "verified": "boolean",
  "false_positive": "boolean",
  "risk_score": "integer (0-100)",
  "cvss_vector": "string",
  "cvss_score": "number"
}
```

### EvidenceResponse

```json
{
  "evidence_type": "string",
  "description": "string",
  "data": "object|null",
  "location": "string|null",
  "metadata": "object"
}
```

### ReferenceResponse

```json
{
  "reference_type": "Cwe|Owasp|Cve|Custom",
  "title": "string",
  "url": "string",
  "description": "string|null"
}
```

### InjectionStatsResponse

```json
{
  "total": "integer",
  "by_category": "object<string, integer>",
  "by_detection_method": "object<string, integer>",
  "by_severity": "object<string, integer>",
  "by_confidence": "object<string, integer>",
  "verified_count": "integer",
  "false_positive_count": "integer",
  "avg_confidence": "number"
}
```

### InjectionCategoryResponse

```json
{
  "category": "string",
  "display_name": "string",
  "description": "string",
  "severity": "string",
  "cwe_ids": "string[]",
  "owasp_refs": "string[]"
}
```

### DetectionMethodResponse

```json
{
  "method": "string",
  "display_name": "string",
  "description": "string",
  "reliability": "string"
}
```

## Error Responses

### 401 Unauthorized

```json
{
  "error": "Unauthorized",
  "message": "Invalid or missing authentication token"
}
```

### 404 Not Found

```json
{
  "error": "Not Found",
  "message": "Finding not found"
}
```

### 422 Validation Error

```json
{
  "error": "Validation Error",
  "message": "Invalid query parameters",
  "details": [
    {
      "field": "severity",
      "message": "Invalid severity value"
    }
  ]
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

API endpoints are rate limited:
- Default: 100 requests per minute per IP
- Authenticated: 1000 requests per minute per user
- Exceeding limits returns `429 Too Many Requests`

## Pagination

List endpoints support pagination:
- `page`: Page number (1-indexed)
- `per_page`: Items per page (1-100)
- Response includes `total`, `page`, `per_page`

## Filtering Examples

### SQL Injection Findings Only

```
GET /injection/findings?injection_category=sql_injection
```

### High Severity XSS Findings

```
GET /injection/findings?injection_category=xss&severity=high,critical
```

### Time-Based Blind SQLi Findings

```
GET /injection/findings?injection_category=sql_injection&detection_method=time_based
```

### Findings from Specific Scan

```
GET /injection/findings?scan_id=scan_abc123
```

### Recent Verified Findings

```
GET /injection/findings?verified=true&date_from=2024-01-01T00:00:00Z
```

### Search for Specific Payload

```
GET /injection/findings?search=' OR '1'='1
```

## WebSocket (Real-time Updates)

### Scan Progress

```
WS /api/security/scans/{scan_id}/progress
```

Receives real-time `ScanProgress` updates including injection plugin execution status.

### Finding Notifications

```
WS /api/security/findings/stream
```

Receives real-time finding notifications as they are discovered.

## SDK Usage

### Rust

```rust
use openre_api_client::SecurityClient;

let client = SecurityClient::new("https://api.example.com", token);

// List injection findings
let findings = client.injection_findings()
    .category("sql_injection")
    .severity(vec!["high", "critical"])
    .page(1)
    .per_page(50)
    .send()
    .await?;

// Get injection stats
let stats = client.injection_stats()
    .send()
    .await?;

// Get categories
let categories = client.injection_categories().send().await?;
```

### Python

```python
from openre_client import SecurityClient

client = SecurityClient("https://api.example.com", token="your-token")

# List injection findings
findings = client.injection_findings(
    category="sql_injection",
    severity=["high", "critical"],
    page=1,
    per_page=50
)

# Get injection stats
stats = client.injection_stats()

# Get categories
categories = client.injection_categories()
```

### JavaScript/TypeScript

```typescript
import { SecurityClient } from '@openre/api-client';

const client = new SecurityClient('https://api.example.com', 'your-token');

// List injection findings
const findings = await client.injectionFindings({
  category: 'sql_injection',
  severity: ['high', 'critical'],
  page: 1,
  perPage: 50
});

// Get injection stats
const stats = await client.injectionStats();

// Get categories
const categories = await client.injectionCategories();
```

## Changelog

### v1.0.0 (2024-01-15)
- Initial injection API endpoints
- Finding listing with injection-specific filters
- Injection statistics endpoint
- Categories and detection methods reference endpoints
- WebSocket support for real-time updates