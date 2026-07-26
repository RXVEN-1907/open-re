# API Security Plugin Guide

## Overview

The API Security plugins provide comprehensive security assessment for modern API architectures including REST APIs, GraphQL services, and rate limiting implementations.

## Plugins

### 1. REST API Security (`rest_api`)

Discovers and analyzes REST API endpoints for security issues.

#### Capabilities
- **Endpoint Discovery**: Scans common API paths and fetches OpenAPI/Swagger specifications
- **Authentication Testing**: Identifies endpoints missing authentication
- **Authorization Testing**: Checks for improper authorization on sensitive endpoints
- **HTTP Method Analysis**: Detects insecure methods (PUT, DELETE, PATCH, TRACE) without authentication
- **API Versioning**: Identifies potentially deprecated API versions
- **Sensitive Endpoint Detection**: Flags admin, management, debug, and config endpoints

#### Configuration
```json
{
  "request_timeout": 30,
  "max_concurrent_requests": 10,
  "user_agent": "open-re-rest-api-scanner/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true
}
```

#### Findings
- Missing Authentication on Sensitive Endpoint (High)
- Insecure HTTP Method Without Authentication (Medium)
- TRACE Method Enabled (Low)
- OPTIONS Method Information Disclosure (Info)
- Potential Deprecated API Version (Info)

#### API Endpoints
- `GET /api/security/api/findings` - List REST API findings
- `GET /api/security/api/findings/stats` - REST API statistics
- `GET /api/security/api/endpoints` - List discovered endpoints

#### CLI Commands
```bash
sentinel finding security api --scan-id <scan_id>
sentinel finding security api-stats --scan-id <scan_id>
```

---

### 2. GraphQL Security (`graphql`)

Detects GraphQL endpoints and analyzes them for security issues.

#### Capabilities
- **Endpoint Discovery**: Scans common GraphQL paths with introspection queries
- **Introspection Detection**: Identifies if GraphQL introspection is enabled
- **Schema Analysis**: Fetches and analyzes full schema for excessive exposure
- **Query Depth Testing**: Tests for missing query depth limits
- **Query Complexity Testing**: Tests for missing query complexity limits
- **Mutation Discovery**: Enumerates available mutations
- **Batch Query Detection**: Checks for batch query support

#### Configuration
```json
{
  "request_timeout": 30,
  "max_concurrent_requests": 10,
  "user_agent": "open-re-graphql-scanner/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true
}
```

#### Findings
- GraphQL Introspection Enabled (Medium)
- GraphQL Endpoint Missing Authentication (High)
- Excessive GraphQL Schema Exposure (Medium)
- Missing GraphQL Query Depth Limit (Medium)
- Missing GraphQL Query Complexity Limit (Low)
- GraphQL Mutations Discovered (Info)
- GraphQL Batch Queries Supported (Low)

#### API Endpoints
- `GET /api/security/graphql/findings` - List GraphQL findings
- `GET /api/security/graphql/findings/stats` - GraphQL statistics

#### CLI Commands
```bash
sentinel finding security graphql --scan-id <scan_id>
sentinel finding security graphql-stats --scan-id <scan_id>
```

---

### 3. API Rate Limiting (`api_rate_limiting`)

Evaluates API rate limiting implementation.

#### Capabilities
- **Sustained Rate Testing**: Tests rate limiting under sustained load
- **Burst Handling**: Tests burst request handling
- **Authentication Endpoint Protection**: Specific testing for auth endpoints
- **Rate Limit Header Analysis**: Checks for standard rate limit headers
- **Retry-After Header Validation**: Verifies Retry-After header presence

#### Configuration
```json
{
  "request_timeout": 30,
  "max_concurrent_requests": 5,
  "user_agent": "open-re-api-rate-limiter/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true,
  "sustained_requests_per_second": 5,
  "sustained_test_duration_seconds": 10,
  "burst_test_size": 10,
  "auth_endpoint_test_requests": 5,
  "max_test_requests": 50,
  "test_requests_per_endpoint": 20
}
```

#### Findings
- Missing Rate Limiting (High for auth, Medium for others)
- Rate Limiting Headers Missing (Low)
- Insufficient Burst Protection (Medium)
- Authentication Endpoint Missing Rate Limiting (High)
- Missing Retry-After Header (Low)

#### API Endpoints
- `GET /api/security/rate-limiting/findings` - List rate limiting findings
- `GET /api/security/rate-limiting/findings/stats` - Rate limiting statistics

#### CLI Commands
```bash
sentinel finding security rate-limiting --scan-id <scan_id>
sentinel finding security rate-limiting-stats --scan-id <scan_id>
```

---

## Common Patterns

### Authentication
All API security plugins support authentication via Bearer tokens passed in the scan configuration:

```json
{
  "target_url": "https://api.example.com",
  "auth_tokens": ["token1", "token2"]
}
```

### Rate Limiting
All plugins respect conservative rate limits to avoid impacting target systems:
- Default: 5-10 requests per second
- Configurable per plugin
- Automatic backoff on 429 responses

### Scope Enforcement
Plugins respect configured allowed/blocked scopes to prevent testing unauthorized targets.

---

## Integration

### Scan Configuration
```json
{
  "target_id": "target_123",
  "name": "API Security Scan",
  "plugins": ["rest_api", "graphql", "api_rate_limiting"],
  "max_concurrent_plugins": 3
}
```

### Finding Correlation
Findings from different API security plugins can be correlated by:
- Target URL
- Scan ID
- Endpoint path
- Shared tags (api, graphql, rate-limiting)

---

## Testing

### Recommended Targets
- **REST API**: OWASP Juice Shop, DVWA, custom REST APIs
- **GraphQL**: GraphQL Playground, custom GraphQL APIs, Hasura
- **Rate Limiting**: Any API with known rate limits

### Validation
Run integration tests:
```bash
cargo test -p openre-plugins rest_api
cargo test -p openre-plugins graphql
cargo test -p openre-plugins api_rate_limiting
```

---

## References

- OWASP API Security Top 10 2023
- OWASP Top 10 2021
- CWE-284 (Improper Access Control)
- CWE-306 (Missing Authentication)
- CWE-770 (Resource Consumption)
- CWE-400 (Uncontrolled Resource Consumption)