# Access Control Testing Documentation

## Overview

The Access Control testing module provides comprehensive assessment of authorization mechanisms including IDOR detection, missing authorization checks, privilege boundary validation, and information disclosure analysis.

## Plugin: Access Control (`access_control`)

Detects indicators of Insecure Direct Object References (IDOR), missing authorization checks, privilege boundary inconsistencies, and excessive information disclosure.

### Capabilities

#### 1. IDOR Detection
Tests for Insecure Direct Object References by:
- Enumerating common resource patterns (`/api/users/{id}`, `/api/orders/{id}`, etc.)
- Testing cross-user resource access with multiple authentication contexts
- Verifying ownership checks on GET, PUT, PATCH, DELETE operations

#### 2. Missing Authorization Checks
Tests for endpoints missing authentication/authorization:
- Admin endpoints accessible without authentication
- State-changing operations (POST, PUT, DELETE) without auth
- Protected endpoints returning 200/400 instead of 401/403

#### 3. Privilege Boundary Validation
Tests for privilege escalation:
- Regular users accessing admin endpoints
- Cross-user resource modification
- Role-based access control bypasses

#### 3. Information Disclosure Analysis
Tests for excessive data exposure:
- Large data dumps in API responses
- Sensitive fields in responses (passwords, tokens, keys)
- Debug information in production endpoints

### Configuration
```json
{
  "request_timeout": 30,
  "max_concurrent_requests": 10,
  "user_agent": "open-re-access-control/1.0",
  "follow_redirects": true,
  "max_redirects": 10,
  "verify_ssl": true
}
```

### Test Scenarios

#### IDOR Testing
```
Test Pattern: /api/users/{id}
Methods: GET, PUT, PATCH, DELETE
Test IDs: 1, 2, 100, 999, 1000
Contexts: User A token, User B token
Expected: User A cannot access User B's resources
```

#### Missing Authorization
```
Endpoints Tested:
- /api/admin/* (GET)
- /api/users (POST, PUT, DELETE)
- /api/orders (POST, PUT, DELETE)
- /api/documents (POST, PUT, DELETE)
- /api/settings (PUT, DELETE)
- /api/profile (PUT, DELETE)

Expected: 401/403 without auth, 403 with insufficient privileges
```

#### Privilege Boundaries
```
Test: Regular user accessing admin endpoints
Context: User token (non-admin)
Endpoints: /api/admin/users, /api/admin/settings, /api/admin/dashboard
Expected: 403 Forbidden

Test: Cross-user modification
Context: User A token
Target: User B's resources
Methods: PUT, PATCH, DELETE
Expected: 403 Forbidden
```

#### Information Disclosure
```
Endpoints Tested:
- /api/users?limit=1000
- /api/users/1?include=all
- /api/orders?limit=1000
- /api/debug, /actuator/*, /metrics

Checks:
- Response size > 100KB
- Sensitive fields: password, secret, token, key, credential
- Stack traces, stack traces, debug info
```

### Findings

| Finding | Severity | Confidence | Category |
|---------|----------|------------|----------|
| Potential IDOR - Cross-User Resource Access | High | Medium | BrokenAuthentication |
| Missing Authorization Check | High | High | BrokenAuthentication |
| Privilege Escalation - Regular User Accessing Admin Endpoint | Critical | High | BrokenAuthentication |
| Privilege Boundary Violation - Cross-User Modification | High | High | BrokenAuthentication |
| Excessive Information Disclosure | High | Medium | InformationDisclosure |
| Large Data Exposure | Medium | Low | InformationDisclosure |

### API Endpoints
- `GET /api/security/access-control/findings` - List access control findings
- `GET /api/security/access-control/findings/stats` - Access control statistics

### CLI Commands
```bash
sentinel finding security access-control --scan-id <scan_id>
sentinel finding security access-control-stats --scan-id <scan_id>
```

### Authentication Context
The plugin requires authentication tokens for meaningful testing:
```json
{
  "target_url": "https://api.example.com",
  "auth_tokens": ["user1_token", "user2_token", "admin_token"]
}
```

At minimum, two user tokens are needed for IDOR and privilege boundary testing. An admin token enables admin endpoint testing.

### Safe Testing Practices
- Only reads resources (GET) and attempts modifications with safe payloads
- Does not delete or permanently modify resources
- Uses conservative rate limits
- Respects scope enforcement

### References
- OWASP API Security Top 10 2023:
  - API1:2023 - Broken Object Level Authorization
  - API3:2023 - Broken Object Property Level Authorization
  - API5:2023 - Broken Function Level Authorization
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-284: Improper Access Control
- OWASP Top 10 2021 - A01:2021 Broken Access Control

### Testing Targets
- Applications with user-owned resources (DVWA, bWAPP, custom apps)
- APIs with admin panels
- Multi-tenant applications
- Applications with role-based access control

### Integration
```json
{
  "target_id": "target_123",
  "name": "Access Control Scan",
  "plugins": ["access_control"],
  "config": {
    "auth_tokens": ["token1", "token2"]
  }
}
```

### Finding Correlation
Access control findings can be correlated with:
- Injection findings (IDOR + SQLi = data extraction)
- Authentication findings (missing auth + IDOR = full bypass)
- Rate limiting findings (no rate limit + IDOR = enumeration)