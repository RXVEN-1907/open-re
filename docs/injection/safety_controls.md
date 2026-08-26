# Injection Testing Safety Controls

## Overview

The injection testing framework implements comprehensive safety controls to ensure testing is performed responsibly and only against authorized targets. These controls are mandatory and cannot be bypassed.

## Safety Architecture

```
┌─────────────────────────────────────────────────────────────┐
                    SafetyController
├─────────────────────────────────────────────────────────────┤
  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────┐
  │   Scope     │ │  Payload    │ │   Request   │ │  Rate   │
  │  Validator  │ │  Validator  │ │  Validator  │ │ Limiter │
  └─────────────┘ └─────────────┘ └─────────────┘ └─────────┘
         │               │               │            │
         └───────────────┼───────────────┼────────────┘
                         ▼
              ┌─────────────────────┐
              │  Concurrency        │
              │  Semaphore          │
              └─────────────────────┘
                         │
                         ▼
              ┌─────────────────────┐
              │  Request Permit     │
              │  (auto-release)     │
              └─────────────────────┘
```

## Core Safety Controls

### 1. Authorization Verification

**Required by default** (`require_authorization: true`)

```rust
let safety = SafetyController::new(config);
safety.initialize(allowed_scopes, Some(auth_token)).await?;
```

-   Validates authorization token before any testing
-   Token verified against auth service (production) or non-empty check (development)
-   Without valid token: `SafetyError::AuthorizationRequired`

### 2. Scope Enforcement

**Allowed Scopes** (`allowed_scopes`):

```toml
allowed_scopes = ["example.com", "*.test.local", "192.168.1.0/24"]
```

-   Wildcard subdomain support: `*.example.com` matches `api.example.com`, `test.example.com`
-   Exact match: `example.com` matches only `example.com`
-   CIDR notation for IP ranges
-   Empty list = no restrictions (not recommended)

**Blocked Scopes** (`blocked_scopes`):

```toml
blocked_scopes = ["production.internal", "*.gov", "10.0.0.0/8"]
```

-   Checked before allowed scopes
-   Prevents accidental testing of sensitive environments

### 3. Payload Blocking

**Default Blocked Patterns**:

```toml
blocked_patterns = [
    "DROP TABLE",
    "DELETE FROM", 
    "TRUNCATE",
    "SHUTDOWN",
    "REBOOT",
    "rm -rf",
    "format",
    "mkfs"
]
```

-   Case-insensitive substring matching
-   Applied to all payloads before execution
-   Blocked payloads logged and counted
-   Custom patterns can be added via config

### 4. Request Limits

| Limit | Default | Description |
| ------- | --------- | ------------- |
| `max_requests_per_test` | 100 | Max requests per parameter test |
| `max_total_requests` | 10,000 | Max requests per scan |
| `max_payloads_per_param` | 50 | Max payloads per parameter |
| `max_concurrency` | 5 | Max concurrent requests |

### 5. Rate Limiting

**Token Bucket Algorithm**:

-   Configurable `rate_limit_rps` (requests per second)
-   Default: 10 RPS
-   Burst allowance up to bucket size
-   Smooths traffic to prevent target overload

```rust
// Rate limiter acquisition
rate_limiter.acquire().await; // Blocks until token available
```

### 6. Timeouts

| Timeout | Default | Description |
| --------- | --------- | ------------- |
| `request_timeout_secs` | 30 | Per-request timeout |
| `plugin_timeout` | 300s | Per-plugin execution timeout |
| `scan_timeout` | 3600s | Total scan timeout |

### 7. Concurrency Control

**Semaphore-based**:

```rust
let semaphore = Arc::new(Semaphore::new(max_concurrency));
let permit = semaphore.acquire().await?;
// Request executes
drop(permit); // Released automatically
```

-   Prevents resource exhaustion
-   Fair queuing of requests
-   Configurable via `max_concurrency`

### 8. Request Validation

**Validated Properties**:

-   HTTP Method: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
-   Request Size: Max 1MB (configurable)
-   Content-Type: JSON, form-urlencoded, multipart, XML, text

## Configuration

### SafetyConfig Structure

```toml
[safety]
max_requests_per_test = 100
max_total_requests = 10000
rate_limit_rps = 10.0
max_payloads_per_param = 50
max_concurrency = 5
request_timeout_secs = 30
allowed_scopes = ["example.com", "*.test.local"]
blocked_scopes = ["production.*", "*.gov"]
blocked_patterns = [
    "DROP TABLE",
    "DELETE FROM",
    "TRUNCATE",
    "SHUTDOWN",
    "REBOOT",
    "rm -rf",
    "format",
    "mkfs",
    "custom_dangerous_pattern"
]
require_authorization = true
```

### Per-Plugin Configuration

Each injection plugin inherits safety config but can override:

```toml
# In plugin config_schema.JSON
"safety": {
  "max_requests_per_test": { "default": 50 },  # Stricter for this plugin
  "rate_limit_rps": { "default": 5.0 },        # Slower for sensitive tests
  "blocked_patterns": { 
    "default": ["DROP TABLE", "CUSTOM_PATTERN"] 
  }
}
```

## Safety Statistics

Monitor safety metrics during scans:

```rust
let stats = safety_controller.get_stats().await;
println!("Total requests: {}", stats.total_requests);
println!("Blocked payloads: {}", stats.blocked_payloads);
println!("Current test requests: {}", stats.current_test_requests);
println!("Elapsed: {:?}", stats.elapsed_time);
println!("Authorization verified: {}", stats.authorization_verified);
```

**SafetyStats Fields**:

-   `current_test_requests`: Requests in current test
-   `total_requests`: Total requests this scan
-   `blocked_payloads`: Count of blocked payloads
-   `elapsed_time`: Scan duration
-   `rate_limit_rps`: Current rate limit
-   `max_concurrency`: Concurrency limit
-   `max_total_requests`: Total request limit
-   `authorization_verified`: Auth status

## Error Handling

### SafetyError Types

| Error | Cause | Resolution |
| ------- | ------- | ------------ |
| `AuthorizationRequired` | No auth token provided | Provide valid authorization |
| `InvalidAuthorization` | Token validation failed | Check token validity |
| `ScopeViolation(url)` | Target not in allowed scopes | Add target to allowed_scopes |
| `BlockedPayload(pattern)` | Payload contains blocked pattern | Use safe payload or adjust patterns |
| `RequestLimitExceeded` | Max total requests reached | Increase limit or reduce scope |
| `ConcurrencyError` | Semaphore acquisition failed | Reduce concurrency or wait |
| `InvalidUrl` | URL parsing failed | Fix target URL |
| `RateLimitExceeded` | Rate limit exceeded (should not happen) | Check rate limiter config |
| `TimeoutExceeded` | Request/plugin timeout | Increase timeout or optimize |
| `SafetyCheckFailed(msg)` | Generic validation failure | Check error message |

### Handling in Plugins

```rust
// In plugin execute()
if let Err(e) = self.safety.check_scope(target_url) {
    warn!("Scope check failed: {}", e);
    return vec![]; // Skip this target
}

for payload in payloads {
    if let Err(e) = self.safety.check_payload(&payload.raw) {
        warn!("Payload blocked: {}", e);
        continue; // Skip this payload
    }
    
    let permit = self.safety.acquire_request_permit().await?;
    // ... execute request
}
```

## Best Practices

### For Security Teams

1.  **Always Require Authorization**

   ```toml
   require_authorization = true
   ```

2.  **Define Explicit Scopes**

   ```toml
   allowed_scopes = ["staging.example.com", "test.example.com"]
   blocked_scopes = ["production.example.com", "*.internal"]
   ```

3.  **Use Conservative Limits**

   ```toml
   rate_limit_rps = 5.0
   max_concurrency = 3
   max_requests_per_test = 50
   ```

4.  **Block Dangerous Patterns**

   ```toml
   blocked_patterns = [
       "DROP TABLE", "DELETE FROM", "TRUNCATE",
       "SHUTDOWN", "REBOOT", "rm -rf",
       "format", "mkfs", "wget", "curl",
       "nc ", "netcat", "Bash -i", "sh -i"
   ]
   ```

### For Developers

1.  **Test Safety Controls**

   ```rust
   #[test]
   fn test_payload_blocking() {
       let safety = SafetyConfig::default();
       let controller = SafetyController::new(safety);
       
       assert!(controller.check_payload("DROP TABLE users").is_err());
       assert!(controller.check_payload("SELECT * FROM users").is_ok());
   }
   ```

2.  **Log Blocked Payloads**

   ```rust
   if let Err(e) = safety.check_payload(&payload) {
       info!("Blocked payload: {} - {}", payload, e);
       safety.blocked_payloads.push(payload);
       continue;
   }
   ```

3.  **Monitor Statistics**

   ```rust
   // Periodic logging
   let stats = safety.get_stats().await;
   info!("Safety stats: {:?}", stats);
   ```

## Compliance

### Authorization Tracking

Every scan records:

-   Authorization token hash (not the token itself)
-   Timestamp of authorization verification
-   Scopes authorized for

### Audit Trail

Safety events logged:

-   Authorization verification (success/failure)
-   Scope violations (blocked targets)
-   Payload blocks (pattern matched)
-   Rate limit events
-   Limit exceeded events

### Data Protection

-   No sensitive data in logs (tokens, payloads with secrets)
-   Request/response bodies only stored for findings
-   Configurable retention for scan data

## Disabling Safety Controls (NOT RECOMMENDED)

For testing framework itself:

```toml
[safety]
require_authorization = false
allowed_scopes = []  # No restrictions
blocked_patterns = []  # No payload blocking
rate_limit_rps = 0  # No rate limiting
max_concurrency = 50  # High concurrency
```

**Warning**: Only use in isolated test environments with explicit approval.

## Integration with CI/CD

### Pre-Scan Validation

```yaml
# .GitHub/workflows/security-scan.yml
- name: Validate Safety Config
  run: |
    Cargo test -p openre-plugins safety_controls
    
- name: Check Authorization
  run: |
    if [ -z "$SCAN_AUTH_TOKEN" ]; then
      echo "Authorization token required"
      exit 1
    fi
```

### Scan Execution

```yaml
- name: Run Injection Scan
  env:
    SCAN_AUTH_TOKEN: ${{ secrets.SCAN_AUTH_TOKEN }}
    ALLOWED_SCOPES: "staging.example.com,test.example.com"
  run: |
    sentinel scan start \
      --target ${{ GitHub.event.inputs.target }} \
      --plugins sql_injection,XSS,command_injection \
      --auth-token $SCAN_AUTH_TOKEN \
      --allowed-scopes $ALLOWED_SCOPES
```

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
| ------- | ------- | ---------- |
| "Authorization required" | No token provided | Set `SCAN_AUTH_TOKEN` env var |
| "Scope violation" | Target not allowed | Add to `allowed_scopes` |
| "Payload blocked" | Pattern match | Review payload or adjust patterns |
| "Request limit exceeded" | Too many requests | Increase limits or reduce scope |
| "Rate limit" | Too fast | Reduce `rate_limit_rps` or increase |

### Debug Mode

Enable detailed safety logging:

```bash
RUST_LOG=openre_plugins::injection::safety_controls=debug sentinel scan start ...
```

### Safety Statistics API

```bash
# Get safety stats for scan
curl -H "Authorization: Bearer $TOKEN" \
  /api/security/scans/$SCAN_ID/safety-stats
```

Response:

```json
{
  "current_test_requests": 45,
  "total_requests": 1234,
  "blocked_payloads": 12,
  "elapsed_time": "00:15:30",
  "rate_limit_rps": 10.0,
  "max_concurrency": 5,
  "max_total_requests": 10000,
  "authorization_verified": true
}
```
