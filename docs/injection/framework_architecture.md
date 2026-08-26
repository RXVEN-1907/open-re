# Injection Testing Framework Architecture

## Overview

The Injection Testing Framework is a modular, safe, and extensible system for detecting injection vulnerabilities in web applications. It provides shared infrastructure for payload generation, request mutation, response analysis, confidence scoring, and safety controls across all injection vulnerability types.

## Core Components

### 1. Payload Engine (`payload_engine.rs`)

Responsible for:

-   **Payload Libraries**: Pre-built payloads for each injection category
-   **Context-Aware Selection**: Filters payloads based on technology hints, database type, template engine, OS type
-   **Parameter Mutation**: Applies payloads to parameters with various encodings
-   **Encoding Strategies**: URL, Double URL, HTML Entity, Unicode, Base64, Hex, SQL Comment, XML, JSON
-   **Safe Payload Limits**: Configurable maximum payloads per parameter

#### Injection Categories Supported

| Category | Description | Key Payloads |
| ---------- | ------------- | -------------- |
| `SqlInjection` | SQL injection via error-based, boolean-based, time-based, union-based | `'`, `' OR '1'='1`, `'; WAITFOR DELAY`, `UNION SELECT` |
| `NoSqlInjection` | MongoDB/NoSQL query manipulation | `{"$ne": null}`, `{"$where": "1==1"}` |
| `XSS` | Cross-Site Scripting (reflected, stored, DOM) | `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>` |
| `Ssti` | Server-Side Template Injection | `{{7*7}}`, `${7*7}`, `#set($x=7*7)${x}` |
| `CommandInjection` | OS command injection | `; id`, `\| whoami`,`$(id)`,`; sleep 5` |
| `Xxe` | XML External Entity | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| `LdapInjection` | LDAP filter injection | `\*)( \| (userPassword=_))`,`_)( \| (cn=*))` |
| `XPathInjection` | XPath query injection | `' or '1'='1`, `'] \| //user/password \| ['` |
| `HeaderInjection` | HTTP header injection (CRLF) | `\r\nX-Injected: test`, `%0d%0aX-Injected: test` |

### 2. Request Engine (`request_engine.rs`)

Supports testing of:

-   **Query Parameters** - URL query string parameters
-   **POST Bodies** - Form-urlencoded bodies
-   **JSON Bodies** - JSON request bodies
-   **XML Bodies** - XML request bodies
-   **Multipart Forms** - File uploads and multipart data
-   **HTTP Headers** - Custom and standard headers
-   **Cookies** - Cookie values
-   **Path Parameters** - URL path segments

Features:

-   Automatic baseline request capture
-   Rate limiting between requests
-   Configurable concurrency control
-   Request/response snapshots for evidence

### 3. Response Analyzer (`response_analyzer.rs`)

Implements multiple detection techniques:

| Method | Description | Reliability |
| -------- | ------------- | ------------- |
| **Error-Based** | Detects error messages in responses | High |
| **Boolean-Based** | Compares true/false condition responses | High |
| **Time-Based** | Measures response timing differences | Medium |
| **Reflection** | Detects payload reflection in response | Very High |
| **Pattern Match** | Matches known vulnerability patterns | High |
| **Differential** | Compares baseline vs test responses | Medium |
| **Out-of-Band** | Detects external channel interactions | Very High |
| **Heuristic** | Behavioral analysis | Low |

Category-specific pattern matching for:

-   SQL: UNION SELECT, information_schema, WAITFOR DELAY, pg_sleep
-   XSS: `<script>`, `onerror=`, `JavaScript:`, `onload=`
-   SSTI: `49` (7*7), `__class__`, `__mro__`, `Java.lang.Runtime`
-   Command: `uid=`, `gid=`, `root:`, `C:\Windows`
-   XXE: `/etc/passwd`, `win.ini`, AWS metadata IP
-   LDAP: `cn=`, `objectClass=`, `userPassword=`
-   XPath: node sets, element names, attribute values
-   Header: CRLF injection, cache poisoning, host header

### 4. Confidence Scoring (`confidence_scoring.rs`)

Multi-factor confidence calculation:

```
Final Score = Base × Method Weight × Severity Weight × Category Weight × Evidence Multiplier + Multi-Method Bonus
```

**Weights:**

-   Method: Error-Based (0.85), Time-Based (0.90), Reflection (0.95), Out-of-Band (0.95), Heuristic (0.50)
-   Severity: Critical (1.0), High (0.9), Medium (0.7), Low (0.5), Info (0.3)
-   Category: SQLi (1.0), SSTI (0.98), Command (0.98), XXE (0.97), LDAP (0.9), XPath (0.9), Header (0.85)

**Evidence Bonuses:**

-   Baseline response: +5%
-   Timing info: +5%
-   Diff analysis: +5%
-   Multiple patterns: +5% each (max 15%)
-   Reproducible request: +5%

**Labels:** Very High (≥0.9), High (≥0.75), Medium (≥0.6), Low (≥0.4), Very Low (<0.4)

### 5. Safety Controls (`safety_controls.rs`)

Comprehensive safeguards:

| Control | Description |
| --------- | ------------- |
| **Request Limits** | Max requests per test, max total requests per scan |
| **Rate Limiting** | Token bucket algorithm (configurable RPS) |
| **Timeouts** | Per-request and per-scan timeouts |
| **Payload Limits** | Max payloads per parameter |
| **Concurrency** | Semaphore-based concurrency control |
| **Scope Enforcement** | Allowed/blocked host patterns with wildcards |
| **Authorization** | Required explicit authorization token |
| **Payload Blocking** | Blocks dangerous patterns (DROP TABLE, rm -rf, etc.) |
| **Request Validation** | Method, size, content-type validation |

### 6. Base Injection Plugin (`injection_plugin.rs`)

Reusable base class providing:

-   Shared framework initialization
-   Safety controller integration
-   Payload engine, request engine, response analyzer composition
-   Confidence scoring
-   Finding conversion (InjectionTestResult → Finding)
-   Standardized plugin interface

## Plugin Architecture

Each injection type is implemented as a plugin extending `BaseInjectionPlugin`:

```rust
pub struct SqlInjectionPlugin {
    base: BaseInjectionPlugin,
}

impl Plugin for SqlInjectionPlugin {
    type Config = InjectionPluginConfig;
    
    fn new(config: Self::Config) -> Self { ... }
    fn capabilities(&self) -> Vec<Capability> { ... }
    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> { ... }
}

impl InjectionPlugin for SqlInjectionPlugin {
    fn injection_category(&self) -> InjectionCategory { InjectionCategory::SqlInjection }
    fn version(&self) -> &'static str { "1.0.0" }
    fn payload_engine(&self) -> Box<dyn PayloadEngine> { ... }
    fn response_analyzer(&self) -> Box<dyn ResponseAnalyzer> { ... }
}
```

## Data Flow

```
1. Scan Manager starts scan
   ↓
2. Plugin Manager loads injection plugins
   ↓
3. Plugin.execute() called with target URL and parameters
   ↓
4. BaseInjectionPlugin.execute_injection_tests()
   ↓
5. RequestEngine.test_parameter() for each parameter
   ↓
6. PayloadEngine.get_payloads() → context-aware payloads
   ↓
7. PayloadEngine.mutate_parameter() → mutated requests
   ↓
8. HTTP requests sent with rate limiting & safety checks
   ↓
9. ResponseAnalyzer.analyze() → InjectionTestResult[]
   ↓
10. ConfidenceScorer.score() → final confidence
   ↓
11. results_to_findings() → Finding[]
   ↓
12. Findings stored via ScanStorage
   ↓
13. API exposes findings via /api/security/findings
```

## Configuration

### InjectionPluginConfig

```toml
[settings]
aggressive_mode = false
verify_ssl = true

enabled_tests = ["error_based", "boolean_based", "time_based", "union_based"]
request_timeout = 30
max_concurrent_requests = 10
user_agent = "open-re-injection-tester/1.0"
follow_redirects = true
max_redirects = 10

[safety]
max_requests_per_test = 100
max_total_requests = 10000
rate_limit_rps = 10.0
max_payloads_per_param = 50
max_concurrency = 5
request_timeout_secs = 30
allowed_scopes = ["example.com", "*.test.local"]
blocked_patterns = ["DROP TABLE", "DELETE FROM", "rm -rf"]
require_authorization = true
```

### PayloadContext

Context hints for payload selection:

-   `parameter_name`: Name of parameter being tested
-   `location`: Query, Body, JsonBody, XmlBody, Header, Cookie, Path
-   `expected_type`: string, integer, boolean, etc.
-   `technology_hints`: ["mongodb", "LDAP", "xpath", "jinja2", "twig"]
-   `database_type`: "mysql", "postgresql", "sqlserver", "oracle"
-   `template_engine`: "jinja2", "twig", "freemarker", "velocity"
-   `os_type`: "Linux", "Windows"
-   `is_id_parameter`: Likely an ID parameter
-   `is_auth_context`: Authentication-related parameter

## Integration Points

### Scanner Engine

-   Plugins discovered via `PluginManager.discover_plugins()`
-   Executed via `PluginManager.execute_plugin()`
-   Findings stored via `ScanStorage.save_finding()`

### API Layer

-   `GET /api/security/findings` - All findings with filters
-   `GET /api/security/injection/findings` - Injection-specific findings
-   `GET /api/security/injection/findings/stats` - Injection statistics
-   `GET /api/security/injection/categories` - Available categories
-   `GET /api/security/injection/detection-methods` - Detection methods

### CLI/TUI

-   `sentinel finding security injection` - List injection findings
-   `sentinel finding security injection-stats` - Injection statistics
-   `sentinel finding security injection-categories` - List categories
-   `sentinel finding security detection-methods` - List methods

## Adding New Injection Types

1.  **Add to `InjectionCategory` enum** in `mod.rs`
2.  **Add payloads** in `payload_engine.rs` → `load_builtin_payloads()`
3.  **Add error patterns** in `response_analyzer.rs` → `load_error_patterns()`
4.  **Add pattern matching** in `response_analyzer.rs` → `check_patterns()`
5.  **Create plugin** following `sql_injection.rs` pattern
6.  **Add plugin manifest** in `plugins/security/<name>/`
7.  **Register in plugin registry** (auto-discovered from local_plugin_dir)

## Safety & Ethics

The framework is designed for **authorized security testing only**:

-   Requires explicit authorization token
-   Enforces scope restrictions
-   Blocks destructive payloads by default
-   Rate limits to prevent DoS
-   No exploit chaining or post-exploitation
-   Evidence-based detection only
-   Clear verification steps for each finding

## Testing

Run integration tests:

```bash
Cargo test -p openre-plugins injection_integration_tests
Cargo test -p openre-plugins injection_unit_tests
```

Test against vulnerable applications:

-   OWASP Juice Shop
-   DVWA (Damn Vulnerable Web App)
-   bWAPP
-   WebGoat
