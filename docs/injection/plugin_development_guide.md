# Injection Plugin Development Guide

## Overview

This guide explains how to create new injection vulnerability detection plugins using the shared injection testing framework. The framework provides reusable components for payload generation, request mutation, response analysis, confidence scoring, and safety controls.

## Prerequisites

-   Rust 1.75+
-   Understanding of the target injection vulnerability
-   Familiarity with the open-re plugin system

## Quick Start

### 1. Create Plugin Structure

```
plugins/security/my_injection/
├── plugin.TOML
└── config_schema.JSON
```

### 2. Implement Plugin in `crates/openre-plugins/src/injection/`

Create `my_injection.rs`:

```rust
//! My Injection Plugin
//!
//! Detects [vulnerability type] vulnerabilities.

use crate::injection::{
    ConfidenceScorer, ConfidenceConfig, InjectionCategory, InjectionPluginConfig,
    InjectionTestResult, ParameterLocation, PayloadContext, PayloadEngine, RequestEngine,
    ResponseAnalyzer, SafetyConfig, SafetyController, create_confidence_scorer,
    create_payload_engine, create_request_engine, create_response_analyzer,
    ConfidenceScorer, SafetyConfig, SafetyController,
};
use crate::sdk::{Plugin, CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability};
use openre_core::ids::PluginId;
use openre_scanner::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};

/// My Injection Plugin
pub struct MyInjectionPlugin {
    base: crate::injection::injection_plugin::BaseInjectionPlugin,
}

impl MyInjectionPlugin {
    /// Create a new plugin instance
    pub fn new(config: InjectionPluginConfig) -> Result<Self, String> {
        let base = crate::injection::injection_plugin::BaseInjectionPlugin::new(
            config,
            InjectionCategory::Custom, // Or add new category to enum
        )?;
        
        Ok(Self { base })
    }
    
    fn injection_category(&self) -> InjectionCategory {
        InjectionCategory::Custom
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    fn description(&self) -> &'static str {
        "Detects [vulnerability type] vulnerabilities"
    }
    
    fn references(&self) -> Vec<crate::injection::SecurityReference> {
        vec![
            crate::injection::SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A03:2021".to_string(),
                url: "HTTPS://owasp.org/Top10/A03_2021-Injection/".to_string(),
                description: "OWASP Top 10 2021 - Injection".to_string(),
            },
            crate::injection::SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-XXX".to_string(),
                url: "HTTPS://cwe.mitre.org/data/definitions/XXX.HTML".to_string(),
                description: "CWE description".to_string(),
            },
        ]
    }
    
    fn validate_config(&self, config: &InjectionPluginConfig) -> Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }
}

#[async_trait]
impl Plugin for MyInjectionPlugin {
    type Config = InjectionPluginConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create plugin")
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAccess,
            Capability::ReadConfig,
        ]
    }
    
    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let target_url = request.input.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("HTTP://localhost");
        
        info!("Starting [vulnerability] testing for {}", target_url);
        
        // Define parameters to test
        let parameters = request.input.get("parameters")
            .and_then(|v| serde_json::from_value::<Vec<crate::injection::injection_plugin::ParameterTestConfig>>(v.clone()).ok())
            .unwrap_or_else(|| vec![
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "param1".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
            ]);
        
        // Create payload context with technology hints
        let payload_context = PayloadContext {
            parameter_name: "".to_string(),
            location: ParameterLocation::Query,
            expected_type: None,
            technology_hints: vec!["mytech".to_string()], // Add relevant hints
            database_type: None,
            template_engine: None,
            os_type: None,
            is_id_parameter: false,
            is_auth_context: false,
            custom: HashMap::new(),
        };
        
        // Execute injection tests
        let results = self.base.execute_injection_tests(target_url, parameters, &payload_context).await;
        
        // Convert to findings
        let scan_id = context.job_id.into();
        let findings = self.base.results_to_findings(results, scan_id, target_url);
        
        Ok(CapabilityResponse::success(serde_json::JSON!({
            "findings": findings,
            "tests_performed": results.len(),
            "vulnerabilities_found": findings.len(),
        })))
    }
}

impl crate::injection::InjectionPlugin for MyInjectionPlugin {
    fn injection_category(&self) -> InjectionCategory {
        InjectionCategory::Custom
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    fn description(&self) -> &'static str {
        "Detects [vulnerability type] vulnerabilities"
    }
    
    fn references(&self) -> Vec<crate::injection::SecurityReference> {
        self.references()
    }
    
    fn validate_config(&self, config: &InjectionPluginConfig) -> Result<(), String> {
        self.validate_config(config)
    }
    
    fn payload_engine(&self) -> Box<dyn PayloadEngine> {
        create_payload_engine(self.base.config.safety.clone())
    }
    
    fn response_analyzer(&self) -> Box<dyn ResponseAnalyzer> {
        create_response_analyzer(InjectionCategory::Custom)
    }
}

// Plugin entry point
crate::plugin_entry!(MyInjectionPlugin);
```

### 3. Add Payloads to Payload Engine

In `crates/openre-plugins/src/injection/payload_engine.rs`:

```rust
// In load_builtin_payloads()
self.payloads.insert(InjectionCategory::Custom, Self::my_injection_payloads());

// Add payload function
fn my_injection_payloads() -> Vec<Payload> {
    vec![
        Payload {
            id: "my_injection_1".to_string(),
            category: InjectionCategory::Custom,
            raw: "payload_string".to_string(),
            description: "Description of payload".to_string(),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            risk_level: 3,
            is_safe: true,
            required_context: vec!["mytech".to_string()], // Context hints
            compatible_encodings: vec![Encoding::None, Encoding::Url],
            detection_method: crate::injection::DetectionMethod::ErrorBased,
        },
        // Add more payloads...
    ]
}
```

### 4. Add Error Patterns to Response Analyzer

In `crates/openre-plugins/src/injection/response_analyzer.rs`:

```rust
// In load_error_patterns()
InjectionCategory::Custom => vec![
    ErrorPattern {
        pattern: r"(?i)my.*error".to_string(),
        description: "My injection error".to_string(),
        severity: Severity::High,
        detection_method: DetectionMethod::ErrorBased,
    },
],

// Add pattern matching function
fn check_my_patterns(&self, result: &TestResult, body: &str) -> Vec<InjectionTestResult> {
    let mut findings = Vec::new();
    let body_lower = body.to_lowercase();
    
    let patterns = [
        (r"my_pattern", "My pattern detected"),
    ];
    
    for (pattern, desc) in &patterns {
        if Regex::Regex::new(pattern).map_or(false, |re| re.is_match(&body_lower)) {
            findings.push(InjectionTestResult {
                category: self.category,
                parameter: result.parameter.clone(),
                location: result.location,
                payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                detection_method: DetectionMethod::PatternMatch,
                confidence: 0.85,
                severity: Severity::High,
                evidence: InjectionEvidence {
                    original_request: Some(result.request.clone()),
                    triggering_response: result.response.clone(),
                    baseline_response: result.baseline_response.clone(),
                    diff: None,
                    matched_patterns: vec![pattern.to_string()],
                    timing_info: None,
                },
                reproducible_request: ReproducibleRequest {
                    method: result.request.method.clone(),
                    url: result.request.url.clone(),
                    headers: result.request.headers.clone(),
                    body: result.request.body.clone(),
                    parameter: result.parameter.clone(),
                    payload: result.payload.as_ref().map(|p| p.raw.clone()).unwrap_or_default(),
                    location: result.location,
                },
                verification_steps: vec![
                    "Verify the pattern is reproducible".to_string(),
                    "Analyze the impact".to_string(),
                ],
                tags: vec!["pattern-match".to_string(), "my-injection".to_string()],
            });
        }
    }
    
    findings
}

// In check_patterns() match ARM:
InjectionCategory::Custom => {
    findings.extend(self.check_my_patterns(result, body));
}
```

### 5. Add Context Filtering

In `payload_engine.rs` in `get_payloads()`:

```rust
// In context requirement matching:
"mytech" => context.technology_hints.iter().any(|t| t.to_lowercase().contains("mytech")),
```

### 6. Create Plugin Manifest

`plugins/security/my_injection/plugin.TOML`:

```toml
name = "my_injection"
version = "1.0.0"
description = "Detects [vulnerability type] vulnerabilities"
author = "Your Name"
license = "MIT"
repository = "https://github.com/open-re/open-re"
homepage = "https://github.com/open-re/open-re"

[plugin]
type = "security"
capabilities = ["NetworkAccess", "ReadConfig"]
min_core_version = "0.1.0"
max_core_version = "1.0.0"

[plugin.entry]
WASM = "my_injection.WASM"
native = { Linux = "libmy_injection.so", macOS = "libmy_injection.dylib", Windows = "my_injection.dll" }

[build]
target = "WASM"
rust_version = "1.75"
features = []

[resources]
max_memory_mb = 256
max_fuel = 10000000
max_execution_time_secs = 300

[ui]
views = []
panels = []
menus = []

[config]
schema = "config_schema.JSON"
defaults = {}
```

### 7. Create Config Schema

`plugins/security/my_injection/config_schema.JSON`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "My Injection Plugin Configuration",
  "type": "object",
  "properties": {
    "enabled_tests": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["test1", "test2", "test3"]
      },
      "default": ["test1", "test2", "test3"],
      "description": "Enabled test categories"
    },
    "request_timeout": {
      "type": "integer",
      "minimum": 1,
      "maximum": 300,
      "default": 30,
      "description": "Request timeout in seconds"
    },
    "max_concurrent_requests": {
      "type": "integer",
      "minimum": 1,
      "maximum": 50,
      "default": 10,
      "description": "Maximum concurrent requests"
    },
    "user_agent": {
      "type": "string",
      "default": "open-re-my-tester/1.0",
      "description": "User agent string"
    },
    "follow_redirects": {
      "type": "boolean",
      "default": true,
      "description": "Follow HTTP redirects"
    },
    "max_redirects": {
      "type": "integer",
      "minimum": 0,
      "maximum": 20,
      "default": 10,
      "description": "Maximum redirect depth"
    },
    "safety": {
      "type": "object",
      "properties": {
        "max_requests_per_test": {
          "type": "integer",
          "minimum": 1,
          "maximum": 1000,
          "default": 100,
          "description": "Maximum requests per test"
        },
        "max_total_requests": {
          "type": "integer",
          "minimum": 1,
          "maximum": 100000,
          "default": 10000,
          "description": "Maximum total requests per scan"
        },
        "rate_limit_rps": {
          "type": "number",
          "minimum": 0,
          "maximum": 1000,
          "default": 10.0,
          "description": "Request rate limit (requests per second)"
        },
        "max_payloads_per_param": {
          "type": "integer",
          "minimum": 1,
          "maximum": 500,
          "default": 50,
          "description": "Maximum payloads per parameter"
        },
        "max_concurrency": {
          "type": "integer",
          "minimum": 1,
          "maximum": 50,
          "default": 5,
          "description": "Maximum concurrency"
        },
        "request_timeout_secs": {
          "type": "integer",
          "minimum": 1,
          "maximum": 300,
          "default": 30,
          "description": "Request timeout in seconds"
        },
        "allowed_scopes": {
          "type": "array",
          "items": { "type": "string" },
          "default": [],
          "description": "Allowed target scopes"
        },
        "blocked_patterns": {
          "type": "array",
          "items": { "type": "string" },
          "default": [
            "DROP TABLE",
            "DELETE FROM",
            "TRUNCATE",
            "SHUTDOWN",
            "REBOOT",
            "rm -rf",
            "format",
            "mkfs"
          ],
          "description": "Blocked payload patterns"
        },
        "require_authorization": {
          "type": "boolean",
          "default": true,
          "description": "Require explicit authorization"
        }
      },
      "required": [
        "max_requests_per_test",
        "max_total_requests",
        "rate_limit_rps",
        "max_payloads_per_param",
        "max_concurrency",
        "request_timeout_secs",
        "allowed_scopes",
        "blocked_patterns",
        "require_authorization"
      ]
    }
  },
  "required": [
    "enabled_tests",
    "request_timeout",
    "max_concurrent_requests",
    "user_agent",
    "follow_redirects",
    "max_redirects",
    "safety"
  ]
}
```

## Best Practices

### Payload Design

1.  **Start Safe**: Begin with non-destructive payloads (`is_safe: true`)
2.  **Use Context Hints**: Filter payloads by technology/database/OS
3.  **Multiple Detection Methods**: Include error-based, boolean-based, time-based, reflection
4.  **Encoding Variants**: Test with multiple encodings (URL, HTML entity, etc.)
5.  **Risk Levels**: Assign appropriate risk levels (1-10)

### Response Analysis

1.  **Error Patterns**: Add specific error messages for the technology
2.  **Pattern Matching**: Look for unique indicators in responses
3.  **Differential Analysis**: Compare baseline vs test responses
4.  **Timing Analysis**: For time-based blind injection
5.  **Reflection Detection**: Check if payload appears in response

### Safety

1.  **Block Destructive Patterns**: Add to `blocked_patterns` in safety config
2.  **Limit Requests**: Set reasonable `max_requests_per_test`
3.  **Rate Limit**: Configure `rate_limit_rps` appropriately
4.  **Scope Enforcement**: Define `allowed_scopes` for target restriction
5.  **Authorization**: Require explicit authorization

### Testing

1.  **Unit Tests**: Test payload generation, encoding, mutation
2.  **Integration Tests**: Test against vulnerable applications
3.  **False Positive Reduction**: Verify findings with multiple methods
4.  **Regression Tests**: Ensure existing tests still pass

## Example: Complete LDAP Injection Plugin

See `crates/openre-plugins/src/injection/ldap_injection.rs` for a complete example with:

-   Authentication bypass payloads
-   Blind injection payloads
-   LDAP-specific error patterns
-   LDAP data exposure pattern matching
-   Proper references (CWE-90, OWASP A03:2021)

## Registering the Plugin

1.  Build the plugin:

   ```bash
   Cargo build --release -p openre-plugins
   ```

2.  The plugin will be auto-discovered from `local_plugin_dir` (configured in `PluginConfig`)

3.  Or manually register via API:

   ```bash
   curl -X POST /api/plugins/register \
     -H "Authorization: Bearer <token>" \
     -d '{"path": "/path/to/my_injection"}'
   ```

## Running the Plugin

Via CLI:

```bash
sentinel scan start --target <target_id> --plugins my_injection
```

Via API:

```bash
curl -X POST /api/scans \
  -H "Authorization: Bearer <token>" \
  -d '{"target_id": "...", "plugins": ["my_injection"]}'
```

## Debugging

Enable debug logging:

```bash
RUST_LOG=openre_plugins::injection=debug sentinel scan start ...
```

Check plugin health:

```bash
sentinel plugin health --id my_injection
```

View findings:

```bash
sentinel finding security injection --scan-id <scan_id>
```

## Contributing

1.  Follow the existing code style
2.  Add comprehensive tests
3.  Update documentation
4.  Submit PR with description of vulnerability type detected
5.  Include test results against vulnerable applications
