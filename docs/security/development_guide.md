# Security Module Development Guide

This guide explains how to develop new security assessment plugins for the open-re framework.

## Architecture Overview

Security plugins are implemented as standard open-re plugins with the `PluginType::Security` type. They integrate with the scan engine through the plugin SDK and return findings using the standardized finding schema.

## Plugin Structure

```
plugins/security/<plugin_name>/
├── plugin.toml          # Plugin manifest
├── config_schema.json   # Configuration schema (JSON Schema)
├── src/
│   └── lib.rs           # Plugin implementation
└── Cargo.toml           # Plugin dependencies (optional)
```

## Creating a New Security Plugin

### 1. Create the Plugin Module

Create a new file in `crates/openre-plugins/src/security/<name>.rs`:

```rust
//! <Plugin Name> Plugin
//! 
//! Brief description of what this plugin checks.

use crate::security::{
    SecurityPlugin, SecurityPluginConfig, SecurityReference, standard_references,
    HttpResponse,  // or other helpers as needed
};
use openre_plugins::sdk::{Plugin, CapabilityRequest, CapabilityResponse, AnalysisContext, Capability};
use openre_core::ids::PluginId;
use openre_scanner::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};

/// <Plugin Name> Plugin
pub struct <PluginName>Plugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl <PluginName>Plugin {
    pub fn new(config: SecurityPluginConfig) -> Self {
        let http_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(config.max_redirects as usize))
                .user_agent(&config.user_agent)
                .build()
                .expect("Failed to create HTTP client")
        );
        
        Self { config, http_client }
    }
    
    // Add your analysis methods here
    async fn analyze_target(&self, base_url: &str) -> AnalysisResult {
        // Your analysis logic
    }
}

#[async_trait]
impl Plugin for <PluginName>Plugin {
    type Config = SecurityPluginConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config)
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAccess,
            Capability::ReadConfig,
            // Add other capabilities as needed
        ]
    }
    
    async fn execute(&self, request: CapabilityRequest) -> openre_plugins::sdk::Result<CapabilityResponse> {
        let context = request.context;
        let target_url = context.metadata.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");
        
        info!("Starting <plugin> analysis for {}", target_url);
        
        let analysis = self.analyze_target(target_url).await;
        let mut findings = Vec::new();
        
        // Convert analysis results to findings
        for issue in analysis.issues {
            let mut finding = Finding::new(
                issue.title,
                format!("{}\n\nRecommendation: {}", issue.description, issue.recommendation),
                issue.severity,
                Confidence::High,  // Adjust based on confidence
                Category::SecurityMisconfiguration,  // Or appropriate category
                target_url.to_string(),
                "web_application".to_string(),
                "<plugin_name>".to_string(),
                env!("CARGO_PKG_VERSION").to_string(),
                context.job_id.into(),
            );
            
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: issue.description.clone(),
                data: Some(serde_json::to_value(&issue).unwrap()),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
            });
            
            // Add references
            for reference in self.references() {
                finding = finding.with_reference(Reference {
                    reference_type: match reference.ref_type.as_str() {
                        "CWE" => ReferenceType::Cwe,
                        "OWASP" => ReferenceType::Owasp,
                        _ => ReferenceType::Custom(reference.ref_type),
                    },
                    title: reference.id.clone(),
                    url: reference.url,
                    description: Some(reference.description),
                });
            }
            
            finding = finding.with_tag(format!("{}_{}", <plugin_name>, issue.issue_type));
            findings.push(finding);
        }
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "total_issues": findings.len(),
        })))
    }
}

impl SecurityPlugin for <PluginName>Plugin {
    fn security_category(&self) -> &'static str {
        "<category_name>"  // e.g., "authentication", "session_management", etc.
    }
    
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    
    fn description(&self) -> &'static str {
        "Detailed description of what this plugin checks"
    }
    
    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-XXX".to_string(),
                url: "https://cwe.mitre.org/data/definitions/XXX.html".to_string(),
                description: "Description".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A0X:2021".to_string(),
                url: "https://owasp.org/Top10/A0X_2021-...".to_string(),
                description: "OWASP Top 10 2021 - ...".to_string(),
            },
        ]);
        refs
    }
    
    fn validate_config(&self, config: &SecurityPluginConfig) -> Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

// Plugin entry point
openre_plugins::plugin_entry!(<PluginName>Plugin);
```

### 2. Define Analysis Result Structures

Create structures to hold your analysis results:

```rust
#[derive(Debug, Default, Serialize, Deserialize)]
struct AnalysisResult {
    issues: Vec<SecurityIssue>,
    // Add other fields as needed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityIssue {
    issue_type: String,
    severity: Severity,
    title: String,
    description: String,
    recommendation: String,
    // Add evidence-specific fields
}
```

### 3. Create Plugin Manifest

Create `plugins/security/<name>/plugin.toml`:

```toml
name = "<plugin_name>"
version = "0.1.0"
description = "Description of what this plugin checks"
author = "open-re Team"
license = "MIT"
repository = "https://github.com/open-re/open-re"
homepage = "https://github.com/open-re/open-re"

[plugin]
type = "security"
capabilities = ["ReadBinary", "WriteAnnotations", "QueryDatabase", "NetworkAccess", "ReadConfig"]
min_core_version = "0.1.0"
max_core_version = "1.0.0"

[plugin.entry]
wasm = "<plugin_name>.wasm"
native = { linux = "lib<plugin_name>.so", macos = "lib<plugin_name>.dylib", windows = "<plugin_name>.dll" }

[build]
target = "wasm"
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
schema = "config_schema.json"
defaults = {}
```

### 4. Create Configuration Schema

Create `plugins/security/<name>/config_schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "<Plugin Name> Plugin Configuration",
  "type": "object",
  "properties": {
    "settings": {
      "type": "object",
      "properties": {
        "aggressive_mode": {
          "type": "boolean",
          "default": false,
          "description": "Enable aggressive scanning"
        },
        "verify_ssl": {
          "type": "boolean",
          "default": true,
          "description": "Verify SSL certificates"
        }
      }
    },
    "enabled_checks": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["check1", "check2", "check3"]
      },
      "default": ["check1", "check2", "check3"],
      "description": "Which checks to enable"
    },
    "request_timeout": {
      "type": "integer",
      "default": 30,
      "minimum": 5,
      "maximum": 300,
      "description": "Request timeout in seconds"
    },
    "max_concurrent_requests": {
      "type": "integer",
      "default": 10,
      "minimum": 1,
      "maximum": 100,
      "description": "Maximum concurrent requests"
    },
    "user_agent": {
      "type": "string",
      "default": "open-re-security-scanner/1.0",
      "description": "User agent string for requests"
    },
    "follow_redirects": {
      "type": "boolean",
      "default": true,
      "description": "Follow HTTP redirects"
    },
    "max_redirects": {
      "type": "integer",
      "default": 10,
      "minimum": 0,
      "maximum": 50,
      "description": "Maximum number of redirects to follow"
    }
  },
  "required": ["request_timeout", "max_concurrent_requests", "user_agent"]
}
```

### 5. Register the Plugin Module

Add the module to `crates/openre-plugins/src/security/mod.rs`:

```rust
pub mod <plugin_name>;

// Re-export if needed
pub use <plugin_name>::<PluginName>Plugin;
```

### 6. Add Tests

Create tests in `crates/openre-plugins/tests/`:

```rust
#[tokio::test]
async fn test_<plugin_name>_plugin() {
    let mock_server = MockServer::start().await;
    
    // Mock responses
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string("<html>Test</html>")
            .insert_header("content-type", "text/html"))
        .mount(&mock_server)
        .await;
    
    let config = SecurityPluginConfig::default();
    let plugin = <PluginName>Plugin::new(config);
    
    let context = create_test_context(&mock_server.uri());
    let request = CapabilityRequest {
        capability: openre_core::ids::Capability::NetworkAccess,
        context,
        input: serde_json::json!({"target_url": mock_server.uri()}),
    };
    
    let response = plugin.execute(request).await.unwrap();
    assert!(response.success);
    
    let output = response.output.unwrap();
    let findings = output["findings"].as_array().unwrap();
    
    // Assert expected findings
    assert!(findings.len() > 0);
}
```

## Helper Functions

The `security` module provides common utilities:

### HTTP Response Handling

```rust
use crate::security::HttpResponse;

async fn make_request(&self, url: &str) -> Option<HttpResponse> {
    let response = self.http_client.get(url).send().await.ok()?;
    let status = response.status().as_u16();
    let headers: HashMap<String, String> = response.headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = response.text().await.ok()?;
    
    Some(HttpResponse {
        status,
        headers,
        body,
        url: url.to_string(),
        cookies: extract_cookies(&headers, url),
    })
}
```

### Cookie Extraction

```rust
use crate::security::{extract_cookies, CookieInfo};

let cookies = extract_cookies(&response.headers, &response.url);
for cookie in cookies {
    // Analyze cookie
}
```

### Authentication Page Detection

```rust
use crate::security::{is_auth_page, detect_sso_providers, detect_mfa_indicators};

if is_auth_page(&url, &body) {
    let sso = detect_sso_providers(&body);
    let mfa = detect_mfa_indicators(&body);
}
```

## Finding Best Practices

### Severity Guidelines

| Severity | When to Use |
|----------|-------------|
| Critical | Immediate exploitation possible, sensitive data exposure |
| High | Significant security weakness, likely exploitable |
| Medium | Security weakness, may be exploitable under conditions |
| Low | Minor issue, defense-in-depth improvement |
| Info | Informational, no direct security impact |

### Confidence Guidelines

| Confidence | When to Use |
|------------|-------------|
| Very High | Confirmed vulnerability, direct evidence |
| High | Strong evidence, minimal false positive risk |
| Medium | Reasonable evidence, some uncertainty |
| Low | Weak evidence, higher false positive risk |
| Very Low | Speculative, needs manual verification |

### Evidence Requirements

Always include evidence with findings:

```rust
finding = finding.with_evidence(Evidence {
    evidence_type: EvidenceType::HttpResponse,  // or HttpRequest, CodeSnippet, etc.
    description: "Description of what the evidence shows",
    data: Some(serde_json::json!({
        "key": "value",
        "url": "https://example.com",
        "status": 200,
    })),
    location: Some("https://example.com/path".to_string()),
    metadata: HashMap::new(),
});
```

### Reference Requirements

Include relevant references:

```rust
finding = finding.with_reference(Reference {
    reference_type: ReferenceType::Cwe,  // or Owasp, Cve, etc.
    title: "CWE-XXX".to_string(),
    url: "https://cwe.mitre.org/data/definitions/XXX.html".to_string(),
    description: Some("Description of the weakness".to_string()),
});
```

### Tagging

Use consistent tags for categorization:

```rust
finding = finding.with_tag("category_subcategory".to_string());
// Examples: "auth_login_form", "cookie_secure_flag", "header_csp_missing"
```

## Testing Guidelines

### Unit Tests

Test helper functions and logic in isolation:

```rust
#[test]
fn test_my_helper_function() {
    let result = my_helper("input");
    assert_eq!(result, "expected");
}
```

### Integration Tests

Test with mock HTTP server:

```rust
#[tokio::test]
async fn test_plugin_integration() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path("/test"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_string("<html>Test</html>"))
        .mount(&mock_server)
        .await;
    
    // Test plugin
}
```

### Test Coverage

Aim for:
- Unit tests for all helper functions
- Integration tests for each check type
- Edge case testing (empty responses, malformed headers, etc.)
- False positive verification

## Performance Considerations

1. **Concurrency**: Use `max_concurrent_requests` to limit parallelism
2. **Timeouts**: Respect `request_timeout` for all HTTP requests
3. **Caching**: Use `ScanCache` for sharing data between plugins
4. **Rate Limiting**: Be conservative with request rates
5. **Memory**: Stay within `max_memory_mb` limit

## Security Considerations

1. **No Credential Attacks**: Never attempt to guess passwords or exploit vulnerabilities
2. **Safe Testing**: Rate limiting tests should be conservative
3. **SSL Verification**: Respect `verify_ssl` setting
4. **Input Validation**: Validate all user inputs and configuration
5. **Error Handling**: Don't leak sensitive information in errors

## Common Patterns

### Checking Multiple Endpoints

```rust
let endpoints = vec!["/login", "/register", "/password/reset"];
for endpoint in endpoints {
    let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
    if let Some(response) = self.make_request(&url).await {
        // Analyze response
    }
}
```

### Analyzing Headers

```rust
if let Some(header_value) = response.headers.get("header-name") {
    // Analyze header value
}
```

### Parsing HTML (Simple)

For simple HTML parsing, use regex (for production, consider a proper HTML parser):

```rust
let regex = Regex::new(r#"<input[^>]*name=["']([^"']+)["']"#).unwrap();
for cap in regex.captures_iter(&body) {
    if let Some(name) = cap.get(1) {
        // Found input field
    }
}
```

## Debugging

Enable debug logging:

```rust
tracing::debug!("Analyzing {}", url);
tracing::debug!("Response status: {}", response.status);
tracing::debug!("Found issue: {:?}", issue);
```

## Publishing

1. Build the plugin: `cargo build --release --target wasm32-wasip1`
2. Test with the scanner
3. Create a release with the WASM file and manifest
4. Submit to the plugin registry (when available)

## Example: Complete Minimal Plugin

See `crates/openre-plugins/src/security/auth_discovery.rs` for a complete example.

## Support

For questions about plugin development:
- Check existing plugins for patterns
- Review the plugin SDK documentation
- Open an issue on GitHub