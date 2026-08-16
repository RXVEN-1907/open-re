//! Information Disclosure Plugin
//!
//! Detects exposure of server banners, framework versions, debug pages,
//! stack traces, and common metadata leaks.

use crate::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{
    standard_references, HttpResponse, SecurityPlugin, SecurityPluginConfig, SecurityReference,
};
use async_trait::async_trait;
use chrono::Utc;
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Reference, ReferenceType,
    Severity,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Information Disclosure Plugin
pub struct InformationDisclosurePlugin {
    config: SecurityPluginConfig,
    http_client: Arc<reqwest::Client>,
}

impl InformationDisclosurePlugin {
    pub fn new(config: SecurityPluginConfig) -> Self {
        let http_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .user_agent(&config.user_agent)
                .build()
                .expect("Failed to create HTTP client"),
        );

        Self {
            config,
            http_client,
        }
    }

    /// Analyze information disclosure on target
    async fn analyze_information_disclosure(&self, base_url: &str) -> InfoDisclosureResult {
        let mut result = InfoDisclosureResult::default();

        // 1. Analyze main page headers and body
        let main_response = self.make_request(base_url, "GET").await;
        if let Some(resp) = main_response {
            result.main_page_analysis = Some(self.analyze_response(&resp, "main_page"));
        }

        // 2. Check common debug/exposed endpoints
        let debug_endpoints = self.get_debug_endpoints();
        for endpoint in debug_endpoints {
            let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
            let response = self.make_request(&url, "GET").await;
            if let Some(resp) = response {
                if resp.status == 200 || resp.status == 403 || resp.status == 500 {
                    result
                        .debug_endpoint_analyses
                        .push(self.analyze_response(&resp, &format!("debug:{}", endpoint)));
                }
            }
        }

        // 3. Check for server header disclosure
        if let Some(main) = &result.main_page_analysis {
            result.server_header_analysis = self.analyze_server_header(&main.headers);
        }

        // 4. Check for framework/technology disclosure
        if let Some(main) = &result.main_page_analysis {
            result.technology_analysis =
                self.analyze_technology_disclosure(&main.headers, &main.body_snippet);
        }

        // 5. Check for common sensitive files
        let sensitive_files = self.get_sensitive_files();
        for file in sensitive_files {
            let url = format!("{}{}", base_url.trim_end_matches('/'), file);
            let response = self.make_request(&url, "GET").await;
            if let Some(resp) = response {
                if resp.status == 200 {
                    result
                        .sensitive_file_analyses
                        .push(self.analyze_response(&resp, &format!("sensitive_file:{}", file)));
                }
            }
        }

        // 6. Check for API documentation exposure
        let api_doc_endpoints = self.get_api_doc_endpoints();
        for endpoint in api_doc_endpoints {
            let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
            let response = self.make_request(&url, "GET").await;
            if let Some(resp) = response {
                if resp.status == 200 {
                    result
                        .api_doc_analyses
                        .push(self.analyze_response(&resp, &format!("api_doc:{}", endpoint)));
                }
            }
        }

        result
    }

    async fn make_request(&self, url: &str, method: &str) -> Option<HttpResponse> {
        let request = match method.to_uppercase().as_str() {
            "GET" => self.http_client.get(url),
            "POST" => self.http_client.post(url),
            "HEAD" => self.http_client.head(url),
            _ => self.http_client.get(url),
        };

        let response = match request.send().await {
            Ok(resp) => resp,
            Err(e) => {
                debug!("Request failed for {}: {}", url, e);
                return None;
            }
        };

        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = match response.text().await {
            Ok(b) => b,
            Err(_) => String::new(),
        };

        Some(HttpResponse {
            status,
            headers,
            body,
            url: url.to_string(),
            cookies: Vec::new(),
        })
    }

    fn analyze_response(&self, response: &HttpResponse, source: &str) -> ResponseAnalysis {
        let mut analysis = ResponseAnalysis {
            source: source.to_string(),
            url: response.url.clone(),
            status: response.status,
            headers: response.headers.clone(),
            body_snippet: self.get_body_snippet(&response.body),
            issues: Vec::new(),
        };

        // Check headers for information disclosure
        self.check_header_disclosure(&mut analysis);

        // Check body for information disclosure
        self.check_body_disclosure(&mut analysis);

        analysis
    }

    fn get_body_snippet(&self, body: &str) -> String {
        // Return first 500 chars for evidence
        if body.len() > 500 {
            format!("{}... [truncated]", &body[..500])
        } else {
            body.to_string()
        }
    }

    fn check_header_disclosure(&self, analysis: &mut ResponseAnalysis) {
        // Server header
        if let Some(server) = analysis.headers.get("server") {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "server_header".to_string(),
                severity: Severity::Low,
                title: "Server Header Discloses Version".to_string(),
                description: format!("Server header reveals: {}", server),
                evidence: server.clone(),
                recommendation: "Configure web server to hide or minimize Server header information".to_string(),
            });
        }

        // X-Powered-By header
        if let Some(powered) = analysis.headers.get("x-powered-by") {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "x_powered_by".to_string(),
                severity: Severity::Low,
                title: "X-Powered-By Header Discloses Technology".to_string(),
                description: format!("X-Powered-By header reveals: {}", powered),
                evidence: powered.clone(),
                recommendation: "Remove or obfuscate X-Powered-By header".to_string(),
            });
        }

        // X-AspNet-Version
        if let Some(version) = analysis.headers.get("x-aspnet-version") {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "x_aspnet_version".to_string(),
                severity: Severity::Low,
                title: "X-AspNet-Version Header Discloses Version".to_string(),
                description: format!("X-AspNet-Version header reveals: {}", version),
                evidence: version.clone(),
                recommendation: "Remove X-AspNet-Version header in production".to_string(),
            });
        }

        // X-AspNetMvc-Version
        if let Some(version) = analysis.headers.get("x-aspnetmvc-version") {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "x_aspnetmvc_version".to_string(),
                severity: Severity::Low,
                title: "X-AspNetMvc-Version Header Discloses Version".to_string(),
                description: format!("X-AspNetMvc-Version header reveals: {}", version),
                evidence: version.clone(),
                recommendation: "Remove X-AspNetMvc-Version header in production".to_string(),
            });
        }

        // X-Runtime (Rails)
        if let Some(runtime) = analysis.headers.get("x-runtime") {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "x_runtime".to_string(),
                severity: Severity::Info,
                title: "X-Runtime Header Present".to_string(),
                description: format!(
                    "X-Runtime header reveals request processing time: {}",
                    runtime
                ),
                evidence: runtime.clone(),
                recommendation: "Consider removing X-Runtime header in production".to_string(),
            });
        }

        // X-Request-Id / X-Correlation-Id
        for header in ["x-request-id", "x-correlation-id", "x-trace-id"] {
            if let Some(value) = analysis.headers.get(header) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: format!("{}_exposure", header.replace("-", "_")),
                    severity: Severity::Info,
                    title: format!("{} Header Present", header.to_uppercase()),
                    description: format!("{} header reveals internal tracking ID: {}", header, value),
                    evidence: value.clone(),
                    recommendation: "Consider removing internal tracking headers in production or using non-predictable values".to_string(),
                });
            }
        }

        // Via header (proxy information)
        if let Some(via) = analysis.headers.get("via") {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "via_header".to_string(),
                severity: Severity::Info,
                title: "Via Header Discloses Proxy Chain".to_string(),
                description: format!("Via header reveals proxy information: {}", via),
                evidence: via.clone(),
                recommendation:
                    "Configure proxies to not forward Via header or minimize information"
                        .to_string(),
            });
        }

        // X-Forwarded-* headers
        for header in [
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-server",
        ] {
            if let Some(value) = analysis.headers.get(header) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: format!("{}_exposure", header.replace("-", "_")),
                    severity: Severity::Info,
                    title: format!("{} Header Present", header.to_uppercase()),
                    description: format!("{} header reveals: {}", header, value),
                    evidence: value.clone(),
                    recommendation: "Ensure these headers are only added by trusted proxies"
                        .to_string(),
                });
            }
        }

        // Access-Control-Allow-Origin with credentials (already covered in CORS plugin)
        // But check for overly permissive CORS in general
        if let Some(acao) = analysis.headers.get("access-control-allow-origin") {
            if acao == "*" {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "cors_wildcard".to_string(),
                    severity: Severity::Low,
                    title: "Permissive CORS Policy".to_string(),
                    description: "Access-Control-Allow-Origin is set to '*'".to_string(),
                    evidence: acao.clone(),
                    recommendation: "Restrict CORS to specific origins".to_string(),
                });
            }
        }
    }

    fn check_body_disclosure(&self, analysis: &mut ResponseAnalysis) {
        let body = &analysis.body_snippet;
        let body_lower = body.to_lowercase();

        // Stack traces
        let stack_trace_patterns: [&str; 8] = [
            r"at\s+\w+\.\w+\(.*:\d+\)",                // Java/C# stack trace
            r#"File\s+\".*\",\s+line\s+\d+"#,          // Python traceback
            r"Traceback\s+\(most recent call last\):", // Python
            r"#\d+\s+0x[0-9a-f]+\s+in\s+\w+",          // Go
            r"at\s+[\w\.]+\s+\(.*:\d+\)",              // JavaScript
            r"Error:\s+.*\n\s+at\s+",                  // Node.js
            r"Stack trace:",                           // Generic
            r"Backtrace:",                             // Rust
        ];

        for pattern in stack_trace_patterns {
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(body) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "stack_trace".to_string(),
                    severity: Severity::Medium,
                    title: "Stack Trace Exposed in Response".to_string(),
                    description: "Response body contains a stack trace which may reveal internal application structure".to_string(),
                    evidence: self.extract_match(body, pattern).unwrap_or_default(),
                    recommendation: "Disable detailed error messages in production. Use generic error pages".to_string(),
                });
                break; // Only report once per response
            }
        }

        // Debug pages / detailed error pages
        let debug_patterns = [
            r"debug\s*=\s*true",
            r"DEBUG\s*:\s*True",
            r"APP_DEBUG\s*=\s*true",
            r"Whoops\!", // Laravel
            r"Symfony\\Component\\Debug",
            r"Django\s+Debug\s+Toolbar",
            r"Flask\s+Debug",
            r"Express\s+Error\s+Handler",
            r"ASP\.NET\s+Detailed\s+Error",
            r"Yellow\s+Screen\s+of\s+Death",
            r"Server\s+Error\s+in\s+'/'\s+Application",
        ];

        for pattern in &debug_patterns {
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(&body_lower) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "debug_page".to_string(),
                    severity: Severity::High,
                    title: "Debug/Error Page Exposed".to_string(),
                    description: "Response appears to be a debug or detailed error page".to_string(),
                    evidence: self.extract_match(body, pattern).unwrap_or_default(),
                    recommendation: "Disable debug mode in production. Configure custom error pages".to_string(),
                });
                break;
            }
        }

        // Version numbers in body
        let version_patterns = [
            (r#"version\s*[:=]\s*[\d\.]+"#, "Version Number"),
            (r#"v[\d\.]+\.[\d\.]+\.[\d\.]+"#, "Semantic Version"),
            (r#"[\d]+\.[\d]+\.[\d]+(-[a-zA-Z0-9]+)?"#, "Version Pattern"),
        ];

        for (pattern, desc) in &version_patterns {
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(&body_lower) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "version_disclosure".to_string(),
                    severity: Severity::Low,
                    title: format!("{} Disclosed in Response Body", desc),
                    description: format!(
                        "Response body contains a {} pattern",
                        desc.to_lowercase()
                    ),
                    evidence: self.extract_match(body, pattern).unwrap_or_default(),
                    recommendation: "Remove version information from client-facing responses"
                        .to_string(),
                });
                break;
            }
        }

        // Framework-specific markers
        let framework_markers = [
            ("laravel", "Laravel"),
            ("symfony", "Symfony"),
            ("django", "Django"),
            ("flask", "Flask"),
            ("express", "Express.js"),
            ("rails", "Ruby on Rails"),
            ("spring", "Spring Framework"),
            ("asp.net", "ASP.NET"),
            ("php", "PHP"),
            ("node.js", "Node.js"),
            ("nginx", "Nginx"),
            ("apache", "Apache"),
            ("iis", "IIS"),
            ("tomcat", "Apache Tomcat"),
            ("jetty", "Jetty"),
            ("webpack", "Webpack"),
            ("react", "React"),
            ("vue", "Vue.js"),
            ("angular", "Angular"),
            ("jquery", "jQuery"),
            ("bootstrap", "Bootstrap"),
        ];

        for (marker, name) in &framework_markers {
            if body_lower.contains(marker) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: format!("framework_{}", marker.replace(".", "_")),
                    severity: Severity::Info,
                    title: format!("{} Framework Detected", name),
                    description: format!("Response body contains references to {}", name),
                    evidence: marker.to_string(),
                    recommendation:
                        "Consider removing framework identifiers from client-facing responses"
                            .to_string(),
                });
            }
        }

        // Sensitive data patterns
        let sensitive_patterns = [
            (r#"password\s*[:=]\s*["']?[^"'\s]+"#, "Password"),
            (r#"api[_-]?key\s*[:=]\s*["']?[^"'\s]+"#, "API Key"),
            (r#"secret\s*[:=]\s*["']?[^"'\s]+"#, "Secret"),
            (r#"token\s*[:=]\s*["']?[^"'\s]+"#, "Token"),
            (r#"private[_-]?key\s*[:=]\s*["']?[^"'\s]+"#, "Private Key"),
            (r#"access[_-]?token\s*[:=]\s*["']?[^"'\s]+"#, "Access Token"),
            (r#"auth[_-]?token\s*[:=]\s*["']?[^"'\s]+"#, "Auth Token"),
            (r#"jdbc:.*://.*:.*@"#, "JDBC Connection String"),
            (r#"mongodb://.*:.*@"#, "MongoDB Connection String"),
            (r#"redis://.*:.*@"#, "Redis Connection String"),
            (r#"postgres://.*:.*@"#, "PostgreSQL Connection String"),
            (r#"mysql://.*:.*@"#, "MySQL Connection String"),
        ];

        for (pattern, desc) in &sensitive_patterns {
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(&body_lower) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: format!("sensitive_{}", desc.to_lowercase().replace(" ", "_")),
                    severity: Severity::Critical,
                    title: format!("{} Exposed in Response Body", desc),
                    description: format!("Response body appears to contain a {}", desc.to_lowercase()),
                    evidence: self.extract_match(body, pattern).unwrap_or_default(),
                    recommendation: "Immediately remove sensitive data from response. Rotate any exposed credentials".to_string(),
                });
            }
        }

        // Directory listing
        if body_lower.contains("index of /")
            || body_lower.contains("directory listing")
            || (body_lower.contains("<title>index of") && body_lower.contains("</title>"))
        {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "directory_listing".to_string(),
                severity: Severity::Medium,
                title: "Directory Listing Enabled".to_string(),
                description: "Server returns directory listing for a path".to_string(),
                evidence: "Directory listing detected in response".to_string(),
                recommendation: "Disable directory listing in web server configuration".to_string(),
            });
        }

        // Source code disclosure
        if body_lower.contains("<?php")
            || body_lower.contains("<%@")
            || body_lower.contains("<%=")
            || body_lower.contains("<?=")
            || body_lower.contains("jsp:")
        {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: "source_code_disclosure".to_string(),
                severity: Severity::High,
                title: "Server-Side Source Code Disclosed".to_string(),
                description: "Response contains server-side source code markers".to_string(),
                evidence: "Source code markers detected".to_string(),
                recommendation:
                    "Ensure server-side code is properly executed, not served as plain text"
                        .to_string(),
            });
        }

        // Backup/config files
        let backup_patterns = [
            r#"\.bak"#,
            r#"\.backup"#,
            r#"\.old"#,
            r#"\.orig"#,
            r#"\.save"#,
            r#"\.swp"#,
            r#"\.swo"#,
            r#"~$"#,
            r#"\.tmp"#,
            r#"\.temp"#,
            r#"config\.bak"#,
            r#"\.env\.bak"#,
            r#"settings\.bak"#,
        ];

        for pattern in &backup_patterns {
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(&body_lower) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "backup_file_reference".to_string(),
                    severity: Severity::Low,
                    title: "Backup/Config File Reference Detected".to_string(),
                    description: format!(
                        "Response contains reference to backup or temporary file pattern: {}",
                        pattern
                    ),
                    evidence: pattern.to_string(),
                    recommendation:
                        "Ensure backup and temporary files are not accessible via web server"
                            .to_string(),
                });
                break;
            }
        }

        // Comments with sensitive info
        let comment_patterns = [
            r#"<!--\s*(TODO|FIXME|HACK|XXX|BUG|PASSWORD|SECRET|KEY|TOKEN)"#,
            r#"/\*\s*(TODO|FIXME|HACK|XXX|BUG|PASSWORD|SECRET|KEY|TOKEN)"#,
        ];

        for pattern in &comment_patterns {
            let regex = Regex::new(pattern).unwrap();
            if regex.is_match(&body_lower) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "sensitive_comment".to_string(),
                    severity: Severity::Low,
                    title: "Sensitive Comment in Response".to_string(),
                    description: "HTML/JS comments contain potentially sensitive keywords"
                        .to_string(),
                    evidence: self.extract_match(body, pattern).unwrap_or_default(),
                    recommendation: "Remove sensitive comments from production code".to_string(),
                });
                break;
            }
        }
    }

    fn extract_match(&self, text: &str, pattern: &str) -> Option<String> {
        let regex = Regex::new(pattern).ok()?;
        regex.find(text).map(|m| m.as_str().to_string())
    }

    fn analyze_server_header(&self, headers: &HashMap<String, String>) -> ServerHeaderAnalysis {
        let mut analysis = ServerHeaderAnalysis {
            server_header: headers.get("server").cloned(),
            x_powered_by: headers.get("x-powered-by").cloned(),
            x_aspnet_version: headers.get("x-aspnet-version").cloned(),
            x_aspnetmvc_version: headers.get("x-aspnetmvc-version").cloned(),
            issues: Vec::new(),
        };

        if let Some(server) = &analysis.server_header {
            // Check for version disclosure
            let version_regex = Regex::new(r"[\d]+\.[\d]+\.[\d]+").unwrap();
            if version_regex.is_match(server) {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "server_version".to_string(),
                    severity: Severity::Low,
                    title: "Server Header Contains Version Number".to_string(),
                    description: format!("Server header reveals version: {}", server),
                    evidence: server.clone(),
                    recommendation: "Configure server to hide version in Server header".to_string(),
                });
            }

            // Check for detailed server info
            if server.to_lowercase().contains("ubuntu")
                || server.to_lowercase().contains("debian")
                || server.to_lowercase().contains("centos")
                || server.to_lowercase().contains("red hat")
            {
                analysis.issues.push(InfoDisclosureIssue {
                    issue_type: "server_os_disclosure".to_string(),
                    severity: Severity::Info,
                    title: "Server Header Discloses Operating System".to_string(),
                    description: format!("Server header reveals OS: {}", server),
                    evidence: server.clone(),
                    recommendation: "Configure server to minimize Server header information"
                        .to_string(),
                });
            }
        }

        analysis
    }

    fn analyze_technology_disclosure(
        &self,
        headers: &HashMap<String, String>,
        body: &str,
    ) -> TechnologyAnalysis {
        let mut analysis = TechnologyAnalysis {
            detected_technologies: Vec::new(),
            issues: Vec::new(),
        };

        let body_lower = body.to_lowercase();

        // Check headers for technology hints
        let header_tech = [
            ("x-powered-by", "X-Powered-By"),
            ("server", "Server"),
            ("x-aspnet-version", "ASP.NET"),
            ("x-aspnetmvc-version", "ASP.NET MVC"),
            ("x-runtime", "Ruby on Rails"),
            ("x-drupal-cache", "Drupal"),
            ("x-generator", "Generator"),
            ("x-content-encoded-by", "Content Encoding"),
        ];

        for (header, tech) in &header_tech {
            if let Some(value) = headers.get(*header) {
                analysis.detected_technologies.push(DetectedTechnology {
                    name: tech.to_string(),
                    version: self.extract_version(value),
                    detection_method: format!("HTTP Header: {}", header),
                    confidence: Confidence::High,
                });
            }
        }

        // Check body for technology markers
        let body_tech = [
            ("laravel", "Laravel"),
            ("symfony", "Symfony"),
            ("django", "Django"),
            ("flask", "Flask"),
            ("express", "Express.js"),
            ("rails", "Ruby on Rails"),
            ("spring", "Spring Framework"),
            ("asp.net", "ASP.NET"),
            ("php", "PHP"),
            ("node.js", "Node.js"),
            ("nginx", "Nginx"),
            ("apache", "Apache"),
            ("iis", "IIS"),
            ("tomcat", "Apache Tomcat"),
            ("jetty", "Jetty"),
            ("webpack", "Webpack"),
            ("react", "React"),
            ("vue", "Vue.js"),
            ("angular", "Angular"),
            ("jquery", "jQuery"),
            ("bootstrap", "Bootstrap"),
            ("wordpress", "WordPress"),
            ("drupal", "Drupal"),
            ("joomla", "Joomla"),
            ("magento", "Magento"),
            ("shopify", "Shopify"),
        ];

        for (marker, name) in &body_tech {
            if body_lower.contains(marker) {
                analysis.detected_technologies.push(DetectedTechnology {
                    name: name.to_string(),
                    version: self.extract_version_from_body(body, marker),
                    detection_method: "Response Body".to_string(),
                    confidence: Confidence::Medium,
                });
            }
        }

        // Report technology disclosure
        for tech in &analysis.detected_technologies {
            analysis.issues.push(InfoDisclosureIssue {
                issue_type: format!(
                    "tech_{}",
                    tech.name.to_lowercase().replace(" ", "_").replace(".", "_")
                ),
                severity: Severity::Info,
                title: format!("Technology Detected: {}", tech.name),
                description: format!("Detected {} via {}", tech.name, tech.detection_method),
                evidence: format!("Version: {:?}", tech.version),
                recommendation: "Consider hiding technology stack information in production"
                    .to_string(),
            });
        }

        analysis
    }

    fn extract_version(&self, text: &str) -> Option<String> {
        let version_regex = Regex::new(r"[\d]+\.[\d]+(\.[\d]+)?(-[a-zA-Z0-9]+)?").ok()?;
        version_regex.find(text).map(|m| m.as_str().to_string())
    }

    fn extract_version_from_body(&self, body: &str, marker: &str) -> Option<String> {
        // Look for version near the marker
        let pattern = format!(
            r"{}[^a-zA-Z0-9]*([\d]+\.[\d]+(\.[\d]+)?)",
            regex::escape(marker)
        );
        let regex = Regex::new(&pattern).ok()?;
        regex
            .captures(body)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
    }

    fn get_debug_endpoints(&self) -> Vec<&'static str> {
        vec![
            "/debug",
            "/debug/",
            "/debug/default/view",
            "/actuator",
            "/actuator/",
            "/actuator/health",
            "/actuator/info",
            "/actuator/env",
            "/actuator/metrics",
            "/health",
            "/health/",
            "/healthz",
            "/ready",
            "/live",
            "/metrics",
            "/metrics/",
            "/prometheus",
            "/prometheus/metrics",
            "/status",
            "/status/",
            "/server-status",
            "/server-status/",
            "/admin",
            "/admin/",
            "/adminer",
            "/phpmyadmin",
            "/pma",
            "/swagger",
            "/swagger/",
            "/swagger-ui",
            "/swagger-ui/",
            "/api-docs",
            "/api-docs/",
            "/openapi",
            "/openapi.json",
            "/graphql",
            "/graphql/",
            "/playground",
            "/playground/",
            "/console",
            "/console/",
            "/h2-console",
            "/h2-console/",
            "/_profiler",
            "/_profiler/",
            "/_wdt",
            "/_wdt/",
            "/trace",
            "/trace/",
            "/traces",
            "/traces/",
            "/dump",
            "/dump/",
            "/heapdump",
            "/heapdump/",
            "/env",
            "/env/",
            "/config",
            "/config/",
            "/info",
            "/info/",
            "/system/info",
            "/system/info/",
        ]
    }

    fn get_sensitive_files(&self) -> Vec<&'static str> {
        vec![
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/config.json",
            "/config.yaml",
            "/config.yml",
            "/config.xml",
            "/settings.json",
            "/settings.yaml",
            "/settings.yml",
            "/package.json",
            "/composer.json",
            "/pom.xml",
            "/build.gradle",
            "/Dockerfile",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.htaccess",
            "/web.config",
            "/nginx.conf",
            "/apache.conf",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/id_rsa",
            "/id_dsa",
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/wp-config.php",
            "/configuration.php",
            "/config.php",
            "/.aws/credentials",
            "/.aws/config",
            "/.npmrc",
            "/.yarnrc",
            "/.pypirc",
        ]
    }

    fn get_api_doc_endpoints(&self) -> Vec<&'static str> {
        vec![
            "/swagger.json",
            "/swagger.yaml",
            "/swagger.yml",
            "/openapi.json",
            "/openapi.yaml",
            "/openapi.yml",
            "/api-docs.json",
            "/api-docs.yaml",
            "/swagger/v1/swagger.json",
            "/swagger/v2/swagger.json",
            "/api/swagger.json",
            "/api/openapi.json",
            "/docs/swagger.json",
            "/docs/openapi.json",
            "/redoc",
            "/redoc/",
            "/doc",
            "/doc/",
        ]
    }
}

/// Result of information disclosure analysis
#[derive(Debug, Default, Serialize, Deserialize)]
struct InfoDisclosureResult {
    main_page_analysis: Option<ResponseAnalysis>,
    debug_endpoint_analyses: Vec<ResponseAnalysis>,
    server_header_analysis: ServerHeaderAnalysis,
    technology_analysis: TechnologyAnalysis,
    sensitive_file_analyses: Vec<ResponseAnalysis>,
    api_doc_analyses: Vec<ResponseAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseAnalysis {
    source: String,
    url: String,
    status: u16,
    headers: HashMap<String, String>,
    body_snippet: String,
    issues: Vec<InfoDisclosureIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InfoDisclosureIssue {
    issue_type: String,
    severity: Severity,
    title: String,
    description: String,
    evidence: String,
    recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ServerHeaderAnalysis {
    server_header: Option<String>,
    x_powered_by: Option<String>,
    x_aspnet_version: Option<String>,
    x_aspnetmvc_version: Option<String>,
    issues: Vec<InfoDisclosureIssue>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TechnologyAnalysis {
    detected_technologies: Vec<DetectedTechnology>,
    issues: Vec<InfoDisclosureIssue>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DetectedTechnology {
    name: String,
    version: Option<String>,
    detection_method: String,
    confidence: Confidence,
}

#[async_trait]
impl Plugin for InformationDisclosurePlugin {
    type Config = SecurityPluginConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config)
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> crate::sdk::Result<CapabilityResponse> {
        let context = request.context;
        let target_url = request
            .input
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");

        info!(
            "Starting information disclosure analysis for {}",
            target_url
        );

        let analysis = self.analyze_information_disclosure(target_url).await;
        let mut findings = Vec::new();

        // Collect all issues
        let mut all_issues = Vec::new();

        if let Some(main) = &analysis.main_page_analysis {
            all_issues.extend(main.issues.clone());
        }

        for debug in &analysis.debug_endpoint_analyses {
            all_issues.extend(debug.issues.clone());
        }

        all_issues.extend(analysis.server_header_analysis.issues.clone());
        all_issues.extend(analysis.technology_analysis.issues.clone());

        for sensitive in &analysis.sensitive_file_analyses {
            all_issues.extend(sensitive.issues.clone());
        }

        for api_doc in &analysis.api_doc_analyses {
            all_issues.extend(api_doc.issues.clone());
        }

        let critical_severity = all_issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Critical))
            .count();
        let high_severity = all_issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::High))
            .count();
        let medium_severity = all_issues
            .iter()
            .filter(|i| matches!(i.severity, Severity::Medium))
            .count();

        // Summary finding
        let severity = if critical_severity > 0 {
            Severity::Critical
        } else if high_severity > 0 {
            Severity::High
        } else if medium_severity > 0 {
            Severity::Medium
        } else {
            Severity::Info
        };
        let mut summary_finding = Finding::new(FindingConfig {
            title: "Information Disclosure Analysis Summary".to_string(),
            description: format!(
                "Analyzed information disclosure for {}. Found {} total issues ({} critical, {} high, {} medium). \
                Checked main page, {} debug endpoints, {} sensitive files, and {} API documentation endpoints.",
                target_url,
                all_issues.len(),
                critical_severity,
                high_severity,
                medium_severity,
                analysis.debug_endpoint_analyses.len(),
                analysis.sensitive_file_analyses.len(),
                analysis.api_doc_analyses.len()
            ),
            severity,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target_url.to_string(),
            target_type: "web_application".to_string(),
            plugin_source: "information_disclosure".to_string(),
            plugin_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_id: openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
        });

        summary_finding = summary_finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: "Information disclosure analysis summary".to_string(),
            data: Some(serde_json::json!({
                "main_page_analysis": analysis.main_page_analysis,
                "debug_endpoint_analyses": analysis.debug_endpoint_analyses,
                "server_header_analysis": analysis.server_header_analysis,
                "technology_analysis": analysis.technology_analysis,
                "sensitive_file_analyses": analysis.sensitive_file_analyses,
                "api_doc_analyses": analysis.api_doc_analyses,
                "total_issues": all_issues.len(),
                "critical_severity_issues": critical_severity,
                "high_severity_issues": high_severity,
                "medium_severity_issues": medium_severity,
            })),
            location: Some(target_url.to_string()),
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("information_disclosure".to_string()),
            timestamp: Utc::now(),
        });

        for reference in self.references() {
            summary_finding = summary_finding.with_reference(Reference {
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

        summary_finding = summary_finding.with_tag("info_disclosure_analysis".to_string());
        findings.push(summary_finding);

        // Individual issue findings
        for issue in &all_issues {
            let mut finding = Finding::new(FindingConfig {
                title: format!("Information Disclosure: {}", issue.title),
                description: format!(
                    "{}\n\nEvidence: {}\n\nRecommendation: {}",
                    issue.description, issue.evidence, issue.recommendation
                ),
                severity: issue.severity,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target_url.to_string(),
                target_type: "web_application".to_string(),
                plugin_source: "information_disclosure".to_string(),
                plugin_version: env!("CARGO_PKG_VERSION").to_string(),
                scan_id: openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid()),
            });

            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: "Information disclosure issue details".to_string(),
                data: Some(serde_json::json!({
                    "issue": issue,
                })),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
                http_request: None,
                http_response: None,
                timing: None,
                payload: None,
                reproduction_steps: None,
                plugin_source: Some("information_disclosure".to_string()),
                timestamp: Utc::now(),
            });

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

            finding = finding.with_tag(format!("info_disclosure_{}", issue.issue_type));
            findings.push(finding);
        }

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "total_issues": all_issues.len(),
            "critical_severity_issues": critical_severity,
            "high_severity_issues": high_severity,
            "medium_severity_issues": medium_severity,
        })))
    }
}

impl SecurityPlugin for InformationDisclosurePlugin {
    fn security_category(&self) -> &'static str {
        "information_disclosure"
    }

    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    fn description(&self) -> &'static str {
        "Detects exposure of server banners, framework versions, debug pages, stack traces, and common metadata leaks"
    }

    fn references(&self) -> Vec<SecurityReference> {
        let mut refs = standard_references();
        refs.extend(vec![
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-200".to_string(),
                url: "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                description: "Exposure of Sensitive Information to an Unauthorized Actor"
                    .to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-497".to_string(),
                url: "https://cwe.mitre.org/data/definitions/497.html".to_string(),
                description: "Exposure of System Data to an Unauthorized Control Sphere"
                    .to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-215".to_string(),
                url: "https://cwe.mitre.org/data/definitions/215.html".to_string(),
                description: "Insertion of Sensitive Information Into Debugging Code".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A01:2021".to_string(),
                url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
                description: "OWASP Top 10 2021 - Broken Access Control".to_string(),
            },
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A05:2021".to_string(),
                url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
                description: "OWASP Top 10 2021 - Security Misconfiguration".to_string(),
            },
        ]);
        refs
    }

    fn validate_config(&self, config: &SecurityPluginConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        Ok(())
    }
}

// Plugin entry point
