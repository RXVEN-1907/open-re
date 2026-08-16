//! Sensitive Information Disclosure Plugin
//!
//! Detects exposure of environment files, backup files, configuration files,
//! version-control artifacts, publicly accessible secrets, and debug endpoints.

use crate::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use async_trait::async_trait;
use chrono::Utc;
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Reference, ReferenceType,
    Severity,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Sensitive Information Disclosure Plugin
pub struct SensitiveInfoPlugin {
    config: SensitiveInfoConfig,
    client: Arc<reqwest::Client>,
}

impl SensitiveInfoPlugin {
    /// Create a new Sensitive Information Disclosure plugin
    pub fn new(config: SensitiveInfoConfig) -> std::result::Result<Self, String> {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?,
        );

        Ok(Self { config, client })
    }

    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }

    /// Get plugin description
    fn description(&self) -> &'static str {
        "Detects exposure of environment files, backup files, configuration files, version-control artifacts, publicly accessible secrets, and debug endpoints"
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
                ref_type: "OWASP".to_string(),
                id: "A05:2021".to_string(),
                url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/".to_string(),
                description: "OWASP Top 10 2021 - Security Misconfiguration".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-200".to_string(),
                url: "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                description: "Exposure of Sensitive Information to an Unauthorized Actor"
                    .to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-538".to_string(),
                url: "https://cwe.mitre.org/data/definitions/538.html".to_string(),
                description: "File and Directory Information Exposure".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-540".to_string(),
                url: "https://cwe.mitre.org/data/definitions/540.html".to_string(),
                description: "Inclusion of Sensitive Information in Source Code".to_string(),
            },
        ]
    }

    /// Validate configuration
    fn validate_config(&self, config: &SensitiveInfoConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Test for sensitive file exposure
    async fn test_sensitive_files(
        &self,
        base_url: &str,
        scan_id: openre_core::ids::ScanId,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Environment and configuration files
        let env_files = vec![
            (".env", "Environment configuration file"),
            (".env.local", "Local environment configuration"),
            (".env.development", "Development environment configuration"),
            (".env.production", "Production environment configuration"),
            (".env.staging", "Staging environment configuration"),
            (".env.test", "Test environment configuration"),
            (".env.example", "Example environment configuration"),
            (".env.sample", "Sample environment configuration"),
            (".env.backup", "Backup environment configuration"),
            (".env.old", "Old environment configuration"),
            ("config.env", "Config environment file"),
            ("environment.env", "Environment file"),
            ("settings.env", "Settings environment file"),
            ("secrets.env", "Secrets environment file"),
            ("credentials.env", "Credentials environment file"),
        ];

        for (file, description) in env_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "environment", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // Configuration files
        let config_files = vec![
            ("config.json", "JSON configuration file"),
            ("config.yaml", "YAML configuration file"),
            ("config.yml", "YAML configuration file"),
            ("config.toml", "TOML configuration file"),
            ("config.ini", "INI configuration file"),
            ("config.xml", "XML configuration file"),
            ("config.php", "PHP configuration file"),
            ("config.py", "Python configuration file"),
            ("config.js", "JavaScript configuration file"),
            ("config.rb", "Ruby configuration file"),
            ("config.java", "Java configuration file"),
            ("config.properties", "Java properties file"),
            ("config.conf", "Generic configuration file"),
            ("settings.json", "Settings file"),
            ("settings.yaml", "Settings file"),
            ("settings.yml", "Settings file"),
            ("settings.php", "PHP settings file"),
            ("settings.py", "Python settings file"),
            ("app.json", "Application configuration"),
            ("app.yaml", "Application configuration"),
            ("app.yml", "Application configuration"),
            ("app.config", "Application configuration"),
            ("application.json", "Application configuration"),
            ("application.yaml", "Application configuration"),
            ("application.yml", "Application configuration"),
            ("application.properties", "Spring Boot properties"),
            ("application.yml", "Spring Boot YAML"),
            ("application-dev.properties", "Development properties"),
            ("application-prod.properties", "Production properties"),
            ("application-test.properties", "Test properties"),
            ("bootstrap.yml", "Spring Cloud bootstrap"),
            ("bootstrap.yaml", "Spring Cloud bootstrap"),
            ("bootstrap.properties", "Spring Cloud bootstrap"),
        ];

        for (file, description) in config_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "configuration", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // Backup files
        let backup_files = vec![
            ("backup.zip", "Backup archive"),
            ("backup.tar", "Backup tar archive"),
            ("backup.tar.gz", "Compressed backup"),
            ("backup.tgz", "Compressed backup"),
            ("backup.sql", "Database backup"),
            ("dump.sql", "Database dump"),
            ("database.sql", "Database dump"),
            ("backup.dump", "Database dump"),
            ("site.zip", "Site backup"),
            ("www.zip", "Web root backup"),
            ("public_html.zip", "Public HTML backup"),
            ("backup.old", "Old backup"),
            ("backup.bak", "Backup file"),
            ("backup~", "Backup file (tilde)"),
            ("backup.swp", "Vim swap file"),
            ("backup.swo", "Vim swap file"),
            ("backup.swn", "Vim swap file"),
            ("#backup#", "Emacs backup"),
            (".backup", "Hidden backup"),
            ("backup/", "Backup directory"),
            ("backups/", "Backups directory"),
            ("dumps/", "Database dumps directory"),
        ];

        for (file, description) in backup_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "backup", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // Version control artifacts
        let vcs_files = vec![
            (".git/", "Git repository"),
            (".git/config", "Git configuration"),
            (".git/HEAD", "Git HEAD reference"),
            (".git/index", "Git index"),
            (".git/logs/", "Git logs"),
            (".git/objects/", "Git objects"),
            (".git/refs/", "Git references"),
            (".gitignore", "Git ignore file"),
            (".gitattributes", "Git attributes"),
            (".gitmodules", "Git submodules"),
            (".svn/", "Subversion repository"),
            (".svn/entries", "SVN entries"),
            (".svn/wc.db", "SVN working copy database"),
            (".hg/", "Mercurial repository"),
            (".hg/store/", "Mercurial store"),
            (".hg/dirstate", "Mercurial dirstate"),
            (".bzr/", "Bazaar repository"),
            (".bzr/repository/", "Bazaar repository"),
        ];

        for (file, description) in vcs_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "version-control", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // IDE and editor files
        let ide_files = vec![
            (".idea/", "IntelliJ IDEA project"),
            (".idea/workspace.xml", "IntelliJ workspace"),
            (".idea/misc.xml", "IntelliJ misc config"),
            (".idea/modules.xml", "IntelliJ modules"),
            (".vscode/", "VS Code workspace"),
            (".vscode/settings.json", "VS Code settings"),
            (".vscode/launch.json", "VS Code launch config"),
            (".vscode/tasks.json", "VS Code tasks"),
            (".vscode/extensions.json", "VS Code extensions"),
            (".project", "Eclipse project"),
            (".classpath", "Eclipse classpath"),
            (".settings/", "Eclipse settings"),
            ("*.sublime-project", "Sublime Text project"),
            ("*.sublime-workspace", "Sublime Text workspace"),
            ("*.swp", "Vim swap file"),
            ("*.swo", "Vim swap file"),
            ("*.swn", "Vim swap file"),
            ("*~", "Backup file"),
            (".DS_Store", "macOS directory metadata"),
            ("Thumbs.db", "Windows thumbnail cache"),
        ];

        for (file, description) in ide_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "ide", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // Log files
        let log_files = vec![
            ("access.log", "Access log"),
            ("error.log", "Error log"),
            ("debug.log", "Debug log"),
            ("application.log", "Application log"),
            ("system.log", "System log"),
            ("security.log", "Security log"),
            ("audit.log", "Audit log"),
            ("php_errors.log", "PHP error log"),
            ("nginx_error.log", "Nginx error log"),
            ("apache_error.log", "Apache error log"),
            ("mysql.log", "MySQL log"),
            ("postgresql.log", "PostgreSQL log"),
            ("redis.log", "Redis log"),
            ("docker.log", "Docker log"),
            ("kubernetes.log", "Kubernetes log"),
        ];

        for (file, description) in log_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "log", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // Secret and key files
        let secret_files = vec![
            ("id_rsa", "SSH private key"),
            ("id_dsa", "SSH DSA private key"),
            ("id_ecdsa", "SSH ECDSA private key"),
            ("id_ed25519", "SSH Ed25519 private key"),
            ("id_rsa.pub", "SSH public key"),
            ("authorized_keys", "SSH authorized keys"),
            ("known_hosts", "SSH known hosts"),
            ("config", "SSH config"),
            (".ssh/", "SSH directory"),
            ("server.key", "SSL private key"),
            ("server.crt", "SSL certificate"),
            ("server.pem", "SSL PEM file"),
            ("ca.crt", "CA certificate"),
            ("client.key", "Client private key"),
            ("client.crt", "Client certificate"),
            ("private.key", "Private key"),
            ("public.key", "Public key"),
            ("certificate.pem", "Certificate PEM"),
            ("key.pem", "Private key PEM"),
            ("keystore.jks", "Java keystore"),
            ("truststore.jks", "Java truststore"),
            ("keystore.p12", "PKCS#12 keystore"),
            ("keystore.pfx", "PKCS#12 keystore"),
            ("passwords.txt", "Passwords file"),
            ("secrets.txt", "Secrets file"),
            ("credentials.txt", "Credentials file"),
            ("api_keys.txt", "API keys file"),
            ("tokens.txt", "Tokens file"),
        ];

        for (file, description) in secret_files {
            if let Some(finding) = self
                .test_file(base_url, file, description, "secret", scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // Debug and diagnostic endpoints
        let debug_endpoints = vec![
            ("/debug", "Debug endpoint"),
            ("/debug/", "Debug endpoint"),
            ("/debug/pprof/", "Go pprof endpoint"),
            ("/debug/vars", "Go expvar endpoint"),
            ("/actuator", "Spring Boot actuator"),
            ("/actuator/", "Spring Boot actuator"),
            ("/actuator/env", "Spring Boot environment"),
            ("/actuator/configprops", "Spring Boot config properties"),
            ("/actuator/beans", "Spring Boot beans"),
            ("/actuator/mappings", "Spring Boot mappings"),
            ("/actuator/health", "Spring Boot health"),
            ("/actuator/info", "Spring Boot info"),
            ("/actuator/metrics", "Spring Boot metrics"),
            ("/actuator/httptrace", "Spring Boot HTTP trace"),
            ("/actuator/threaddump", "Spring Boot thread dump"),
            ("/actuator/heapdump", "Spring Boot heap dump"),
            ("/actuator/jolokia", "Spring Boot Jolokia"),
            ("/actuator/loggers", "Spring Boot loggers"),
            ("/actuator/scheduledtasks", "Spring Boot scheduled tasks"),
            ("/actuator/caches", "Spring Boot caches"),
            ("/h2-console", "H2 database console"),
            ("/console", "Console endpoint"),
            ("/admin", "Admin panel"),
            ("/admin/", "Admin panel"),
            ("/phpinfo.php", "PHP info page"),
            ("/info.php", "PHP info page"),
            ("/test.php", "Test PHP page"),
            ("/status", "Status page"),
            ("/status/", "Status page"),
            ("/metrics", "Metrics endpoint"),
            ("/metrics/", "Metrics endpoint"),
            ("/prometheus", "Prometheus metrics"),
            ("/prometheus/", "Prometheus metrics"),
            ("/health", "Health check"),
            ("/health/", "Health check"),
            ("/ping", "Ping endpoint"),
            ("/ping/", "Ping endpoint"),
            ("/version", "Version endpoint"),
            ("/version/", "Version endpoint"),
            ("/build-info", "Build info"),
            ("/git-commit", "Git commit info"),
        ];

        for (endpoint, description) in debug_endpoints {
            if let Some(finding) = self
                .test_endpoint(base_url, endpoint, description, scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        // API documentation endpoints
        let api_docs = vec![
            ("/swagger.json", "Swagger JSON"),
            ("/swagger.yaml", "Swagger YAML"),
            ("/swagger.yml", "Swagger YAML"),
            ("/openapi.json", "OpenAPI JSON"),
            ("/openapi.yaml", "OpenAPI YAML"),
            ("/openapi.yml", "OpenAPI YAML"),
            ("/api-docs", "API docs"),
            ("/api-docs/", "API docs"),
            ("/api-docs.json", "API docs JSON"),
            ("/v3/api-docs", "OpenAPI v3 docs"),
            ("/v2/api-docs", "Swagger v2 docs"),
            ("/swagger-ui", "Swagger UI"),
            ("/swagger-ui/", "Swagger UI"),
            ("/redoc", "ReDoc"),
            ("/redoc/", "ReDoc"),
            ("/docs", "Documentation"),
            ("/docs/", "Documentation"),
            ("/api/docs", "API documentation"),
            ("/api/docs/", "API documentation"),
        ];

        for (endpoint, description) in api_docs {
            if let Some(finding) = self
                .test_endpoint(base_url, endpoint, description, scan_id)
                .await
            {
                findings.push(finding);
            }
        }

        findings
    }

    /// Test a single file for exposure
    async fn test_file(
        &self,
        base_url: &str,
        file: &str,
        description: &str,
        category: &str,
        scan_id: openre_core::ids::ScanId,
    ) -> Option<Finding> {
        let url = format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            if file.starts_with('/') {
                file.to_string()
            } else {
                format!("/{}", file)
            }
        );

        if let Ok(resp) = self.client.get(&url).send().await {
            let status = resp.status().as_u16();

            if status == 200 {
                let body = resp.text().await.unwrap_or_default();

                // Check for sensitive content patterns
                let sensitive_patterns = match category {
                    "environment" => vec![
                        ("DATABASE_URL", "Database URL"),
                        ("DB_PASSWORD", "Database password"),
                        ("DB_USER", "Database user"),
                        ("API_KEY", "API key"),
                        ("SECRET_KEY", "Secret key"),
                        ("JWT_SECRET", "JWT secret"),
                        ("AWS_ACCESS_KEY", "AWS access key"),
                        ("AWS_SECRET_KEY", "AWS secret key"),
                        ("GOOGLE_API_KEY", "Google API key"),
                        ("STRIPE_SECRET", "Stripe secret"),
                        ("PASSWORD", "Password"),
                        ("TOKEN", "Token"),
                        ("PRIVATE_KEY", "Private key"),
                    ],
                    "configuration" => vec![
                        ("password", "Password"),
                        ("secret", "Secret"),
                        ("key", "Key"),
                        ("token", "Token"),
                        ("credential", "Credential"),
                    ],
                    "backup" => vec![
                        ("INSERT INTO", "SQL dump"),
                        ("CREATE TABLE", "SQL dump"),
                        ("DROP TABLE", "SQL dump"),
                        ("mysqldump", "MySQL dump"),
                        ("pg_dump", "PostgreSQL dump"),
                    ],
                    "version-control" => vec![
                        ("[core]", "Git config"),
                        ("repositoryformatversion", "Git config"),
                        ("filemode", "Git config"),
                        ("bare", "Git config"),
                        ("logallrefupdates", "Git config"),
                    ],
                    "ide" => vec![
                        ("workspace", "IDE workspace"),
                        ("project", "IDE project"),
                        ("component", "IDE component"),
                    ],
                    "log" => vec![
                        ("ERROR", "Error log"),
                        ("WARN", "Warning log"),
                        ("Exception", "Exception"),
                        ("stack trace", "Stack trace"),
                        ("at ", "Stack trace"),
                    ],
                    "secret" => vec![
                        ("-----BEGIN", "Private key"),
                        ("PRIVATE KEY", "Private key"),
                        ("ssh-rsa", "SSH key"),
                        ("ssh-dss", "SSH key"),
                        ("ecdsa-sha2", "SSH key"),
                        ("ssh-ed25519", "SSH key"),
                    ],
                    "debug" => vec![
                        ("debug", "Debug info"),
                        ("trace", "Trace info"),
                        ("environment", "Environment info"),
                        ("config", "Config info"),
                    ],
                    "api-docs" => vec![
                        ("swagger", "Swagger"),
                        ("openapi", "OpenAPI"),
                        ("paths", "API paths"),
                        ("definitions", "API definitions"),
                    ],
                    _ => vec![],
                };

                for (pattern, desc) in sensitive_patterns {
                    if body.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Some(self.create_finding(
                            &format!("Exposed {} File with Sensitive Data", category),
                            &format!(
                                "{} file {} exposes sensitive data: {}",
                                description, file, desc
                            ),
                            Severity::High,
                            Confidence::High,
                            Category::InformationDisclosure,
                            &url,
                            file,
                            category,
                            vec![
                                "exposed-file".to_string(),
                                category.to_string(),
                                "sensitive-data".to_string(),
                            ],
                            vec![
                                    "Remove sensitive files from web-accessible directories"
                                        .to_string(),
                                    "Configure web server to deny access to sensitive files"
                                        .to_string(),
                                    "Use .htaccess or equivalent to block access".to_string(),
                                ],
                            scan_id,
                        ));
                    }
                }

                // Even without specific patterns, the file itself is exposed
                return Some(self.create_finding(
                    &format!("Exposed {} File", category),
                    &format!("{} file {} is publicly accessible", description, file),
                    match category {
                        "secret" | "environment" => Severity::Critical,
                        "backup" | "version-control" => Severity::High,
                        "configuration" => Severity::High,
                        "log" => Severity::Medium,
                        "ide" => Severity::Low,
                        "debug" => Severity::Medium,
                        "api-docs" => Severity::Info,
                        _ => Severity::Medium,
                    },
                    Confidence::Medium,
                    Category::InformationDisclosure,
                    &url,
                    file,
                    category,
                    vec!["exposed-file".to_string(), category.to_string()],
                    vec![
                        "Remove sensitive files from web-accessible directories".to_string(),
                        "Configure web server to deny access to sensitive files".to_string(),
                        "Use .htaccess or equivalent to block access".to_string(),
                    ],
                    scan_id,
                ));
            }
        }

        None
    }

    /// Test a debug/endpoint for exposure
    async fn test_endpoint(
        &self,
        base_url: &str,
        endpoint: &str,
        description: &str,
        scan_id: openre_core::ids::ScanId,
    ) -> Option<Finding> {
        let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);

        if let Ok(resp) = self.client.get(&url).send().await {
            let status = resp.status().as_u16();

            if status == 200 {
                let body = resp.text().await.unwrap_or_default();

                // Check for sensitive content
                let sensitive_patterns = vec![
                    ("password", "Password"),
                    ("secret", "Secret"),
                    ("token", "Token"),
                    ("key", "Key"),
                    ("credential", "Credential"),
                    ("environment", "Environment"),
                    ("config", "Configuration"),
                    ("database", "Database"),
                    ("connection", "Connection"),
                    ("DEBUG", "Debug mode"),
                    ("TRACE", "Trace mode"),
                ];

                for (pattern, desc) in sensitive_patterns {
                    if body.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Some(self.create_finding(
                            &format!("Exposed Debug Endpoint with Sensitive Data"),
                            &format!(
                                "Debug endpoint {} exposes sensitive data: {}",
                                endpoint, desc
                            ),
                            Severity::High,
                            Confidence::High,
                            Category::InformationDisclosure,
                            &url,
                            endpoint,
                            "debug",
                            vec!["debug-endpoint".to_string(), "sensitive-data".to_string()],
                            vec![
                                "Disable debug endpoints in production".to_string(),
                                "Restrict access to debug endpoints".to_string(),
                            ],
                            scan_id,
                        ));
                    }
                }

                return Some(self.create_finding(
                    &format!("Exposed Debug Endpoint"),
                    &format!(
                        "Debug endpoint {} is publicly accessible: {}",
                        endpoint, description
                    ),
                    Severity::Medium,
                    Confidence::Medium,
                    Category::InformationDisclosure,
                    &url,
                    endpoint,
                    "debug",
                    vec!["debug-endpoint".to_string()],
                    vec![
                        "Disable debug endpoints in production".to_string(),
                        "Restrict access to debug endpoints".to_string(),
                    ],
                    scan_id,
                ));
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
        url: &str,
        file: &str,
        category_str: &str,
        tags: Vec<String>,
        verification_steps: Vec<String>,
        scan_id: openre_core::ids::ScanId,
    ) -> Finding {
        let mut finding = Finding::new(FindingConfig {
            title: title.to_string(),
            description: description.to_string(),
            severity,
            confidence,
            category,
            target: url.to_string(),
            target_type: "web_application".to_string(),
            plugin_source: "sensitive_info".to_string(),
            plugin_version: self.version().to_string(),
            scan_id,
        });

        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!("Sensitive file exposure test for {}", file),
            data: Some(serde_json::json!({
                "url": url,
                "file": file,
                "category": category_str,
            })),
            location: Some(url.to_string()),
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("sensitive_info".to_string()),
            timestamp: Utc::now(),
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
        finding = finding.with_tag("sensitive-info".to_string());

        finding
    }
}

#[async_trait]
impl Plugin for SensitiveInfoPlugin {
    type Config = SensitiveInfoConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create Sensitive Info plugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let scan_id = openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid());
        let target_url = request
            .input
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");

        info!(
            "Starting sensitive information disclosure analysis for {}",
            target_url
        );

        // Test for sensitive files
        let findings = self.test_sensitive_files(target_url, scan_id).await;

        info!("Found {} sensitive information issues", findings.len());

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "vulnerabilities_found": findings.len(),
        })))
    }
}

/// Sensitive Information Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SensitiveInfoConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for SensitiveInfoConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-sensitive-info/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

// Plugin entry point
