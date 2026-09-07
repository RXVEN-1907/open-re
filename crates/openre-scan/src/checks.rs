//! Security check implementations

use crate::client::Client;
use crate::extensions::{EvidenceExt, FindingExt, RemediationGuidanceExt};
use crate::output::{Finding, FindingConfig, Severity, Confidence, Category, Evidence, EvidenceType, RemediationGuidance, RemediationEffort, RemediationPriority, ScanId};
use anyhow::Result;
use regex::Regex;
use select::document::Document;
use select::predicate::Name;
use std::time::Duration;
use tokio::time::sleep;
use url::Url;

/// Generate a new scan ID
fn scan_id() -> ScanId {
    ScanId::new()
}

/// Get all checks for a given profile
pub fn get_all_checks(profile: &crate::profiles::ScanProfile) -> Vec<Check> {
    match profile {
        crate::profiles::ScanProfile::Quick => vec![
            Check::HttpHeaders,
            Check::SecurityHeaders,
            Check::CookieSecurity,
            Check::TlsCertificate,
            Check::InformationDisclosure,
            Check::TechnologyFingerprint,
        ],
        crate::profiles::ScanProfile::Standard => vec![
            Check::HttpHeaders,
            Check::TlsCertificate,
            Check::CookieSecurity,
            Check::SecurityHeaders,
            Check::ContentSecurityPolicy,
            Check::CorsConfiguration,
            Check::InformationDisclosure,
            Check::TechnologyFingerprint,
            Check::RobotsTxt,
            Check::SitemapXml,
            Check::DirectoryListing,
            Check::SensitiveFiles,
            Check::FormAnalysis,
            Check::LinkAnalysis,
            Check::ScriptAnalysis,
            Check::MetaTags,
        ],
        crate::profiles::ScanProfile::Full => vec![
            Check::HttpHeaders,
            Check::TlsCertificate,
            Check::CookieSecurity,
            Check::SecurityHeaders,
            Check::ContentSecurityPolicy,
            Check::CorsConfiguration,
            Check::InformationDisclosure,
            Check::TechnologyFingerprint,
            Check::RobotsTxt,
            Check::SitemapXml,
            Check::DirectoryListing,
            Check::SensitiveFiles,
            Check::FormAnalysis,
            Check::LinkAnalysis,
            Check::ScriptAnalysis,
            Check::MetaTags,
            Check::HttpMethods,
            Check::SslTlsConfiguration,
        ],
    }
}

/// Get description for a check
pub fn get_check_description(check: &Check) -> &'static str {
    match check {
        Check::HttpHeaders => "HTTP header analysis",
        Check::TlsCertificate => "TLS certificate validation",
        Check::CookieSecurity => "Cookie security flags",
        Check::SecurityHeaders => "Security headers (HSTS, CSP, etc.)",
        Check::ContentSecurityPolicy => "CSP directive analysis",
        Check::CorsConfiguration => "CORS misconfiguration",
        Check::InformationDisclosure => "Debug info & version disclosure",
        Check::TechnologyFingerprint => "Tech stack detection",
        Check::RobotsTxt => "robots.txt enumeration",
        Check::SitemapXml => "sitemap.xml discovery",
        Check::DirectoryListing => "Directory listing detection",
        Check::SensitiveFiles => "Sensitive file exposure (20+ paths)",
        Check::FormAnalysis => "Form security (GET passwords, CSRF)",
        Check::LinkAnalysis => "Mixed content & external links",
        Check::ScriptAnalysis => "Inline/external script analysis",
        Check::MetaTags => "Security-relevant meta tags",
        Check::HttpMethods => "Dangerous HTTP methods (TRACE, PUT, etc.)",
        Check::SslTlsConfiguration => "SSL/TLS deep configuration",
    }
}

#[derive(Debug, Clone)]
pub enum Check {
    HttpHeaders,
    TlsCertificate,
    CookieSecurity,
    SecurityHeaders,
    ContentSecurityPolicy,
    CorsConfiguration,
    InformationDisclosure,
    TechnologyFingerprint,
    RobotsTxt,
    SitemapXml,
    DirectoryListing,
    SensitiveFiles,
    FormAnalysis,
    LinkAnalysis,
    ScriptAnalysis,
    MetaTags,
    HttpMethods,
    SslTlsConfiguration,
}

impl Check {
    pub fn name(&self) -> &'static str {
        match self {
            Check::HttpHeaders => "http-headers",
            Check::TlsCertificate => "tls-certificate",
            Check::CookieSecurity => "cookie-security",
            Check::SecurityHeaders => "security-headers",
            Check::ContentSecurityPolicy => "csp",
            Check::CorsConfiguration => "cors",
            Check::InformationDisclosure => "info-disclosure",
            Check::TechnologyFingerprint => "tech-fingerprint",
            Check::RobotsTxt => "robots-txt",
            Check::SitemapXml => "sitemap",
            Check::DirectoryListing => "dir-listing",
            Check::SensitiveFiles => "sensitive-files",
            Check::FormAnalysis => "forms",
            Check::LinkAnalysis => "links",
            Check::ScriptAnalysis => "scripts",
            Check::MetaTags => "meta-tags",
            Check::HttpMethods => "http-methods",
            Check::SslTlsConfiguration => "ssl-config",
        }
    }

    pub async fn run(&self, client: &Client, target: &Url) -> Result<Vec<Finding>> {
        match self {
            Check::HttpHeaders => check_http_headers(client, target).await,
            Check::TlsCertificate => check_tls_certificate(client, target).await,
            Check::CookieSecurity => check_cookie_security(client, target).await,
            Check::SecurityHeaders => check_security_headers(client, target).await,
            Check::ContentSecurityPolicy => check_csp(client, target).await,
            Check::CorsConfiguration => check_cors(client, target).await,
            Check::InformationDisclosure => check_information_disclosure(client, target).await,
            Check::TechnologyFingerprint => check_technology_fingerprint(client, target).await,
            Check::RobotsTxt => check_robots_txt(client, target).await,
            Check::SitemapXml => check_sitemap(client, target).await,
            Check::DirectoryListing => check_directory_listing(client, target).await,
            Check::SensitiveFiles => check_sensitive_files(client, target).await,
            Check::FormAnalysis => check_forms(client, target).await,
            Check::LinkAnalysis => check_links(client, target).await,
            Check::ScriptAnalysis => check_scripts(client, target).await,
            Check::MetaTags => check_meta_tags(client, target).await,
            Check::HttpMethods => check_http_methods(client, target).await,
            Check::SslTlsConfiguration => check_ssl_config(client, target).await,
        }
    }
}

// Check implementations
async fn check_http_headers(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    if let Some(server) = headers.get("server") {
        let finding = Finding::new(FindingConfig {
            title: "Server Header Disclosure".to_string(),
            description: format!("Server header reveals: {}", server.to_str().unwrap_or("unknown")),
            severity: Severity::Info,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "http-headers".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence =
            Evidence::new(EvidenceType::HttpResponse, "Server header present".to_string())
                .with_data(
                    serde_json::json!({"header": "server", "value": server.to_str().unwrap_or("")}),
                )
                .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    if let Some(powered) = headers.get("x-powered-by") {
        let finding = Finding::new(FindingConfig {
            title: "X-Powered-By Header Disclosure".to_string(),
            description: format!(
                "X-Powered-By header reveals: {}",
                powered.to_str().unwrap_or("unknown")
            ),
            severity: Severity::Low,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "http-headers".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "X-Powered-By header present".to_string(),
        )
        .with_data(
            serde_json::json!({"header": "x-powered-by", "value": powered.to_str().unwrap_or("")}),
        )
        .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

async fn check_security_headers(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    let security_headers = [
        ("x-frame-options", "X-Frame-Options", Severity::Medium, "Clickjacking protection"),
        (
            "x-content-type-options",
            "X-Content-Type-Options",
            Severity::Medium,
            "MIME type sniffing protection",
        ),
        (
            "strict-transport-security",
            "Strict-Transport-Security",
            Severity::High,
            "HSTS enforcement",
        ),
        (
            "content-security-policy",
            "Content-Security-Policy",
            Severity::High,
            "Content Security Policy",
        ),
        ("referrer-policy", "Referrer-Policy", Severity::Medium, "Referrer policy"),
        ("permissions-policy", "Permissions-Policy", Severity::Low, "Feature policy"),
        ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", Severity::Low, "COOP"),
        ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy", Severity::Low, "CORP"),
    ];

    for (header_name, display_name, severity, description) in security_headers {
        if headers.get(header_name).is_none() {
            let finding = Finding::new(FindingConfig {
                title: format!("Missing {} Header", display_name),
                description: format!("{} header is missing. {}", display_name, description),
                severity,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "security-headers".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                format!("Missing {} header", display_name),
            )
            .with_data(serde_json::json!({"missing_header": header_name}))
            .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                format!("Add {} header", display_name),
                vec![format!("Add the {} header to your HTTP responses", display_name)],
                RemediationEffort::Low,
                RemediationPriority::High,
            );
            findings.push(finding.with_evidence(evidence).with_remediation(remediation));
        }
    }

    Ok(findings)
}

async fn check_cookie_security(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;

    for cookie_header in response.headers().get_all("set-cookie") {
        if let Ok(cookie_str) = cookie_header.to_str() {
            let cookie = cookie_str;

            if !cookie.to_lowercase().contains("secure") && target.scheme() == "https" {
                let finding = Finding::new(FindingConfig {
                    title: "Cookie Missing Secure Flag".to_string(),
                    description: format!("Cookie set without Secure flag on HTTPS: {}", cookie),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "cookie-security".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    "Cookie without Secure flag".to_string(),
                )
                .with_data(serde_json::json!({"cookie": cookie}))
                .with_location(target.to_string());
                let remediation = RemediationGuidance::new(
                    "Add Secure flag to cookies".to_string(),
                    vec!["Set the Secure attribute on all cookies served over HTTPS".to_string()],
                    RemediationEffort::Low,
                    RemediationPriority::High,
                );
                findings.push(finding.with_evidence(evidence).with_remediation(remediation));
            }

            if !cookie.to_lowercase().contains("httponly") {
                let finding = Finding::new(FindingConfig {
                    title: "Cookie Missing HttpOnly Flag".to_string(),
                    description: format!("Cookie set without HttpOnly flag: {}", cookie),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "cookie-security".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    "Cookie without HttpOnly flag".to_string(),
                )
                .with_data(serde_json::json!({"cookie": cookie}))
                .with_location(target.to_string());
                let remediation = RemediationGuidance::new(
                    "Add HttpOnly flag to cookies".to_string(),
                    vec!["Set the HttpOnly attribute on session cookies".to_string()],
                    RemediationEffort::Low,
                    RemediationPriority::High,
                );
                findings.push(finding.with_evidence(evidence).with_remediation(remediation));
            }

            if !cookie.to_lowercase().contains("samesite") {
                let finding = Finding::new(FindingConfig {
                    title: "Cookie Missing SameSite Attribute".to_string(),
                    description: format!("Cookie set without SameSite attribute: {}", cookie),
                    severity: Severity::Low,
                    confidence: Confidence::Medium,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "cookie-security".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    "Cookie without SameSite".to_string(),
                )
                .with_data(serde_json::json!({"cookie": cookie}))
                .with_location(target.to_string());
                findings.push(finding.with_evidence(evidence));
            }
        }
    }

    Ok(findings)
}

async fn check_tls_certificate(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if target.scheme() != "https" {
        let finding = Finding::new(FindingConfig {
            title: "Not Using HTTPS".to_string(),
            description: "Target is not using HTTPS encryption".to_string(),
            severity: Severity::High,
            confidence: Confidence::VeryHigh,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "tls-certificate".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let remediation = RemediationGuidance::new(
            "Enable HTTPS".to_string(),
            vec![
                "Obtain and install a valid TLS certificate".to_string(),
                "Configure HTTPS on your web server".to_string(),
                "Redirect all HTTP traffic to HTTPS".to_string(),
            ],
            RemediationEffort::Medium,
            RemediationPriority::Immediate,
        );
        findings.push(finding.with_remediation(remediation));
        return Ok(findings);
    }

    match client.get(target.as_str()).send().await {
        Ok(_) => {
            let finding = Finding::new(FindingConfig {
                title: "HTTPS Enabled".to_string(),
                description: "Target is accessible via HTTPS".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: Category::Configuration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "tls-certificate".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            findings.push(finding);
        }
        Err(e) => {
            let finding = Finding::new(FindingConfig {
                title: "HTTPS Connection Failed".to_string(),
                description: format!("Failed to connect via HTTPS: {}", e),
                severity: Severity::High,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "tls-certificate".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            findings.push(finding);
        }
    }

    Ok(findings)
}

async fn check_csp(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    if let Some(csp) = headers.get("content-security-policy") {
        let csp_str = csp.to_str().unwrap_or("");

        if csp_str.contains("unsafe-inline") {
            let finding = Finding::new(FindingConfig {
                title: "CSP Allows unsafe-inline".to_string(),
                description: "Content-Security-Policy contains 'unsafe-inline' directive"
                    .to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "csp".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "CSP with unsafe-inline".to_string())
                    .with_data(serde_json::json!({"csp": csp_str}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }

        if csp_str.contains("unsafe-eval") {
            let finding = Finding::new(FindingConfig {
                title: "CSP Allows unsafe-eval".to_string(),
                description: "Content-Security-Policy contains 'unsafe-eval' directive".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "csp".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "CSP with unsafe-eval".to_string())
                    .with_data(serde_json::json!({"csp": csp_str}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }

        if csp_str.contains("'*'") || csp_str.contains("\"*\"") {
            let finding = Finding::new(FindingConfig {
                title: "CSP Uses Wildcard".to_string(),
                description:
                    "Content-Security-Policy uses wildcard (*) which may be overly permissive"
                        .to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "csp".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "CSP with wildcard".to_string())
                    .with_data(serde_json::json!({"csp": csp_str}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    } else {
        let finding = Finding::new(FindingConfig {
            title: "Missing Content-Security-Policy".to_string(),
            description: "No Content-Security-Policy header found".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "csp".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let remediation = RemediationGuidance::new(
            "Implement Content-Security-Policy".to_string(),
            vec![
                "Add a Content-Security-Policy header to restrict resource loading".to_string(),
                "Start with a restrictive policy and adjust as needed".to_string(),
                "Use nonce or hash-based approach for inline scripts".to_string(),
            ],
            RemediationEffort::Medium,
            RemediationPriority::High,
        );
        findings.push(finding.with_remediation(remediation));
    }

    Ok(findings)
}

async fn check_cors(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    if let Some(acao) = headers.get("access-control-allow-origin") {
        let acao_str = acao.to_str().unwrap_or("");
        if acao_str == "*" {
            let finding = Finding::new(FindingConfig {
                title: "CORS Allows All Origins".to_string(),
                description: "Access-Control-Allow-Origin is set to * (wildcard)".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "cors".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "CORS wildcard origin".to_string())
                    .with_data(serde_json::json!({"acao": acao_str}))
                    .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                "Restrict CORS origins".to_string(),
                vec![
                    "Set Access-Control-Allow-Origin to specific trusted origins".to_string(),
                    "Avoid using wildcard (*) for origins that handle sensitive data".to_string(),
                ],
                RemediationEffort::Low,
                RemediationPriority::Medium,
            );
            findings.push(finding.with_evidence(evidence).with_remediation(remediation));
        }
    }

    if let Some(acac) = headers.get("access-control-allow-credentials") {
        if acac.to_str().unwrap_or("").to_lowercase() == "true" {
            if let Some(acao) = headers.get("access-control-allow-origin") {
                if acao.to_str().unwrap_or("") == "*" {
                    let finding = Finding::new(FindingConfig {
                        title: "CORS Credentials with Wildcard Origin".to_string(),
                        description:
                            "Access-Control-Allow-Credentials is true with wildcard origin"
                                .to_string(),
                        severity: Severity::High,
                        confidence: Confidence::High,
                        category: Category::SecurityMisconfiguration,
                        target: target.to_string(),
                        target_type: "web".to_string(),
                        plugin_source: "cors".to_string(),
                        plugin_version: "1.0".to_string(),
                        scan_id: scan_id(),
                    });
                    findings.push(finding);
                }
            }
        }
    }

    Ok(findings)
}

async fn check_information_disclosure(
    client: &Client,
    target: &Url,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers();

    let debug_headers = ["x-debug-token", "x-drupal-cache", "x-varnish", "via", "x-cache"];
    for header in debug_headers {
        if headers.contains_key(header) {
            let finding = Finding::new(FindingConfig {
                title: format!("Debug Header Exposed: {}", header),
                description: format!("Debug header {} is present in response", header),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "info-disclosure".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                format!("Debug header {} found", header),
            ).with_data(serde_json::json!({"header": header, "value": headers.get(header).unwrap().to_str().unwrap_or("")}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("");
        if server_str.contains('/') {
            let finding = Finding::new(FindingConfig {
                title: "Server Version Disclosure".to_string(),
                description: format!("Server header reveals version: {}", server_str),
                severity: Severity::Low,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "info-disclosure".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "Server version disclosed".to_string())
                    .with_data(serde_json::json!({"server": server_str}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    Ok(findings)
}

async fn check_technology_fingerprint(
    client: &Client,
    target: &Url,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();

    let tech_signatures = [
        ("x-powered-by", "PHP", r"PHP/"),
        ("x-powered-by", "ASP.NET", r"ASP\.NET"),
        ("server", "Apache", r"Apache/"),
        ("server", "nginx", r"nginx/"),
        ("server", "IIS", r"Microsoft-IIS/"),
        ("x-generator", "WordPress", r"WordPress"),
        ("x-drupal-cache", "Drupal", r""),
        ("x-drupal-dynamic-cache", "Drupal", r""),
    ];

    for (header_name, tech_name, pattern) in tech_signatures {
        if let Some(header) = headers.get(header_name) {
            let header_str = header.to_str().unwrap_or("");
            if pattern.is_empty() || Regex::new(pattern).unwrap().is_match(header_str) {
                let finding = Finding::new(FindingConfig {
                    title: format!("Technology Detected: {}", tech_name),
                    description: format!("{} detected via {} header", tech_name, header_name),
                    severity: Severity::Info,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "tech-fingerprint".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    format!("{} detected", tech_name),
                ).with_data(serde_json::json!({"technology": tech_name, "header": header_name, "value": header_str}))
                .with_location(target.to_string());
                findings.push(finding.with_evidence(evidence));
            }
        }
    }

    let body_signatures = [
        ("WordPress", r"wp-content|wp-includes"),
        ("Drupal", r"drupal\.js|Drupal\.settings"),
        ("Joomla", r"joomla|Joomla"),
        ("React", r"react\.js|ReactDOM"),
        ("Vue", r"vue\.js|Vue\.js"),
        ("Angular", r"angular\.js|ng-app"),
        ("jQuery", r"jquery"),
        ("Bootstrap", r"bootstrap"),
    ];

    for (tech_name, pattern) in body_signatures {
        if Regex::new(pattern).unwrap().is_match(&body) {
            let finding = Finding::new(FindingConfig {
                title: format!("Technology Detected: {}", tech_name),
                description: format!("{} detected in page content", tech_name),
                severity: Severity::Info,
                confidence: Confidence::Medium,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "tech-fingerprint".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                format!("{} detected in body", tech_name),
            )
            .with_data(serde_json::json!({"technology": tech_name, "source": "body"}))
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    Ok(findings)
}

async fn check_robots_txt(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut robots_url = target.clone();
    robots_url.set_path("/robots.txt");

    match client.get(robots_url.as_str()).send().await {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await.unwrap_or_default();
            let finding = Finding::new(FindingConfig {
                title: "robots.txt Found".to_string(),
                description: "robots.txt file is accessible".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "robots-txt".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "robots.txt accessible".to_string())
                    .with_data(
                        serde_json::json!({"content": body.chars().take(500).collect::<String>()}),
                    )
                    .with_location(robots_url.to_string());
            findings.push(finding.with_evidence(evidence));

            for line in body.lines() {
                if line.to_lowercase().starts_with("disallow:") && !line.contains("disallow: /") {
                    let path = line.split(':').nth(1).unwrap_or("").trim();
                    if !path.is_empty() && path != "/" {
                        let finding = Finding::new(FindingConfig {
                            title: "Interesting robots.txt Entry".to_string(),
                            description: format!("robots.txt disallows: {}", path),
                            severity: Severity::Info,
                            confidence: Confidence::Low,
                            category: Category::InformationDisclosure,
                            target: target.to_string(),
                            target_type: "web".to_string(),
                            plugin_source: "robots-txt".to_string(),
                            plugin_version: "1.0".to_string(),
                            scan_id: scan_id(),
                        });
                        let evidence = Evidence::new(
                            EvidenceType::HttpResponse,
                            format!("Disallowed path: {}", path),
                        )
                        .with_location(robots_url.to_string());
                        findings.push(finding.with_evidence(evidence));
                    }
                }
            }
        }
        Ok(_) => {
            // Non-success status, ignore
        }
        Err(_) => {
            // Request failed, ignore
        }
    }

    Ok(findings)
}

async fn check_sitemap(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut sitemap_url = target.clone();
    sitemap_url.set_path("/sitemap.xml");

    match client.get(sitemap_url.as_str()).send().await {
        Ok(response) if response.status().is_success() => {
            let finding = Finding::new(FindingConfig {
                title: "sitemap.xml Found".to_string(),
                description: "sitemap.xml file is accessible".to_string(),
                severity: Severity::Info,
                confidence: Confidence::High,
                category: Category::InformationDisclosure,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "sitemap".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "sitemap.xml accessible".to_string())
                    .with_location(sitemap_url.to_string());
            findings.push(finding.with_evidence(evidence));
        }
        Ok(_) => {}
        Err(_) => {}
    }

    Ok(findings)
}

async fn check_directory_listing(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let listing_indicators = [
        "Index of /",
        "Directory listing for",
        "<title>Index of",
        "Parent Directory",
        "[DIR]",
        "Name</a>",
        "Last modified</a>",
    ];

    for indicator in listing_indicators {
        if body.contains(indicator) {
            let finding = Finding::new(FindingConfig {
                title: "Directory Listing Enabled".to_string(),
                description: format!(
                    "Directory listing appears to be enabled: found '{}'",
                    indicator
                ),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "dir-listing".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "Directory listing detected".to_string())
                    .with_data(serde_json::json!({"indicator": indicator}))
                    .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                "Disable directory listing".to_string(),
                vec![
                    "Configure web server to disable directory indexing".to_string(),
                    "Add default index file (index.html, index.php, etc.)".to_string(),
                ],
                RemediationEffort::Low,
                RemediationPriority::High,
            );
            findings.push(finding.with_evidence(evidence).with_remediation(remediation));
            break;
        }
    }

    Ok(findings)
}

async fn check_sensitive_files(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let sensitive_paths = [
        ".git/",
        ".env",
        "config.php",
        "wp-config.php",
        "settings.py",
        "config.yaml",
        "docker-compose.yml",
        "Dockerfile",
        "README.md",
        "CHANGELOG.md",
        "package.json",
        "composer.json",
        "requirements.txt",
        "pom.xml",
        "build.gradle",
        ".htaccess",
        "web.config",
        "robots.txt",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        ".well-known/security.txt",
    ];

    for path in sensitive_paths {
        let mut test_url = target.clone();
        test_url.set_path(&format!("/{}", path));

        match client.head(test_url.as_str()).send().await {
            Ok(response) if response.status().is_success() => {
                let finding = Finding::new(FindingConfig {
                    title: format!("Sensitive File Exposed: {}", path),
                    description: format!("Sensitive file accessible: {}", test_url),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::InformationDisclosure,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "sensitive-files".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    format!("Sensitive file found: {}", path),
                ).with_data(serde_json::json!({"file": path, "url": test_url.to_string(), "status": response.status().as_u16()}))
                .with_location(test_url.to_string());
                findings.push(finding.with_evidence(evidence));
            }
            Ok(_) => {}
            Err(_) => {}
        }

        sleep(Duration::from_millis(50)).await;
    }

    Ok(findings)
}

async fn check_forms(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let forms = document.find(Name("form")).collect::<Vec<_>>();

    for form in forms {
        let action = form.attr("action").unwrap_or("");
        let method = form.attr("method").unwrap_or("GET").to_uppercase();

        let password_inputs =
            form.find(Name("input")).filter(|n| n.attr("type") == Some("password")).count();

        if password_inputs > 0 && method == "GET" {
            let finding = Finding::new(FindingConfig {
                title: "Password Field in GET Form".to_string(),
                description:
                    "Form with password field uses GET method, exposing credentials in URL"
                        .to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "forms".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "Password field in GET form".to_string())
                    .with_data(serde_json::json!({"action": action, "method": method}))
                    .with_location(target.to_string());
            let remediation = RemediationGuidance::new(
                "Use POST for forms with password fields".to_string(),
                vec![
                    "Change form method to POST".to_string(),
                    "Ensure HTTPS is used for all forms handling credentials".to_string(),
                ],
                RemediationEffort::Low,
                RemediationPriority::Immediate,
            );
            findings.push(finding.with_evidence(evidence).with_remediation(remediation));
        }

        let autocomplete = form.attr("autocomplete");
        if autocomplete == Some("on") && password_inputs > 0 {
            let finding = Finding::new(FindingConfig {
                title: "Autocomplete Enabled on Password Form".to_string(),
                description: "Form with password field has autocomplete enabled".to_string(),
                severity: Severity::Low,
                confidence: Confidence::Medium,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "forms".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Autocomplete on password form".to_string(),
            )
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }

        let has_csrf = form.find(Name("input")).any(|n| {
            let name = n.attr("name").unwrap_or("");
            name.to_lowercase().contains("csrf")
                || name.to_lowercase().contains("token")
                || name.to_lowercase().contains("_token")
        });

        if !has_csrf && method == "POST" && password_inputs > 0 {
            let finding = Finding::new(FindingConfig {
                title: "Missing CSRF Protection on Login Form".to_string(),
                description: "POST form with password field lacks apparent CSRF token".to_string(),
                severity: Severity::Medium,
                confidence: Confidence::Medium,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "forms".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence = Evidence::new(
                EvidenceType::HttpResponse,
                "Possible missing CSRF token".to_string(),
            )
            .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    Ok(findings)
}

async fn check_links(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let links = document.find(Name("a")).filter_map(|n| n.attr("href")).collect::<Vec<_>>();

    let mut _external_links = 0;
    let mut http_links = 0;
    let mut mailto_links = 0;

    for link in &links {
        if link.starts_with("http://") {
            http_links += 1;
        } else if link.starts_with("https://") {
            if !link.contains(target.host_str().unwrap_or("")) {
                _external_links += 1;
            }
        } else if link.starts_with("mailto:") {
            mailto_links += 1;
        }
    }

    if http_links > 0 {
        let finding = Finding::new(FindingConfig {
            title: "Mixed Content: HTTP Links on HTTPS Page".to_string(),
            description: format!("Found {} HTTP links on HTTPS page", http_links),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "links".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(EvidenceType::HttpResponse, "HTTP links found".to_string())
            .with_data(serde_json::json!({"http_links": http_links}))
            .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    if mailto_links > 0 {
        let finding = Finding::new(FindingConfig {
            title: "Email Addresses Exposed in mailto Links".to_string(),
            description: format!("Found {} mailto: links", mailto_links),
            severity: Severity::Low,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "links".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(EvidenceType::HttpResponse, "mailto links found".to_string())
            .with_data(serde_json::json!({"mailto_links": mailto_links}))
            .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

async fn check_scripts(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let scripts = document.find(Name("script")).filter_map(|n| n.attr("src")).collect::<Vec<_>>();

    for script in scripts {
        if script.starts_with("http://") {
            let finding = Finding::new(FindingConfig {
                title: "Mixed Content: HTTP Script on HTTPS Page".to_string(),
                description: format!("External script loaded over HTTP: {}", script),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category: Category::SecurityMisconfiguration,
                target: target.to_string(),
                target_type: "web".to_string(),
                plugin_source: "scripts".to_string(),
                plugin_version: "1.0".to_string(),
                scan_id: scan_id(),
            });
            let evidence =
                Evidence::new(EvidenceType::HttpResponse, "HTTP script source".to_string())
                    .with_data(serde_json::json!({"script": script}))
                    .with_location(target.to_string());
            findings.push(finding.with_evidence(evidence));
        }
    }

    let inline_scripts = document.find(Name("script")).filter(|n| n.attr("src").is_none()).count();
    if inline_scripts > 0 {
        let finding = Finding::new(FindingConfig {
            title: "Inline Scripts Detected".to_string(),
            description: format!("Found {} inline script(s) which may violate CSP", inline_scripts),
            severity: Severity::Info,
            confidence: Confidence::Medium,
            category: Category::SecurityMisconfiguration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "scripts".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence =
            Evidence::new(EvidenceType::HttpResponse, "Inline scripts found".to_string())
                .with_data(serde_json::json!({"count": inline_scripts}))
                .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}

async fn check_meta_tags(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let response = client.get(target.as_str()).send().await?;
    let body = response.text().await.unwrap_or_default();

    let document = Document::from(body.as_str());
    let metas = document.find(Name("meta")).collect::<Vec<_>>();

    for meta in metas {
        if let Some(name) = meta.attr("name") {
            if name.to_lowercase() == "generator" {
                if let Some(content) = meta.attr("content") {
                    let finding = Finding::new(FindingConfig {
                        title: "Generator Meta Tag Disclosure".to_string(),
                        description: format!("Generator meta tag reveals: {}", content),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: Category::InformationDisclosure,
                        target: target.to_string(),
                        target_type: "web".to_string(),
                        plugin_source: "meta-tags".to_string(),
                        plugin_version: "1.0".to_string(),
                        scan_id: scan_id(),
                    });
                    let evidence =
                        Evidence::new(EvidenceType::HttpResponse, "Generator meta tag".to_string())
                            .with_data(serde_json::json!({"content": content}))
                            .with_location(target.to_string());
                    findings.push(finding.with_evidence(evidence));
                }
            }
        }

        if let Some(http_equiv) = meta.attr("http-equiv") {
            if http_equiv.to_lowercase() == "refresh" {
                if let Some(content) = meta.attr("content") {
                    let finding = Finding::new(FindingConfig {
                        title: "Meta Refresh Redirect".to_string(),
                        description: format!("Meta refresh redirect found: {}", content),
                        severity: Severity::Low,
                        confidence: Confidence::High,
                        category: Category::SecurityMisconfiguration,
                        target: target.to_string(),
                        target_type: "web".to_string(),
                        plugin_source: "meta-tags".to_string(),
                        plugin_version: "1.0".to_string(),
                        scan_id: scan_id(),
                    });
                    let evidence =
                        Evidence::new(EvidenceType::HttpResponse, "Meta refresh".to_string())
                            .with_data(serde_json::json!({"content": content}))
                            .with_location(target.to_string());
                    findings.push(finding.with_evidence(evidence));
                }
            }
        }
    }

    Ok(findings)
}

async fn check_http_methods(client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let methods = ["TRACE", "TRACK", "PUT", "DELETE", "PATCH", "OPTIONS"];

    for method in methods {
        let req = client.request(method.parse().unwrap(), target.as_str());
        if let Ok(response) = req.send().await {
            if response.status().is_success() || response.status().as_u16() == 204 {
                let severity = match method {
                    "TRACE" | "TRACK" => Severity::Medium,
                    "PUT" | "DELETE" => Severity::High,
                    _ => Severity::Low,
                };

                let finding = Finding::new(FindingConfig {
                    title: format!("HTTP {} Method Enabled", method),
                    description: format!("Server accepts {} requests", method),
                    severity,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: target.to_string(),
                    target_type: "web".to_string(),
                    plugin_source: "http-methods".to_string(),
                    plugin_version: "1.0".to_string(),
                    scan_id: scan_id(),
                });
                let evidence = Evidence::new(
                    EvidenceType::HttpResponse,
                    format!("{} method allowed", method),
                )
                .with_data(
                    serde_json::json!({"method": method, "status": response.status().as_u16()}),
                )
                .with_location(target.to_string());
                findings.push(finding.with_evidence(evidence));
            }
        }
    }

    Ok(findings)
}

async fn check_ssl_config(_client: &Client, target: &Url) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    if target.scheme() == "https" {
        let finding = Finding::new(FindingConfig {
            title: "SSL/TLS Configuration Check".to_string(),
            description: "SSL/TLS configuration analysis requires specialized tools (e.g., testssl.sh, sslyze)".to_string(),
            severity: Severity::Info,
            confidence: Confidence::Low,
            category: Category::Configuration,
            target: target.to_string(),
            target_type: "web".to_string(),
            plugin_source: "ssl-config".to_string(),
            plugin_version: "1.0".to_string(),
            scan_id: scan_id(),
        });
        let evidence = Evidence::new(
            EvidenceType::HttpResponse,
            "SSL/TLS check placeholder".to_string(),
        ).with_data(serde_json::json!({"note": "Use testssl.sh or sslyze for comprehensive SSL/TLS testing"}))
        .with_location(target.to_string());
        findings.push(finding.with_evidence(evidence));
    }

    Ok(findings)
}