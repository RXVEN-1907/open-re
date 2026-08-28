//! Technology Detection Plugin
//!
//! Identifies web frameworks, CMS platforms, JavaScript frameworks,
//! reverse proxies, load balancers, and common libraries.

use crate::{
    Capability, CapabilityRequest, CapabilityResponse, PluginMetadata, ReconPlugin,
    ReconPluginConfig, ReconType,
};
use openre_core::error::OpenreResult as Result;
use openre_core::plugin::{CommandContext, CommandRegistration, CommandResult, Plugin};
use openre_core::result::FindingConfig;
use openre_scanner::{
    context::ScanContext,
    result::{
        Category, Confidence, Evidence, EvidenceType, Finding, Reference, ReferenceType, Severity,
    },
    target::TargetType,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Technology Detection Plugin
pub struct TechDetectionPlugin {
    config: ReconPluginConfig,
    client: Client,
    fingerprints: TechnologyFingerprints,
}

impl TechDetectionPlugin {
    pub fn new(config: ReconPluginConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .redirect(reqwest::redirect::Policy::limited(config.max_redirects))
            .user_agent(&config.user_agent)
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(crate::internal_err)?;

        Ok(Self {
            config,
            client,
            fingerprints: TechnologyFingerprints::default(),
        })
    }

    /// Detect technologies from response
    async fn detect_technologies(&self, url: &str) -> Result<TechnologyDetectionResult> {
        let mut result = TechnologyDetectionResult::default();

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(crate::internal_err)?;
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response.text().await.unwrap_or_default();

        // Detect from headers
        self.detect_from_headers(&headers, &mut result);

        // Detect from body content
        self.detect_from_body(&body, &mut result);

        // Detect from cookies
        self.detect_from_cookies(&headers, &mut result);

        Ok(result)
    }

    fn detect_from_headers(
        &self,
        headers: &HashMap<String, String>,
        result: &mut TechnologyDetectionResult,
    ) {
        // Server header
        if let Some(server) = headers.get("server") {
            result.web_server = Some(server.clone());
            self.match_server(server, result);
        }

        // X-Powered-By
        if let Some(powered) = headers.get("x-powered-by") {
            result.powered_by = Some(powered.clone());
            self.match_powered_by(powered, result);
        }

        // Via header (proxies)
        if let Some(via) = headers.get("via") {
            result.proxy = Some(via.clone());
            self.match_proxy(via, result);
        }

        // X-AspNet-Version
        if let Some(aspnet) = headers.get("x-aspnet-version") {
            result.technologies.push(Technology {
                name: "ASP.NET".to_string(),
                version: Some(aspnet.clone()),
                category: TechnologyCategory::Framework,
                confidence: Confidence::High,
            });
        }

        // X-Runtime (Rails)
        if let Some(runtime) = headers.get("x-runtime") {
            result.technologies.push(Technology {
                name: "Ruby on Rails".to_string(),
                version: None,
                category: TechnologyCategory::Framework,
                confidence: Confidence::Medium,
            });
        }

        // X-Drupal-Cache, X-Generator (Drupal)
        if headers.contains_key("x-drupal-cache") || headers.contains_key("x-generator") {
            result.technologies.push(Technology {
                name: "Drupal".to_string(),
                version: None,
                category: TechnologyCategory::CMS,
                confidence: Confidence::High,
            });
        }

        // WP-Super-Cache, X-Pingback (WordPress)
        if headers.contains_key("x-pingback")
            || headers.get("server").map_or(false, |s| s.contains("wp"))
        {
            result.technologies.push(Technology {
                name: "WordPress".to_string(),
                version: None,
                category: TechnologyCategory::CMS,
                confidence: Confidence::Medium,
            });
        }
    }

    fn detect_from_body(&self, body: &str, result: &mut TechnologyDetectionResult) {
        let body_lower = body.to_lowercase();

        // JavaScript frameworks
        let js_frameworks = [
            (
                "React",
                vec!["react", "react-dom", "__react", "data-reactroot"],
            ),
            ("Vue.js", vec!["vue.js", "vue.min.js", "__vue__", "data-v-"]),
            (
                "Angular",
                vec!["angular", "ng-app", "ng-controller", "ng-version"],
            ),
            ("jQuery", vec!["jquery", "jquery.min.js", "$(", "jQuery"]),
            (
                "Bootstrap",
                vec![
                    "bootstrap",
                    "bootstrap.min.css",
                    "btn-primary",
                    "container-fluid",
                ],
            ),
            ("Next.js", vec!["__next", "next.js", "_next/static"]),
            ("Nuxt.js", vec!["nuxt", "__nuxt", "_nuxt/"]),
            ("Svelte", vec!["svelte", "__svelte"]),
        ];

        for (name, patterns) in js_frameworks {
            if patterns.iter().any(|p| body_lower.contains(p)) {
                result.technologies.push(Technology {
                    name: name.to_string(),
                    version: None,
                    category: TechnologyCategory::JavaScriptFramework,
                    confidence: Confidence::Medium,
                });
            }
        }

        // CMS detection
        let cms_patterns = [
            (
                "WordPress",
                vec!["wp-content", "wp-includes", "wp-json", "wordpress"],
            ),
            (
                "Drupal",
                vec!["drupal", "sites/default/files", "drupal.settings"],
            ),
            ("Joomla", vec!["joomla", "com_content", "option=com_"]),
            (
                "Magento",
                vec!["magento", "mage/cookies", "mage/translation"],
            ),
            (
                "Shopify",
                vec!["shopify", "cdn.shopify.com", "shopify.theme"],
            ),
        ];

        for (name, patterns) in cms_patterns {
            if patterns.iter().any(|p| body_lower.contains(p)) {
                result.technologies.push(Technology {
                    name: name.to_string(),
                    version: None,
                    category: TechnologyCategory::CMS,
                    confidence: Confidence::Medium,
                });
            }
        }

        // Framework detection
        let framework_patterns = [
            ("Laravel", vec!["laravel", "laravel_session", "csrf_token"]),
            (
                "Django",
                vec!["csrfmiddlewaretoken", "django", "__admin_media_prefix__"],
            ),
            ("Express", vec!["express", "x-powered-by: express"]),
            ("Spring", vec!["spring", "jsessionid", "_spring_"]),
            (
                "ASP.NET Core",
                vec!["asp.net", "__requestverificationtoken"],
            ),
            ("Flask", vec!["flask", "werkzeug", "jinja2"]),
        ];

        for (name, patterns) in framework_patterns {
            if patterns.iter().any(|p| body_lower.contains(p)) {
                result.technologies.push(Technology {
                    name: name.to_string(),
                    version: None,
                    category: TechnologyCategory::Framework,
                    confidence: Confidence::Medium,
                });
            }
        }
    }

    fn detect_from_cookies(
        &self,
        headers: &HashMap<String, String>,
        result: &mut TechnologyDetectionResult,
    ) {
        if let Some(set_cookie) = headers.get("set-cookie") {
            let cookie_lower = set_cookie.to_lowercase();

            if cookie_lower.contains("phpsessid") {
                result.technologies.push(Technology {
                    name: "PHP".to_string(),
                    version: None,
                    category: TechnologyCategory::Language,
                    confidence: Confidence::High,
                });
            }

            if cookie_lower.contains("jsessionid") {
                result.technologies.push(Technology {
                    name: "Java/JSP".to_string(),
                    version: None,
                    category: TechnologyCategory::Language,
                    confidence: Confidence::High,
                });
            }

            if cookie_lower.contains("asp.net_sessionid") {
                result.technologies.push(Technology {
                    name: "ASP.NET".to_string(),
                    version: None,
                    category: TechnologyCategory::Framework,
                    confidence: Confidence::High,
                });
            }
        }
    }

    fn match_server(&self, server: &str, result: &mut TechnologyDetectionResult) {
        let server_lower = server.to_lowercase();

        if server_lower.contains("nginx") {
            result.technologies.push(Technology {
                name: "Nginx".to_string(),
                version: self.extract_version(&server_lower, "nginx/"),
                category: TechnologyCategory::WebServer,
                confidence: Confidence::High,
            });
        }

        if server_lower.contains("apache") {
            result.technologies.push(Technology {
                name: "Apache".to_string(),
                version: self.extract_version(&server_lower, "apache/"),
                category: TechnologyCategory::WebServer,
                confidence: Confidence::High,
            });
        }

        if server_lower.contains("iis") {
            result.technologies.push(Technology {
                name: "Microsoft IIS".to_string(),
                version: self.extract_version(&server_lower, "iis/"),
                category: TechnologyCategory::WebServer,
                confidence: Confidence::High,
            });
        }

        if server_lower.contains("cloudflare") {
            result.technologies.push(Technology {
                name: "Cloudflare".to_string(),
                version: None,
                category: TechnologyCategory::CDN,
                confidence: Confidence::High,
            });
        }

        if server_lower.contains("aws") || server_lower.contains("amazon") {
            result.technologies.push(Technology {
                name: "AWS".to_string(),
                version: None,
                category: TechnologyCategory::CloudProvider,
                confidence: Confidence::Medium,
            });
        }
    }

    fn match_powered_by(&self, powered: &str, result: &mut TechnologyDetectionResult) {
        let powered_lower = powered.to_lowercase();

        if powered_lower.contains("php") {
            result.technologies.push(Technology {
                name: "PHP".to_string(),
                version: self.extract_version(&powered_lower, "php/"),
                category: TechnologyCategory::Language,
                confidence: Confidence::High,
            });
        }

        if powered_lower.contains("express") {
            result.technologies.push(Technology {
                name: "Express.js".to_string(),
                version: None,
                category: TechnologyCategory::Framework,
                confidence: Confidence::High,
            });
        }
    }

    fn match_proxy(&self, via: &str, result: &mut TechnologyDetectionResult) {
        let via_lower = via.to_lowercase();

        if via_lower.contains("varnish") {
            result.technologies.push(Technology {
                name: "Varnish".to_string(),
                version: None,
                category: TechnologyCategory::Proxy,
                confidence: Confidence::High,
            });
        }

        if via_lower.contains("squid") {
            result.technologies.push(Technology {
                name: "Squid".to_string(),
                version: None,
                category: TechnologyCategory::Proxy,
                confidence: Confidence::High,
            });
        }

        if via_lower.contains("haproxy") {
            result.technologies.push(Technology {
                name: "HAProxy".to_string(),
                version: None,
                category: TechnologyCategory::LoadBalancer,
                confidence: Confidence::High,
            });
        }
    }

    fn extract_version(&self, haystack: &str, needle: &str) -> Option<String> {
        if let Some(pos) = haystack.find(needle) {
            let start = pos + needle.len();
            let end = haystack[start..]
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .map(|i| start + i)
                .unwrap_or(haystack.len());
            Some(haystack[start..end].to_string())
        } else {
            None
        }
    }
}

/// Database of known technology fingerprints used during detection.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TechnologyFingerprints {
    /// Known `Server` header values mapped to canonical technology names
    pub servers: HashMap<String, String>,
    /// Known `X-Powered-By` values mapped to canonical technology names
    pub powered_by: HashMap<String, String>,
    /// Body content patterns mapped to technology names
    pub body_patterns: HashMap<String, Vec<String>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct TechnologyDetectionResult {
    web_server: Option<String>,
    powered_by: Option<String>,
    proxy: Option<String>,
    technologies: Vec<Technology>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Technology {
    name: String,
    version: Option<String>,
    category: TechnologyCategory,
    confidence: Confidence,
}

#[derive(Debug, Serialize, Deserialize)]
enum TechnologyCategory {
    WebServer,
    Framework,
    CMS,
    JavaScriptFramework,
    Language,
    CDN,
    Proxy,
    LoadBalancer,
    CloudProvider,
    Database,
    Other,
}

#[async_trait::async_trait]
impl Plugin for TechDetectionPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "tech_detection".to_string(),
            version: "0.1.0".to_string(),
            description: "Technology detection plugin".to_string(),
            author: "open-re team".to_string(),
            license: "MIT".to_string(),
            repository: "https://github.com/RXVEN-1907/open-re".to_string(),
            homepage: None,
            categories: vec!["reconnaissance".to_string()],
            keywords: vec!["technology".to_string(), "fingerprinting".to_string()],
        }
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    fn commands(&self) -> Vec<CommandRegistration> {
        vec![]
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> anyhow::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl ReconPlugin for TechDetectionPlugin {
    fn recon_type(&self) -> ReconType {
        ReconType::TechnologyDetection
    }

    fn supported_target_types(&self) -> Vec<TargetType> {
        vec![
            TargetType::LocalWebApp,
            TargetType::RemoteWebApp,
            TargetType::RestApi,
            TargetType::GraphQLApi,
        ]
    }

    async fn recon(&self, context: &ScanContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let target_url = context.target.metadata.base_url.as_str().to_string();

        info!("Starting technology detection for: {}", target_url);

        let detection = self.detect_technologies(&target_url).await?;

        // Create findings for each detected technology
        for tech in detection.technologies {
            let severity = match tech.category {
                TechnologyCategory::Framework | TechnologyCategory::CMS => Severity::Info,
                TechnologyCategory::WebServer
                | TechnologyCategory::Proxy
                | TechnologyCategory::LoadBalancer => Severity::Info,
                _ => Severity::Info,
            };

            findings.push(
                Finding::new(FindingConfig {
                    title: format!("Technology Detected: {}", tech.name),
                    description: format!(
                        "Detected {} ({:?}) with {:?} confidence",
                        tech.name, tech.category, tech.confidence
                    ),
                    severity: severity,
                    confidence: tech.confidence,
                    category: Category::InformationDisclosure,
                    target: target_url.clone(),
                    target_type: "web_application".to_string(),
                    plugin_source: "tech_detection".to_string(),
                    plugin_version: "0.1.0".to_string(),
                    scan_id: context.scan_id,
                })
                .with_evidence(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: format!("Detected technology: {}", tech.name),
                    data: Some(serde_json::json!({
                        "technology": tech.name,
                        "version": tech.version,
                        "category": format!("{:?}", tech.category),
                        "confidence": format!("{:?}", tech.confidence),
                    })),
                    location: Some(target_url.clone()),
                    metadata: HashMap::new(),
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: None,
                    timestamp: chrono::Utc::now(),
                }),
            );
        }

        info!(
            "Technology detection completed for: {} - {} technologies found",
            target_url,
            findings.len()
        );
        Ok(findings)
    }
}

/// Plugin entry point
#[cfg(feature = "wasm-plugin")]
#[no_mangle]
pub extern "C" fn plugin_init(config_ptr: *const u8, config_len: usize) -> i32 {
    if config_ptr.is_null() || config_len == 0 {
        return -1;
    }
    let config_slice = unsafe { std::slice::from_raw_parts(config_ptr, config_len) };
    let config: ReconPluginConfig = match serde_json::from_slice(config_slice) {
        Ok(c) => c,
        Err(_) => return -1,
    };
    let plugin = TechDetectionPlugin::new(config);
    0
}

#[cfg(feature = "wasm-plugin")]
#[no_mangle]
pub extern "C" fn plugin_execute(
    request_ptr: *const u8,
    request_len: usize,
    response_ptr: *mut u8,
    response_len: *mut usize,
) -> i32 {
    0
}

#[cfg(feature = "wasm-plugin")]
#[no_mangle]
pub extern "C" fn plugin_shutdown() -> i32 {
    0
}
