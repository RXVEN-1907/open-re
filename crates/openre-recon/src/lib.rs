//! Reconnaissance plugins for open-re security scanner
//!
//! This crate provides reconnaissance plugins that can be loaded by the scanner
//! to perform target intelligence gathering before vulnerability testing.

pub mod auth_discovery;
pub mod cookie_analysis;
pub mod endpoint_discovery;
pub mod header_analysis;
pub mod http_fingerprint;
pub mod robots_sitemap;
pub mod tech_detection;
pub mod tls_analysis;

use openre_core::error::OpenreResult as Result;
use openre_plugins::sdk::{
    AnalysisContext, Capability, CapabilityRequest, CapabilityResponse, Plugin,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Re-export plugin types
pub use auth_discovery::AuthDiscoveryPlugin;
pub use cookie_analysis::CookieAnalysisPlugin;
pub use endpoint_discovery::EndpointDiscoveryPlugin;
pub use header_analysis::HeaderAnalysisPlugin;
pub use http_fingerprint::HttpFingerprintPlugin;
pub use robots_sitemap::RobotsSitemapPlugin;
pub use tech_detection::TechDetectionPlugin;
pub use tls_analysis::TlsAnalysisPlugin;

/// Plugin configuration
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ReconPluginConfig {
    pub timeout_secs: u64,
    pub max_redirects: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub verify_tls: bool,
}

impl ReconPluginConfig {
    pub fn default() -> Self {
        Self {
            timeout_secs: 30,
            max_redirects: 10,
            user_agent: "openre-recon/0.1.0".to_string(),
            follow_redirects: true,
            verify_tls: true,
        }
    }
}

/// Map a foreign error into the core error type.
pub(crate) fn internal_err<E>(e: E) -> openre_core::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    openre_core::Error::Internal(anyhow::Error::from(e))
}

/// Parse an HTML document, mapping errors to the core error type.
pub(crate) fn parse_html(content: &str) -> Result<select::document::Document> {
    select::document::Document::from_read(std::io::Cursor::new(content.as_bytes().to_vec()))
        .map_err(internal_err)
}

/// Base reconnaissance plugin trait
#[async_trait::async_trait]
pub trait ReconPlugin: Plugin {
    /// Get the reconnaissance type this plugin performs
    fn recon_type(&self) -> ReconType;

    /// Get the target types this plugin supports
    fn supported_target_types(&self) -> Vec<openre_scanner::target::TargetType>;

    /// Perform reconnaissance
    async fn recon(
        &self,
        context: &openre_scanner::context::ScanContext,
    ) -> Result<Vec<openre_scanner::result::Finding>>;
}

/// Types of reconnaissance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconType {
    HttpFingerprint,
    TechnologyDetection,
    TlsAnalysis,
    RobotsSitemap,
    EndpointDiscovery,
    CookieAnalysis,
    HeaderAnalysis,
    AuthDiscovery,
}

impl std::fmt::Display for ReconType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconType::HttpFingerprint => write!(f, "http_fingerprint"),
            ReconType::TechnologyDetection => write!(f, "technology_detection"),
            ReconType::TlsAnalysis => write!(f, "tls_analysis"),
            ReconType::RobotsSitemap => write!(f, "robots_sitemap"),
            ReconType::EndpointDiscovery => write!(f, "endpoint_discovery"),
            ReconType::CookieAnalysis => write!(f, "cookie_analysis"),
            ReconType::HeaderAnalysis => write!(f, "header_analysis"),
            ReconType::AuthDiscovery => write!(f, "auth_discovery"),
        }
    }
}

/// Recon result metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconMetadata {
    pub recon_type: ReconType,
    pub target_url: String,
    pub duration_ms: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub plugin_version: String,
    pub additional: HashMap<String, serde_json::Value>,
}
