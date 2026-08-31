//! Target Manager - Target validation, normalization, metadata, and scan configuration

use crate::error::{ScannerError, ScannerResult};
pub use openre_core::ids::TargetId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use url::Url;
use validator::Validate;

/// Type of target to scan
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    /// Local web application (running on localhost)
    LocalWebApp,
    /// Remote web application (user must be authorized)
    RemoteWebApp,
    /// REST API endpoint
    RestApi,
    /// GraphQL API endpoint
    GraphQLApi,
    /// WebSocket endpoint
    WebSocket,
    /// Custom target type for extensibility
    Custom(String),
}

impl TargetType {
    /// Get the string representation of the target type
    pub fn as_str(&self) -> &str {
        match self {
            TargetType::LocalWebApp => "local_web_app",
            TargetType::RemoteWebApp => "remote_web_app",
            TargetType::RestApi => "rest_api",
            TargetType::GraphQLApi => "graphql_api",
            TargetType::WebSocket => "websocket",
            TargetType::Custom(s) => s.as_str(),
        }
    }

    /// Check if target type requires authentication
    pub fn requires_auth(&self) -> bool {
        matches!(
            self,
            TargetType::RemoteWebApp
                | TargetType::RestApi
                | TargetType::GraphQLApi
                | TargetType::WebSocket
        )
    }

    /// Check if target is a web application
    pub fn is_web_app(&self) -> bool {
        matches!(self, TargetType::LocalWebApp | TargetType::RemoteWebApp)
    }

    /// Check if target is an API
    pub fn is_api(&self) -> bool {
        matches!(self, TargetType::RestApi | TargetType::GraphQLApi)
    }
}

impl std::fmt::Display for TargetType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for TargetType {
    type Err = ScannerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "local_web_app" => Ok(TargetType::LocalWebApp),
            "remote_web_app" => Ok(TargetType::RemoteWebApp),
            "rest_api" => Ok(TargetType::RestApi),
            "graphql_api" => Ok(TargetType::GraphQLApi),
            "websocket" => Ok(TargetType::WebSocket),
            _ => Ok(TargetType::Custom(s.to_string())),
        }
    }
}

/// Metadata about a target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMetadata {
    /// Human-readable name
    pub name: String,
    /// Description of the target
    pub description: Option<String>,
    /// Base URL of the target
    pub base_url: Url,
    /// Additional headers to include in requests
    pub headers: HashMap<String, String>,
    /// Cookies to include in requests
    pub cookies: HashMap<String, String>,
    /// Authentication configuration
    pub auth: Option<AuthConfig>,
    /// Rate limiting configuration
    pub rate_limit: Option<RateLimitConfig>,
    /// TLS configuration
    pub tls_config: Option<TlsConfig>,
    /// Proxy configuration
    pub proxy: Option<ProxyConfig>,
    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl TargetMetadata {
    /// Create new target metadata
    pub fn new(name: String, base_url: Url) -> Self {
        let now = chrono::Utc::now();
        Self {
            name,
            description: None,
            base_url,
            headers: HashMap::new(),
            cookies: HashMap::new(),
            auth: None,
            rate_limit: None,
            tls_config: None,
            proxy: None,
            custom: HashMap::new(),
            tags: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Set description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Add header
    pub fn with_header(mut self, key: String, value: String) -> Self {
        self.headers.insert(key, value);
        self
    }

    /// Add cookie
    pub fn with_cookie(mut self, key: String, value: String) -> Self {
        self.cookies.insert(key, value);
        self
    }

    /// Set authentication
    pub fn with_auth(mut self, auth: AuthConfig) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Set rate limit
    pub fn with_rate_limit(mut self, rate_limit: RateLimitConfig) -> Self {
        self.rate_limit = Some(rate_limit);
        self
    }

    /// Set TLS config
    pub fn with_tls_config(mut self, tls_config: TlsConfig) -> Self {
        self.tls_config = Some(tls_config);
        self
    }

    /// Set proxy
    pub fn with_proxy(mut self, proxy: ProxyConfig) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Add tag
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    /// Add custom metadata
    pub fn with_custom(mut self, key: String, value: serde_json::Value) -> Self {
        self.custom.insert(key, value);
        self
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthConfig {
    /// Bearer token authentication
    BearerToken { token: String },
    /// Basic authentication
    Basic { username: String, password: String },
    /// API key authentication
    ApiKey { header: String, key: String },
    /// Cookie-based authentication
    Cookie { name: String, value: String },
    /// OAuth2 authentication
    OAuth2 { client_id: String, client_secret: String, token_url: Url, scopes: Vec<String> },
    /// Custom authentication
    Custom { config: HashMap<String, serde_json::Value> },
}

impl AuthConfig {
    /// Apply authentication to a request builder
    pub fn apply_to_request(&self, request: &mut http::request::Builder) -> ScannerResult<()> {
        match self {
            AuthConfig::BearerToken { token } => {
                let builder = std::mem::take(request);
                *request = builder.header("Authorization", format!("Bearer {}", token));
            }
            AuthConfig::Basic { username, password } => {
                let credentials = base64::encode(format!("{}:{}", username, password));
                let builder = std::mem::take(request);
                *request = builder.header("Authorization", format!("Basic {}", credentials));
            }
            AuthConfig::ApiKey { header, key } => {
                let builder = std::mem::take(request);
                *request = builder.header(header, key);
            }
            AuthConfig::Cookie { name, value } => {
                let cookie = format!("{}={}", name, value);
                let builder = std::mem::take(request);
                *request = builder.header("Cookie", cookie);
            }
            AuthConfig::OAuth2 { .. } => {
                // OAuth2 would require token refresh logic - placeholder for now
                return Err(ScannerError::Authentication("OAuth2 not yet implemented".to_string()));
            }
            AuthConfig::Custom { config } => {
                for (key, value) in config {
                    if let Some(str_value) = value.as_str() {
                        let builder = std::mem::take(request);
                        *request = builder.header(key, str_value);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RateLimitConfig {
    /// Maximum requests per second
    #[validate(range(min = 1))]
    pub requests_per_second: u32,
    /// Burst allowance
    #[validate(range(min = 1))]
    pub burst: u32,
    /// Timeout for rate limiter
    pub timeout: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { requests_per_second: 10, burst: 20, timeout: Duration::from_secs(30) }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Verify TLS certificates
    pub verify_certificates: bool,
    /// Custom CA certificate path
    pub ca_cert_path: Option<String>,
    /// Client certificate path
    pub client_cert_path: Option<String>,
    /// Client key path
    pub client_key_path: Option<String>,
    /// Server name for SNI
    pub server_name: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_certificates: true,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            server_name: None,
        }
    }
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy URL
    pub url: Url,
    /// Proxy authentication
    pub auth: Option<ProxyAuth>,
    /// Bypass list (hosts that should not use proxy)
    pub bypass: Vec<String>,
}

/// Proxy authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyAuth {
    /// Username
    pub username: String,
    /// Password
    pub password: String,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ScanConfig {
    /// Target ID
    pub target_id: TargetId,
    /// Scan name
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// Scan description
    pub description: Option<String>,
    /// Plugins to run (empty = all compatible)
    pub plugins: Vec<String>,
    /// Plugins to exclude
    pub exclude_plugins: Vec<String>,
    /// Maximum scan duration
    pub max_duration: Duration,
    /// Maximum concurrent plugins
    #[validate(range(min = 1, max = 100))]
    pub max_concurrent_plugins: usize,
    /// Timeout per plugin
    pub plugin_timeout: Duration,
    /// Retry configuration
    pub retry_config: RetryConfig,
    /// Enable debug logging
    pub debug: bool,
    /// Custom configuration for plugins
    pub plugin_config: HashMap<String, serde_json::Value>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            target_id: TargetId::new(),
            name: "Unnamed Scan".to_string(),
            description: None,
            plugins: Vec::new(),
            exclude_plugins: Vec::new(),
            max_duration: Duration::from_secs(3600), // 1 hour
            max_concurrent_plugins: 5,
            plugin_timeout: Duration::from_secs(300), // 5 minutes
            retry_config: RetryConfig::default(),
            debug: false,
            plugin_config: HashMap::new(),
            tags: Vec::new(),
        }
    }
}

/// Retry configuration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RetryConfig {
    /// Maximum retry attempts
    #[validate(range(min = 0, max = 10))]
    pub max_attempts: u32,
    /// Base delay between retries
    pub base_delay: Duration,
    /// Maximum delay between retries
    pub max_delay: Duration,
    /// Exponential backoff multiplier
    #[validate(range(min = 1.0, max = 10.0))]
    pub backoff_multiplier: f64,
    /// Jitter factor (0.0 - 1.0)
    #[validate(range(min = 0.0, max = 1.0))]
    pub jitter: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter: 0.1,
        }
    }
}

/// Target representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    /// Unique target ID
    pub id: TargetId,
    /// Target type
    pub target_type: TargetType,
    /// Target metadata
    pub metadata: TargetMetadata,
    /// Scan configurations associated with this target
    pub scan_configs: Vec<ScanConfig>,
    /// Created timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Updated timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Target {
    /// Create a new target
    pub fn new(target_type: TargetType, metadata: TargetMetadata) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: TargetId::new(),
            target_type,
            metadata,
            scan_configs: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a target from a URL
    pub fn from_url(url: Url, target_type: TargetType) -> ScannerResult<Self> {
        // Validate URL
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(ScannerError::TargetValidation(
                "URL must use http or https scheme".to_string(),
            ));
        }

        let metadata = TargetMetadata::new(url.host_str().unwrap_or("unknown").to_string(), url);

        Ok(Self::new(target_type, metadata))
    }

    /// Add a scan configuration
    pub fn add_scan_config(&mut self, config: ScanConfig) {
        self.scan_configs.push(config);
        self.updated_at = chrono::Utc::now();
    }

    /// Validate target for scanning
    pub fn validate(&self) -> ScannerResult<()> {
        // Validate URL
        if self.metadata.base_url.scheme() != "http" && self.metadata.base_url.scheme() != "https" {
            return Err(ScannerError::TargetValidation(
                "Target URL must use http or https scheme".to_string(),
            ));
        }

        // Validate authentication if required
        if self.target_type.requires_auth() && self.metadata.auth.is_none() {
            return Err(ScannerError::TargetValidation(
                "Authentication required for this target type".to_string(),
            ));
        }

        // Validate rate limit config
        if let Some(rate_limit) = &self.metadata.rate_limit {
            rate_limit.validate()?;
        }

        Ok(())
    }

    /// Normalize target (ensure consistent formatting)
    pub fn normalize(&mut self) {
        // Ensure URL has trailing slash for web apps
        if self.target_type.is_web_app() {
            let mut url = self.metadata.base_url.clone();
            if url.path() == "" || url.path() == "/" {
                url.set_path("/");
            } else if !url.path().ends_with('/') {
                let new_path = format!("{}/", url.path());
                url.set_path(&new_path);
            }
            self.metadata.base_url = url;
        }

        // Normalize headers (lowercase keys)
        let normalized_headers: HashMap<String, String> =
            self.metadata.headers.drain().map(|(k, v)| (k.to_lowercase(), v)).collect();
        self.metadata.headers = normalized_headers;

        self.updated_at = chrono::Utc::now();
    }
}

/// Target Manager - responsible for target validation, normalization, and metadata
pub struct TargetManager {
    targets: dashmap::DashMap<TargetId, Target>,
}

impl TargetManager {
    /// Create a new target manager
    pub fn new() -> Self {
        Self { targets: dashmap::DashMap::new() }
    }

    /// Register a new target
    pub fn register(&self, target: Target) -> ScannerResult<TargetId> {
        target.validate()?;
        let id = target.id;
        self.targets.insert(id, target);
        Ok(id)
    }

    /// Get a target by ID
    pub fn get(&self, id: &TargetId) -> Option<Target> {
        self.targets.get(id).map(|t| t.clone())
    }

    /// Get all targets
    pub fn list(&self) -> Vec<Target> {
        self.targets.iter().map(|t| t.clone()).collect()
    }

    /// Update a target
    pub fn update(&self, id: &TargetId, mut target: Target) -> ScannerResult<()> {
        target.validate()?;
        target.id = *id;
        target.updated_at = chrono::Utc::now();
        self.targets.insert(*id, target);
        Ok(())
    }

    /// Delete a target
    pub fn delete(&self, id: &TargetId) -> bool {
        self.targets.remove(id).is_some()
    }

    /// Find targets by type
    pub fn find_by_type(&self, target_type: &TargetType) -> Vec<Target> {
        self.targets.iter().filter(|t| t.target_type == *target_type).map(|t| t.clone()).collect()
    }

    /// Find targets by tag
    pub fn find_by_tag(&self, tag: &str) -> Vec<Target> {
        self.targets
            .iter()
            .filter(|t| t.metadata.tags.contains(&tag.to_string()))
            .map(|t| t.clone())
            .collect()
    }

    /// Normalize a target
    pub fn normalize(&self, id: &TargetId) -> ScannerResult<()> {
        if let Some(mut target) = self.targets.get_mut(id) {
            target.normalize();
            Ok(())
        } else {
            Err(ScannerError::TargetNotFound(id.to_string()))
        }
    }
}

impl Default for TargetManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_type_from_str() {
        assert_eq!("local_web_app".parse::<TargetType>().unwrap(), TargetType::LocalWebApp);
        assert_eq!("rest_api".parse::<TargetType>().unwrap(), TargetType::RestApi);
        assert_eq!(
            "custom_type".parse::<TargetType>().unwrap(),
            TargetType::Custom("custom_type".to_string())
        );
    }

    #[test]
    fn test_target_type_requires_auth() {
        assert!(!TargetType::LocalWebApp.requires_auth());
        assert!(TargetType::RemoteWebApp.requires_auth());
        assert!(TargetType::RestApi.requires_auth());
    }

    #[test]
    fn test_target_from_url() {
        let url = "https://example.com".parse().unwrap();
        let target = Target::from_url(url, TargetType::RemoteWebApp).unwrap();
        assert_eq!(target.target_type, TargetType::RemoteWebApp);
        assert_eq!(target.metadata.base_url.host_str(), Some("example.com"));
    }

    #[test]
    fn test_target_validation() {
        let url = "https://example.com".parse().unwrap();
        let mut target = Target::from_url(url, TargetType::RemoteWebApp).unwrap();
        // Should fail without auth
        assert!(target.validate().is_err());

        // Add auth and should pass
        target.metadata.auth = Some(AuthConfig::BearerToken { token: "test-token".to_string() });
        assert!(target.validate().is_ok());
    }

    #[test]
    fn test_target_normalize() {
        let url = "https://example.com/path".parse().unwrap();
        let mut target = Target::from_url(url, TargetType::LocalWebApp).unwrap();
        target.normalize();
        assert_eq!(target.metadata.base_url.path(), "/path/");
    }

    #[test]
    fn test_target_manager() {
        let manager = TargetManager::new();
        let url = "https://example.com".parse().unwrap();
        let target = Target::from_url(url, TargetType::LocalWebApp).unwrap();
        let id = manager.register(target.clone()).unwrap();

        let retrieved = manager.get(&id).unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.target_type, TargetType::LocalWebApp);

        let list = manager.list();
        assert_eq!(list.len(), 1);

        assert!(manager.delete(&id));
        assert!(manager.get(&id).is_none());
    }
}
