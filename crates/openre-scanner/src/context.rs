//! Scan Context - Shared context passed to every plugin

use crate::error::{ScannerError, ScannerResult};
use crate::target::{ScanConfig, Target, TargetMetadata};
use openre_core::ids::{ScanId, TargetId};
use reqwest::{Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use url::Url;

/// Shared HTTP client for all plugins
#[derive(Clone)]
pub struct SharedHttpClient {
    /// Underlying reqwest client
    client: Client,
    /// Default headers
    default_headers: HashMap<String, String>,
    /// Default timeout
    default_timeout: Duration,
    /// Rate limiter
    rate_limiter: Option<Arc<RateLimiter>>,
}

/// Rate limiter for HTTP requests
pub struct RateLimiter {
    /// Maximum requests per second
    max_per_second: u32,
    /// Token bucket
    tokens: Arc<parking_lot::Mutex<f64>>,
    /// Last refill time
    last_refill: Arc<parking_lot::Mutex<std::time::Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(max_per_second: u32) -> Self {
        Self {
            max_per_second,
            tokens: Arc::new(parking_lot::Mutex::new(max_per_second as f64)),
            last_refill: Arc::new(parking_lot::Mutex::new(std::time::Instant::now())),
        }
    }

    /// Acquire a token (blocking)
    pub async fn acquire(&self) {
        loop {
            let mut tokens = self.tokens.lock();
            let mut last_refill = self.last_refill.lock();
            let now = std::time::Instant::now();
            let elapsed = now.duration_since(*last_refill).as_secs_f64();

            // Refill tokens
            *tokens =
                (*tokens + elapsed * self.max_per_second as f64).min(self.max_per_second as f64);
            *last_refill = now;

            if *tokens >= 1.0 {
                *tokens -= 1.0;
                return;
            }

            // Wait for next token
            drop(tokens);
            drop(last_refill);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl SharedHttpClient {
    /// Create a new shared HTTP client
    pub fn new(config: &ScanConfig, target_metadata: &TargetMetadata) -> ScannerResult<Self> {
        let mut builder = ClientBuilder::new()
            .timeout(config.plugin_timeout)
            .redirect(reqwest::redirect::Policy::limited(10))
            .gzip(true)
            .brotli(true)
            .deflate(true);

        // Add default headers
        let mut default_headers = HashMap::new();
        default_headers.insert("User-Agent".to_string(), "open-re-scanner/0.1".to_string());
        default_headers.insert("Accept".to_string(), "*/*".to_string());

        // Add target-specific headers
        for (key, value) in &target_metadata.headers {
            default_headers.insert(key.clone(), value.clone());
        }

        // Add cookies
        if !target_metadata.cookies.is_empty() {
            let cookie_header = target_metadata
                .cookies
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            default_headers.insert("Cookie".to_string(), cookie_header);
        }

        // Apply authentication
        if let Some(auth) = &target_metadata.auth {
            match auth {
                crate::target::AuthConfig::BearerToken { token } => {
                    default_headers
                        .insert("Authorization".to_string(), format!("Bearer {}", token));
                }
                crate::target::AuthConfig::Basic { username, password } => {
                    let credentials = base64::encode(format!("{}:{}", username, password));
                    default_headers.insert(
                        "Authorization".to_string(),
                        format!("Basic {}", credentials),
                    );
                }
                crate::target::AuthConfig::ApiKey { header, key } => {
                    default_headers.insert(header.clone(), key.clone());
                }
                crate::target::AuthConfig::Cookie { name, value } => {
                    let cookie = format!("{}={}", name, value);
                    if let Some(existing) = default_headers.get("Cookie") {
                        default_headers
                            .insert("Cookie".to_string(), format!("{}; {}", existing, cookie));
                    } else {
                        default_headers.insert("Cookie".to_string(), cookie);
                    }
                }
                _ => {}
            }
        }

        // Set default headers on builder
        for (key, value) in &default_headers {
            builder = builder.default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    key.parse::<reqwest::header::HeaderName>().unwrap(),
                    value.parse::<reqwest::header::HeaderValue>().unwrap(),
                );
                headers
            });
        }

        // Configure TLS
        if let Some(tls_config) = &target_metadata.tls_config {
            if !tls_config.verify_certificates {
                builder = builder.danger_accept_invalid_certs(true);
            }
            // Note: Custom CA certs would require more complex setup
        }

        // Configure proxy
        if let Some(proxy) = &target_metadata.proxy {
            let proxy_req = reqwest::Proxy::all(proxy.url.as_str())?;
            builder = builder.proxy(proxy_req);
        }

        let client = builder.build()?;

        // Create rate limiter if configured
        let rate_limiter = target_metadata
            .rate_limit
            .as_ref()
            .map(|rl| Arc::new(RateLimiter::new(rl.requests_per_second)));

        Ok(Self {
            client,
            default_headers,
            default_timeout: config.plugin_timeout,
            rate_limiter,
        })
    }

    /// Get the underlying client
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Execute a request with rate limiting
    pub async fn execute(&self, request: reqwest::Request) -> ScannerResult<reqwest::Response> {
        if let Some(limiter) = &self.rate_limiter {
            limiter.acquire().await;
        }
        Ok(self.client.execute(request).await?)
    }

    /// Build a GET request
    pub fn get(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.get(url))
    }

    /// Build a POST request
    pub fn post(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.post(url))
    }

    /// Build a PUT request
    pub fn put(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.put(url))
    }

    /// Build a DELETE request
    pub fn delete(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.delete(url))
    }

    /// Build a HEAD request
    pub fn head(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.head(url))
    }

    /// Build an OPTIONS request
    pub fn options(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.request(reqwest::Method::OPTIONS, url))
    }

    /// Build a PATCH request
    pub fn patch(&self, url: &str) -> ScannerResult<reqwest::RequestBuilder> {
        let url = self.resolve_url(url)?;
        Ok(self.client.patch(url))
    }

    /// Resolve a relative URL against the target base URL
    fn resolve_url(&self, url: &str) -> ScannerResult<Url> {
        if url.starts_with("http://") || url.starts_with("https://") {
            Ok(url.parse()?)
        } else {
            // This would need the target base URL - simplified for now
            Ok(url.parse()?)
        }
    }
}

/// Authentication state for the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    /// Whether authentication is configured
    pub configured: bool,
    /// Authentication type
    pub auth_type: Option<String>,
    /// Current session tokens
    pub tokens: HashMap<String, String>,
    /// Token expiry
    pub token_expiry: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether authentication is valid
    pub valid: bool,
    /// Last authentication error
    pub last_error: Option<String>,
}

impl AuthState {
    /// Create new auth state
    pub fn new() -> Self {
        Self {
            configured: false,
            auth_type: None,
            tokens: HashMap::new(),
            token_expiry: None,
            valid: false,
            last_error: None,
        }
    }

    /// Set authentication as configured
    pub fn set_configured(&mut self, auth_type: String) {
        self.configured = true;
        self.auth_type = Some(auth_type);
    }

    /// Update tokens
    pub fn update_tokens(
        &mut self,
        tokens: HashMap<String, String>,
        expiry: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        self.tokens = tokens;
        self.token_expiry = expiry;
        self.valid = true;
        self.last_error = None;
    }

    /// Set authentication error
    pub fn set_error(&mut self, error: String) {
        self.valid = false;
        self.last_error = Some(error);
    }

    /// Check if tokens are expired
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.token_expiry {
            chrono::Utc::now() >= expiry
        } else {
            false
        }
    }
}

impl Default for AuthState {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan cache for sharing data between plugins
pub struct ScanCache {
    /// In-memory cache
    cache: Arc<dashmap::DashMap<String, CacheEntry>>,
    /// Default TTL
    default_ttl: Duration,
}

/// Cache entry
#[derive(Debug, Clone)]
struct CacheEntry {
    value: serde_json::Value,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ScanCache {
    /// Create a new scan cache
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(dashmap::DashMap::new()),
            default_ttl,
        }
    }

    /// Get a value from cache
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        if let Some(entry) = self.cache.get(key) {
            if let Some(expires) = entry.expires_at {
                if chrono::Utc::now() > expires {
                    self.cache.remove(key);
                    return None;
                }
            }
            Some(entry.value.clone())
        } else {
            None
        }
    }

    /// Set a value in cache
    pub fn set(&self, key: String, value: serde_json::Value, ttl: Option<Duration>) {
        let expires_at = ttl
            .or(Some(self.default_ttl))
            .map(|ttl| chrono::Utc::now() + ttl);
        self.cache.insert(key, CacheEntry { value, expires_at });
    }

    /// Remove a value from cache
    pub fn remove(&self, key: &str) -> bool {
        self.cache.remove(key).is_some()
    }

    /// Clear all cache
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

/// Shared metadata between plugins
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedMetadata {
    /// Discovered endpoints
    pub endpoints: Vec<DiscoveredEndpoint>,
    /// Discovered parameters
    pub parameters: HashMap<String, Vec<DiscoveredParameter>>,
    /// Discovered technologies
    pub technologies: Vec<TechnologyFingerprint>,
    /// Custom metadata
    pub custom: HashMap<String, serde_json::Value>,
}

/// Discovered endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredEndpoint {
    /// URL
    pub url: String,
    /// HTTP method
    pub method: String,
    /// Parameters
    pub parameters: Vec<DiscoveredParameter>,
    /// Response status
    pub status_code: Option<u16>,
    /// Content type
    pub content_type: Option<String>,
    /// Discovery source
    pub source: String,
}

/// Discovered parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredParameter {
    /// Parameter name
    pub name: String,
    /// Parameter type (query, body, header, path)
    pub param_type: String,
    /// Parameter location
    pub location: String,
    /// Example value
    pub example_value: Option<String>,
    /// Whether required
    pub required: bool,
}

/// Technology fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyFingerprint {
    /// Technology name
    pub name: String,
    /// Version
    pub version: Option<String>,
    /// Confidence
    pub confidence: f32,
    /// Detection method
    pub method: String,
    /// Categories
    pub categories: Vec<String>,
}

/// Scan Context - shared context passed to every plugin
#[derive(Clone)]
pub struct ScanContext {
    /// Scan ID
    pub scan_id: ScanId,
    /// Scan configuration
    pub config: ScanConfig,
    /// Target being scanned
    pub target: Target,
    /// Shared HTTP client
    pub http_client: SharedHttpClient,
    /// Authentication state
    pub auth_state: Arc<RwLock<AuthState>>,
    /// Scan cache
    pub cache: Arc<ScanCache>,
    /// Shared metadata
    pub metadata: Arc<RwLock<SharedMetadata>>,
    /// Minimum log level for scan events
    pub log_level: tracing::Level,
    /// Cancellation token
    pub cancellation_token: crate::scan::CancellationToken,
    /// Start time
    pub start_time: std::time::Instant,
}

impl ScanContext {
    /// Create a new scan context
    pub fn new(scan_id: ScanId, config: ScanConfig, target: Target) -> ScannerResult<Self> {
        let http_client = SharedHttpClient::new(&config, &target.metadata)?;
        let auth_state = Arc::new(RwLock::new(AuthState::new()));
        let cache = Arc::new(ScanCache::new(config.plugin_timeout));
        let metadata = Arc::new(RwLock::new(SharedMetadata::default()));
        let cancellation_token = crate::scan::CancellationToken::new();

        Ok(Self {
            scan_id,
            config,
            target,
            http_client,
            auth_state,
            cache,
            metadata,
            log_level: tracing::Level::INFO,
            cancellation_token,
            start_time: std::time::Instant::now(),
        })
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cancellation_token.is_cancelled()
    }

    /// Subscribe to cancellation
    pub fn subscribe_cancellation(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.cancellation_token.subscribe()
    }

    /// Add discovered endpoint
    pub async fn add_endpoint(&self, endpoint: DiscoveredEndpoint) {
        let mut metadata = self.metadata.write().await;
        metadata.endpoints.push(endpoint);
    }

    /// Add discovered parameter
    pub async fn add_parameter(&self, endpoint_url: &str, parameter: DiscoveredParameter) {
        let mut metadata = self.metadata.write().await;
        metadata
            .parameters
            .entry(endpoint_url.to_string())
            .or_default()
            .push(parameter);
    }

    /// Add technology fingerprint
    pub async fn add_technology(&self, tech: TechnologyFingerprint) {
        let mut metadata = self.metadata.write().await;
        metadata.technologies.push(tech);
    }

    /// Get shared metadata
    pub async fn get_metadata(&self) -> SharedMetadata {
        self.metadata.read().await.clone()
    }

    /// Set custom metadata
    pub async fn set_metadata(&self, key: String, value: serde_json::Value) {
        let mut metadata = self.metadata.write().await;
        metadata.custom.insert(key, value);
    }

    /// Get custom metadata
    pub async fn get_custom_metadata(&self, key: &str) -> Option<serde_json::Value> {
        let metadata = self.metadata.read().await;
        metadata.custom.get(key).cloned()
    }

    /// Log a message
    pub fn log(&self, level: tracing::Level, message: &str) {
        match level {
            tracing::Level::ERROR => tracing::error!(scan_id = %self.scan_id, "{}", message),
            tracing::Level::WARN => tracing::warn!(scan_id = %self.scan_id, "{}", message),
            tracing::Level::INFO => tracing::info!(scan_id = %self.scan_id, "{}", message),
            tracing::Level::DEBUG => tracing::debug!(scan_id = %self.scan_id, "{}", message),
            tracing::Level::TRACE => tracing::trace!(scan_id = %self.scan_id, "{}", message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10);
        // Just test creation
        assert_eq!(limiter.max_per_second, 10);
    }

    #[test]
    fn test_auth_state() {
        let mut auth = AuthState::new();
        assert!(!auth.configured);
        assert!(!auth.valid);

        auth.set_configured("bearer".to_string());
        assert!(auth.configured);
        assert_eq!(auth.auth_type, Some("bearer".to_string()));

        auth.update_tokens(
            [("access_token".to_string(), "token123".to_string())].into(),
            Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        );
        assert!(auth.valid);
        assert!(!auth.is_expired());
    }

    #[test]
    fn test_scan_cache() {
        let cache = ScanCache::new(Duration::from_secs(60));
        assert!(cache.is_empty());

        cache.set(
            "key1".to_string(),
            serde_json::json!({"test": "value"}),
            None,
        );
        assert_eq!(cache.len(), 1);

        let value = cache.get("key1").unwrap();
        assert_eq!(value["test"], "value");

        cache.remove("key1");
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn test_shared_metadata() {
        let mut metadata = SharedMetadata::default();
        metadata.endpoints.push(DiscoveredEndpoint {
            url: "https://example.com/api/users".to_string(),
            method: "GET".to_string(),
            parameters: vec![],
            status_code: Some(200),
            content_type: Some("application/json".to_string()),
            source: "crawler".to_string(),
        });

        assert_eq!(metadata.endpoints.len(), 1);
    }
}
