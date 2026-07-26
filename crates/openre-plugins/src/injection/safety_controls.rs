//! Safety Controls
//!
//! Implements safeguards for injection testing including:
//! - Configurable request limits
//! - Rate limiting
//! - Timeouts
//! - Maximum payload counts
//! - Maximum concurrency
//! - Scope enforcement
//! - Authorization verification

use crate::injection::SafetyConfig;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, info, warn};

/// Safety controller for injection testing
pub struct SafetyController {
    config: SafetyConfig,
    request_count: Arc<Mutex<usize>>,
    total_request_count: Arc<Mutex<usize>>,
    rate_limiter: Arc<RateLimiter>,
    concurrency_semaphore: Arc<Semaphore>,
    start_time: Instant,
    blocked_payloads: Vec<String>,
    allowed_scopes: Vec<String>,
    authorization_verified: Arc<Mutex<bool>>,
}

impl SafetyController {
    /// Create a new safety controller
    pub fn new(config: SafetyConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_rps));
        let concurrency_semaphore = Arc::new(Semaphore::new(config.max_concurrency));
        
        Self {
            config,
            request_count: Arc::new(Mutex::new(0)),
            total_request_count: Arc::new(Mutex::new(0)),
            rate_limiter,
            concurrency_semaphore,
            start_time: Instant::now(),
            blocked_payloads: Vec::new(),
            allowed_scopes: Vec::new(),
            authorization_verified: Arc::new(Mutex::new(false)),
        }
    }
    
    /// Initialize with scan configuration
    pub async fn initialize(&self, allowed_scopes: Vec<String>, authorization_token: Option<String>) -> Result<(), SafetyError> {
        self.allowed_scopes = allowed_scopes;
        
        // Verify authorization if required
        if self.config.require_authorization {
            if let Some(token) = authorization_token {
                self.verify_authorization(token).await?;
            } else {
                return Err(SafetyError::AuthorizationRequired);
            }
        }
        
        *self.authorization_verified.lock().await = true;
        info!("Safety controller initialized with {} allowed scopes", self.allowed_scopes.len());
        Ok(())
    }
    
    /// Verify authorization token
    async fn verify_authorization(&self, token: String) -> Result<(), SafetyError> {
        // In production, this would validate against an auth service
        // For now, we just check if token is non-empty
        if token.is_empty() {
            return Err(SafetyError::InvalidAuthorization);
        }
        debug!("Authorization verified");
        Ok(())
    }
    
    /// Check if a target URL is within allowed scopes
    pub fn check_scope(&self, url: &str) -> Result<(), SafetyError> {
        if self.allowed_scopes.is_empty() {
            // No scope restrictions configured
            return Ok(());
        }
        
        let parsed = url::Url::parse(url).map_err(|_| SafetyError::InvalidUrl)?;
        let host = parsed.host_str().unwrap_or("");
        
        let allowed = self.allowed_scopes.iter().any(|scope| {
            if scope.starts_with("*.") {
                // Wildcard subdomain
                let domain = &scope[2..];
                host == domain || host.ends_with(&format!(".{}", domain))
            } else {
                host == scope || host.ends_with(&format!(".{}", scope))
            }
        });
        
        if !allowed {
            warn!("Scope check failed for URL: {} (host: {})", url, host);
            return Err(SafetyError::ScopeViolation(url.to_string()));
        }
        
        Ok(())
    }
    
    /// Check if a payload is blocked
    pub fn check_payload(&self, payload: &str) -> Result<(), SafetyError> {
        for pattern in &self.config.blocked_patterns {
            if payload.to_lowercase().contains(&pattern.to_lowercase()) {
                warn!("Blocked payload detected: {}", pattern);
                self.blocked_payloads.push(payload.to_string());
                return Err(SafetyError::BlockedPayload(pattern.clone()));
            }
        }
        Ok(())
    }
    
    /// Acquire permission to make a request
    pub async fn acquire_request_permit(&self) -> Result<RequestPermit, SafetyError> {
        // Check total request limit
        {
            let total = *self.total_request_count.lock().await;
            if total >= self.config.max_total_requests {
                return Err(SafetyError::RequestLimitExceeded);
            }
        }
        
        // Check per-test limit (handled by caller)
        
        // Acquire concurrency semaphore
        let permit = self.concurrency_semaphore.acquire().await
            .map_err(|_| SafetyError::ConcurrencyError)?;
        
        // Rate limiting
        self.rate_limiter.acquire().await;
        
        // Increment counters
        *self.request_count.lock().await += 1;
        *self.total_request_count.lock().await += 1;
        
        Ok(RequestPermit {
            _permit: permit,
            controller: self.clone(),
        })
    }
    
    /// Get current request count
    pub async fn get_request_count(&self) -> usize {
        *self.request_count.lock().await
    }
    
    /// Get total request count
    pub async fn get_total_request_count(&self) -> usize {
        *self.total_request_count.lock().await
    }
    
    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
    
    /// Get blocked payloads
    pub fn get_blocked_payloads(&self) -> Vec<String> {
        self.blocked_payloads.clone()
    }
    
    /// Reset per-test counters
    pub async fn reset_test_counters(&self) {
        *self.request_count.lock().await = 0;
    }
    
    /// Check if authorization is verified
    pub async fn is_authorized(&self) -> bool {
        *self.authorization_verified.lock().await
    }
    
    /// Get safety statistics
    pub async fn get_stats(&self) -> SafetyStats {
        SafetyStats {
            current_test_requests: *self.request_count.lock().await,
            total_requests: *self.total_request_count.lock().await,
            blocked_payloads: self.blocked_payloads.len(),
            elapsed_time: self.start_time.elapsed(),
            rate_limit_rps: self.config.rate_limit_rps,
            max_concurrency: self.config.max_concurrency,
            max_total_requests: self.config.max_total_requests,
            authorization_verified: *self.authorization_verified.lock().await,
        }
    }
}

impl Clone for SafetyController {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            request_count: self.request_count.clone(),
            total_request_count: self.total_request_count.clone(),
            rate_limiter: self.rate_limiter.clone(),
            concurrency_semaphore: self.concurrency_semaphore.clone(),
            start_time: self.start_time,
            blocked_payloads: self.blocked_payloads.clone(),
            allowed_scopes: self.allowed_scopes.clone(),
            authorization_verified: self.authorization_verified.clone(),
        }
    }
}

/// Request permit that automatically releases on drop
pub struct RequestPermit {
    _permit: tokio::sync::SemaphorePermit<'static>,
    controller: SafetyController,
}

impl Drop for RequestPermit {
    fn drop(&mut self) {
        // Permit automatically released when dropped
    }
}

/// Rate limiter using token bucket algorithm
struct RateLimiter {
    rate: f64,
    tokens: Arc<Mutex<f64>>,
    last_refill: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    fn new(rate: f64) -> Self {
        Self {
            rate,
            tokens: Arc::new(Mutex::new(rate)),
            last_refill: Arc::new(Mutex::new(Instant::now())),
        }
    }
    
    async fn acquire(&self) {
        if self.rate <= 0.0 {
            return; // No rate limiting
        }
        
        loop {
            let mut tokens = self.tokens.lock().await;
            let mut last_refill = self.last_refill.lock().await;
            let now = Instant::now();
            let elapsed = now.duration_since(*last_refill).as_secs_f64();
            
            // Refill tokens
            *tokens = (*tokens + elapsed * self.rate).min(self.rate);
            *last_refill = now;
            
            if *tokens >= 1.0 {
                *tokens -= 1.0;
                return;
            }
            
            // Calculate wait time
            let wait_time = (1.0 - *tokens) / self.rate;
            drop(tokens);
            drop(last_refill);
            
            tokio::time::sleep(Duration::from_secs_f64(wait_time)).await;
        }
    }
}

/// Safety statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyStats {
    pub current_test_requests: usize,
    pub total_requests: usize,
    pub blocked_payloads: usize,
    pub elapsed_time: Duration,
    pub rate_limit_rps: f64,
    pub max_concurrency: usize,
    pub max_total_requests: usize,
    pub authorization_verified: bool,
}

/// Safety errors
#[derive(Debug, thiserror::Error)]
pub enum SafetyError {
    #[error("Authorization required but not provided")]
    AuthorizationRequired,
    
    #[error("Invalid authorization token")]
    InvalidAuthorization,
    
    #[error("Scope violation: {0}")]
    ScopeViolation(String),
    
    #[error("Blocked payload pattern: {0}")]
    BlockedPayload(String),
    
    #[error("Request limit exceeded")]
    RequestLimitExceeded,
    
    #[error("Concurrency limit exceeded")]
    ConcurrencyError,
    
    #[error("Invalid URL: {0}")]
    InvalidUrl,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Timeout exceeded")]
    TimeoutExceeded,
    
    #[error("Safety check failed: {0}")]
    SafetyCheckFailed(String),
}

/// Scope validator for target URLs
pub struct ScopeValidator {
    allowed_scopes: Vec<String>,
    blocked_scopes: Vec<String>,
}

impl ScopeValidator {
    pub fn new(allowed_scopes: Vec<String>, blocked_scopes: Vec<String>) -> Self {
        Self {
            allowed_scopes,
            blocked_scopes,
        }
    }
    
    pub fn validate(&self, url: &str) -> Result<(), SafetyError> {
        let parsed = url::Url::parse(url).map_err(|_| SafetyError::InvalidUrl)?;
        let host = parsed.host_str().unwrap_or("");
        
        // Check blocked scopes first
        for blocked in &self.blocked_scopes {
            if self.host_matches(host, blocked) {
                return Err(SafetyError::ScopeViolation(format!("Blocked scope: {}", blocked)));
            }
        }
        
        // If allowed scopes specified, check against them
        if !self.allowed_scopes.is_empty() {
            let allowed = self.allowed_scopes.iter().any(|scope| self.host_matches(host, scope));
            if !allowed {
                return Err(SafetyError::ScopeViolation(format!("Host not in allowed scopes: {}", host)));
            }
        }
        
        Ok(())
    }
    
    fn host_matches(&self, host: &str, scope: &str) -> bool {
        if scope.starts_with("*.") {
            let domain = &scope[2..];
            host == domain || host.ends_with(&format!(".{}", domain))
        } else {
            host == scope || host.ends_with(&format!(".{}", scope))
        }
    }
}

/// Payload validator
pub struct PayloadValidator {
    blocked_patterns: Vec<String>,
    max_payload_length: usize,
}

impl PayloadValidator {
    pub fn new(blocked_patterns: Vec<String>, max_payload_length: usize) -> Self {
        Self {
            blocked_patterns,
            max_payload_length,
        }
    }
    
    pub fn validate(&self, payload: &str) -> Result<(), SafetyError> {
        // Check length
        if payload.len() > self.max_payload_length {
            return Err(SafetyError::SafetyCheckFailed(
                format!("Payload exceeds maximum length: {} > {}", payload.len(), self.max_payload_length)
            ));
        }
        
        // Check blocked patterns
        for pattern in &self.blocked_patterns {
            if payload.to_lowercase().contains(&pattern.to_lowercase()) {
                return Err(SafetyError::BlockedPayload(pattern.clone()));
            }
        }
        
        Ok(())
    }
}

/// Request validator
pub struct RequestValidator {
    max_request_size: usize,
    allowed_methods: Vec<Method>,
    allowed_content_types: Vec<String>,
}

impl RequestValidator {
    pub fn new(
        max_request_size: usize,
        allowed_methods: Vec<Method>,
        allowed_content_types: Vec<String>,
    ) -> Self {
        Self {
            max_request_size,
            allowed_methods,
            allowed_content_types,
        }
    }
    
    pub fn validate(&self, request: &crate::injection::request_engine::TestRequest) -> Result<(), SafetyError> {
        // Check method
        if !self.allowed_methods.contains(&request.method) {
            return Err(SafetyError::SafetyCheckFailed(
                format!("Method not allowed: {}", request.method)
            ));
        }
        
        // Check request size
        let body_size = request.body.as_ref().map(|b| b.len()).unwrap_or(0);
        if body_size > self.max_request_size {
            return Err(SafetyError::SafetyCheckFailed(
                format!("Request body too large: {} > {}", body_size, self.max_request_size)
            ));
        }
        
        // Check content type
        if let Some(content_type) = request.headers.get("Content-Type") {
            let allowed = self.allowed_content_types.iter().any(|ct| content_type.contains(ct));
            if !allowed && !self.allowed_content_types.is_empty() {
                return Err(SafetyError::SafetyCheckFailed(
                    format!("Content-Type not allowed: {}", content_type)
                ));
            }
        }
        
        Ok(())
    }
}

impl Default for RequestValidator {
    fn default() -> Self {
        Self {
            max_request_size: 1024 * 1024, // 1MB
            allowed_methods: vec![Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::HEAD, Method::OPTIONS],
            allowed_content_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "text/xml".to_string(),
                "application/xml".to_string(),
                "text/plain".to_string(),
            ],
        }
    }
}