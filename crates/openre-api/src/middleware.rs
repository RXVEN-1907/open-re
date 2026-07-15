//! Middleware for open-re API

use crate::{AppState, ApiError, ApiResult};
use axum::{
    extract::{State, Request},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    body::Body,
};
use std::sync::Arc;
use std::time::Instant;
use tokio::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    trace::TraceLayer,
    limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer,
    compression::CompressionLayer,
    cors::CorsLayer,
};
use uuid::Uuid;
use tracing::{info, warn, error, Span};
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

/// Request ID middleware
pub async fn request_id(
    State(_state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request.headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    
    // Add to request extensions for handlers to use
    request.extensions_mut().insert(RequestId(request_id.clone()));
    
    // Add to response headers
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).unwrap(),
    );
    
    response
}

/// Request ID extractor
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

/// Logging middleware
pub async fn logging(
    State(_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let request_id = request.extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| "unknown".to_string());
    
    let method = request.method().clone();
    let uri = request.uri().clone();
    let version = request.version();
    
    let start = Instant::now();
    
    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        uri = %uri,
        version = ?version,
    );
    
    let response = next.run(request).instrument(span).await;
    
    let duration = start.elapsed();
    let status = response.status();
    
    if status.is_server_error() {
        error!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = %duration.as_millis(),
            "Request failed"
        );
    } else if status.is_client_error() {
        warn!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = %duration.as_millis(),
            "Client error"
        );
    } else {
        info!(
            request_id = %request_id,
            method = %method,
            uri = %uri,
            status = %status,
            duration_ms = %duration.as_millis(),
            "Request completed"
        );
    }
    
    response
}

/// Rate limiting middleware
pub async fn rate_limit(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let limiter = &state.rate_limiter;
    
    // Get client identifier (IP or user ID)
    let client_id = get_client_id(&request);
    
    // Check rate limit
    if limiter.check_key(&client_id).is_err() {
        return Err(ApiError::RateLimited("Rate limit exceeded".into()));
    }
    
    Ok(next.run(request).await)
}

fn get_client_id(request: &Request) -> String {
    // Try to get user ID from auth
    if let Some(claims) = request.extensions().get::<crate::auth::Claims>() {
        return format!("user:{}", claims.sub);
    }
    
    // Fall back to IP
    request.headers()
        .get("x-forwarded-for")
        .or_else(|| request.headers().get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .map(|s| format!("ip:{}", s.split(',').next().unwrap_or(s).trim()))
        .unwrap_or_else(|| "ip:unknown".to_string())
}

/// Request validation middleware
pub async fn validation(
    State(_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    // Validate content type for mutating requests
    if matches!(request.method(), axum::http::Method::POST | axum::http::Method::PUT | axum::http::Method::PATCH) {
        let content_type = request.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        
        if !content_type.starts_with("application/json") 
            && !content_type.starts_with("multipart/form-data")
            && !content_type.is_empty() {
            return Err(ApiError::BadRequest("Unsupported content type".into()));
        }
    }
    
    Ok(next.run(request).await)
}

/// Security headers middleware
pub async fn security_headers(
    State(_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("X-XSS-Protection", HeaderValue::from_static("1; mode=block"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("strict-origin-when-cross-origin"));
    headers.insert("Permissions-Policy", HeaderValue::from_static("geolocation=(), microphone=(), camera=()"));
    
    // CSP header
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:;"
        ),
    );
    
    response
}

/// CORS middleware configuration
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
        .allow_credentials(true)
        .max_age(Duration::from_secs(3600))
}

/// Compression middleware
pub fn compression_layer() -> CompressionLayer {
    CompressionLayer::new()
        .gzip(true)
        .br(true)
        .deflate(true)
        .zstd(true)
}

/// Request body limit middleware
pub fn body_limit_layer(limit_bytes: usize) -> RequestBodyLimitLayer {
    RequestBodyLimitLayer::new(limit_bytes)
}

/// Timeout middleware
pub fn timeout_layer(timeout: Duration) -> TimeoutLayer {
    TimeoutLayer::new(timeout)
}

/// Create the full middleware stack
pub fn middleware_stack(state: Arc<AppState>) -> ServiceBuilder<
    tower::layer::util::Stack<
        TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>,
        tower::layer::util::Stack<
            CompressionLayer,
            tower::layer::util::Stack<
                RequestBodyLimitLayer,
                tower::layer::util::Stack<
                    TimeoutLayer,
                    tower::layer::util::Stack<
                        CorsLayer,
                        tower::layer::util::Identity
                    >
                >
            >
        >
    >
> {
    ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(compression_layer())
        .layer(body_limit_layer(50 * 1024 * 1024)) // 50MB
        .layer(timeout_layer(Duration::from_secs(30)))
        .layer(cors_layer())
}