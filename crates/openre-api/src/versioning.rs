//! API versioning for open-re

use crate::{ApiError, ApiResult};
use axum::{
    extract::{FromRequestParts, Request},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::str::FromStr;
use tracing::{debug, warn};

/// API version
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApiVersion {
    V1,
    V2,
}

impl ApiVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiVersion::V1 => "v1",
            ApiVersion::V2 => "v2",
        }
    }

    pub fn current() -> Self {
        ApiVersion::V1
    }

    pub fn latest() -> Self {
        ApiVersion::V2
    }

    pub fn all() -> Vec<Self> {
        vec![ApiVersion::V1, ApiVersion::V2]
    }
}

impl FromStr for ApiVersion {
    type Err = ApiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "v1" | "1" => Ok(ApiVersion::V1),
            "v2" | "2" => Ok(ApiVersion::V2),
            _ => Err(ApiError::BadRequest(format!("Unsupported API version: {}", s))),
        }
    }
}

impl std::fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Version extractor from request
#[derive(Debug, Clone)]
pub struct VersionExtractor(pub ApiVersion);

#[async_trait::async_trait]
impl<S> FromRequestParts<S> for VersionExtractor
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut axum::http::request::Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Check Accept header for version
        if let Some(accept) = parts.headers.get(header::ACCEPT) {
            if let Ok(accept_str) = accept.to_str() {
                // Parse Accept header like: application/vnd.openre.v1+json
                if let Some(version) = parse_accept_version(accept_str) {
                    return Ok(VersionExtractor(version));
                }
            }
        }

        // Check custom header
        if let Some(version_header) = parts.headers.get("x-api-version") {
            if let Ok(version_str) = version_header.to_str() {
                if let Ok(version) = version_str.parse::<ApiVersion>() {
                    return Ok(VersionExtractor(version));
                }
            }
        }

        // Check URL path prefix
        if let Some(path) = parts.uri.path().strip_prefix("/api/") {
            if let Some(version_str) = path.split('/').next() {
                if let Ok(version) = version_str.parse::<ApiVersion>() {
                    return Ok(VersionExtractor(version));
                }
            }
        }

        // Default to current version
        Ok(VersionExtractor(ApiVersion::current()))
    }
}

fn parse_accept_version(accept: &str) -> Option<ApiVersion> {
    // Parse media type like: application/vnd.openre.v1+json
    for part in accept.split(',') {
        let part = part.trim();
        if part.starts_with("application/vnd.openre.") {
            if let Some(version_part) = part.strip_prefix("application/vnd.openre.") {
                if let Some(version_str) = version_part.split('+').next() {
                    return version_str.parse().ok();
                }
            }
        }
    }
    None
}

/// Version middleware - adds version headers to responses
pub async fn version_middleware(
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    
    // Add API version headers
    response.headers_mut().insert(
        "x-api-version",
        HeaderValue::from_static(ApiVersion::current().as_str()),
    );
    response.headers_mut().insert(
        "x-api-supported-versions",
        HeaderValue::from_static("v1, v2"),
    );
    response.headers_mut().insert(
        "x-api-deprecated-versions",
        HeaderValue::from_static(""),
    );
    
    response
}

/// Version negotiation middleware
pub async fn version_negotiation(
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let version = extract_version(&request)?;
    
    // Check if version is supported
    if !is_version_supported(version) {
        return Err(ApiError::NotAcceptable(format!(
            "API version {} is not supported. Supported versions: v1, v2",
            version
        )));
    }
    
    // Check if version is deprecated
    if is_version_deprecated(version) {
        warn!("Deprecated API version {} requested", version);
        // Could add deprecation warning header
    }
    
    // Add version to request extensions for handlers
    let mut request = request;
    request.extensions_mut().insert(version);
    
    Ok(next.run(request).await)
}

fn extract_version(request: &Request) -> Result<ApiVersion, ApiError> {
    // Check Accept header
    if let Some(accept) = request.headers().get(header::ACCEPT) {
        if let Ok(accept_str) = accept.to_str() {
            if let Some(version) = parse_accept_version(accept_str) {
                return Ok(version);
            }
        }
    }

    // Check custom header
    if let Some(version_header) = request.headers().get("x-api-version") {
        if let Ok(version_str) = version_header.to_str() {
            return version_str.parse();
        }
    }

    // Check URL path
    if let Some(path) = request.uri().path().strip_prefix("/api/") {
        if let Some(version_str) = path.split('/').next() {
            return version_str.parse();
        }
    }

    Ok(ApiVersion::current())
}

fn is_version_supported(version: ApiVersion) -> bool {
    matches!(version, ApiVersion::V1 | ApiVersion::V2)
}

fn is_version_deprecated(version: ApiVersion) -> bool {
    // V1 is deprecated but still supported
    matches!(version, ApiVersion::V1)
}

/// Version-specific route builder
pub struct VersionedRouter {
    v1_routes: axum::Router,
    v2_routes: axum::Router,
}

impl VersionedRouter {
    pub fn new() -> Self {
        Self {
            v1_routes: axum::Router::new(),
            v2_routes: axum::Router::new(),
        }
    }

    pub fn v1(mut self, routes: axum::Router) -> Self {
        self.v1_routes = routes;
        self
    }

    pub fn v2(mut self, routes: axum::Router) -> Self {
        self.v2_routes = routes;
        self
    }

    pub fn build(self) -> axum::Router {
        axum::Router::new()
            .nest("/api/v1", self.v1_routes)
            .nest("/api/v2", self.v2_routes)
            // Also support version-less routes (default to current)
            .nest("/api", self.v1_routes.clone())
    }
}

/// Deprecation warning header
pub const DEPRECATION_HEADER: &str = "x-api-deprecation-warning";

/// Add deprecation warning to response
pub fn add_deprecation_warning(response: &mut Response, message: &str) {
    response.headers_mut().insert(
        DEPRECATION_HEADER,
        HeaderValue::from_str(message).unwrap_or(HeaderValue::from_static("")),
    );
}

/// Version info for OpenAPI
pub fn version_info() -> Vec<VersionInfo> {
    vec![
        VersionInfo {
            version: "v1",
            status: VersionStatus::Deprecated,
            release_date: "2024-01-01",
            sunset_date: Some("2025-01-01"),
            docs_url: Some("/docs/v1"),
        },
        VersionInfo {
            version: "v2",
            status: VersionStatus::Current,
            release_date: "2024-06-01",
            sunset_date: None,
            docs_url: Some("/docs/v2"),
        },
    ]
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionInfo {
    pub version: &'static str,
    pub status: VersionStatus,
    pub release_date: &'static str,
    pub sunset_date: Option<&'static str>,
    pub docs_url: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionStatus {
    Current,
    Deprecated,
    Sunset,
    Retired,
}