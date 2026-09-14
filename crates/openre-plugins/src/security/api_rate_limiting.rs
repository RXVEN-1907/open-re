//! Rate limit detection and bypass testing Security Plugin
//!
//! This plugin tests API rate limiting implementations by:
//! - Sending sustained requests to detect rate limiting thresholds
//! - Testing burst handling capabilities
//! - Specifically testing authentication endpoints for rate limiting
//! - Validating rate limit headers and Retry-After responses
//!
//! Configuration parameters (see config_schema.json):
//! - `burst_test_size`: Number of requests in burst test (default: 10)
//! - `sustained_requests_per_second`: Sustained rate for testing (default: 5)
//! - `sustained_test_duration_seconds`: Duration of sustained test (default: 10)
//! - `auth_endpoint_test_requests`: Requests to test auth endpoints (default: 5)
//! - `max_test_requests`: Maximum total test requests per endpoint (default: 50)
//! - `test_requests_per_endpoint`: Test requests per endpoint (default: 20)

use crate::{PluginManifest, SimplePluginMetadata};
use openre_core::Capability;

pub fn manifest() -> PluginManifest {
    let metadata = SimplePluginMetadata {
        name: "security-api_rate_limiting".to_string(),
        version: "0.1.0".to_string(),
        description: "Rate limit detection and bypass testing".to_string(),
        author: "open-re team".to_string(),
        license: "MIT".to_string(),
        repository: "https://github.com/RXVEN-1907/open-re".to_string(),
        homepage: None,
        categories: vec!["security".to_string(), "analysis".to_string()],
        keywords: vec!["security".to_string(), "api-rate-limiting".to_string()],
    };

    PluginManifest::from_simple(
        metadata,
        vec![Capability::NetworkAccess, Capability::CallAi],
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest() {
        let m = manifest();
        assert_eq!(m.name, "security-api_rate_limiting");
        assert!(!m.plugin.capabilities.is_empty());
    }
}
