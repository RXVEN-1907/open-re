//! Built-in Security Plugins

pub mod access_control;
pub mod api_rate_limiting;
pub mod auth_discovery;
pub mod cookie_security;
pub mod cors_analysis;
pub mod csp_analysis;
pub mod file_upload;
pub mod graphql_analysis;
pub mod information_disclosure;
pub mod path_traversal;
pub mod rate_limiting;
pub mod rest_api_analysis;
pub mod security_headers;
pub mod sensitive_info;
pub mod session_management;
pub mod sql_injection;
pub mod xss_analysis;

use crate::{Capability, CapabilitySet, PluginManifest, PluginMetadata};

/// Get all built-in security plugin manifests
pub fn builtin_security_plugins() -> Vec<PluginManifest> {
    vec![
        access_control::manifest(),
        api_rate_limiting::manifest(),
        auth_discovery::manifest(),
        cookie_security::manifest(),
        cors_analysis::manifest(),
        csp_analysis::manifest(),
        file_upload::manifest(),
        graphql_analysis::manifest(),
        information_disclosure::manifest(),
        path_traversal::manifest(),
        rate_limiting::manifest(),
        rest_api_analysis::manifest(),
        security_headers::manifest(),
        sensitive_info::manifest(),
        session_management::manifest(),
        sql_injection::manifest(),
        xss_analysis::manifest(),
    ]
}
