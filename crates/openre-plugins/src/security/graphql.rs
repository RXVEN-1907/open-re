//! GraphQL Security Plugin
//!
//! Detects GraphQL endpoints and analyzes them for security issues including
//! introspection availability, excessive schema exposure, query depth limits,
//! and mutation discovery.

use crate::sdk::{
    AnalysisContext, CapabilityRequest, CapabilityResponse, Plugin, PluginId, Result,
};
use crate::security::{SecurityPlugin, SecurityPluginConfig, SecurityReference};
use async_trait::async_trait;
use chrono::Utc;
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Reference, ReferenceType,
    Severity,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// GraphQL Security Plugin
pub struct GraphqlPlugin {
    config: GraphqlConfig,
    client: Arc<reqwest::Client>,
}

impl GraphqlPlugin {
    /// Create a new GraphQL security plugin
    pub fn new(config: GraphqlConfig) -> std::result::Result<Self, String> {
        let client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(
                    config.max_redirects as usize,
                ))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?,
        );

        Ok(Self { config, client })
    }

    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }

    /// Get plugin description
    fn description(&self) -> &'static str {
        "Detects GraphQL endpoints and analyzes them for security issues including introspection availability, excessive schema exposure, query depth limits, and mutation discovery"
    }

    /// Get plugin references
    fn references(&self) -> Vec<SecurityReference> {
        vec![
            SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "API8:2023".to_string(),
                url: "https://owasp.org/API-Security/editions/2023/en/0x81-security-misconfiguration/".to_string(),
                description: "OWASP API Security Top 10 2023 - Security Misconfiguration".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-200".to_string(),
                url: "https://cwe.mitre.org/data/definitions/200.html".to_string(),
                description: "Exposure of Sensitive Information to an Unauthorized Actor".to_string(),
            },
            SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-770".to_string(),
                url: "https://cwe.mitre.org/data/definitions/770.html".to_string(),
                description: "Allocation of Resources Without Limits or Throttling".to_string(),
            },
        ]
    }

    /// Validate configuration
    fn validate_config(&self, config: &GraphqlConfig) -> std::result::Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Discover GraphQL endpoints
    async fn discover_endpoints(&self, base_url: &str) -> Vec<GraphqlEndpoint> {
        let mut endpoints = Vec::new();

        // Common GraphQL endpoint paths
        let common_paths = vec![
            "/graphql",
            "/graphql/",
            "/api/graphql",
            "/api/graphql/",
            "/v1/graphql",
            "/v2/graphql",
            "/graphql/api",
            "/graphql/v1",
            "/gql",
            "/gql/",
            "/query",
            "/query/",
        ];

        for path in common_paths {
            let url = format!("{}{}", base_url.trim_end_matches('/'), path);

            // Test with a simple introspection query
            let introspection_query = r#"{"query":"{__schema{queryType{name}}}"}"#;

            if let Ok(resp) = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .body(introspection_query)
                .send()
                .await
            {
                let status = resp.status();
                if status.is_success()
                    || status.as_u16() == 400
                    || status.as_u16() == 401
                    || status.as_u16() == 403
                {
                    let body = resp.text().await.unwrap_or_default();
                    let introspection_enabled =
                        body.contains("__schema") || body.contains("queryType");

                    endpoints.push(GraphqlEndpoint {
                        url: url.clone(),
                        path: path.to_string(),
                        introspection_enabled,
                        status: status.as_u16(),
                        requires_auth: status.as_u16() == 401 || status.as_u16() == 403,
                    });
                }
            }
        }

        endpoints
    }

    /// Test GraphQL endpoint for security issues
    async fn test_endpoint(
        &self,
        endpoint: &GraphqlEndpoint,
        scan_id: openre_core::ids::ScanId,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Test 1: Introspection enabled
        if endpoint.introspection_enabled {
            findings.push(self.create_finding(
                "GraphQL Introspection Enabled",
                &format!(
                    "GraphQL endpoint {} has introspection enabled, exposing full schema",
                    endpoint.url
                ),
                Severity::Medium,
                Confidence::High,
                Category::InformationDisclosure,
                endpoint,
                vec!["introspection".to_string(), "schema-exposure".to_string()],
                vec![
                    "Disable introspection in production".to_string(),
                    "Restrict introspection to authenticated/admin users only".to_string(),
                ],
                scan_id,
            ));
        }

        // Test 2: Missing authentication on GraphQL endpoint
        if !endpoint.requires_auth {
            findings.push(self.create_finding(
                "GraphQL Endpoint Missing Authentication",
                &format!(
                    "GraphQL endpoint {} does not require authentication",
                    endpoint.url
                ),
                Severity::High,
                Confidence::High,
                Category::BrokenAuthentication,
                endpoint,
                vec!["missing-auth".to_string(), "graphql".to_string()],
                vec!["Implement authentication for GraphQL endpoint".to_string()],
                scan_id,
            ));
        }

        // Test 3: Excessive schema exposure (if introspection enabled)
        if endpoint.introspection_enabled {
            if let Some(schema_info) = self.fetch_full_schema(&endpoint.url).await {
                if schema_info.type_count > 100 {
                    findings.push(self.create_finding(
                        "Excessive GraphQL Schema Exposure",
                        &format!("GraphQL schema exposes {} types, potentially revealing sensitive internal structure", schema_info.type_count),
                        Severity::Medium,
                        Confidence::Medium,
                        Category::InformationDisclosure,
                        endpoint,
                        vec!["schema-exposure".to_string(), "excessive-types".to_string()],
                        vec!["Review schema for sensitive types and consider schema hiding".to_string()],
                        scan_id,
                    ));
                }

                // Check for sensitive type names
                let sensitive_types = [
                    "password",
                    "secret",
                    "token",
                    "key",
                    "credential",
                    "auth",
                    "internal",
                    "admin",
                    "private",
                ];
                for sensitive in &sensitive_types {
                    if schema_info
                        .type_names
                        .iter()
                        .any(|name| name.to_lowercase().contains(sensitive))
                    {
                        findings.push(self.create_finding(
                            "Potentially Sensitive Type in GraphQL Schema",
                            &format!(
                                "GraphQL schema contains type with sensitive name: {}",
                                sensitive
                            ),
                            Severity::Medium,
                            Confidence::Medium,
                            Category::InformationDisclosure,
                            endpoint,
                            vec!["sensitive-type".to_string(), "schema-exposure".to_string()],
                            vec!["Review if sensitive types should be exposed via GraphQL"
                                    .to_string()],
                            scan_id,
                        ));
                    }
                }
            }
        }

        // Test 4: Query depth limits (test with deeply nested query)
        if endpoint.introspection_enabled {
            let deep_query = self.generate_deep_query(20);
            if let Ok(resp) = self
                .client
                .post(&endpoint.url)
                .header("Content-Type", "application/json")
                .body(serde_json::json!({"query": deep_query}).to_string())
                .send()
                .await
            {
                if resp.status().is_success() {
                    findings.push(self.create_finding(
                        "Missing GraphQL Query Depth Limit",
                        &format!("GraphQL endpoint {} accepts deeply nested queries (depth 20) without limit", endpoint.url),
                        Severity::Medium,
                        Confidence::High,
                        Category::SecurityMisconfiguration,
                        endpoint,
                        vec!["query-depth".to_string(), "dos-potential".to_string()],
                        vec!["Implement query depth limiting (recommended max: 5-10)".to_string()],
                        scan_id,
                    ));
                }
            }
        }

        // Test 5: Query complexity/cost analysis
        if endpoint.introspection_enabled {
            let complex_query = self.generate_complex_query();
            if let Ok(resp) = self
                .client
                .post(&endpoint.url)
                .header("Content-Type", "application/json")
                .body(serde_json::json!({"query": complex_query}).to_string())
                .send()
                .await
            {
                if resp.status().is_success() {
                    findings.push(self.create_finding(
                        "Missing GraphQL Query Complexity Limit",
                        &format!(
                            "GraphQL endpoint {} accepts complex queries without cost analysis",
                            endpoint.url
                        ),
                        Severity::Low,
                        Confidence::Medium,
                        Category::SecurityMisconfiguration,
                        endpoint,
                        vec!["query-complexity".to_string(), "dos-potential".to_string()],
                        vec!["Implement query complexity analysis and cost limits".to_string()],
                        scan_id,
                    ));
                }
            }
        }

        // Test 6: Mutation discovery
        if endpoint.introspection_enabled {
            if let Some(mutations) = self.discover_mutations(&endpoint.url).await {
                if !mutations.is_empty() {
                    findings.push(self.create_finding(
                        "GraphQL Mutations Discovered",
                        &format!("GraphQL endpoint {} exposes {} mutations: {}", endpoint.url, mutations.len(), mutations.join(", ")),
                        Severity::Info,
                        Confidence::High,
                        Category::InformationDisclosure,
                        endpoint,
                        vec!["mutations".to_string(), "graphql".to_string()],
                        vec!["Review mutations for sensitive operations and ensure proper authorization".to_string()],
                        scan_id,
                    ));
                }
            }
        }

        // Test 7: Batch query support (potential for abuse)
        if endpoint.introspection_enabled {
            let batch_query =
                r#"[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]"#;
            if let Ok(resp) = self
                .client
                .post(&endpoint.url)
                .header("Content-Type", "application/json")
                .body(batch_query)
                .send()
                .await
            {
                if resp.status().is_success() {
                    findings.push(self.create_finding(
                        "GraphQL Batch Queries Supported",
                        &format!("GraphQL endpoint {} supports batch queries, which can be abused for enumeration", endpoint.url),
                        Severity::Low,
                        Confidence::Medium,
                        Category::SecurityMisconfiguration,
                        endpoint,
                        vec!["batch-queries".to_string(), "enumeration".to_string()],
                        vec!["Consider disabling batch queries or implementing rate limiting per batch".to_string()],
                        scan_id,
                    ));
                }
            }
        }

        findings
    }

    /// Fetch full schema via introspection
    async fn fetch_full_schema(&self, url: &str) -> Option<SchemaInfo> {
        let introspection_query = r#"
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        ...FullType
                    }
                    directives {
                        name
                        description
                        locations
                        args {
                            ...InputValue
                        }
                    }
                }
            }
            fragment FullType on __Type {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        ...InputValue
                    }
                    type {
                        ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    ...InputValue
                }
                interfaces {
                    ...TypeRef
                }
                enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                }
                possibleTypes {
                    ...TypeRef
                }
            }
            fragment InputValue on __InputValue {
                name
                description
                type { ...TypeRef }
                defaultValue
            }
            fragment TypeRef on __Type {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                        }
                    }
                }
            }
        "#;

        if let Ok(resp) = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"query": introspection_query}).to_string())
            .send()
            .await
        {
            if resp.status().is_success() {
                let body = resp.text().await.ok()?;
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(types) = json
                        .get("data")
                        .and_then(|d| d.get("__schema"))
                        .and_then(|s| s.get("types"))
                        .and_then(|t| t.as_array())
                    {
                        let type_names: Vec<String> = types
                            .iter()
                            .filter_map(|t| t.get("name").and_then(|n| n.as_str()))
                            .map(|s| s.to_string())
                            .collect();

                        return Some(SchemaInfo {
                            type_count: types.len(),
                            type_names,
                        });
                    }
                }
            }
        }
        None
    }

    /// Discover mutations from schema
    async fn discover_mutations(&self, url: &str) -> Option<Vec<String>> {
        let mutation_query = r#"
            query {
                __schema {
                    mutationType {
                        fields {
                            name
                            description
                        }
                    }
                }
            }
        "#;

        if let Ok(resp) = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(serde_json::json!({"query": mutation_query}).to_string())
            .send()
            .await
        {
            if resp.status().is_success() {
                let body = resp.text().await.ok()?;
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(fields) = json
                        .get("data")
                        .and_then(|d| d.get("__schema"))
                        .and_then(|s| s.get("mutationType"))
                        .and_then(|m| m.get("fields"))
                        .and_then(|f| f.as_array())
                    {
                        let mutations: Vec<String> = fields
                            .iter()
                            .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
                            .map(|s| s.to_string())
                            .collect();
                        return Some(mutations);
                    }
                }
            }
        }
        None
    }

    /// Generate deeply nested query for depth testing
    fn generate_deep_query(&self, depth: usize) -> String {
        let mut query = String::from("{");
        for i in 0..depth {
            query.push_str(&format!("level{}: ", i));
            query.push('{');
        }
        query.push_str("__typename");
        for _ in 0..depth {
            query.push('}');
        }
        query.push('}');
        query
    }

    /// Generate complex query for complexity testing
    fn generate_complex_query(&self) -> String {
        r#"
            query {
                users(first: 100) {
                    edges {
                        node {
                            id
                            name
                            email
                            posts(first: 50) {
                                edges {
                                    node {
                                        id
                                        title
                                        content
                                        comments(first: 20) {
                                            edges {
                                                node {
                                                    id
                                                    text
                                                    author {
                                                        id
                                                        name
                                                        profile {
                                                            bio
                                                            avatar
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        "#
        .to_string()
    }

    /// Create a finding from endpoint test
    fn create_finding(
        &self,
        title: &str,
        description: &str,
        severity: Severity,
        confidence: Confidence,
        category: Category,
        endpoint: &GraphqlEndpoint,
        tags: Vec<String>,
        verification_steps: Vec<String>,
        scan_id: openre_core::ids::ScanId,
    ) -> Finding {
        let mut finding = Finding::new(FindingConfig {
            title: title.to_string(),
            description: description.to_string(),
            severity,
            confidence,
            category,
            target: endpoint.url.clone(),
            target_type: "web_api".to_string(),
            plugin_source: "graphql_security".to_string(),
            plugin_version: self.version().to_string(),
            scan_id,
        });

        finding = finding.with_evidence(Evidence {
            evidence_type: EvidenceType::HttpResponse,
            description: format!("GraphQL endpoint test for {}", endpoint.url),
            data: Some(serde_json::json!({
                "endpoint": {
                    "url": endpoint.url,
                    "path": endpoint.path,
                    "introspection_enabled": endpoint.introspection_enabled,
                    "status": endpoint.status,
                    "requires_auth": endpoint.requires_auth,
                }
            })),
            location: Some(endpoint.url.clone()),
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("graphql_security".to_string()),
            timestamp: Utc::now(),
        });

        for reference in self.references() {
            finding = finding.with_reference(Reference {
                reference_type: match reference.ref_type.as_str() {
                    "CWE" => ReferenceType::Cwe,
                    "OWASP" => ReferenceType::Owasp,
                    "CVE" => ReferenceType::Cve,
                    _ => ReferenceType::Custom(reference.ref_type),
                },
                title: reference.id.clone(),
                url: reference.url.clone(),
                description: Some(reference.description.clone()),
            });
        }

        for tag in tags {
            finding = finding.with_tag(tag);
        }
        finding = finding.with_tag("graphql".to_string());

        finding
    }
}

#[async_trait]
impl Plugin for GraphqlPlugin {
    type Config = GraphqlConfig;

    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create GraphQL plugin")
    }

    fn capabilities(&self) -> Vec<Capability> {
        vec![Capability::NetworkAccess, Capability::ReadConfig]
    }

    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let scan_id = openre_core::ids::ScanId::from_uuid(context.job_id.as_uuid());
        let target_url = request
            .input
            .get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");

        info!("Starting GraphQL security analysis for {}", target_url);

        // Discover endpoints
        let endpoints = self.discover_endpoints(target_url).await;
        let endpoints_count = endpoints.len();
        info!("Discovered {} GraphQL endpoints", endpoints_count);

        // Test each endpoint
        let mut all_findings = Vec::new();
        for endpoint in endpoints {
            let findings = self.test_endpoint(&endpoint, scan_id).await;
            all_findings.extend(findings);
        }

        info!("Found {} security issues", all_findings.len());

        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": all_findings,
            "endpoints_tested": endpoints_count,
            "vulnerabilities_found": all_findings.len(),
        })))
    }
}

/// GraphQL Plugin Configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GraphqlConfig {
    pub request_timeout: u64,
    pub max_concurrent_requests: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub verify_ssl: bool,
}

impl Default for GraphqlConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            max_concurrent_requests: 10,
            user_agent: "open-re-graphql-scanner/1.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

/// GraphQL Endpoint representation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GraphqlEndpoint {
    url: String,
    path: String,
    introspection_enabled: bool,
    status: u16,
    requires_auth: bool,
}

/// Schema information from introspection
#[derive(Debug, Clone)]
struct SchemaInfo {
    type_count: usize,
    type_names: Vec<String>,
}

// Plugin entry point
