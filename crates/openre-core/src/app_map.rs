//! Application Map data model for representing web application structure

use crate::ids::{
    AuthEndpointId, EndpointId, FindingId, FormId, ParameterId, RelationshipId, ResourceId, ScanId,
    TargetId, TechnologyId, UrlId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

/// Core Application Map structure representing a web application's attack surface
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMap {
    /// Target information
    pub target: TargetInfo,
    /// Discovered URLs organized in a hierarchy
    pub urls: Vec<UrlNode>,
    /// API endpoints discovered
    pub endpoints: Vec<Endpoint>,
    /// Parameters found across all endpoints
    pub parameters: Vec<Parameter>,
    /// Forms discovered
    pub forms: Vec<Form>,
    /// Technologies detected
    pub technologies: Vec<Technology>,
    /// Authentication endpoints
    pub auth_endpoints: Vec<AuthEndpoint>,
    /// Resources (files, assets, etc.)
    pub resources: Vec<Resource>,
    /// Relationships between all entities
    pub relationships: Vec<AppMapRelationship>,
    /// Metadata
    pub metadata: AppMapMetadata,
}

/// Target information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetInfo {
    /// Target ID
    pub id: TargetId,
    /// Base URL
    pub base_url: String,
    /// Target type (web, api, binary, etc.)
    pub target_type: String,
    /// Scan ID that generated this map
    pub scan_id: ScanId,
    /// Timestamp of map creation
    pub created_at: DateTime<Utc>,
    /// Tags
    pub tags: Vec<String>,
}

/// URL node in the application map hierarchy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlNode {
    /// Unique URL ID
    pub id: UrlId,
    /// Full URL
    pub url: String,
    /// HTTP method used to discover
    pub method: HttpMethod,
    /// How this URL was discovered
    pub discovered_via: DiscoverySource,
    /// HTTP status code (if fetched)
    pub status_code: Option<u16>,
    /// Response headers
    pub response_headers: HashMap<String, String>,
    /// Technologies detected at this URL
    pub technologies: Vec<TechnologyRef>,
    /// Parameters found at this URL
    pub parameters: Vec<ParameterRef>,
    /// Forms found at this URL
    pub forms: Vec<FormRef>,
    /// Authentication info if applicable
    pub auth_info: Option<AuthInfo>,
    /// Child URLs (directory hierarchy)
    pub children: Vec<UrlId>,
    /// Parent URL
    pub parent: Option<UrlId>,
    /// Depth in hierarchy
    pub depth: usize,
    /// Whether this URL was crawled
    pub crawled: bool,
    /// Timestamp of discovery
    pub discovered_at: DateTime<Utc>,
}

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Trace,
    Connect,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Delete => write!(f, "DELETE"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Head => write!(f, "HEAD"),
            HttpMethod::Options => write!(f, "OPTIONS"),
            HttpMethod::Trace => write!(f, "TRACE"),
            HttpMethod::Connect => write!(f, "CONNECT"),
        }
    }
}

/// Source of URL discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoverySource {
    /// From sitemap.xml
    Sitemap,
    /// From robots.txt
    RobotsTxt,
    /// From crawling links
    Crawling,
    /// From JavaScript analysis
    JavaScriptAnalysis,
    /// From API documentation (OpenAPI, Swagger)
    ApiDocumentation,
    /// From directory listing
    DirectoryListing,
    /// From fuzzing
    Fuzzing,
    /// From referrer headers
    Referrer,
    /// From manual input
    Manual,
    /// From technology detection
    TechnologyDetection,
}

/// Reference to a technology
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyRef {
    pub technology_id: TechnologyId,
    pub confidence: f32,
    pub version: Option<String>,
}

/// Reference to a parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterRef {
    pub parameter_id: ParameterId,
    pub location: ParameterLocation,
}

/// Reference to a form
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormRef {
    pub form_id: FormId,
}

/// Authentication information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthInfo {
    /// Authentication type
    pub auth_type: AuthType,
    /// Login URL
    pub login_url: Option<String>,
    /// Session cookie names
    pub session_cookies: Vec<String>,
    /// Auth headers
    pub auth_headers: Vec<String>,
    /// Whether authentication is required
    pub required: bool,
}

/// Authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthType {
    /// Form-based authentication
    Form,
    /// HTTP Basic Auth
    Basic,
    /// HTTP Digest Auth
    Digest,
    /// Bearer token (JWT, OAuth)
    Bearer,
    /// API Key
    ApiKey,
    /// Cookie-based session
    Cookie,
    /// NTLM
    Ntlm,
    /// Kerberos
    Kerberos,
    /// Custom/Other
    Custom,
}

/// API Endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Unique endpoint ID
    pub id: EndpointId,
    /// Path pattern (e.g., /api/users/{id})
    pub path: String,
    /// Supported HTTP methods
    pub methods: Vec<HttpMethod>,
    /// Parameters accepted by this endpoint
    pub parameters: Vec<Parameter>,
    /// Authentication requirement
    pub authentication: AuthRequirement,
    /// Sensitivity level
    pub sensitivity: SensitivityLevel,
    /// Technology stack detected
    pub technology_stack: Vec<TechnologyRef>,
    /// Associated findings
    pub findings: Vec<FindingRef>,
    /// Rate limiting info
    pub rate_limit: Option<RateLimitInfo>,
    /// CORS configuration
    pub cors: Option<CorsInfo>,
}

/// Parameter in an endpoint or URL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    /// Unique parameter ID
    pub id: ParameterId,
    /// Parameter name
    pub name: String,
    /// Parameter location
    pub location: ParameterLocation,
    /// Data type
    pub data_type: ParameterType,
    /// Whether required
    pub required: bool,
    /// Default value
    pub default_value: Option<String>,
    /// Example values
    pub examples: Vec<String>,
    /// Validation rules
    pub validation: Option<ParameterValidation>,
    /// Associated findings
    pub findings: Vec<FindingRef>,
}

/// Parameter location
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterLocation {
    Query,
    Path,
    Header,
    Cookie,
    Body,
    FormData,
}

/// Parameter data type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Integer,
    Float,
    Boolean,
    Array,
    Object,
    File,
    Date,
    DateTime,
    Uuid,
    Email,
    Url,
    Custom(String),
}

/// Parameter validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterValidation {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub enum_values: Option<Vec<String>>,
}

/// Authentication requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthRequirement {
    /// No authentication required
    None,
    /// Authentication optional
    Optional,
    /// Authentication required
    Required,
    /// Admin privileges required
    Admin,
}

/// Sensitivity level of endpoint/data
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitivityLevel {
    /// Public information
    Public,
    /// Authenticated user access
    Authenticated,
    /// Admin access
    Admin,
    /// Internal/internal-only
    Internal,
    /// Highly sensitive (PII, secrets, etc.)
    Critical,
}

/// Rate limiting information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitInfo {
    pub requests_per_window: u32,
    pub window_seconds: u32,
    pub limit_header: Option<String>,
    pub remaining_header: Option<String>,
    pub reset_header: Option<String>,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorsInfo {
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_headers: Vec<String>,
    pub allow_credentials: bool,
    pub max_age: Option<u32>,
}

/// Form discovered in the application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Form {
    /// Unique form ID
    pub id: FormId,
    /// Form action URL
    pub action: String,
    /// Form method
    pub method: HttpMethod,
    /// Form fields
    pub fields: Vec<FormField>,
    /// Form ID attribute
    pub form_id: Option<String>,
    /// Form class attribute
    pub form_class: Option<String>,
    /// Whether it's a login form
    pub is_login_form: bool,
    /// Whether it's a search form
    pub is_search_form: bool,
    /// CSRF token field name if detected
    pub csrf_field: Option<String>,
    /// Associated URL
    pub url_id: UrlId,
}

/// Form field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub field_type: FormFieldType,
    pub required: bool,
    pub placeholder: Option<String>,
    pub default_value: Option<String>,
    pub autocomplete: Option<String>,
}

/// Form field types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormFieldType {
    Text,
    Password,
    Email,
    Number,
    Tel,
    Url,
    Search,
    Hidden,
    Checkbox,
    Radio,
    Select,
    Textarea,
    File,
    Submit,
    Button,
    Date,
    DateTime,
    Color,
    Range,
    Custom(String),
}

/// Technology detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technology {
    /// Unique technology ID
    pub id: TechnologyId,
    /// Technology name
    pub name: String,
    /// Category (framework, server, library, cms, etc.)
    pub category: TechnologyCategory,
    /// Version if detected
    pub version: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Detection method
    pub detection_method: DetectionMethod,
    /// URLs where detected
    pub detected_at_urls: Vec<UrlId>,
    /// CPE identifier if available
    pub cpe: Option<String>,
}

/// Technology categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnologyCategory {
    Framework,
    Server,
    Library,
    Cms,
    Language,
    Database,
    Cache,
    Cdn,
    Waf,
    Analytics,
    Ui,
    Security,
    Other,
}

/// Detection method for technology
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    Header,
    Cookie,
    Html,
    JavaScript,
    Url,
    MetaTag,
    ScriptSrc,
    Dns,
    Ssl,
    RobotsTxt,
    Sitemap,
    ApiResponse,
    ErrorPage,
    DefaultFile,
    Custom,
}

/// Authentication endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEndpoint {
    /// Unique auth endpoint ID
    pub id: AuthEndpointId,
    /// URL
    pub url: String,
    /// Authentication type
    pub auth_type: AuthType,
    /// Login form ID if form-based
    pub login_form_id: Option<FormId>,
    /// Parameters for authentication
    pub parameters: Vec<Parameter>,
    /// Whether multi-factor authentication is detected
    pub mfa_detected: bool,
    /// Password policy info if detected
    pub password_policy: Option<PasswordPolicy>,
    /// Session management details
    pub session_management: Option<SessionManagement>,
    /// OAuth/OpenID Connect info if applicable
    pub oauth_info: Option<OAuthInfo>,
}

/// Password policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: Option<u8>,
    pub requires_uppercase: bool,
    pub requires_lowercase: bool,
    pub requires_numbers: bool,
    pub requires_symbols: bool,
    pub max_age_days: Option<u32>,
    pub history_count: Option<u32>,
}

/// Session management details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionManagement {
    pub cookie_name: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub max_age: Option<u32>,
}

/// OAuth/OpenID Connect information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthInfo {
    pub provider: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes: Vec<String>,
    pub response_types: Vec<String>,
}

/// Resource (file, asset, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Unique resource ID
    pub id: ResourceId,
    /// Resource URL
    pub url: String,
    /// Resource type
    pub resource_type: ResourceType,
    /// MIME type
    pub mime_type: Option<String>,
    /// Size in bytes
    pub size_bytes: Option<u64>,
    /// Hash (SHA256)
    pub hash_sha256: Option<String>,
    /// Whether it's a sensitive resource
    pub sensitive: bool,
    /// Associated findings
    pub findings: Vec<FindingRef>,
    /// Parent URL
    pub url_id: UrlId,
}

/// Resource types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    JavaScript,
    Css,
    Image,
    Font,
    Document,
    Archive,
    Executable,
    Config,
    SourceCode,
    Backup,
    Log,
    Database,
    Certificate,
    Key,
    Other,
}

/// Reference to a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRef {
    pub finding_id: FindingId,
    pub severity: crate::result::Severity,
    pub category: crate::result::Category,
}

/// Relationships between entities in the application map
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMapRelationship {
    /// Unique relationship ID
    pub id: RelationshipId,
    /// Relationship type
    pub relationship_type: AppMapRelationshipType,
    /// Source entity ID
    pub source_id: String,
    /// Target entity ID
    pub target_id: String,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Description
    pub description: String,
}

/// Types of relationships in the application map
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppMapRelationshipType {
    /// Parent URL contains child URL
    Contains,
    /// Parameter belongs to endpoint
    ParameterOf,
    /// Form exists at URL
    FormAt,
    /// Auth endpoint protects endpoint
    AuthProtects,
    /// Technology detected at URL
    TechnologyDetected,
    /// Finding associated with endpoint
    FindingAt,
    /// URL redirects to another URL
    Redirects,
    /// Endpoint consumes/produces resource
    ResourceAt,
    /// Form submits to endpoint
    FormSubmitsTo,
    /// Parameter used in form
    ParameterInForm,
}

/// Application map metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppMapMetadata {
    /// Total URLs discovered
    pub total_urls: usize,
    /// Total endpoints discovered
    pub total_endpoints: usize,
    /// Total parameters discovered
    pub total_parameters: usize,
    /// Total forms discovered
    pub total_forms: usize,
    /// Total technologies detected
    pub total_technologies: usize,
    /// Total auth endpoints
    pub total_auth_endpoints: usize,
    /// Total resources
    pub total_resources: usize,
    /// Coverage percentage (estimated)
    pub coverage_percentage: Option<f32>,
    /// Scan duration
    pub scan_duration_seconds: u64,
    /// Tools used
    pub tools_used: Vec<String>,
    /// Configuration used
    pub configuration: HashMap<String, serde_json::Value>,
}

impl ApplicationMap {
    /// Create a new empty application map
    pub fn new(target_info: TargetInfo) -> Self {
        Self {
            target: target_info,
            urls: Vec::new(),
            endpoints: Vec::new(),
            parameters: Vec::new(),
            forms: Vec::new(),
            technologies: Vec::new(),
            auth_endpoints: Vec::new(),
            resources: Vec::new(),
            relationships: Vec::new(),
            metadata: AppMapMetadata {
                total_urls: 0,
                total_endpoints: 0,
                total_parameters: 0,
                total_forms: 0,
                total_technologies: 0,
                total_auth_endpoints: 0,
                total_resources: 0,
                coverage_percentage: None,
                scan_duration_seconds: 0,
                tools_used: Vec::new(),
                configuration: HashMap::new(),
            },
        }
    }

    /// Add a URL node
    pub fn add_url(&mut self, url: UrlNode) {
        self.urls.push(url);
        self.metadata.total_urls = self.urls.len();
    }

    /// Add an endpoint
    pub fn add_endpoint(&mut self, endpoint: Endpoint) {
        self.endpoints.push(endpoint);
        self.metadata.total_endpoints = self.endpoints.len();
    }

    /// Add a parameter
    pub fn add_parameter(&mut self, parameter: Parameter) {
        self.parameters.push(parameter);
        self.metadata.total_parameters = self.parameters.len();
    }

    /// Add a form
    pub fn add_form(&mut self, form: Form) {
        self.forms.push(form);
        self.metadata.total_forms = self.forms.len();
    }

    /// Add a technology
    pub fn add_technology(&mut self, technology: Technology) {
        self.technologies.push(technology);
        self.metadata.total_technologies = self.technologies.len();
    }

    /// Add an auth endpoint
    pub fn add_auth_endpoint(&mut self, auth_endpoint: AuthEndpoint) {
        self.auth_endpoints.push(auth_endpoint);
        self.metadata.total_auth_endpoints = self.auth_endpoints.len();
    }

    /// Add a resource
    pub fn add_resource(&mut self, resource: Resource) {
        self.resources.push(resource);
        self.metadata.total_resources = self.resources.len();
    }

    /// Add a relationship
    pub fn add_relationship(&mut self, relationship: AppMapRelationship) {
        self.relationships.push(relationship);
    }

    /// Get URL by ID
    pub fn get_url(&self, id: &UrlId) -> Option<&UrlNode> {
        self.urls.iter().find(|u| &u.id == id)
    }

    /// Get endpoint by ID
    pub fn get_endpoint(&self, id: &EndpointId) -> Option<&Endpoint> {
        self.endpoints.iter().find(|e| &e.id == id)
    }

    /// Get all URLs at a specific depth
    pub fn get_urls_at_depth(&self, depth: usize) -> Vec<&UrlNode> {
        self.urls.iter().filter(|u| u.depth == depth).collect()
    }

    /// Get child URLs for a parent
    pub fn get_children(&self, parent_id: &UrlId) -> Vec<&UrlNode> {
        self.urls.iter().filter(|u| u.parent.as_ref() == Some(parent_id)).collect()
    }

    /// Get endpoints by sensitivity level
    pub fn get_endpoints_by_sensitivity(&self, level: SensitivityLevel) -> Vec<&Endpoint> {
        self.endpoints.iter().filter(|e| e.sensitivity == level).collect()
    }

    /// Get technologies by category
    pub fn get_technologies_by_category(&self, category: TechnologyCategory) -> Vec<&Technology> {
        self.technologies.iter().filter(|t| t.category == category).collect()
    }

    /// Export to DOT format for graph visualization
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph ApplicationMap {\n");
        dot.push_str("  rankdir=TB;\n");
        dot.push_str("  node [shape=box];\n");

        // Add URL nodes
        for url in &self.urls {
            let label = url.url.replace('"', "\\\"");
            let color = match url.status_code {
                Some(200) => "green",
                Some(300..=399) => "yellow",
                Some(400..=499) => "orange",
                Some(500..=599) => "red",
                _ => "gray",
            };
            dot.push_str(&format!(
                "  \"url_{}\" [label=\"{}\", color={}];\n",
                url.id.0, label, color
            ));
        }

        // Add containment relationships
        for rel in &self.relationships {
            if matches!(rel.relationship_type, AppMapRelationshipType::Contains) {
                dot.push_str(&format!(
                    "  \"url_{}\" -> \"url_{}\" [label=\"Contains\"];\n",
                    rel.source_id, rel.target_id
                ));
            }
        }

        dot.push_str("}\n");
        dot
    }

    /// Export to Mermaid format
    pub fn to_mermaid(&self) -> String {
        let mut mermaid = String::new();
        mermaid.push_str("graph TD\n");

        // Add URL nodes
        for url in &self.urls {
            let label = url.url.replace('"', "#quot;");
            mermaid.push_str(&format!("  url_{}[\"{}\"]\n", url.id.0, label));
        }

        // Add containment relationships
        for rel in &self.relationships {
            if matches!(rel.relationship_type, AppMapRelationshipType::Contains) {
                mermaid.push_str(&format!("  url_{} --> url_{}\n", rel.source_id, rel.target_id));
            }
        }

        mermaid
    }
}

/// Output formats for application map
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppMapOutputFormat {
    Json,
    Yaml,
    Dot,
    Mermaid,
    Html,
}

impl std::str::FromStr for AppMapOutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(AppMapOutputFormat::Json),
            "yaml" => Ok(AppMapOutputFormat::Yaml),
            "dot" => Ok(AppMapOutputFormat::Dot),
            "mermaid" => Ok(AppMapOutputFormat::Mermaid),
            "html" => Ok(AppMapOutputFormat::Html),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ScanId, TargetId};

    #[test]
    fn test_application_map_creation() {
        let target_info = TargetInfo {
            id: TargetId::new(),
            base_url: "https://example.com".to_string(),
            target_type: "web".to_string(),
            scan_id: ScanId::new(),
            created_at: Utc::now(),
            tags: vec!["test".to_string()],
        };

        let app_map = ApplicationMap::new(target_info);
        assert_eq!(app_map.urls.len(), 0);
        assert_eq!(app_map.metadata.total_urls, 0);
    }

    #[test]
    fn test_add_url() {
        let target_info = TargetInfo {
            id: TargetId::new(),
            base_url: "https://example.com".to_string(),
            target_type: "web".to_string(),
            scan_id: ScanId::new(),
            created_at: Utc::now(),
            tags: vec![],
        };

        let mut app_map = ApplicationMap::new(target_info);

        let url_node = UrlNode {
            id: UrlId::new(),
            url: "https://example.com/api/users".to_string(),
            method: HttpMethod::Get,
            discovered_via: DiscoverySource::Crawling,
            status_code: Some(200),
            response_headers: HashMap::new(),
            technologies: Vec::new(),
            parameters: Vec::new(),
            forms: Vec::new(),
            auth_info: None,
            children: Vec::new(),
            parent: None,
            depth: 1,
            crawled: true,
            discovered_at: Utc::now(),
        };

        app_map.add_url(url_node);
        assert_eq!(app_map.urls.len(), 1);
        assert_eq!(app_map.metadata.total_urls, 1);
    }

    #[test]
    fn test_to_dot() {
        let target_info = TargetInfo {
            id: TargetId::new(),
            base_url: "https://example.com".to_string(),
            target_type: "web".to_string(),
            scan_id: ScanId::new(),
            created_at: Utc::now(),
            tags: vec![],
        };

        let mut app_map = ApplicationMap::new(target_info);

        let url1 = UrlNode {
            id: UrlId::new(),
            url: "https://example.com".to_string(),
            method: HttpMethod::Get,
            discovered_via: DiscoverySource::Manual,
            status_code: Some(200),
            response_headers: HashMap::new(),
            technologies: Vec::new(),
            parameters: Vec::new(),
            forms: Vec::new(),
            auth_info: None,
            children: vec![],
            parent: None,
            depth: 0,
            crawled: true,
            discovered_at: Utc::now(),
        };

        let url2 = UrlNode {
            id: UrlId::new(),
            url: "https://example.com/api".to_string(),
            method: HttpMethod::Get,
            discovered_via: DiscoverySource::Crawling,
            status_code: Some(200),
            response_headers: HashMap::new(),
            technologies: Vec::new(),
            parameters: Vec::new(),
            forms: Vec::new(),
            auth_info: None,
            children: vec![],
            parent: Some(url1.id),
            depth: 1,
            crawled: true,
            discovered_at: Utc::now(),
        };

        app_map.add_url(url1.clone());
        app_map.add_url(url2.clone());
        app_map.add_relationship(AppMapRelationship {
            id: RelationshipId::new(),
            relationship_type: AppMapRelationshipType::Contains,
            source_id: url1.id.0.to_string(),
            target_id: url2.id.0.to_string(),
            confidence: 1.0,
            description: "Root contains API".to_string(),
        });

        let dot = app_map.to_dot();
        assert!(dot.contains("digraph ApplicationMap"));
        assert!(dot.contains("url_"));
        assert!(dot.contains("Contains"));
    }
}
