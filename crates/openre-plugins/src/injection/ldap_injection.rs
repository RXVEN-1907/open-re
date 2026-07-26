//! LDAP Injection Plugin
//!
//! Detects LDAP injection vulnerabilities using safe validation techniques.

use crate::injection::{
    ConfidenceScorer, ConfidenceConfig, InjectionCategory, InjectionPluginConfig,
    InjectionTestResult, ParameterLocation, PayloadContext, PayloadEngine, RequestEngine,
    ResponseAnalyzer, SafetyConfig, SafetyController, create_confidence_scorer,
    create_payload_engine, create_request_engine, create_response_analyzer,
    ConfidenceScorer, SafetyConfig, SafetyController,
};
use crate::sdk::{Plugin, AnalysisContext, Result, Capability};
use openre_core::ids::PluginId;
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};

/// LDAP Injection Plugin
pub struct LdapInjectionPlugin {
    base: crate::injection::injection_plugin::BaseInjectionPlugin,
}

impl LdapInjectionPlugin {
    /// Create a new LDAP injection plugin
    pub fn new(config: InjectionPluginConfig) -> Result<Self, String> {
        let base = crate::injection::injection_plugin::BaseInjectionPlugin::new(
            config,
            InjectionCategory::LdapInjection,
        )?;
        
        Ok(Self { base })
    }
    
    /// Get the injection category
    fn injection_category(&self) -> InjectionCategory {
        InjectionCategory::LdapInjection
    }
    
    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    /// Get plugin description
    fn description(&self) -> &'static str {
        "Detects LDAP injection vulnerabilities using safe validation techniques"
    }
    
    /// Get plugin references
    fn references(&self) -> Vec<crate::injection::SecurityReference> {
        vec![
            crate::injection::SecurityReference {
                ref_type: "OWASP".to_string(),
                id: "A03:2021".to_string(),
                url: "https://owasp.org/Top10/A03_2021-Injection/".to_string(),
                description: "OWASP Top 10 2021 - Injection".to_string(),
            },
            crate::injection::SecurityReference {
                ref_type: "CWE".to_string(),
                id: "CWE-90".to_string(),
                url: "https://cwe.mitre.org/data/definitions/90.html".to_string(),
                description: "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')".to_string(),
            },
        ]
    }
    
    /// Validate configuration
    fn validate_config(&self, config: &InjectionPluginConfig) -> Result<(), String> {
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        Ok(())
    }
}

#[async_trait]
impl Plugin for LdapInjectionPlugin {
    type Config = InjectionPluginConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create LDAP injection plugin")
    }
    
    fn capabilities(&self) -> Vec<Capability> {
        vec![
            Capability::NetworkAccess,
            Capability::ReadConfig,
        ]
    }
    
    async fn execute(&self, request: CapabilityRequest) -> Result<CapabilityResponse> {
        let context = request.context;
        let target_url = request.input.get("target_url")
            .and_then(|v| v.as_str())
            .unwrap_or("http://localhost");
        
        info!("Starting LDAP injection testing for {}", target_url);
        
        // Extract parameters to test from input
        let parameters = request.input.get("parameters")
            .and_then(|v| serde_json::from_value::<Vec<crate::injection::injection_plugin::ParameterTestConfig>>(v.clone()).ok())
            .unwrap_or_else(|| vec![
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "username".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "user".to_string(),
                    location: ParameterLocation::Body,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "filter".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "dn".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
            ]);
        
        // Create payload context
        let payload_context = PayloadContext {
            parameter_name: "".to_string(),
            location: ParameterLocation::Query,
            expected_type: None,
            technology_hints: vec!["ldap".to_string()],
            database_type: None,
            template_engine: None,
            os_type: None,
            is_id_parameter: false,
            is_auth_context: true,
            custom: HashMap::new(),
        };
        
        // Execute injection tests
        let results = self.base.execute_injection_tests(target_url, parameters, &payload_context).await;
        
        // Convert to findings
        let scan_id = context.job_id.into();
        let findings = self.base.results_to_findings(results, scan_id, target_url);
        
        Ok(CapabilityResponse::success(serde_json::json!({
            "findings": findings,
            "tests_performed": results.len(),
            "vulnerabilities_found": findings.len(),
        })))
    }
}

impl crate::injection::InjectionPlugin for LdapInjectionPlugin {
    fn injection_category(&self) -> InjectionCategory {
        InjectionCategory::LdapInjection
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    fn description(&self) -> &'static str {
        "Detects LDAP injection vulnerabilities using safe validation techniques"
    }
    
    fn references(&self) -> Vec<crate::injection::SecurityReference> {
        self.references()
    }
    
    fn validate_config(&self, config: &InjectionPluginConfig) -> Result<(), String> {
        self.validate_config(config)
    }
    
    fn payload_engine(&self) -> Box<dyn PayloadEngine> {
        create_payload_engine(self.base.config.safety.clone())
    }
    
    fn response_analyzer(&self) -> Box<dyn ResponseAnalyzer> {
        create_response_analyzer(InjectionCategory::LdapInjection)
    }
}

// Plugin entry point
crate::plugin_entry!(LdapInjectionPlugin);