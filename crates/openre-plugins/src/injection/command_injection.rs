//! Command Injection Plugin
//!
//! Detects command injection vulnerabilities using safe validation techniques.

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

/// Command Injection Plugin
pub struct CommandInjectionPlugin {
    base: crate::injection::injection_plugin::BaseInjectionPlugin,
}

impl CommandInjectionPlugin {
    /// Create a new Command Injection plugin
    pub fn new(config: InjectionPluginConfig) -> Result<Self, String> {
        let base = crate::injection::injection_plugin::BaseInjectionPlugin::new(
            config,
            InjectionCategory::CommandInjection,
        )?;
        
        Ok(Self { base })
    }
    
    /// Get the injection category
    fn injection_category(&self) -> InjectionCategory {
        InjectionCategory::CommandInjection
    }
    
    /// Get plugin version
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    /// Get plugin description
    fn description(&self) -> &'static str {
        "Detects command injection vulnerabilities using safe validation techniques"
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
                id: "CWE-78".to_string(),
                url: "https://cwe.mitre.org/data/definitions/78.html".to_string(),
                description: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')".to_string(),
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
impl Plugin for CommandInjectionPlugin {
    type Config = InjectionPluginConfig;
    
    fn new(config: Self::Config) -> Self {
        Self::new(config).expect("Failed to create Command Injection plugin")
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
        
        info!("Starting Command Injection testing for {}", target_url);
        
        // Extract parameters to test from input
        let parameters = request.input.get("parameters")
            .and_then(|v| serde_json::from_value::<Vec<crate::injection::injection_plugin::ParameterTestConfig>>(v.clone()).ok())
            .unwrap_or_else(|| vec![
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "cmd".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "exec".to_string(),
                    location: ParameterLocation::Body,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "command".to_string(),
                    location: ParameterLocation::Body,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "ip".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
                crate::injection::injection_plugin::ParameterTestConfig {
                    name: "host".to_string(),
                    location: ParameterLocation::Query,
                    required: false,
                },
            ]);
        
        // Create payload context
        let payload_context = PayloadContext {
            parameter_name: "".to_string(),
            location: ParameterLocation::Query,
            expected_type: None,
            technology_hints: vec![],
            database_type: None,
            template_engine: None,
            os_type: None,
            is_id_parameter: false,
            is_auth_context: false,
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

impl crate::injection::InjectionPlugin for CommandInjectionPlugin {
    fn injection_category(&self) -> InjectionCategory {
        InjectionCategory::CommandInjection
    }
    
    fn version(&self) -> &'static str {
        "1.0.0"
    }
    
    fn description(&self) -> &'static str {
        "Detects command injection vulnerabilities using safe validation techniques"
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
        create_response_analyzer(InjectionCategory::CommandInjection)
    }
}

// Plugin entry point
crate::plugin_entry!(CommandInjectionPlugin);