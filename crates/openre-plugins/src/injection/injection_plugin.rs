//! Injection Plugin Base
//!
//! Base implementation for injection vulnerability plugins using the shared framework.

use crate::injection::{
    ConfidenceScorer, InjectionCategory, InjectionPluginConfig, InjectionTestResult,
    ParameterLocation, PayloadContext, PayloadEngine, RequestEngine, ResponseAnalyzer,
    SafetyConfig, SafetyController, create_confidence_scorer, create_payload_engine,
    create_request_engine, create_response_analyzer, ConfidenceConfig, ConfidenceScorer,
    SafetyConfig, SafetyController,
};
use crate::sdk::{Plugin, AnalysisContext, Result, Capability};
use openre_core::ids::PluginId;
use openre_core::result::{Finding, Severity, Confidence, Category, Evidence, EvidenceType, Reference, ReferenceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, info, warn};

/// Base injection plugin that uses the shared framework
pub struct BaseInjectionPlugin {
    config: InjectionPluginConfig,
    safety: SafetyController,
    payload_engine: Box<dyn PayloadEngine>,
    request_engine: RequestEngine,
    response_analyzer: Box<dyn ResponseAnalyzer>,
    confidence_scorer: ConfidenceScorer,
    http_client: Arc<reqwest::Client>,
}

impl BaseInjectionPlugin {
    /// Create a new base injection plugin
    pub fn new(
        config: InjectionPluginConfig,
        category: InjectionCategory,
    ) -> Result<Self, String> {
        // Validate config
        if config.request_timeout == 0 {
            return Err("request_timeout must be greater than 0".to_string());
        }
        if config.max_concurrent_requests == 0 {
            return Err("max_concurrent_requests must be greater than 0".to_string());
        }
        
        let safety = SafetyController::new(config.safety.clone());
        let payload_engine = create_payload_engine(config.safety.clone());
        let request_engine = create_request_engine(config.safety.clone(), payload_engine.clone());
        let response_analyzer = create_response_analyzer(category);
        let confidence_scorer = create_confidence_scorer(ConfidenceConfig::default());
        
        let http_client = Arc::new(
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(config.request_timeout))
                .redirect(reqwest::redirect::Policy::limited(config.max_redirects as usize))
                .user_agent(&config.user_agent)
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?
        );
        
        Ok(Self {
            config,
            safety,
            payload_engine,
            request_engine,
            response_analyzer,
            confidence_scorer,
            http_client,
        })
    }
    
    /// Initialize safety controller
    pub async fn initialize_safety(&self, allowed_scopes: Vec<String>, auth_token: Option<String>) -> Result<(), String> {
        self.safety.initialize(allowed_scopes, auth_token).await
            .map_err(|e| format!("Safety initialization failed: {}", e))
    }
    
    /// Execute injection tests for a target
    pub async fn execute_injection_tests(
        &self,
        target_url: &str,
        parameters: Vec<ParameterTestConfig>,
        context: &PayloadContext,
    ) -> Vec<InjectionTestResult> {
        // Check scope
        if let Err(e) = self.safety.check_scope(target_url) {
            warn!("Scope check failed for {}: {}", target_url, e);
            return vec![];
        }
        
        // Create base request
        let base_request = TestRequest {
            method: reqwest::Method::GET,
            url: target_url.to_string(),
            headers: HashMap::new(),
            body: None,
        };
        
        // Test each parameter
        let mut all_results = Vec::new();
        for param_config in parameters {
            // Check scope for each request
            if let Err(e) = self.safety.check_scope(target_url) {
                warn!("Scope check failed: {}", e);
                continue;
            }
            
            // Check payload safety
            // (Payloads are checked in payload engine)
            
            let results = self.request_engine.test_parameter(
                &base_request,
                &param_config.name,
                param_config.location,
                self.injection_category(),
                context,
            ).await;
            
            all_results.extend(results);
            
            // Reset per-test counters
            self.safety.reset_test_counters().await;
        }
        
        // Analyze results
        let mut analyzed_results = Vec::new();
        for result in all_results {
            let analyzed = self.response_analyzer.analyze(&result, result.baseline_response.as_ref());
            analyzed_results.extend(analyzed);
        }
        
        // Score confidence
        for result in &mut analyzed_results {
            result.confidence = self.confidence_scorer.score(result);
        }
        
        analyzed_results
    }
    
    /// Convert injection test results to findings
    pub fn results_to_findings(
        &self,
        results: Vec<InjectionTestResult>,
        scan_id: openre_core::ids::ScanId,
        target_url: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        for result in results {
            let mut finding = Finding::new(
                format!("{:?} in parameter '{}'", result.category, result.parameter),
                format!(
                    "Detected {:?} in parameter '{}' at location {:?} using {:?} detection.\n\nPayload: {}\n\nConfidence: {:.0}%\n\nVerification steps:\n{}",
                    result.category,
                    result.parameter,
                    result.location,
                    result.detection_method,
                    result.payload,
                    result.confidence * 100.0,
                    result.verification_steps.join("\n")
                ),
                match result.severity {
                    crate::injection::Severity::Critical => Severity::Critical,
                    crate::injection::Severity::High => Severity::High,
                    crate::injection::Severity::Medium => Severity::Medium,
                    crate::injection::Severity::Low => Severity::Low,
                    crate::injection::Severity::Info => Severity::Info,
                },
                match result.confidence {
                    c if c >= 0.9 => Confidence::VeryHigh,
                    c if c >= 0.75 => Confidence::High,
                    c if c >= 0.6 => Confidence::Medium,
                    c if c >= 0.4 => Confidence::Low,
                    _ => Confidence::VeryLow,
                },
                match result.category {
                    InjectionCategory::SqlInjection => Category::Injection,
                    InjectionCategory::NoSqlInjection => Category::Injection,
                    InjectionCategory::Xss => Category::Xss,
                    InjectionCategory::Ssti => Category::Injection,
                    InjectionCategory::CommandInjection => Category::Injection,
                    InjectionCategory::Xxe => Category::Injection,
                    InjectionCategory::LdapInjection => Category::Injection,
                    InjectionCategory::XPathInjection => Category::Injection,
                    InjectionCategory::HeaderInjection => Category::Injection,
                    InjectionCategory::Custom => Category::Custom("injection".to_string()),
                },
                target_url.to_string(),
                "web_application".to_string(),
                self.plugin_source().to_string(),
                self.version().to_string(),
                scan_id,
            );
            
            // Add evidence
            finding = finding.with_evidence(Evidence {
                evidence_type: EvidenceType::HttpResponse,
                description: format!("Injection test response for parameter '{}'", result.parameter),
                data: Some(serde_json::json!({
                    "parameter": result.parameter,
                    "location": format!("{:?}", result.location),
                    "payload": result.payload,
                    "detection_method": format!("{:?}", result.detection_method),
                    "confidence": result.confidence,
                    "evidence": result.evidence,
                })),
                location: Some(target_url.to_string()),
                metadata: HashMap::new(),
            });
            
            // Add references
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
            
            // Add tags
            for tag in &result.tags {
                finding = finding.with_tag(tag.clone());
            }
            finding = finding.with_tag(format!("{:?}", result.category).to_lowercase());
            finding = finding.with_tag(format!("{:?}", result.detection_method).to_lowercase());
            
            findings.push(finding);
        }
        
        findings
    }
    
    /// Get plugin source name
    fn plugin_source(&self) -> &str {
        "injection_framework"
    }
}

/// Parameter test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterTestConfig {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
}

/// Test request for injection testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRequest {
    pub method: reqwest::Method,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// HTTP response for testing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub body_length: usize,
    pub url: String,
}

/// Re-export for convenience
pub use crate::injection::{
    InjectionCategory, InjectionPluginConfig, InjectionTestResult, ParameterLocation,
    PayloadContext, PayloadEngine, RequestEngine, ResponseAnalyzer, SafetyConfig,
    SafetyController, DetectionMethod, Severity, InjectionEvidence,
    HttpResponseSnapshot, HttpRequestSnapshot, ResponseDiff, TimingInfo,
    ReproducibleRequest, Payload, Encoding,
};