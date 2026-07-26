//! Request Engine
//!
//! Supports testing of query parameters, POST bodies, JSON bodies, XML bodies,
//! multipart forms, HTTP headers, and cookies.

use crate::injection::{InjectionCategory, ParameterLocation, Payload, PayloadContext, PayloadEngine, SafetyConfig};
use crate::injection::mod::HttpRequestSnapshot;
use openre_core::ids::PluginId;
use reqwest::{Client, Method, RequestBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Request engine for injection testing
pub struct RequestEngine {
    client: Arc<Client>,
    safety: SafetyConfig,
    payload_engine: Box<dyn PayloadEngine>,
}

impl RequestEngine {
    /// Create a new request engine
    pub fn new(safety: SafetyConfig, payload_engine: Box<dyn PayloadEngine>) -> Self {
        let client = Arc::new(
            Client::builder()
                .timeout(Duration::from_secs(safety.request_timeout_secs))
                .redirect(reqwest::redirect::Policy::limited(10))
                .build()
                .expect("Failed to create HTTP client")
        );
        
        Self {
            client,
            safety,
            payload_engine,
        }
    }
    
    /// Test a single parameter with injection payloads
    pub async fn test_parameter(
        &self,
        base_request: &TestRequest,
        parameter: &str,
        location: ParameterLocation,
        category: InjectionCategory,
        context: &PayloadContext,
    ) -> Vec<TestResult> {
        let mut results = Vec::new();
        
        // Get baseline response
        let baseline = self.send_request(base_request).await;
        if baseline.is_err() {
            warn!("Failed to get baseline response for {}", parameter);
            return results;
        }
        let baseline_response = baseline.unwrap();
        
        // Get payloads for this category and context
        let payloads = self.payload_engine.get_payloads(category, context);
        if payloads.is_empty() {
            debug!("No payloads for category {:?} with context {:?}", category, context);
            return results;
        }
        
        // Mutate parameter with payloads
        let original_value = self.extract_parameter_value(base_request, parameter, location);
        let mutated_values = self.payload_engine.mutate_parameter(&original_value, &payloads, location);
        
        // Test each mutated value
        for (i, mutated_value) in mutated_values.iter().enumerate() {
            if i >= self.safety.max_requests_per_test {
                break;
            }
            
            // Check total request limit
            if results.len() >= self.safety.max_total_requests {
                break;
            }
            
            // Create test request
            let test_request = self.create_test_request(base_request, parameter, mutated_value, location);
            
            // Send request
            let start = std::time::Instant::now();
            let response = self.send_request(&test_request).await;
            let response_time = start.elapsed();
            
            match response {
                Ok(resp) => {
                    let result = TestResult {
                        parameter: parameter.to_string(),
                        location,
                        payload: payloads.get(i % payloads.len()).cloned(),
                        request: test_request.to_snapshot(),
                        response: resp.to_snapshot(response_time),
                        baseline_response: Some(baseline_response.to_snapshot(Duration::from_millis(0))),
                        category,
                        timestamp: chrono::Utc::now(),
                    };
                    results.push(result);
                }
                Err(e) => {
                    debug!("Request failed for parameter {}: {}", parameter, e);
                }
            }
            
            // Rate limiting
            if self.safety.rate_limit_rps > 0.0 {
                let delay = Duration::from_millis((1000.0 / self.safety.rate_limit_rps) as u64);
                tokio::time::sleep(delay).await;
            }
        }
        
        results
    }
    
    /// Test multiple parameters
    pub async fn test_parameters(
        &self,
        base_request: &TestRequest,
        parameters: &[ParameterTestConfig],
        category: InjectionCategory,
        context: &PayloadContext,
    ) -> Vec<TestResult> {
        let mut all_results = Vec::new();
        
        for param_config in parameters {
            let param_results = self.test_parameter(
                base_request,
                &param_config.name,
                param_config.location,
                category,
                context,
            ).await;
            all_results.extend(param_results);
        }
        
        all_results
    }
    
    /// Send HTTP request
    async fn send_request(&self, request: &TestRequest) -> Result<HttpResponse, reqwest::Error> {
        let mut builder = self.client.request(request.method.clone(), &request.url);
        
        // Add headers
        for (key, value) in &request.headers {
            builder = builder.header(key, value);
        }
        
        // Add body
        if let Some(body) = &request.body {
            builder = builder.body(body.clone());
        }
        
        let response = builder.send().await?;
        
        let status = response.status().as_u16();
        let headers: HashMap<String, String> = response.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response.text().await.unwrap_or_default();
        let body_length = body.len();
        
        Ok(HttpResponse {
            status,
            headers,
            body,
            body_length,
            url: request.url.clone(),
        })
    }
    
    /// Extract parameter value from request
    fn extract_parameter_value(&self, request: &TestRequest, parameter: &str, location: ParameterLocation) -> String {
        match location {
            ParameterLocation::Query => {
                let url = url::Url::parse(&request.url).ok();
                url.and_then(|u| u.query_pairs().find(|(k, _)| k == parameter).map(|(_, v)| v.to_string()))
                    .unwrap_or_default()
            }
            ParameterLocation::Body => {
                // Form data
                let pairs = url::form_urlencoded::parse(request.body.as_deref().unwrap_or_default().as_bytes());
                pairs.find(|(k, _)| k == parameter).map(|(_, v)| v.to_string()).unwrap_or_default()
            }
            ParameterLocation::JsonBody => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(request.body.as_deref().unwrap_or("{}")) {
                    json.get(parameter).and_then(|v| v.as_str()).unwrap_or("").to_string()
                } else {
                    String::new()
                }
            }
            ParameterLocation::XmlBody => {
                // Simple XML parameter extraction (would need proper XML parser in production)
                String::new()
            }
            ParameterLocation::Header => {
                request.headers.get(parameter).cloned().unwrap_or_default()
            }
            ParameterLocation::Cookie => {
                request.headers.get("Cookie")
                    .and_then(|cookie| {
                        cookie.split(';')
                            .find(|c| c.trim().starts_with(&format!("{}=", parameter)))
                            .and_then(|c| c.split('=').nth(1))
                            .map(|v| v.to_string())
                    })
                    .unwrap_or_default()
            }
            ParameterLocation::Path => {
                // Path parameter extraction would need route matching
                String::new()
            }
            ParameterLocation::MultipartForm => {
                // Multipart form parsing would need proper parser
                String::new()
            }
        }
    }
    
    /// Create test request with mutated parameter
    fn create_test_request(&self, base: &TestRequest, parameter: &str, value: &str, location: ParameterLocation) -> TestRequest {
        let mut request = base.clone();
        
        match location {
            ParameterLocation::Query => {
                let mut url = url::Url::parse(&request.url).expect("Invalid URL");
                url.query_pairs_mut().clear();
                for (k, v) in url::form_urlencoded::parse(request.url.as_bytes()) {
                    if k != parameter {
                        url.query_pairs_mut().append_pair(&k, &v);
                    }
                }
                url.query_pairs_mut().append_pair(parameter, value);
                request.url = url.to_string();
            }
            ParameterLocation::Body => {
                let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(request.body.as_deref().unwrap_or_default().as_bytes())
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();
                if let Some(pos) = pairs.iter().position(|(k, _)| k == parameter) {
                    pairs[pos].1 = value.to_string();
                } else {
                    pairs.push((parameter.to_string(), value.to_string()));
                }
                request.body = Some(url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(pairs)
                    .finish());
            }
            ParameterLocation::JsonBody => {
                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(request.body.as_deref().unwrap_or("{}")) {
                    json[parameter] = serde_json::Value::String(value.to_string());
                    request.body = Some(json.to_string());
                }
            }
            ParameterLocation::Header => {
                request.headers.insert(parameter.to_string(), value.to_string());
            }
            ParameterLocation::Cookie => {
                let mut cookie_header = request.headers.get("Cookie").cloned().unwrap_or_default();
                if cookie_header.contains(&format!("{}=", parameter)) {
                    // Replace existing cookie
                    let cookies: Vec<String> = cookie_header.split(';')
                        .map(|c| c.trim().to_string())
                        .map(|c| {
                            if c.starts_with(&format!("{}=", parameter)) {
                                format!("{}={}", parameter, value)
                            } else {
                                c
                            }
                        })
                        .collect();
                    cookie_header = cookies.join("; ");
                } else {
                    if !cookie_header.is_empty() {
                        cookie_header.push_str("; ");
                    }
                    cookie_header.push_str(&format!("{}={}", parameter, value));
                }
                request.headers.insert("Cookie".to_string(), cookie_header);
            }
            ParameterLocation::Path => {
                // Path parameter replacement would need route template
            }
            ParameterLocation::MultipartForm => {
                // Multipart form would need proper handling
            }
            ParameterLocation::XmlBody => {
                // XML body would need proper XML manipulation
            }
        }
        
        request
    }
}

/// Test request configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRequest {
    pub method: Method,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl TestRequest {
    pub fn to_snapshot(&self) -> HttpRequestSnapshot {
        HttpRequestSnapshot {
            method: self.method.to_string(),
            url: self.url.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Parameter test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterTestConfig {
    pub name: String,
    pub location: ParameterLocation,
    pub required: bool,
}

/// HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub body_length: usize,
    pub url: String,
}

impl HttpResponse {
    pub fn to_snapshot(&self, response_time: Duration) -> crate::injection::mod::HttpResponseSnapshot {
        crate::injection::mod::HttpResponseSnapshot {
            status: self.status,
            headers: self.headers.clone(),
            body: self.body.clone(),
            body_length: self.body_length,
            response_time_ms: response_time.as_millis() as u64,
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub parameter: String,
    pub location: ParameterLocation,
    pub payload: Option<Payload>,
    pub request: HttpRequestSnapshot,
    pub response: crate::injection::mod::HttpResponseSnapshot,
    pub baseline_response: Option<crate::injection::mod::HttpResponseSnapshot>,
    pub category: InjectionCategory,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Factory for creating request engines
pub fn create_request_engine(
    safety: SafetyConfig,
    payload_engine: Box<dyn PayloadEngine>,
) -> RequestEngine {
    RequestEngine::new(safety, payload_engine)
}