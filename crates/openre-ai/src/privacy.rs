//! Privacy controls for open-re AI

use crate::providers::*;
use openre_core::error::Result;
use openre_config::PrivacyConfig;
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Privacy controller for AI requests
pub struct PrivacyController {
    config: PrivacyConfig,
    redaction_patterns: Vec<Regex>,
    audit_log: Arc<RwLock<Vec<PrivacyAuditEntry>>>,
}

impl PrivacyController {
    pub fn new(config: PrivacyConfig) -> Result<Self> {
        let mut patterns = Vec::new();
        
        // Default redaction patterns
        patterns.push(Regex::new(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+")?);
        patterns.push(Regex::new(r"(?i)bearer\s+[a-zA-Z0-9\-_]+")?);
        patterns.push(Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")?); // Credit cards
        patterns.push(Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")?); // Emails
        patterns.push(Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")?); // IP addresses
        
        // Add custom patterns from config
        for pattern in &config.custom_redaction_patterns {
            if let Ok(re) = Regex::new(pattern) {
                patterns.push(re);
            }
        }

        Ok(Self {
            config,
            redaction_patterns: patterns,
            audit_log: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Sanitize request before sending to provider
    pub fn sanitize_request(&self, request: &mut CompletionRequest) -> Result<()> {
        // Redact sensitive data from messages
        for msg in &mut request.messages {
            if let Some(content) = &mut msg.content {
                *content = self.redact(content);
            }
        }

        // Redact from tool arguments
        if let Some(tools) = &mut request.tools {
            for tool in tools {
                tool.parameters = self.redact_json(&tool.parameters);
            }
        }

        Ok(())
    }

    /// Sanitize response from provider
    pub fn sanitize_response(&self, response: &mut CompletionResponse) -> Result<()> {
        for choice in &mut response.choices {
            if let Some(content) = &mut choice.message.content {
                *content = self.redact(content);
            }
        }
        Ok(())
    }

    /// Redact sensitive data from string
    fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in &self.redaction_patterns {
            result = pattern.replace_all(&result, "[REDACTED]").to_string();
        }
        result
    }

    /// Redact sensitive data from JSON
    fn redact_json(&self, value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::String(s) => serde_json::Value::String(self.redact(s)),
            serde_json::Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    // Skip known sensitive keys
                    if self.is_sensitive_key(k) {
                        new_map.insert(k.clone(), serde_json::Value::String("[REDACTED]".to_string()));
                    } else {
                        new_map.insert(k.clone(), self.redact_json(v));
                    }
                }
                serde_json::Value::Object(new_map)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| self.redact_json(v)).collect())
            }
            _ => value.clone(),
        }
    }

    fn is_sensitive_key(&self, key: &str) -> bool {
        let sensitive_keys = [
            "api_key", "apikey", "secret", "password", "token", "authorization",
            "auth", "credential", "private_key", "access_token", "refresh_token",
        ];
        sensitive_keys.iter().any(|k| key.to_lowercase().contains(k))
    }

    /// Check if request should be allowed based on privacy settings
    pub fn check_request_allowed(&self, request: &CompletionRequest) -> Result<PrivacyDecision> {
        // Check if local-only mode and request would go to remote
        if self.config.local_only {
            // This would be checked by the router, but we can validate here too
            return Ok(PrivacyDecision::Allowed);
        }

        // Check data classification
        let classification = self.classify_request(request);
        if classification == DataClassification::Restricted && !self.config.allow_restricted_data {
            return Ok(PrivacyDecision::Denied("Restricted data detected".to_string()));
        }

        Ok(PrivacyDecision::Allowed)
    }

    /// Classify request data sensitivity
    fn classify_request(&self, request: &CompletionRequest) -> DataClassification {
        let mut has_pii = false;
        let mut has_secrets = false;
        let mut has_code = false;

        for msg in &request.messages {
            if let Some(content) = &msg.content {
                let lower = content.to_lowercase();
                
                // Check for PII
                if self.contains_pii(content) {
                    has_pii = true;
                }
                
                // Check for secrets
                if self.contains_secrets(content) {
                    has_secrets = true;
                }

                // Check for code
                if self.contains_code(content) {
                    has_code = true;
                }
            }
        }

        if has_secrets {
            DataClassification::Restricted
        } else if has_pii {
            DataClassification::Confidential
        } else if has_code {
            DataClassification::Internal
        } else {
            DataClassification::Public
        }
    }

    fn contains_pii(&self, text: &str) -> bool {
        // Email
        if Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap().is_match(text) {
            return true;
        }
        // Phone
        if Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap().is_match(text) {
            return true;
        }
        // SSN
        if Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap().is_match(text) {
            return true;
        }
        false
    }

    fn contains_secrets(&self, text: &str) -> bool {
        let secret_patterns = [
            r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*\S+",
            r"(?i)bearer\s+[a-zA-Z0-9\-_]+",
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            r"ssh-rsa\s+[A-Za-z0-9+/]+",
        ];
        
        for pattern in &secret_patterns {
            if Regex::new(pattern).unwrap().is_match(text) {
                return true;
            }
        }
        false
    }

    fn contains_code(&self, text: &str) -> bool {
        // Simple heuristic: contains common code patterns
        let code_indicators = [
            "function", "class", "def ", "fn ", "public ", "private ",
            "import ", "include ", "#include", "using namespace",
            "{", "}", "();", "->", "=>", "::", "::",
        ];
        
        code_indicators.iter().any(|indicator| text.contains(indicator))
    }

    /// Log privacy audit entry
    pub async fn audit(&self, entry: PrivacyAuditEntry) {
        let mut log = self.audit_log.write().await;
        log.push(entry);
        
        // Keep only last 10000 entries
        if log.len() > 10000 {
            log.drain(0..log.len() - 10000);
        }
    }

    /// Get audit log
    pub async fn get_audit_log(&self, limit: usize) -> Vec<PrivacyAuditEntry> {
        let log = self.audit_log.read().await;
        log.iter().rev().take(limit).cloned().collect()
    }
}

/// Privacy decision
#[derive(Debug, Clone)]
pub enum PrivacyDecision {
    Allowed,
    Denied(String),
    Redacted(String),
}

/// Data classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Privacy audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action: PrivacyAction,
    pub provider: Option<String>,
    pub classification: DataClassification,
    pub details: String,
    pub user_id: Option<String>,
}

/// Privacy action types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyAction {
    RequestSanitized,
    ResponseSanitized,
    RequestAllowed,
    RequestDenied,
    DataRedacted,
    LocalOnlyEnforced,
    RemoteFallbackBlocked,
}