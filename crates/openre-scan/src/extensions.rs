//! Extension traits for openre-core types

use openre_core::result::{
    Evidence, EvidenceType, Finding, RemediationEffort, RemediationGuidance, RemediationPriority,
};
use serde_json::Value;
use std::collections::HashMap;

/// Extension trait for Finding
pub trait FindingExt {
    fn with_evidence(self, evidence: Evidence) -> Self;
    fn with_remediation(self, remediation: RemediationGuidance) -> Self;
}

impl FindingExt for Finding {
    fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    fn with_remediation(mut self, remediation: RemediationGuidance) -> Self {
        self.remediation = Some(remediation);
        self
    }
}

/// Extension trait for Evidence
pub trait EvidenceExt {
    fn new(evidence_type: EvidenceType, description: String) -> Self;
    fn with_data(self, data: Value) -> Self;
    fn with_location(self, location: String) -> Self;
}

impl EvidenceExt for Evidence {
    fn new(evidence_type: EvidenceType, description: String) -> Self {
        Self {
            evidence_type,
            description,
            data: None,
            location: None,
            metadata: HashMap::new(),
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: None,
            timestamp: chrono::Utc::now(),
        }
    }

    fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    fn with_location(mut self, location: String) -> Self {
        self.location = Some(location);
        self
    }
}

/// Extension trait for RemediationGuidance
pub trait RemediationGuidanceExt {
    fn new(
        summary: String,
        steps: Vec<String>,
        effort: RemediationEffort,
        priority: RemediationPriority,
    ) -> Self;
}

impl RemediationGuidanceExt for RemediationGuidance {
    fn new(
        summary: String,
        steps: Vec<String>,
        effort: RemediationEffort,
        priority: RemediationPriority,
    ) -> Self {
        Self { summary, steps, code_examples: Vec::new(), references: Vec::new(), effort, priority }
    }
}
