//! Mock FindingProvider for testing

use openre_security_ai::{FindingProvider, ScanMetadata, AiResult};
use openre_core::result::{Finding, FindingFilter};
use openre_core::ids::{ScanId, FindingId};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock finding provider for testing
pub struct MockFindingProvider {
    findings: Arc<RwLock<HashMap<(ScanId, FindingId), Finding>>>,
    scans: Arc<RwLock<HashMap<ScanId, ScanMetadata>>>,
}

impl MockFindingProvider {
    /// Create a new mock provider
    pub fn new() -> Self {
        Self {
            findings: Arc::new(RwLock::new(HashMap::new())),
            scans: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a finding to the mock provider
    pub async fn add_finding(&self, scan_id: ScanId, finding: Finding) {
        self.findings.write().await.insert((scan_id, finding.id), finding);
    }

    /// Add scan metadata to the mock provider
    pub async fn add_scan_metadata(&self, metadata: ScanMetadata) {
        self.scans.write().await.insert(metadata.scan_id, metadata);
    }
}

#[async_trait]
impl FindingProvider for MockFindingProvider {
    async fn get_finding(&self, scan_id: ScanId, finding_id: FindingId) -> AiResult<Option<Finding>> {
        Ok(self.findings.read().await.get(&(scan_id, finding_id)).cloned())
    }

    async fn list_findings(&self, scan_id: ScanId, filter: Option<&FindingFilter>) -> AiResult<Vec<Finding>> {
        let findings: Vec<Finding> = self.findings.read().await
            .iter()
            .filter(|((s_id, _), _)| *s_id == scan_id)
            .map(|(_, finding)| finding.clone())
            .collect();

        if let Some(filter) = filter {
            Ok(findings.into_iter().filter(|f| matches_filter(f, filter)).collect())
        } else {
            Ok(findings)
        }
    }

    async fn get_scan_metadata(&self, scan_id: ScanId) -> AiResult<ScanMetadata> {
        self.scans.read().await.get(&scan_id)
            .cloned()
            .ok_or(openre_security_ai::AiAnalystError::ScanNotFound(scan_id))
    }
}

/// Simple filter matching for mock provider
fn matches_filter(finding: &Finding, filter: &FindingFilter) -> bool {
    // This is a simplified implementation - in reality, this would match the logic in result.rs
    if let Some(severities) = &filter.severity {
        if !severities.contains(&finding.severity) {
            return false;
        }
    }

    if let Some(categories) = &filter.category {
        if !categories.contains(&finding.category) {
            return false;
        }
    }

    true
}