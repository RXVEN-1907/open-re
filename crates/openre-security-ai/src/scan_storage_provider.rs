//! FindingProvider implementation using ScanStorage

use crate::{AiAnalystError, AiResult, FindingProvider, ScanMetadata};
use async_trait::async_trait;
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Finding, FindingFilter};
use openre_scanner::storage::ScanStorage;
use std::sync::Arc;

/// FindingProvider implementation that uses ScanStorage
pub struct ScanStorageFindingProvider {
    scan_storage: Arc<dyn ScanStorage>,
}

impl ScanStorageFindingProvider {
    /// Create a new ScanStorageFindingProvider
    pub fn new(scan_storage: Arc<dyn ScanStorage>) -> Self {
        Self { scan_storage }
    }
}

#[async_trait]
impl FindingProvider for ScanStorageFindingProvider {
    async fn get_finding(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<Option<Finding>> {
        // Get the finding from storage
        match self.scan_storage.get_finding(&finding_id).await {
            Ok(Some(finding)) => {
                // Verify that the finding belongs to the specified scan
                if finding.scan_id == scan_id {
                    Ok(Some(finding))
                } else {
                    // Finding exists but doesn't belong to this scan
                    Ok(None)
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AiAnalystError::Internal(format!("Failed to get finding: {}", e))),
        }
    }

    async fn list_findings(
        &self,
        scan_id: ScanId,
        filter: Option<&FindingFilter>,
    ) -> AiResult<Vec<Finding>> {
        // Get all findings for the scan
        match self.scan_storage.get_findings(&scan_id).await {
            Ok(findings) => {
                if let Some(filter) = filter {
                    // Apply filtering if specified
                    let filtered: Vec<Finding> = findings
                        .into_iter()
                        .filter(|finding| {
                            // Filter by severity if specified
                            if let Some(severities) = &filter.severity {
                                severities.contains(&finding.severity)
                            } else {
                                true
                            }
                        })
                        .filter(|finding| {
                            // Filter by category if specified
                            if let Some(categories) = &filter.category {
                                categories.contains(&finding.category)
                            } else {
                                true
                            }
                        })
                        .collect();
                    Ok(filtered)
                } else {
                    Ok(findings)
                }
            }
            Err(e) => Err(AiAnalystError::Internal(format!("Failed to list findings: {}", e))),
        }
    }

    async fn get_scan_metadata(&self, scan_id: ScanId) -> AiResult<ScanMetadata> {
        // Get the scan session from storage
        match self.scan_storage.get_scan(&scan_id).await {
            Ok(Some(session)) => {
                // Count findings for this scan
                let finding_count = match self.scan_storage.get_findings(&scan_id).await {
                    Ok(findings) => findings.len(),
                    Err(e) => {
                        return Err(AiAnalystError::Internal(format!(
                            "Failed to count findings: {}",
                            e
                        )))
                    }
                };

                Ok(ScanMetadata {
                    scan_id,
                    target: session.target.metadata.base_url.to_string(),
                    started_at: session.started_at.unwrap_or(session.created_at),
                    completed_at: session.completed_at,
                    finding_count,
                    status: format!("{:?}", session.status), // Convert enum to string
                })
            }
            Ok(None) => Err(AiAnalystError::ScanNotFound(scan_id)),
            Err(e) => Err(AiAnalystError::Internal(format!("Failed to get scan metadata: {}", e))),
        }
    }
}
