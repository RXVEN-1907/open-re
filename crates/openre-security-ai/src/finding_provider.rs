//! FindingProvider trait for resolving scan data

use crate::{AiResult, AiAnalystError};
use openre_core::result::{Finding, FindingFilter};
use openre_core::ids::{ScanId, FindingId};
use async_trait::async_trait;

/// Metadata about a scan
#[derive(Debug, Clone)]
pub struct ScanMetadata {
    /// Scan ID
    pub scan_id: ScanId,

    /// Target that was scanned
    pub target: String,

    /// Timestamp when scan started
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when scan completed
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Number of findings
    pub finding_count: usize,

    /// Scan status
    pub status: String,
}

/// Trait for resolving scan data - allows the analyst to be decoupled from storage
#[async_trait]
pub trait FindingProvider: Send + Sync {
    /// Get a specific finding by ID
    async fn get_finding(&self, scan_id: ScanId, finding_id: FindingId) -> AiResult<Option<Finding>>;

    /// List findings for a scan with optional filtering
    async fn list_findings(&self, scan_id: ScanId, filter: Option<&FindingFilter>) -> AiResult<Vec<Finding>>;

    /// Get metadata about a scan
    async fn get_scan_metadata(&self, scan_id: ScanId) -> AiResult<ScanMetadata>;
}