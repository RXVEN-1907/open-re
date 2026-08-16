//! AI Security Analyst - analysis layer over deterministic scanner findings
//!
//! This crate provides an AI-powered analysis service that interprets, correlates,
//! explains, prioritizes, and assists with security scan findings. It never invents
//! findings — it only augments the deterministic results from the scanner engine.

pub mod analyst;
pub mod cache;
pub mod context;
pub mod errors;
pub mod finding_provider;
pub mod prompts;
pub mod safety;
pub mod scan_storage_provider;
pub mod types;

pub use analyst::SecurityAnalyst;
pub use errors::{AiAnalystError, AiResult};
pub use finding_provider::{FindingProvider, ScanMetadata};
pub use scan_storage_provider::ScanStorageFindingProvider;
pub use types::*;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{
        AiAnalystError, AiResult, CorrelationReport, ExecutiveSummary, FindingExplanation,
        FindingProvider, PrioritizedFindings, QueryResponse, RemediationPlan, ScanComparison,
        ScanMetadata, SecurityAnalyst,
    };
}

#[cfg(test)]
pub mod test_utils {
    pub use crate::finding_provider::ScanMetadata;
}
