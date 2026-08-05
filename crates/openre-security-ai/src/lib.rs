//! AI Security Analyst - analysis layer over deterministic scanner findings
//!
//! This crate provides an AI-powered analysis service that interprets, correlates,
//! explains, prioritizes, and assists with security scan findings. It never invents
//! findings — it only augments the deterministic results from the scanner engine.

pub mod errors;
pub mod types;
pub mod finding_provider;
pub mod scan_storage_provider;
pub mod context;
pub mod prompts;
pub mod cache;
pub mod safety;
pub mod analyst;

pub use errors::{AiAnalystError, AiResult};
pub use types::*;
pub use finding_provider::{FindingProvider, ScanMetadata};
pub use scan_storage_provider::ScanStorageFindingProvider;
pub use analyst::SecurityAnalyst;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{
        SecurityAnalyst,
        FindingProvider,
        ScanMetadata,
        AiResult,
        AiAnalystError,
        FindingExplanation,
        RemediationPlan,
        CorrelationReport,
        PrioritizedFindings,
        ExecutiveSummary,
        QueryResponse,
        ScanComparison,
    };
}

#[cfg(test)]
pub mod test_utils {
    pub use crate::finding_provider::ScanMetadata;
}