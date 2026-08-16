//! Intelligence layer for open-re security scanner
//!
//! This crate provides advanced intelligence capabilities including:
//! - Enhanced finding correlation and relationship analysis
//! - CVE matching against vulnerability databases
//! - Dependency analysis for outdated/vulnerable packages
//! - Security knowledge base with CWE/OWASP/CAPEC mapping
//! - Root cause analysis for underlying issues
//! - Scan diff intelligence for change tracking
//! - Developer workflow enhancements
//! - Performance optimizations with caching and incremental processing
//! - TUI enhancements for improved developer experience

pub mod correlation;
pub mod cve_intelligence;
pub mod dependency_analysis;
pub mod error;
pub mod knowledge_base;
pub mod performance;
pub mod root_cause;
pub mod scan_diff;
pub mod tui_enhancements;
pub mod types;
pub mod workflow;

#[cfg(test)]
mod comprehensive_test;

// Re-export main components
pub use correlation::CorrelationEngine;
pub use cve_intelligence::{CveIntelligence, CveProvider};
pub use dependency_analysis::DependencyAnalyzer;
pub use error::IntelligenceError;
pub use knowledge_base::KnowledgeBase;
pub use performance::PerformanceOptimizer;
pub use root_cause::RootCauseAnalyzer;
pub use scan_diff::ScanDiffAnalyzer;
pub use tui_enhancements::TuiEnhancer;
pub use types::*;
pub use workflow::WorkflowManager;

/// Intelligence module result type
pub type IntelligenceResult<T> = Result<T, error::IntelligenceError>;
