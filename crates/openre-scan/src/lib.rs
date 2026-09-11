//! openre-scan - Lightweight Standalone Security Scanner
//!
//! A minimal, fast security assessment tool for web applications and APIs.

// Re-export core types - make them publicly available
pub use openre_core::ids::ScanId;
pub use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, FindingFilter,
    FindingSort, RemediationEffort, RemediationGuidance, RemediationPriority, Severity,
};

// Re-export scanner API
pub use crate::scanner::{ScanError, ScanResult, ScanTarget, Scanner};

// Re-export types and functions for public API
pub use crate::checks::{get_all_checks, get_check_description, Check};
pub use crate::client::{build_client, build_client_with_config};
pub use crate::config::ScanConfig;
pub use crate::extensions::{EvidenceExt, FindingExt, RemediationGuidanceExt};
pub use crate::output::{
    display_results, print_json_results, print_sarif_results, print_severity_summary,
    print_table_results, OutputFormat,
};
pub use crate::profiles::ScanProfile;
pub use crate::runner::{run_scan, run_scan_internal};
pub use crate::version::show_version;

pub mod checks;
pub mod client;
pub mod config;
pub mod extensions;
pub mod output;
pub mod profiles;
pub mod runner;
pub mod scanner;
pub mod version;

// TUI module (optional)
#[cfg(feature = "tui")]
pub mod tui;
