//! Security scanning engine for open-re
//!
//! This crate provides the core scanning engine that orchestrates security checks
//! through a plugin architecture. It supports scanning local web applications,
//! remote web applications, REST APIs, and future target types through extensible plugins.

pub mod api;
pub mod context;
pub mod error;
pub mod plugin;
pub mod result;
pub mod scan;
pub mod storage;
pub mod target;
pub mod tui;

pub use context::{AuthState, ScanCache, ScanContext, SharedHttpClient};
pub use error::{ScannerError, ScannerResult};
pub use plugin::{PluginCapability, PluginInfo, PluginManager};
pub use result::{Category, Confidence, Evidence, Finding, FindingId, Reference, Severity};
pub use scan::{ScanManager, ScanProgress, ScanSession, ScanStatus};
pub use storage::{
    FindingRecord, MemoryScanStorage, PluginExecutionRecord, ScanRecord, ScanStorage,
    SqliteScanStorage,
};
pub use target::{ScanConfig, Target, TargetMetadata, TargetType};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{
        AuthState, Category, Confidence, Evidence, Finding, FindingId, FindingRecord,
        PluginCapability, PluginExecutionRecord, PluginInfo, PluginManager, Reference, ScanCache,
        ScanConfig, ScanContext, ScanManager, ScanProgress, ScanRecord, ScanSession, ScanStatus,
        ScanStorage, ScannerError, ScannerResult, Severity, SharedHttpClient, Target,
        TargetMetadata, TargetType,
    };
}
