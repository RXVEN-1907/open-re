//! Security scanning engine for open-re
//!
//! This crate provides the core scanning engine that orchestrates security checks
//! through a plugin architecture. It supports scanning local web applications,
//! remote web applications, REST APIs, and future target types through extensible plugins.

pub mod target;
pub mod scan;
pub mod plugin;
pub mod result;
pub mod context;
pub mod storage;
pub mod api;
pub mod tui;
pub mod error;

pub use error::{ScannerError, ScannerResult};
pub use target::{Target, TargetType, TargetMetadata, ScanConfig};
pub use scan::{ScanManager, ScanSession, ScanStatus, ScanProgress};
pub use plugin::{PluginManager, PluginInfo, PluginCapability};
pub use result::{Finding, FindingId, Severity, Confidence, Category, Evidence, Reference};
pub use context::{ScanContext, SharedHttpClient, AuthState, ScanCache};
pub use storage::{ScanStorage, ScanRecord, FindingRecord, PluginExecutionRecord};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::{
        ScannerError, ScannerResult,
        Target, TargetType, TargetMetadata, ScanConfig,
        ScanManager, ScanSession, ScanStatus, ScanProgress,
        PluginManager, PluginInfo, PluginCapability,
        Finding, FindingId, Severity, Confidence, Category, Evidence, Reference,
        ScanContext, SharedHttpClient, AuthState, ScanCache,
        ScanStorage, ScanRecord, FindingRecord, PluginExecutionRecord,
    };
}