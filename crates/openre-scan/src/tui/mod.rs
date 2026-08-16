//! TUI module for openre-scan
//!
//! Provides an interactive terminal user interface for running scans.

#[cfg(feature = "tui")]
pub mod app;

#[cfg(feature = "tui")]
pub use app::run_tui;
