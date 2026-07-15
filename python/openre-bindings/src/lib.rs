//! Python bindings for open-re Rust crates

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use pyo3_asyncio::tokio::future_into_py;
use std::sync::Arc;

mod client;
mod models;
mod analysis;
mod plugins;

use client::PyOpenREClient;
use models::*;
use analysis::PyAnalysisManager;
use plugins::PyPluginManager;

/// Initialize the openre_bindings module
#[pymodule]
fn openre_bindings(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes
    m.add_class::<PyOpenREClient>()?;
    m.add_class::<PyProject>()?;
    m.add_class::<PyFile>()?;
    m.add_class::<PyFunction>()?;
    m.add_class::<PyAnalysisJob>()?;
    m.add_class::<PyAnalysisResult>()?;
    m.add_class::<PyPlugin>()?;
    m.add_class::<PyUser>()?;
    m.add_class::<PyAPIKey>()?;
    m.add_class::<PyAnalysisManager>()?;
    m.add_class::<PyPluginManager>()?;
    m.add_class::<PyPluginSource>()?;
    
    // Enums
    m.add_class::<PyJobStatus>()?;
    m.add_class::<PyJobPriority>()?;
    m.add_class::<PyFileStatus>()?;
    
    // Version
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    
    Ok(())
}