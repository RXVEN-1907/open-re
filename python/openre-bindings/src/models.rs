//! Python bindings for OpenRE models

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Job status enum
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PyJobStatus {
    Pending = 0,
    Queued = 1,
    Running = 2,
    Completed = 3,
    Failed = 4,
    Cancelled = 5,
    Scheduled = 6,
}

/// Job priority enum
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PyJobPriority {
    High = 0,
    Default = 1,
    Low = 2,
}

/// File status enum
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PyFileStatus {
    Uploaded = 0,
    Analyzing = 1,
    Completed = 2,
    Failed = 3,
}

/// Project model
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyProject {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub description: Option<String>,
    #[pyo3(get)]
    pub owner_id: String,
    #[pyo3(get)]
    pub is_public: bool,
    #[pyo3(get)]
    pub settings: Option<PyObject>,
    #[pyo3(get)]
    pub created_at: String,
    #[pyo3(get)]
    pub updated_at: String,
}

#[pymethods]
impl PyProject {
    #[new]
    #[pyo3(signature = (id, name, description=None, owner_id, is_public=false, settings=None, created_at, updated_at))]
    fn new(
        id: String,
        name: String,
        description: Option<String>,
        owner_id: String,
        is_public: bool,
        settings: Option<PyObject>,
        created_at: String,
        updated_at: String,
    ) -> Self {
        Self {
            id,
            name,
            description,
            owner_id,
            is_public,
            settings,
            created_at,
            updated_at,
        }
    }

    fn __repr__(&self) -> String {
        format!("Project(id={}, name={})", self.id, self.name)
    }
}

/// File model
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyFile {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub user_id: String,
    #[pyo3(get)]
    pub project_id: Option<String>,
    #[pyo3(get)]
    pub filename: String,
    #[pyo3(get)]
    pub content_type: String,
    #[pyo3(get)]
    pub size: u64,
    #[pyo3(get)]
    pub object_id: String,
    #[pyo3(get)]
    pub status: String,
    #[pyo3(get)]
    pub hash: String,
    #[pyo3(get)]
    pub created_at: String,
    #[pyo3(get)]
    pub updated_at: String,
}

#[pymethods]
impl PyFile {
    #[new]
    #[pyo3(signature = (id, user_id, filename, content_type, size, object_id, status, hash, created_at, updated_at, project_id=None))]
    fn new(
        id: String,
        user_id: String,
        filename: String,
        content_type: String,
        size: u64,
        object_id: String,
        status: String,
        hash: String,
        created_at: String,
        updated_at: String,
        project_id: Option<String>,
    ) -> Self {
        Self {
            id,
            user_id,
            project_id,
            filename,
            content_type,
            size,
            object_id,
            status,
            hash,
            created_at,
            updated_at,
        }
    }

    fn __repr__(&self) -> String {
        format!("File(id={}, filename={})", self.id, self.filename)
    }
}

/// Function parameter
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyFunctionParameter {
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub type_: String,
    #[pyo3(get)]
    pub location: String,
}

#[pymethods]
impl PyFunctionParameter {
    #[new]
    fn new(name: String, type_: String, location: String) -> Self {
        Self { name, type_, location }
    }
}

/// Function model
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyFunction {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub file_id: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub address: u64,
    #[pyo3(get)]
    pub size: u32,
    #[pyo3(get)]
    pub is_entry: bool,
    #[pyo3(get)]
    pub is_thunk: bool,
    #[pyo3(get)]
    pub calling_convention: Option<String>,
    #[pyo3(get)]
    pub return_type: Option<String>,
    #[pyo3(get)]
    pub parameters: Vec<PyFunctionParameter>,
    #[pyo3(get)]
    pub stack_frame_size: Option<u32>,
    #[pyo3(get)]
    pub cyclomatic_complexity: Option<u32>,
    #[pyo3(get)]
    pub created_at: String,
    #[pyo3(get)]
    pub updated_at: String,
}

#[pymethods]
impl PyFunction {
    #[new]
    #[pyo3(signature = (id, file_id, name, address, size, is_entry, is_thunk, calling_convention=None, return_type=None, parameters=None, stack_frame_size=None, cyclomatic_complexity=None, created_at, updated_at))]
    fn new(
        id: String,
        file_id: String,
        name: String,
        address: u64,
        size: u32,
        is_entry: bool,
        is_thunk: bool,
        calling_convention: Option<String>,
        return_type: Option<String>,
        parameters: Option<Vec<PyFunctionParameter>>,
        stack_frame_size: Option<u32>,
        cyclomatic_complexity: Option<u32>,
        created_at: String,
        updated_at: String,
    ) -> Self {
        Self {
            id,
            file_id,
            name,
            address,
            size,
            is_entry,
            is_thunk,
            calling_convention,
            return_type,
            parameters: parameters.unwrap_or_default(),
            stack_frame_size,
            cyclomatic_complexity,
            created_at,
            updated_at,
        }
    }

    fn __repr__(&self) -> String {
        format!("Function(id={}, name={}, address=0x{:x})", self.id, self.name, self.address)
    }
}

/// Analysis job
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyAnalysisJob {
    #[pyo3(get)]
    pub job_id: String,
    #[pyo3(get)]
    pub job_type: String,
    #[pyo3(get)]
    pub status: PyJobStatus,
    #[pyo3(get)]
    pub progress: Option<f32>,
    #[pyo3(get)]
    pub current_stage: Option<String>,
    #[pyo3(get)]
    pub stages_completed: u32,
    #[pyo3(get)]
    pub total_stages: u32,
    #[pyo3(get)]
    pub error: Option<String>,
    #[pyo3(get)]
    pub created_at: String,
    #[pyo3(get)]
    pub started_at: Option<String>,
    #[pyo3(get)]
    pub completed_at: Option<String>,
}

#[pymethods]
impl PyAnalysisJob {
    #[new]
    #[pyo3(signature = (job_id, job_type, status, progress=None, current_stage=None, stages_completed=0, total_stages=0, error=None, created_at, started_at=None, completed_at=None))]
    fn new(
        job_id: String,
        job_type: String,
        status: PyJobStatus,
        progress: Option<f32>,
        current_stage: Option<String>,
        stages_completed: u32,
        total_stages: u32,
        error: Option<String>,
        created_at: String,
        started_at: Option<String>,
        completed_at: Option<String>,
    ) -> Self {
        Self {
            job_id,
            job_type,
            status,
            progress,
            current_stage,
            stages_completed,
            total_stages,
            error,
            created_at,
            started_at,
            completed_at,
        }
    }

    fn __repr__(&self) -> String {
        format!("AnalysisJob(id={}, type={}, status={:?})", self.job_id, self.job_type, self.status)
    }
}

/// Analysis result
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyAnalysisResult {
    #[pyo3(get)]
    pub job_id: String,
    #[pyo3(get)]
    pub result: PyObject,
    #[pyo3(get)]
    pub completed_at: String,
}

#[pymethods]
impl PyAnalysisResult {
    #[new]
    fn new(job_id: String, result: PyObject, completed_at: String) -> Self {
        Self { job_id, result, completed_at }
    }
}

/// Plugin model
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyPlugin {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub version: String,
    #[pyo3(get)]
    pub description: String,
    #[pyo3(get)]
    pub author: String,
    #[pyo3(get)]
    pub plugin_type: String,
    #[pyo3(get)]
    pub capabilities: Vec<String>,
    #[pyo3(get)]
    pub enabled: bool,
    #[pyo3(get)]
    pub config: Option<PyObject>,
    #[pyo3(get)]
    pub installed_at: String,
    #[pyo3(get)]
    pub updated_at: String,
}

#[pymethods]
impl PyPlugin {
    #[new]
    #[pyo3(signature = (id, name, version, description, author, plugin_type, capabilities, enabled, config=None, installed_at, updated_at))]
    fn new(
        id: String,
        name: String,
        version: String,
        description: String,
        author: String,
        plugin_type: String,
        capabilities: Vec<String>,
        enabled: bool,
        config: Option<PyObject>,
        installed_at: String,
        updated_at: String,
    ) -> Self {
        Self {
            id,
            name,
            version,
            description,
            author,
            plugin_type,
            capabilities,
            enabled,
            config,
            installed_at,
            updated_at,
        }
    }

    fn __repr__(&self) -> String {
        format!("Plugin(id={}, name={}, version={})", self.id, self.name, self.version)
    }
}

/// User model
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyUser {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub email: String,
    #[pyo3(get)]
    pub username: String,
    #[pyo3(get)]
    pub full_name: Option<String>,
    #[pyo3(get)]
    pub roles: Vec<String>,
    #[pyo3(get)]
    pub permissions: Vec<String>,
    #[pyo3(get)]
    pub is_active: bool,
    #[pyo3(get)]
    pub created_at: String,
    #[pyo3(get)]
    pub last_login: Option<String>,
}

#[pymethods]
impl PyUser {
    #[new]
    #[pyo3(signature = (id, email, username, full_name=None, roles=None, permissions=None, is_active=true, created_at, last_login=None))]
    fn new(
        id: String,
        email: String,
        username: String,
        full_name: Option<String>,
        roles: Option<Vec<String>>,
        permissions: Option<Vec<String>>,
        is_active: bool,
        created_at: String,
        last_login: Option<String>,
    ) -> Self {
        Self {
            id,
            email,
            username,
            full_name,
            roles: roles.unwrap_or_default(),
            permissions: permissions.unwrap_or_default(),
            is_active,
            created_at,
            last_login,
        }
    }
}

/// API Key model
#[pyclass]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PyAPIKey {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub name: String,
    #[pyo3(get)]
    pub prefix: String,
    #[pyo3(get)]
    pub scopes: Vec<String>,
    #[pyo3(get)]
    pub expires_at: Option<String>,
    #[pyo3(get)]
    pub last_used: Option<String>,
    #[pyo3(get)]
    pub created_at: String,
}

#[pymethods]
impl PyAPIKey {
    #[new]
    #[pyo3(signature = (id, name, prefix, scopes, expires_at=None, last_used=None, created_at))]
    fn new(
        id: String,
        name: String,
        prefix: String,
        scopes: Vec<String>,
        expires_at: Option<String>,
        last_used: Option<String>,
        created_at: String,
    ) -> Self {
        Self {
            id,
            name,
            prefix,
            scopes,
            expires_at,
            last_used,
            created_at,
        }
    }
}