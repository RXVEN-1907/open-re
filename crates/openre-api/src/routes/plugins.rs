//! Plugin routes

use crate::validation::{IdParam, PaginationParams};
use crate::{ApiResult, AppState, ValidatedJson};
use axum::Extension;
use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use openre_core::ids::PluginId;
use openre_core::plugin::{PluginManifest, PluginMetadata, PluginSource, PluginStatus};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Plugin routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(list_plugins).post(install_plugin))
        .route("/:id", get(get_plugin).delete(uninstall_plugin))
        .route("/:id/enable", post(enable_plugin))
        .route("/:id/disable", post(disable_plugin))
        .route("/:id/configure", put(configure_plugin))
        .with_state(state)
}

/// List plugins
#[utoipa::path(
    get,
    path = "/api/plugins",
    params(PaginationParams, PluginFilterParams),
    responses(
        (status = 200, description = "List of plugins", body = PluginListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "plugins"
)]
async fn list_plugins(
    State(state): State<std::sync::Arc<AppState>>,
    Query(pagination): Query<PaginationParams>,
    Query(filter): Query<PluginFilterParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PluginListResponse>> {
    let _ = claims;

    let mut plugins = state.plugin_registry.list_all().await;

    plugins.retain(|m| match filter.plugin_type.as_deref() {
        Some(t) => m.manifest.plugin.r#type.as_str() == t,
        None => true,
    });
    plugins.retain(|m| match filter.enabled {
        Some(true) => m.enabled,
        Some(false) => !m.enabled,
        None => true,
    });
    plugins.retain(|m| match filter.search.as_deref() {
        Some(q) => m.manifest.name.contains(q) || m.manifest.description.contains(q),
        None => true,
    });

    let total = plugins.len() as u64;
    plugins.sort_by(|a, b| b.installed_at.cmp(&a.installed_at));

    let items: Vec<PluginResponse> = plugins
        .iter()
        .skip(pagination.offset() as usize)
        .take(pagination.limit() as usize)
        .map(plugin_response_from_entry)
        .collect();

    Ok(Json(PluginListResponse {
        plugins: items,
        total,
        page: pagination.page(),
        per_page: pagination.per_page(),
    }))
}

/// Get plugin
#[utoipa::path(
    get,
    path = "/api/plugins/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "Plugin details", body = PluginResponse),
        (status = 404, description = "Plugin not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "plugins"
)]
async fn get_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PluginResponse>> {
    let _ = claims;

    let metadata = state
        .plugin_registry
        .get_metadata(&id)
        .await
        .map_err(|e| match &e {
            openre_core::error::Error::NotFound(_) => {
                crate::error::ApiError::NotFound("Plugin not found".into())
            }
            _ => crate::error::ApiError::Internal(e.to_string()),
        })?;

    Ok(Json(plugin_response_from_metadata(&metadata)))
}

/// Install plugin
#[utoipa::path(
    post,
    path = "/api/plugins",
    request_body = InstallPluginRequest,
    responses(
        (status = 201, description = "Plugin installed", body = PluginResponse),
        (status = 400, description = "Invalid request", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
        (status = 403, description = "Forbidden", body = crate::error::ApiErrorResponse),
    ),
    tag = "plugins"
)]
async fn install_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Extension(claims): Extension<crate::auth::Claims>,
    ValidatedJson(payload): ValidatedJson<InstallPluginRequest>,
) -> ApiResult<Json<PluginResponse>> {
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    match payload.source {
        ApiPluginSource::Local { path } => {
            let dir = std::path::PathBuf::from(path);
            let manifest = PluginManifest::from_dir(&dir).map_err(|e| {
                crate::error::ApiError::BadRequest(format!("Invalid plugin manifest: {}", e))
            })?;

            let id = manifest.plugin_id();
            let name = manifest.name.clone();
            let version = manifest.version.clone();
            let description = manifest.description.clone();
            let author = manifest.author.clone();
            let plugin_type = manifest.plugin.r#type.as_str().to_string();
            let capabilities = manifest
                .plugin
                .capabilities
                .iter()
                .map(|c| format!("{:?}", c))
                .collect();

            let installed_at = chrono::Utc::now();
            let metadata = PluginMetadata {
                id,
                manifest,
                source: openre_core::plugin::PluginSource::Local { path: dir.clone() },
                path: dir,
                installed_at,
                status: PluginStatus::Active,
            };

            state.plugin_registry.register(metadata).await?;

            Ok(Json(PluginResponse {
                id,
                name,
                version,
                description,
                author,
                plugin_type,
                capabilities,
                enabled: true,
                config: None,
                installed_at,
                updated_at: installed_at,
            }))
        }
        _ => Err(crate::error::ApiError::NotImplemented(
            "only local plugin installation is supported".into(),
        )),
    }
}

/// Uninstall plugin
async fn uninstall_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<()> {
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    state.plugin_registry.unregister(&id).await?;

    Ok(())
}

/// Enable plugin
async fn enable_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PluginResponse>> {
    let _ = (state, id);
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    Err(crate::error::ApiError::NotImplemented(
        "plugin enable/disable not implemented yet".into(),
    ))
}

/// Disable plugin
async fn disable_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PluginResponse>> {
    let _ = (state, id);
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    Err(crate::error::ApiError::NotImplemented(
        "plugin enable/disable not implemented yet".into(),
    ))
}

/// Configure plugin
async fn configure_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<ConfigurePluginRequest>,
) -> ApiResult<Json<PluginResponse>> {
    let _ = (state, id, payload);
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    Err(crate::error::ApiError::NotImplemented(
        "plugin configuration persistence not implemented yet".into(),
    ))
}

// Request/Response types

#[derive(Debug, Deserialize, IntoParams)]
pub struct PluginFilterParams {
    pub plugin_type: Option<String>,
    pub enabled: Option<bool>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PluginListResponse {
    pub plugins: Vec<PluginResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PluginResponse {
    pub id: PluginId,
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub plugin_type: String,
    pub capabilities: Vec<String>,
    pub enabled: bool,
    pub config: Option<serde_json::Value>,
    pub installed_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn plugin_response_from_entry(entry: &openre_core::plugin::RegistryEntry) -> PluginResponse {
    PluginResponse {
        id: entry.manifest.plugin_id(),
        name: entry.manifest.name.clone(),
        version: entry.manifest.version.clone(),
        description: entry.manifest.description.clone(),
        author: entry.manifest.author.clone(),
        plugin_type: entry.manifest.plugin.r#type.as_str().to_string(),
        capabilities: entry
            .manifest
            .plugin
            .capabilities
            .iter()
            .map(|c| format!("{:?}", c))
            .collect(),
        enabled: entry.enabled,
        config: None,
        installed_at: entry.installed_at,
        updated_at: entry.updated_at.unwrap_or(entry.installed_at),
    }
}

fn plugin_response_from_metadata(m: &PluginMetadata) -> PluginResponse {
    PluginResponse {
        id: m.id,
        name: m.manifest.name.clone(),
        version: m.manifest.version.clone(),
        description: m.manifest.description.clone(),
        author: m.manifest.author.clone(),
        plugin_type: m.manifest.plugin.r#type.as_str().to_string(),
        capabilities: m
            .manifest
            .plugin
            .capabilities
            .iter()
            .map(|c| format!("{:?}", c))
            .collect(),
        enabled: matches!(m.status, PluginStatus::Active),
        config: None,
        installed_at: m.installed_at,
        updated_at: m.installed_at,
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct InstallPluginRequest {
    pub source: ApiPluginSource,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ApiPluginSource {
    Registry { name: String },
    Local { path: String },
    Git { url: String, rev: Option<String> },
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ConfigurePluginRequest {
    pub config: serde_json::Value,
}
