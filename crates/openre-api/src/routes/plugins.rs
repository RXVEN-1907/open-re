//! Plugin routes

use crate::{AppState, ApiResult, ValidatedJson};
use axum::{
    extract::{Path, Query, State},
    routing::{get, post, delete},
    Json,
    Router,
};
use openre_core::ids::PluginId;
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
    let plugins = state.plugin_registry.list_plugins(
        filter.plugin_type.as_deref(),
        filter.enabled,
        pagination.offset(),
        pagination.limit(),
    ).await?;

    let total = state.plugin_registry.count_plugins(
        filter.plugin_type.as_deref(),
        filter.enabled,
    ).await?;

    Ok(Json(PluginListResponse {
        plugins: plugins.into_iter().map(PluginResponse::from).collect(),
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
    let plugin = state.plugin_registry.get_plugin(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Plugin not found".into()))?;

    Ok(Json(PluginResponse::from(plugin)))
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

    let plugin = state.plugin_registry.install_plugin(
        &payload.source,
        payload.version.as_deref(),
    ).await?;

    Ok(Json(PluginResponse::from(plugin)))
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

    state.plugin_registry.uninstall_plugin(id).await?;

    Ok(())
}

/// Enable plugin
async fn enable_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PluginResponse>> {
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    let plugin = state.plugin_registry.enable_plugin(id).await?;

    Ok(Json(PluginResponse::from(plugin)))
}

/// Disable plugin
async fn disable_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PluginResponse>> {
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    let plugin = state.plugin_registry.disable_plugin(id).await?;

    Ok(Json(PluginResponse::from(plugin)))
}

/// Configure plugin
async fn configure_plugin(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<PluginId>,
    Extension(claims): Extension<crate::auth::Claims>,
    Json(payload): Json<ConfigurePluginRequest>,
) -> ApiResult<Json<PluginResponse>> {
    // Check admin permission
    if !claims.roles.contains(&"admin".to_string()) {
        return Err(crate::error::ApiError::Forbidden("Admin required".into()));
    }

    let plugin = state.plugin_registry.configure_plugin(id, payload.config).await?;

    Ok(Json(PluginResponse::from(plugin)))
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

impl From<openre_plugins::PluginInfo> for PluginResponse {
    fn from(p: openre_plugins::PluginInfo) -> Self {
        Self {
            id: p.id,
            name: p.name,
            version: p.version,
            description: p.description,
            author: p.author,
            plugin_type: p.plugin_type,
            capabilities: p.capabilities,
            enabled: p.enabled,
            config: p.config,
            installed_at: p.installed_at,
            updated_at: p.updated_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct InstallPluginRequest {
    pub source: PluginSource,
    pub version: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PluginSource {
    Registry { name: String },
    Local { path: String },
    Git { url: String, rev: Option<String> },
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ConfigurePluginRequest {
    pub config: serde_json::Value,
}