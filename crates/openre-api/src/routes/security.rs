//! Security Findings Routes
//! 
//! API endpoints for retrieving security assessment findings

use crate::{AppState, ApiResult};
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json,
    Router,
};
use openre_core::ids::{ScanId, FindingId};
use openre_scanner::result::{Finding, FindingFilter, FindingSort, Severity, Confidence, Category};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

/// Security findings routes
pub fn routes(state: std::sync::Arc<AppState>) -> Router {
    Router::new()
        .route("/findings", get(list_findings))
        .route("/findings/:id", get(get_finding))
        .route("/findings/stats", get(get_finding_stats))
        .route("/scans/:scan_id/findings", get(get_scan_findings))
        .route("/scans/:scan_id/findings/stats", get(get_scan_finding_stats))
        // Injection-specific endpoints
        .route("/injection/findings", get(list_injection_findings))
        .route("/injection/findings/stats", get(get_injection_stats))
        .route("/injection/categories", get(get_injection_categories))
        .route("/injection/detection-methods", get(get_detection_methods))
        // API Security endpoints
        .route("/api/findings", get(list_api_findings))
        .route("/api/findings/stats", get(get_api_stats))
        .route("/api/endpoints", get(list_api_endpoints))
        // GraphQL endpoints
        .route("/graphql/findings", get(list_graphql_findings))
        .route("/graphql/findings/stats", get(get_graphql_stats))
        // Rate limiting endpoints
        .route("/rate-limiting/findings", get(list_rate_limiting_findings))
        .route("/rate-limiting/findings/stats", get(get_rate_limiting_stats))
        // Access control endpoints
        .route("/access-control/findings", get(list_access_control_findings))
        .route("/access-control/findings/stats", get(get_access_control_stats))
        // File upload endpoints
        .route("/file-upload/findings", get(list_file_upload_findings))
        .route("/file-upload/findings/stats", get(get_file_upload_stats))
        // Path traversal endpoints
        .route("/path-traversal/findings", get(list_path_traversal_findings))
        .route("/path-traversal/findings/stats", get(get_path_traversal_stats))
        // Sensitive info endpoints
        .route("/sensitive-info/findings", get(list_sensitive_info_findings))
        .route("/sensitive-info/findings/stats", get(get_sensitive_info_stats))
        .with_state(state)
}

/// List findings with filtering
#[utoipa::path(
    get,
    path = "/api/security/findings",
    params(FindingListParams),
    responses(
        (status = 200, description = "List of security findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<FindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: params.plugin_source,
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get a specific finding
#[utoipa::path(
    get,
    path = "/api/security/findings/{id}",
    params(IdParam),
    responses(
        (status = 200, description = "Finding details", body = FindingResponse),
        (status = 404, description = "Finding not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_finding(
    State(state): State<std::sync::Arc<AppState>>,
    Path(id): Path<FindingId>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingResponse>> {
    let finding = state.scan_storage.get_finding(id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Finding not found".into()))?;
    
    Ok(Json(FindingResponse::from(finding)))
}

/// Get finding statistics
#[utoipa::path(
    get,
    path = "/api/security/findings/stats",
    params(FindingStatsParams),
    responses(
        (status = 200, description = "Finding statistics", body = FindingStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_finding_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<FindingStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: params.plugin_source,
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(FindingStatsResponse::from(stats)))
}

/// Get findings for a specific scan
#[utoipa::path(
    get,
    path = "/api/security/scans/{scan_id}/findings",
    params(ScanFindingsParams),
    responses(
        (status = 200, description = "Scan findings", body = FindingListResponse),
        (status = 404, description = "Scan not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_scan_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Path(scan_id): Path<ScanId>,
    Query(params): Query<ScanFindingsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    // Verify scan access
    let scan = state.scan_storage.get_scan(scan_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Scan not found".into()))?;
    
    // Check access (simplified - in reality would check project ownership)
    // For now, allow all authenticated users to view scan findings
    
    let filter = FindingFilter {
        scan_id: Some(scan_id),
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
        ..Default::default()
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get finding statistics for a specific scan
#[utoipa::path(
    get,
    path = "/api/security/scans/{scan_id}/findings/stats",
    params(ScanFindingStatsParams),
    responses(
        (status = 200, description = "Scan finding statistics", body = FindingStatsResponse),
        (status = 404, description = "Scan not found", body = crate::error::ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_scan_finding_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Path(scan_id): Path<ScanId>,
    Query(params): Query<ScanFindingStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingStatsResponse>> {
    // Verify scan access
    let scan = state.scan_storage.get_scan(scan_id).await?
        .ok_or_else(|| crate::error::ApiError::NotFound("Scan not found".into()))?;
    
    let filter = FindingFilter {
        scan_id: Some(scan_id),
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
        ..Default::default()
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(FindingStatsResponse::from(stats)))
}

// Request/Response types

#[derive(Debug, Deserialize, IntoParams)]
pub struct FindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub category: Option<Vec<Category>>,
    pub target: Option<String>,
    pub plugin_source: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct FindingStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub category: Option<Vec<Category>>,
    pub target: Option<String>,
    pub plugin_source: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ScanFindingsParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub category: Option<Vec<Category>>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ScanFindingStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub category: Option<Vec<Category>>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingListResponse {
    pub findings: Vec<FindingResponse>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingResponse {
    pub id: FindingId,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub category: Category,
    pub target: String,
    pub target_type: String,
    pub evidence: Vec<EvidenceResponse>,
    pub references: Vec<ReferenceResponse>,
    pub plugin_source: String,
    pub plugin_version: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub scan_id: ScanId,
    pub metadata: serde_json::Value,
    pub tags: Vec<String>,
    pub verified: bool,
    pub false_positive: bool,
    pub risk_score: Option<u8>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f32>,
}

impl From<Finding> for FindingResponse {
    fn from(f: Finding) -> Self {
        Self {
            id: f.id,
            title: f.title,
            description: f.description,
            severity: f.severity,
            confidence: f.confidence,
            category: f.category,
            target: f.target,
            target_type: f.target_type,
            evidence: f.evidence.into_iter().map(EvidenceResponse::from).collect(),
            references: f.references.into_iter().map(ReferenceResponse::from).collect(),
            plugin_source: f.plugin_source,
            plugin_version: f.plugin_version,
            timestamp: f.timestamp,
            scan_id: f.scan_id,
            metadata: serde_json::to_value(f.metadata).unwrap_or(serde_json::Value::Null),
            tags: f.tags,
            verified: f.verified,
            false_positive: f.false_positive,
            risk_score: f.risk_score,
            cvss_vector: f.cvss_vector,
            cvss_score: f.cvss_score,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EvidenceResponse {
    pub evidence_type: String,
    pub description: String,
    pub data: Option<serde_json::Value>,
    pub location: Option<String>,
    pub metadata: serde_json::Value,
}

impl From<openre_scanner::result::Evidence> for EvidenceResponse {
    fn from(e: openre_scanner::result::Evidence) -> Self {
        Self {
            evidence_type: format!("{:?}", e.evidence_type),
            description: e.description,
            data: e.data,
            location: e.location,
            metadata: serde_json::to_value(e.metadata).unwrap_or(serde_json::Value::Null),
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ReferenceResponse {
    pub reference_type: String,
    pub title: String,
    pub url: String,
    pub description: Option<String>,
}

impl From<openre_scanner::result::Reference> for ReferenceResponse {
    fn from(r: openre_scanner::result::Reference) -> Self {
        Self {
            reference_type: format!("{:?}", r.reference_type),
            title: r.title,
            url: r.url,
            description: r.description,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FindingStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub by_plugin: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_risk_score: f32,
    pub max_risk_score: u8,
}

impl From<openre_scanner::result::FindingStats> for FindingStatsResponse {
    fn from(s: openre_scanner::result::FindingStats) -> Self {
        Self {
            total: s.total,
            by_severity: s.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
            by_confidence: s.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
            by_category: s.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
            by_plugin: s.by_plugin,
            verified_count: s.verified_count,
            false_positive_count: s.false_positive_count,
            avg_risk_score: s.avg_risk_score,
            max_risk_score: s.max_risk_score,
        }
    }
}

/// Injection-specific finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct InjectionFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub injection_category: Option<Vec<String>>,
    pub detection_method: Option<Vec<String>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// Injection statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct InjectionStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub injection_category: Option<Vec<String>>,
    pub detection_method: Option<Vec<String>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// Injection category response
#[derive(Debug, Serialize, ToSchema)]
pub struct InjectionCategoryResponse {
    pub category: String,
    pub display_name: String,
    pub description: String,
    pub severity: String,
    pub cwe_ids: Vec<String>,
    pub owasp_refs: Vec<String>,
}

/// Detection method response
#[derive(Debug, Serialize, ToSchema)]
pub struct DetectionMethodResponse {
    pub method: String,
    pub display_name: String,
    pub description: String,
    pub reliability: String,
}

/// Injection statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct InjectionStatsResponse {
    pub total: u64,
    pub by_category: std::collections::HashMap<String, u64>,
    pub by_detection_method: std::collections::HashMap<String, u64>,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List injection findings with filtering
#[utoipa::path(
    get,
    path = "/api/security/injection/findings",
    params(InjectionFindingListParams),
    responses(
        (status = 200, description = "List of injection findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_injection_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<InjectionFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("injection_framework".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get injection finding statistics
#[utoipa::path(
    get,
    path = "/api/security/injection/findings/stats",
    params(InjectionStatsParams),
    responses(
        (status = 200, description = "Injection finding statistics", body = InjectionStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_injection_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<InjectionStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<InjectionStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("injection_framework".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    // Convert to injection-specific stats
    let mut by_category = std::collections::HashMap::new();
    let mut by_detection_method = std::collections::HashMap::new();
    
    // Extract injection-specific metadata from findings
    let findings = state.scan_storage.list_findings(filter, FindingSort::SeverityDesc, 0, 10000).await?;
    for finding in findings {
        if let Some(category) = finding.metadata.get("injection_category") {
            *by_category.entry(category.as_str().unwrap_or("unknown").to_string()).or_insert(0) += 1;
        }
        if let Some(method) = finding.metadata.get("detection_method") {
            *by_detection_method.entry(method.as_str().unwrap_or("unknown").to_string()).or_insert(0) += 1;
        }
    }
    
    Ok(Json(InjectionStatsResponse {
        total: stats.total,
        by_category,
        by_detection_method,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0, // Would need to calculate from findings
    }))
}

/// Get available injection categories
#[utoipa::path(
    get,
    path = "/api/security/injection/categories",
    responses(
        (status = 200, description = "List of injection categories", body = Vec<InjectionCategoryResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_injection_categories(
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<InjectionCategoryResponse>>> {
    let categories = vec![
        InjectionCategoryResponse {
            category: "sql_injection".to_string(),
            display_name: "SQL Injection".to_string(),
            description: "Injection of SQL commands through user input".to_string(),
            severity: "High".to_string(),
            cwe_ids: vec!["CWE-89".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "nosql_injection".to_string(),
            display_name: "NoSQL Injection".to_string(),
            description: "Injection of NoSQL query operators through user input".to_string(),
            severity: "High".to_string(),
            cwe_ids: vec!["CWE-943".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "xss".to_string(),
            display_name: "Cross-Site Scripting (XSS)".to_string(),
            description: "Injection of malicious scripts into web pages".to_string(),
            severity: "High".to_string(),
            cwe_ids: vec!["CWE-79".to_string(), "CWE-80".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "ssti".to_string(),
            display_name: "Server-Side Template Injection (SSTI)".to_string(),
            description: "Injection of template expressions into server-side templates".to_string(),
            severity: "Critical".to_string(),
            cwe_ids: vec!["CWE-1336".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "command_injection".to_string(),
            display_name: "Command Injection".to_string(),
            description: "Injection of OS commands through user input".to_string(),
            severity: "Critical".to_string(),
            cwe_ids: vec!["CWE-78".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "xxe".to_string(),
            display_name: "XML External Entity (XXE)".to_string(),
            description: "Exploitation of unsafe XML parser configurations".to_string(),
            severity: "Critical".to_string(),
            cwe_ids: vec!["CWE-611".to_string()],
            owasp_refs: vec!["A05:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "ldap_injection".to_string(),
            display_name: "LDAP Injection".to_string(),
            description: "Injection of LDAP filter expressions".to_string(),
            severity: "High".to_string(),
            cwe_ids: vec!["CWE-90".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "xpath_injection".to_string(),
            display_name: "XPath Injection".to_string(),
            description: "Injection of XPath query expressions".to_string(),
            severity: "High".to_string(),
            cwe_ids: vec!["CWE-643".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
        InjectionCategoryResponse {
            category: "header_injection".to_string(),
            display_name: "HTTP Header Injection".to_string(),
            description: "Injection of CRLF sequences into HTTP headers".to_string(),
            severity: "High".to_string(),
            cwe_ids: vec!["CWE-113".to_string()],
            owasp_refs: vec!["A03:2021".to_string()],
        },
    ];
    
    Ok(Json(categories))
}

/// Get available detection methods
#[utoipa::path(
    get,
    path = "/api/security/injection/detection-methods",
    responses(
        (status = 200, description = "List of detection methods", body = Vec<DetectionMethodResponse>),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_detection_methods(
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<Vec<DetectionMethodResponse>>> {
    let methods = vec![
        DetectionMethodResponse {
            method: "error_based".to_string(),
            display_name: "Error-Based".to_string(),
            description: "Detection through error messages in responses".to_string(),
            reliability: "High".to_string(),
        },
        DetectionMethodResponse {
            method: "boolean_based".to_string(),
            display_name: "Boolean-Based Blind".to_string(),
            description: "Detection through boolean condition responses".to_string(),
            reliability: "High".to_string(),
        },
        DetectionMethodResponse {
            method: "time_based".to_string(),
            display_name: "Time-Based Blind".to_string(),
            description: "Detection through response timing differences".to_string(),
            reliability: "Medium".to_string(),
        },
        DetectionMethodResponse {
            method: "reflection".to_string(),
            display_name: "Reflection-Based".to_string(),
            description: "Detection through payload reflection in response".to_string(),
            reliability: "Very High".to_string(),
        },
        DetectionMethodResponse {
            method: "pattern_match".to_string(),
            display_name: "Pattern Matching".to_string(),
            description: "Detection through known vulnerability patterns".to_string(),
            reliability: "High".to_string(),
        },
        DetectionMethodResponse {
            method: "differential".to_string(),
            display_name: "Differential Analysis".to_string(),
            description: "Detection through response comparison".to_string(),
            reliability: "Medium".to_string(),
        },
        DetectionMethodResponse {
            method: "out_of_band".to_string(),
            display_name: "Out-of-Band".to_string(),
            description: "Detection through external channel interactions".to_string(),
            reliability: "Very High".to_string(),
        },
        DetectionMethodResponse {
            method: "heuristic".to_string(),
            display_name: "Heuristic Analysis".to_string(),
            description: "Detection through behavioral heuristics".to_string(),
            reliability: "Low".to_string(),
        },
    ];
    
    Ok(Json(methods))
}

/// API Security finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct ApiFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// API statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct ApiStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// API statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List API security findings
#[utoipa::path(
    get,
    path = "/api/security/api/findings",
    params(ApiFindingListParams),
    responses(
        (status = 200, description = "List of API security findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_api_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<ApiFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("rest_api_security".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get API security statistics
#[utoipa::path(
    get,
    path = "/api/security/api/findings/stats",
    params(ApiStatsParams),
    responses(
        (status = 200, description = "API security statistics", body = ApiStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_api_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<ApiStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<ApiStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("rest_api_security".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(ApiStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}

/// List API endpoints discovered
#[utoipa::path(
    get,
    path = "/api/security/api/endpoints",
    params(ApiFindingListParams),
    responses(
        (status = 200, description = "List of discovered API endpoints", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_api_endpoints(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<ApiFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("rest_api_security".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// GraphQL finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct GraphqlFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// GraphQL statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct GraphqlStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// GraphQL statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct GraphqlStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List GraphQL findings
#[utoipa::path(
    get,
    path = "/api/security/graphql/findings",
    params(GraphqlFindingListParams),
    responses(
        (status = 200, description = "List of GraphQL findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_graphql_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<GraphqlFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("graphql_security".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get GraphQL statistics
#[utoipa::path(
    get,
    path = "/api/security/graphql/findings/stats",
    params(GraphqlStatsParams),
    responses(
        (status = 200, description = "GraphQL statistics", body = GraphqlStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_graphql_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<GraphqlStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<GraphqlStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("graphql_security".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(GraphqlStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}

/// Rate limiting finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct RateLimitingFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// Rate limiting statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct RateLimitingStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// Rate limiting statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct RateLimitingStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List rate limiting findings
#[utoipa::path(
    get,
    path = "/api/security/rate-limiting/findings",
    params(RateLimitingFindingListParams),
    responses(
        (status = 200, description = "List of rate limiting findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_rate_limiting_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<RateLimitingFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("api_rate_limiting".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get rate limiting statistics
#[utoipa::path(
    get,
    path = "/api/security/rate-limiting/findings/stats",
    params(RateLimitingStatsParams),
    responses(
        (status = 200, description = "Rate limiting statistics", body = RateLimitingStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_rate_limiting_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<RateLimitingStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<RateLimitingStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("api_rate_limiting".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(RateLimitingStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}

/// Access control finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct AccessControlFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// Access control statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct AccessControlStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// Access control statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct AccessControlStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List access control findings
#[utoipa::path(
    get,
    path = "/api/security/access-control/findings",
    params(AccessControlFindingListParams),
    responses(
        (status = 200, description = "List of access control findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_access_control_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<AccessControlFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("access_control".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get access control statistics
#[utoipa::path(
    get,
    path = "/api/security/access-control/findings/stats",
    params(AccessControlStatsParams),
    responses(
        (status = 200, description = "Access control statistics", body = AccessControlStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_access_control_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<AccessControlStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<AccessControlStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("access_control".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(AccessControlStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}

/// File upload finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct FileUploadFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// File upload statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct FileUploadStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// File upload statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct FileUploadStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List file upload findings
#[utoipa::path(
    get,
    path = "/api/security/file-upload/findings",
    params(FileUploadFindingListParams),
    responses(
        (status = 200, description = "List of file upload findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_file_upload_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<FileUploadFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("file_upload".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get file upload statistics
#[utoipa::path(
    get,
    path = "/api/security/file-upload/findings/stats",
    params(FileUploadStatsParams),
    responses(
        (status = 200, description = "File upload statistics", body = FileUploadStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_file_upload_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<FileUploadStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FileUploadStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("file_upload".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(FileUploadStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}

/// Path traversal finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct PathTraversalFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// Path traversal statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct PathTraversalStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// Path traversal statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct PathTraversalStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List path traversal findings
#[utoipa::path(
    get,
    path = "/api/security/path-traversal/findings",
    params(PathTraversalFindingListParams),
    responses(
        (status = 200, description = "List of path traversal findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_path_traversal_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<PathTraversalFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("path_traversal".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get path traversal statistics
#[utoipa::path(
    get,
    path = "/api/security/path-traversal/findings/stats",
    params(PathTraversalStatsParams),
    responses(
        (status = 200, description = "Path traversal statistics", body = PathTraversalStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_path_traversal_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<PathTraversalStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<PathTraversalStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("path_traversal".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(PathTraversalStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}

/// Sensitive info finding list parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct SensitiveInfoFindingListParams {
    #[serde(flatten)]
    pub pagination: crate::routes::PaginationParams,
    
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
    pub sort: Option<FindingSort>,
}

/// Sensitive info statistics parameters
#[derive(Debug, Deserialize, IntoParams)]
pub struct SensitiveInfoStatsParams {
    pub severity: Option<Vec<Severity>>,
    pub confidence: Option<Vec<Confidence>>,
    pub target: Option<String>,
    pub scan_id: Option<ScanId>,
    pub verified: Option<bool>,
    pub false_positive: Option<bool>,
    pub tags: Option<Vec<String>>,
    pub date_from: Option<chrono::DateTime<chrono::Utc>>,
    pub date_to: Option<chrono::DateTime<chrono::Utc>>,
    pub search: Option<String>,
    pub min_risk_score: Option<u8>,
    pub max_risk_score: Option<u8>,
}

/// Sensitive info statistics response
#[derive(Debug, Serialize, ToSchema)]
pub struct SensitiveInfoStatsResponse {
    pub total: u64,
    pub by_severity: std::collections::HashMap<String, u64>,
    pub by_confidence: std::collections::HashMap<String, u64>,
    pub by_category: std::collections::HashMap<String, u64>,
    pub verified_count: u64,
    pub false_positive_count: u64,
    pub avg_confidence: f32,
}

/// List sensitive info findings
#[utoipa::path(
    get,
    path = "/api/security/sensitive-info/findings",
    params(SensitiveInfoFindingListParams),
    responses(
        (status = 200, description = "List of sensitive info findings", body = FindingListResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn list_sensitive_info_findings(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<SensitiveInfoFindingListParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<FindingListResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("sensitive_info".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let findings = state.scan_storage.list_findings(
        filter,
        params.sort.unwrap_or(FindingSort::SeverityDesc),
        params.offset(),
        params.limit(),
    ).await?;
    
    let total = state.scan_storage.count_findings(filter).await?;
    
    Ok(Json(FindingListResponse {
        findings: findings.into_iter().map(FindingResponse::from).collect(),
        total,
        page: params.page(),
        per_page: params.per_page(),
    }))
}

/// Get sensitive info statistics
#[utoipa::path(
    get,
    path = "/api/security/sensitive-info/findings/stats",
    params(SensitiveInfoStatsParams),
    responses(
        (status = 200, description = "Sensitive info statistics", body = SensitiveInfoStatsResponse),
        (status = 401, description = "Unauthorized", body = crate::error::ApiErrorResponse),
    ),
    tag = "security"
)]
async fn get_sensitive_info_stats(
    State(state): State<std::sync::Arc<AppState>>,
    Query(params): Query<SensitiveInfoStatsParams>,
    Extension(claims): Extension<crate::auth::Claims>,
) -> ApiResult<Json<SensitiveInfoStatsResponse>> {
    let filter = FindingFilter {
        severity: params.severity,
        confidence: params.confidence,
        category: params.category,
        target: params.target,
        plugin_source: Some("sensitive_info".to_string()),
        scan_id: params.scan_id,
        verified: params.verified,
        false_positive: params.false_positive,
        tags: params.tags,
        date_from: params.date_from,
        date_to: params.date_to,
        search: params.search,
        min_risk_score: params.min_risk_score,
        max_risk_score: params.max_risk_score,
    };
    
    let stats = state.scan_storage.get_finding_stats(filter).await?;
    
    Ok(Json(SensitiveInfoStatsResponse {
        total: stats.total,
        by_severity: stats.by_severity.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_confidence: stats.by_confidence.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        by_category: stats.by_category.into_iter().map(|(k, v)| (format!("{:?}", k), v)).collect(),
        verified_count: stats.verified_count,
        false_positive_count: stats.false_positive_count,
        avg_confidence: 0.0,
    }))
}