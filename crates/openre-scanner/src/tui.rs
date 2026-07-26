//! TUI Foundation - Command structure for the scanner CLI

use crate::error::{ScannerError, ScannerResult};
use crate::scan::{ScanManager, ScanSession, ScanStatus, ScanProgress, ScanId};
use crate::target::{Target, TargetId, TargetType, TargetMetadata, ScanConfig};
use crate::result::{Finding, FindingId, FindingFilter, FindingSort, FindingStats};
use crate::plugin::{PluginManager, PluginInfo, PluginId};
use crate::storage::{ScanStorage, MemoryScanStorage};
use clap::{Parser, Subcommand, Args};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Main CLI application
#[derive(Parser, Debug)]
#[command(name = "sentinel")]
#[command(about = "open-re Security Scanner - Modular security assessment framework")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output format (table, json, yaml)
    #[arg(short, long, global = true, default_value = "table")]
    pub format: OutputFormat,

    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<String>,
}

/// Output format
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Yaml,
}

/// Main commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan management commands
    #[command(subcommand)]
    Scan(ScanCommands),

    /// Target management commands
    #[command(subcommand)]
    Target(TargetCommands),

    /// Plugin management commands
    #[command(subcommand)]
    Plugin(PluginCommands),

    /// Finding query commands
    #[command(subcommand)]
    Finding(FindingCommands),

    /// Configuration commands
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Server commands
    #[command(subcommand)]
    Server(ServerCommands),
}

/// Scan commands
#[derive(Subcommand, Debug)]
pub enum ScanCommands {
    /// Create and start a new scan
    Start(ScanStartArgs),

    /// Get scan status
    Status(ScanStatusArgs),

    /// List scans
    List(ScanListArgs),

    /// Cancel a running scan
    Cancel(ScanCancelArgs),

    /// Pause a running scan
    Pause(ScanPauseArgs),

    /// Resume a paused scan
    Resume(ScanResumeArgs),

    /// Get scan progress
    Progress(ScanProgressArgs),

    /// Get scan findings
    Findings(ScanFindingsArgs),

    /// Get scan logs
    Logs(ScanLogsArgs),

    /// Delete a scan
    Delete(ScanDeleteArgs),
}

/// Scan start arguments
#[derive(Args, Debug)]
pub struct ScanStartArgs {
    /// Target ID to scan
    #[arg(short, long)]
    pub target: TargetId,

    /// Scan name
    #[arg(short, long)]
    pub name: String,

    /// Scan description
    #[arg(long)]
    pub description: Option<String>,

    /// Plugins to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub plugins: Option<Vec<String>>,

    /// Plugins to exclude (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub exclude_plugins: Option<Vec<String>>,

    /// Maximum scan duration in seconds
    #[arg(long, default_value = "3600")]
    pub max_duration: u64,

    /// Maximum concurrent plugins
    #[arg(long, default_value = "5")]
    pub max_concurrent: usize,

    /// Plugin timeout in seconds
    #[arg(long, default_value = "300")]
    pub plugin_timeout: u64,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,

    /// Tags (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
}

/// Scan status arguments
#[derive(Args, Debug)]
pub struct ScanStatusArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,
}

/// Scan list arguments
#[derive(Args, Debug)]
pub struct ScanListArgs {
    /// Maximum number of scans to show
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,

    /// Filter by status
    #[arg(long)]
    pub status: Option<ScanStatus>,

    /// Filter by target ID
    #[arg(long)]
    pub target: Option<TargetId>,
}

/// Scan cancel arguments
#[derive(Args, Debug)]
pub struct ScanCancelArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,
}

/// Scan pause arguments
#[derive(Args, Debug)]
pub struct ScanPauseArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,
}

/// Scan resume arguments
#[derive(Args, Debug)]
pub struct ScanResumeArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,
}

/// Scan progress arguments
#[derive(Args, Debug)]
pub struct ScanProgressArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,

    /// Watch for updates
    #[arg(short, long)]
    pub watch: bool,
}

/// Scan findings arguments
#[derive(Args, Debug)]
pub struct ScanFindingsArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Filter by confidence
    #[arg(long, value_delimiter = ',')]
    pub confidence: Option<Vec<String>>,

    /// Filter by category
    #[arg(long, value_delimiter = ',')]
    pub category: Option<Vec<String>>,

    /// Search in title/description
    #[arg(long)]
    pub search: Option<String>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,

    /// Sort order
    #[arg(long, default_value = "severity_desc")]
    pub sort: FindingSort,
}

/// Scan logs arguments
#[derive(Args, Debug)]
pub struct ScanLogsArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,

    /// Maximum number of logs
    #[arg(short, long, default_value = "100")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Scan delete arguments
#[derive(Args, Debug)]
pub struct ScanDeleteArgs {
    /// Scan ID
    #[arg(short, long)]
    pub id: ScanId,

    /// Force delete without confirmation
    #[arg(long)]
    pub force: bool,
}

/// Target commands
#[derive(Subcommand, Debug)]
pub enum TargetCommands {
    /// Create a new target
    Create(TargetCreateArgs),

    /// Get target details
    Get(TargetGetArgs),

    /// List targets
    List(TargetListArgs),

    /// Update a target
    Update(TargetUpdateArgs),

    /// Delete a target
    Delete(TargetDeleteArgs),

    /// Validate a target
    Validate(TargetValidateArgs),
}

/// Target create arguments
#[derive(Args, Debug)]
pub struct TargetCreateArgs {
    /// Target name
    #[arg(short, long)]
    pub name: String,

    /// Target type
    #[arg(short, long, value_enum)]
    pub target_type: TargetType,

    /// Base URL
    #[arg(short, long)]
    pub url: String,

    /// Description
    #[arg(long)]
    pub description: Option<String>,

    /// Headers (key=value, comma-separated)
    #[arg(long, value_delimiter = ',', value_parser = parse_key_value)]
    pub headers: Option<Vec<(String, String)>>,

    /// Cookies (key=value, comma-separated)
    #[arg(long, value_delimiter = ',', value_parser = parse_key_value)]
    pub cookies: Option<Vec<(String, String)>>,

    /// Authentication type
    #[arg(long, value_enum)]
    pub auth_type: Option<AuthType>,

    /// Authentication token/credentials
    #[arg(long)]
    pub auth_value: Option<String>,

    /// Rate limit (requests per second)
    #[arg(long)]
    pub rate_limit: Option<u32>,

    /// Tags (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
}

/// Target get arguments
#[derive(Args, Debug)]
pub struct TargetGetArgs {
    /// Target ID
    #[arg(short, long)]
    pub id: TargetId,
}

/// Target list arguments
#[derive(Args, Debug)]
pub struct TargetListArgs {
    /// Maximum number of targets
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,

    /// Filter by target type
    #[arg(long, value_enum)]
    pub target_type: Option<TargetType>,

    /// Filter by tag
    #[arg(long)]
    pub tag: Option<String>,
}

/// Target update arguments
#[derive(Args, Debug)]
pub struct TargetUpdateArgs {
    /// Target ID
    #[arg(short, long)]
    pub id: TargetId,

    /// New name
    #[arg(long)]
    pub name: Option<String>,

    /// New description
    #[arg(long)]
    pub description: Option<String>,

    /// New base URL
    #[arg(long)]
    pub url: Option<String>,

    /// Tags (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
}

/// Target delete arguments
#[derive(Args, Debug)]
pub struct TargetDeleteArgs {
    /// Target ID
    #[arg(short, long)]
    pub id: TargetId,

    /// Force delete without confirmation
    #[arg(long)]
    pub force: bool,
}

/// Target validate arguments
#[derive(Args, Debug)]
pub struct TargetValidateArgs {
    /// Target ID
    #[arg(short, long)]
    pub id: TargetId,
}

/// Authentication type for CLI
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum AuthType {
    Bearer,
    Basic,
    ApiKey,
    Cookie,
}

/// Plugin commands
#[derive(Subcommand, Debug)]
pub enum PluginCommands {
    /// List all plugins
    List(PluginListArgs),

    /// Get plugin details
    Get(PluginGetArgs),

    /// Enable a plugin
    Enable(PluginEnableArgs),

    /// Disable a plugin
    Disable(PluginDisableArgs),

    /// Get plugin configuration
    ConfigGet(PluginConfigGetArgs),

    /// Set plugin configuration
    ConfigSet(PluginConfigSetArgs),

    /// Discover plugins
    Discover(PluginDiscoverArgs),

    /// Health check
    Health(PluginHealthArgs),
}

/// Plugin list arguments
#[derive(Args, Debug)]
pub struct PluginListArgs {
    /// Show only enabled plugins
    #[arg(long)]
    pub enabled_only: bool,
}

/// Plugin get arguments
#[derive(Args, Debug)]
pub struct PluginGetArgs {
    /// Plugin ID
    #[arg(short, long)]
    pub id: PluginId,
}

/// Plugin enable arguments
#[derive(Args, Debug)]
pub struct PluginEnableArgs {
    /// Plugin ID
    #[arg(short, long)]
    pub id: PluginId,
}

/// Plugin disable arguments
#[derive(Args, Debug)]
pub struct PluginDisableArgs {
    /// Plugin ID
    #[arg(short, long)]
    pub id: PluginId,
}

/// Plugin config get arguments
#[derive(Args, Debug)]
pub struct PluginConfigGetArgs {
    /// Plugin ID
    #[arg(short, long)]
    pub id: PluginId,
}

/// Plugin config set arguments
#[derive(Args, Debug)]
pub struct PluginConfigSetArgs {
    /// Plugin ID
    #[arg(short, long)]
    pub id: PluginId,

    /// Configuration as JSON
    #[arg(long)]
    pub config: String,
}

/// Plugin discover arguments
#[derive(Args, Debug)]
pub struct PluginDiscoverArgs {
    /// Plugin directory
    #[arg(short, long)]
    pub dir: Option<String>,
}

/// Plugin health arguments
#[derive(Args, Debug)]
pub struct PluginHealthArgs {
    /// Plugin ID (optional, checks all if not provided)
    #[arg(short, long)]
    pub id: Option<PluginId>,
}

/// Finding commands
#[derive(Subcommand, Debug)]
pub enum FindingCommands {
    /// List findings
    List(FindingListArgs),

    /// Get finding details
    Get(FindingGetArgs),

    /// Get finding statistics
    Stats(FindingStatsArgs),

    /// Update finding (mark verified/false positive)
    Update(FindingUpdateArgs),

    /// Security-specific finding commands
    #[command(subcommand)]
    Security(SecurityFindingCommands),
}

/// Security-specific finding commands
#[derive(Subcommand, Debug)]
pub enum SecurityFindingCommands {
    /// List authentication findings
    Auth(AuthFindingArgs),

    /// List session management findings
    Session(SessionFindingArgs),

    /// List cookie security findings
    Cookie(CookieFindingArgs),

    /// List security header findings
    Headers(HeadersFindingArgs),

    /// List CORS findings
    Cors(CorsFindingArgs),

    /// List rate limiting findings
    RateLimit(RateLimitFindingArgs),

    /// List information disclosure findings
    InfoDisclosure(InfoDisclosureFindingArgs),

    /// List injection findings
    Injection(InjectionFindingArgs),

    /// Get injection findings statistics
    InjectionStats(InjectionStatsArgs),

    /// Get injection categories
    InjectionCategories,

    /// Get detection methods
    DetectionMethods,

    /// List REST API findings
    Api(ApiFindingArgs),

    /// Get REST API statistics
    ApiStats(ApiStatsArgs),

    /// List GraphQL findings
    Graphql(GraphqlFindingArgs),

    /// Get GraphQL statistics
    GraphqlStats(GraphqlStatsArgs),

    /// List rate limiting findings
    RateLimiting(RateLimitingFindingArgs),

    /// Get rate limiting statistics
    RateLimitingStats(RateLimitingStatsArgs),

    /// List access control findings
    AccessControl(AccessControlFindingArgs),

    /// Get access control statistics
    AccessControlStats(AccessControlStatsArgs),

    /// List file upload findings
    FileUpload(FileUploadFindingArgs),

    /// Get file upload statistics
    FileUploadStats(FileUploadStatsArgs),

    /// List path traversal findings
    PathTraversal(PathTraversalFindingArgs),

    /// Get path traversal statistics
    PathTraversalStats(PathTraversalStatsArgs),

    /// List sensitive info findings
    SensitiveInfo(SensitiveInfoFindingArgs),

    /// Get sensitive info statistics
    SensitiveInfoStats(SensitiveInfoStatsArgs),

    /// Get security findings summary
    Summary(SecuritySummaryArgs),
}

/// Authentication findings arguments
#[derive(Args, Debug)]
pub struct AuthFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Session management findings arguments
#[derive(Args, Debug)]
pub struct SessionFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Cookie security findings arguments
#[derive(Args, Debug)]
pub struct CookieFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Security header findings arguments
#[derive(Args, Debug)]
pub struct HeadersFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// CORS findings arguments
#[derive(Args, Debug)]
pub struct CorsFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Rate limiting findings arguments
#[derive(Args, Debug)]
pub struct RateLimitFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Information disclosure findings arguments
#[derive(Args, Debug)]
pub struct InfoDisclosureFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Injection findings arguments
#[derive(Args, Debug)]
pub struct InjectionFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Filter by injection category
    #[arg(long, value_delimiter = ',')]
    pub injection_category: Option<Vec<String>>,

    /// Filter by detection method
    #[arg(long, value_delimiter = ',')]
    pub detection_method: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Injection statistics arguments
#[derive(Args, Debug)]
pub struct InjectionStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Filter by injection category
    #[arg(long, value_delimiter = ',')]
    pub injection_category: Option<Vec<String>>,

    /// Filter by detection method
    #[arg(long, value_delimiter = ',')]
    pub detection_method: Option<Vec<String>>,
}

/// REST API findings arguments
#[derive(Args, Debug)]
pub struct ApiFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// REST API statistics arguments
#[derive(Args, Debug)]
pub struct ApiStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// GraphQL findings arguments
#[derive(Args, Debug)]
pub struct GraphqlFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// GraphQL statistics arguments
#[derive(Args, Debug)]
pub struct GraphqlStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// Rate limiting findings arguments
#[derive(Args, Debug)]
pub struct RateLimitingFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Rate limiting statistics arguments
#[derive(Args, Debug)]
pub struct RateLimitingStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// Access control findings arguments
#[derive(Args, Debug)]
pub struct AccessControlFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Access control statistics arguments
#[derive(Args, Debug)]
pub struct AccessControlStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// File upload findings arguments
#[derive(Args, Debug)]
pub struct FileUploadFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// File upload statistics arguments
#[derive(Args, Debug)]
pub struct FileUploadStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// Path traversal findings arguments
#[derive(Args, Debug)]
pub struct PathTraversalFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Path traversal statistics arguments
#[derive(Args, Debug)]
pub struct PathTraversalStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// Sensitive info findings arguments
#[derive(Args, Debug)]
pub struct SensitiveInfoFindingArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,
}

/// Sensitive info statistics arguments
#[derive(Args, Debug)]
pub struct SensitiveInfoStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,
}

/// Security summary arguments
#[derive(Args, Debug)]
pub struct SecuritySummaryArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,
}

/// Finding list arguments
#[derive(Args, Debug)]
pub struct FindingListArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,

    /// Filter by severity
    #[arg(long, value_delimiter = ',')]
    pub severity: Option<Vec<String>>,

    /// Filter by confidence
    #[arg(long, value_delimiter = ',')]
    pub confidence: Option<Vec<String>>,

    /// Filter by category
    #[arg(long, value_delimiter = ',')]
    pub category: Option<Vec<String>>,

    /// Filter by target
    #[arg(long)]
    pub target: Option<String>,

    /// Filter by plugin source
    #[arg(long)]
    pub plugin: Option<String>,

    /// Search in title/description
    #[arg(long)]
    pub search: Option<String>,

    /// Maximum number of findings
    #[arg(short, long, default_value = "50")]
    pub limit: usize,

    /// Offset for pagination
    #[arg(long, default_value = "0")]
    pub offset: usize,

    /// Sort order
    #[arg(long, default_value = "severity_desc")]
    pub sort: FindingSort,
}

/// Finding get arguments
#[derive(Args, Debug)]
pub struct FindingGetArgs {
    /// Finding ID
    #[arg(short, long)]
    pub id: FindingId,
}

/// Finding stats arguments
#[derive(Args, Debug)]
pub struct FindingStatsArgs {
    /// Filter by scan ID
    #[arg(long)]
    pub scan_id: Option<ScanId>,
}

/// Finding update arguments
#[derive(Args, Debug)]
pub struct FindingUpdateArgs {
    /// Finding ID
    #[arg(short, long)]
    pub id: FindingId,

    /// Mark as verified
    #[arg(long)]
    pub verified: Option<bool>,

    /// Mark as false positive
    #[arg(long)]
    pub false_positive: Option<bool>,
}

/// Config commands
#[derive(Subcommand, Debug)]
pub enum ConfigCommands {
    /// Show current configuration
    Show,

    /// Set configuration value
    Set(ConfigSetArgs),

    /// Get configuration value
    Get(ConfigGetArgs),

    /// Reset configuration to defaults
    Reset,
}

/// Config set arguments
#[derive(Args, Debug)]
pub struct ConfigSetArgs {
    /// Configuration key
    #[arg(short, long)]
    pub key: String,

    /// Configuration value
    #[arg(short, long)]
    pub value: String,
}

/// Config get arguments
#[derive(Args, Debug)]
pub struct ConfigGetArgs {
    /// Configuration key
    #[arg(short, long)]
    pub key: String,
}

/// Server commands
#[derive(Subcommand, Debug)]
pub enum ServerCommands {
    /// Start the API server
    Start(ServerStartArgs),

    /// Show server status
    Status,
}

/// Server start arguments
#[derive(Args, Debug)]
pub struct ServerStartArgs {
    /// Host to bind to
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    /// Port to bind to
    #[arg(short, long, default_value = "8080")]
    pub port: u16,

    /// Enable TLS
    #[arg(long)]
    pub tls: bool,

    /// TLS certificate path
    #[arg(long)]
    pub cert: Option<String>,

    /// TLS key path
    #[arg(long)]
    pub key: Option<String>,
}

/// Parse key=value pair
fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let parts: Vec<&str> = s.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(format!("Invalid key=value pair: {}", s));
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

/// TUI Application state
pub struct TuiApp {
    pub scan_manager: Arc<ScanManager>,
    pub plugin_manager: Arc<PluginManager>,
    pub storage: Arc<dyn ScanStorage>,
    pub target_manager: Arc<crate::target::TargetManager>,
    pub format: OutputFormat,
}

impl TuiApp {
    /// Create a new TUI application
    pub fn new(
        scan_manager: Arc<ScanManager>,
        plugin_manager: Arc<PluginManager>,
        storage: Arc<dyn ScanStorage>,
        target_manager: Arc<crate::target::TargetManager>,
        format: OutputFormat,
    ) -> Self {
        Self {
            scan_manager,
            plugin_manager,
            storage,
            target_manager,
            format,
        }
    }

    /// Run a command
    pub async fn run_command(&self, command: Commands) -> ScannerResult<()> {
        match command {
            Commands::Scan(cmd) => self.run_scan_command(cmd).await,
            Commands::Target(cmd) => self.run_target_command(cmd).await,
            Commands::Plugin(cmd) => self.run_plugin_command(cmd).await,
            Commands::Finding(cmd) => self.run_finding_command(cmd).await,
            Commands::Config(cmd) => self.run_config_command(cmd).await,
            Commands::Server(cmd) => self.run_server_command(cmd).await,
        }
    }

    /// Run scan command
    async fn run_scan_command(&self, command: ScanCommands) -> ScannerResult<()> {
        match command {
            ScanCommands::Start(args) => self.cmd_scan_start(args).await,
            ScanCommands::Status(args) => self.cmd_scan_status(args).await,
            ScanCommands::List(args) => self.cmd_scan_list(args).await,
            ScanCommands::Cancel(args) => self.cmd_scan_cancel(args).await,
            ScanCommands::Pause(args) => self.cmd_scan_pause(args).await,
            ScanCommands::Resume(args) => self.cmd_scan_resume(args).await,
            ScanCommands::Progress(args) => self.cmd_scan_progress(args).await,
            ScanCommands::Findings(args) => self.cmd_scan_findings(args).await,
            ScanCommands::Logs(args) => self.cmd_scan_logs(args).await,
            ScanCommands::Delete(args) => self.cmd_scan_delete(args).await,
        }
    }

    /// Run target command
    async fn run_target_command(&self, command: TargetCommands) -> ScannerResult<()> {
        match command {
            TargetCommands::Create(args) => self.cmd_target_create(args).await,
            TargetCommands::Get(args) => self.cmd_target_get(args).await,
            TargetCommands::List(args) => self.cmd_target_list(args).await,
            TargetCommands::Update(args) => self.cmd_target_update(args).await,
            TargetCommands::Delete(args) => self.cmd_target_delete(args).await,
            TargetCommands::Validate(args) => self.cmd_target_validate(args).await,
        }
    }

    /// Run plugin command
    async fn run_plugin_command(&self, command: PluginCommands) -> ScannerResult<()> {
        match command {
            PluginCommands::List(args) => self.cmd_plugin_list(args).await,
            PluginCommands::Get(args) => self.cmd_plugin_get(args).await,
            PluginCommands::Enable(args) => self.cmd_plugin_enable(args).await,
            PluginCommands::Disable(args) => self.cmd_plugin_disable(args).await,
            PluginCommands::ConfigGet(args) => self.cmd_plugin_config_get(args).await,
            PluginCommands::ConfigSet(args) => self.cmd_plugin_config_set(args).await,
            PluginCommands::Discover(args) => self.cmd_plugin_discover(args).await,
            PluginCommands::Health(args) => self.cmd_plugin_health(args).await,
        }
    }

    /// Run finding command
    async fn run_finding_command(&self, command: FindingCommands) -> ScannerResult<()> {
        match command {
            FindingCommands::List(args) => self.cmd_finding_list(args).await,
            FindingCommands::Get(args) => self.cmd_finding_get(args).await,
            FindingCommands::Stats(args) => self.cmd_finding_stats(args).await,
            FindingCommands::Update(args) => self.cmd_finding_update(args).await,
            FindingCommands::Security(args) => self.run_security_finding_command(args).await,
        }
    }

    /// Run config command
    async fn run_config_command(&self, command: ConfigCommands) -> ScannerResult<()> {
        match command {
            ConfigCommands::Show => self.cmd_config_show().await,
            ConfigCommands::Set(args) => self.cmd_config_set(args).await,
            ConfigCommands::Get(args) => self.cmd_config_get(args).await,
            ConfigCommands::Reset => self.cmd_config_reset().await,
        }
    }

    /// Run server command
    async fn run_server_command(&self, command: ServerCommands) -> ScannerResult<()> {
        match command {
            ServerCommands::Start(args) => self.cmd_server_start(args).await,
            ServerCommands::Status => self.cmd_server_status().await,
        }
    }

    // Scan command implementations (placeholders for now)
    async fn cmd_scan_start(&self, args: ScanStartArgs) -> ScannerResult<()> {
        info!("Starting scan: {} on target {}", args.name, args.target);
        // TODO: Implement actual scan start
        println!("Scan started (placeholder)");
        Ok(())
    }

    async fn cmd_scan_status(&self, args: ScanStatusArgs) -> ScannerResult<()> {
        info!("Getting status for scan: {}", args.id);
        if let Some(scan) = self.scan_manager.get_scan(&args.id) {
            self.output_scan(&scan)?;
        } else {
            println!("Scan not found: {}", args.id);
        }
        Ok(())
    }

    async fn cmd_scan_list(&self, args: ScanListArgs) -> ScannerResult<()> {
        info!("Listing scans");
        let scans = self.scan_manager.list_scans();
        let scans: Vec<_> = scans.into_iter()
            .skip(args.offset)
            .take(args.limit)
            .collect();
        self.output_scans(&scans)?;
        Ok(())
    }

    async fn cmd_scan_cancel(&self, args: ScanCancelArgs) -> ScannerResult<()> {
        info!("Cancelling scan: {}", args.id);
        self.scan_manager.cancel_scan(&args.id).await?;
        println!("Scan cancelled: {}", args.id);
        Ok(())
    }

    async fn cmd_scan_pause(&self, args: ScanPauseArgs) -> ScannerResult<()> {
        info!("Pausing scan: {}", args.id);
        self.scan_manager.pause_scan(&args.id).await?;
        println!("Scan paused: {}", args.id);
        Ok(())
    }

    async fn cmd_scan_resume(&self, args: ScanResumeArgs) -> ScannerResult<()> {
        info!("Resuming scan: {}", args.id);
        self.scan_manager.resume_scan(&args.id).await?;
        println!("Scan resumed: {}", args.id);
        Ok(())
    }

    async fn cmd_scan_progress(&self, args: ScanProgressArgs) -> ScannerResult<()> {
        info!("Getting progress for scan: {}", args.id);
        if let Some(progress) = self.scan_manager.get_progress(&args.id) {
            self.output_progress(&progress)?;
        } else {
            println!("Scan not found: {}", args.id);
        }
        Ok(())
    }

    async fn cmd_scan_findings(&self, args: ScanFindingsArgs) -> ScannerResult<()> {
        info!("Getting findings for scan: {}", args.id);
        let filter = FindingFilter {
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            confidence: args.confidence.map(|c| c.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: args.category.map(|c| c.into_iter().filter_map(|v| v.parse().ok()).collect()),
            scan_id: Some(args.id),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, args.sort, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_scan_logs(&self, args: ScanLogsArgs) -> ScannerResult<()> {
        info!("Getting logs for scan: {}", args.id);
        let logs = self.scan_manager.get_logs(&args.id);
        let logs: Vec<_> = logs.into_iter().skip(args.offset).take(args.limit).collect();
        self.output_logs(&logs)?;
        Ok(())
    }

    async fn cmd_scan_delete(&self, args: ScanDeleteArgs) -> ScannerResult<()> {
        info!("Deleting scan: {}", args.id);
        if !args.force {
            print!("Are you sure you want to delete scan {}? (y/N): ", args.id);
            use std::io::{self, Write};
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled");
                return Ok(());
            }
        }
        self.storage.delete_scan(&args.id).await?;
        println!("Scan deleted: {}", args.id);
        Ok(())
    }

    // Target command implementations
    async fn cmd_target_create(&self, args: TargetCreateArgs) -> ScannerResult<()> {
        info!("Creating target: {}", args.name);
        let url = args.url.parse()?;
        let mut metadata = TargetMetadata::new(args.name, url);
        if let Some(desc) = args.description {
            metadata = metadata.with_description(desc);
        }
        if let Some(headers) = args.headers {
            for (k, v) in headers {
                metadata = metadata.with_header(k, v);
            }
        }
        if let Some(cookies) = args.cookies {
            for (k, v) in cookies {
                metadata = metadata.with_cookie(k, v);
            }
        }
        if let Some(tags) = args.tags {
            for tag in tags {
                metadata = metadata.with_tag(tag);
            }
        }
        let target = Target::new(args.target_type, metadata);
        let target_id = self.target_manager.register(target.clone())?;
        self.storage.save_target(&target).await?;
        println!("Target created: {}", target_id);
        Ok(())
    }

    async fn cmd_target_get(&self, args: TargetGetArgs) -> ScannerResult<()> {
        info!("Getting target: {}", args.id);
        if let Some(target) = self.target_manager.get(&args.id) {
            self.output_target(&target)?;
        } else {
            println!("Target not found: {}", args.id);
        }
        Ok(())
    }

    async fn cmd_target_list(&self, args: TargetListArgs) -> ScannerResult<()> {
        info!("Listing targets");
        let mut targets = self.target_manager.list();
        if let Some(tt) = args.target_type {
            targets.retain(|t| t.target_type == tt);
        }
        if let Some(tag) = args.tag {
            targets.retain(|t| t.metadata.tags.contains(&tag));
        }
        let targets: Vec<_> = targets.into_iter().skip(args.offset).take(args.limit).collect();
        self.output_targets(&targets)?;
        Ok(())
    }

    async fn cmd_target_update(&self, args: TargetUpdateArgs) -> ScannerResult<()> {
        info!("Updating target: {}", args.id);
        let mut target = self.target_manager.get(&args.id)
            .ok_or_else(|| ScannerError::TargetNotFound(args.id.to_string()))?;
        if let Some(name) = args.name {
            target.metadata.name = name;
        }
        if let Some(desc) = args.description {
            target.metadata.description = Some(desc);
        }
        if let Some(url) = args.url {
            target.metadata.base_url = url.parse()?;
        }
        if let Some(tags) = args.tags {
            target.metadata.tags = tags;
        }
        self.target_manager.update(&args.id, target.clone())?;
        self.storage.save_target(&target).await?;
        println!("Target updated: {}", args.id);
        Ok(())
    }

    async fn cmd_target_delete(&self, args: TargetDeleteArgs) -> ScannerResult<()> {
        info!("Deleting target: {}", args.id);
        if !args.force {
            print!("Are you sure you want to delete target {}? (y/N): ", args.id);
            use std::io::{self, Write};
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Cancelled");
                return Ok(());
            }
        }
        self.target_manager.delete(&args.id);
        self.storage.delete_target(&args.id).await?;
        println!("Target deleted: {}", args.id);
        Ok(())
    }

    async fn cmd_target_validate(&self, args: TargetValidateArgs) -> ScannerResult<()> {
        info!("Validating target: {}", args.id);
        if let Some(target) = self.target_manager.get(&args.id) {
            match target.validate() {
                Ok(_) => println!("Target {} is valid", args.id),
                Err(e) => println!("Target {} is invalid: {}", args.id, e),
            }
        } else {
            println!("Target not found: {}", args.id);
        }
        Ok(())
    }

    // Plugin command implementations
    async fn cmd_plugin_list(&self, args: PluginListArgs) -> ScannerResult<()> {
        info!("Listing plugins");
        let plugins = if args.enabled_only {
            self.plugin_manager.list_enabled_plugins().await?
        } else {
            self.plugin_manager.list_plugins().await?
        };
        self.output_plugins(&plugins)?;
        Ok(())
    }

    async fn cmd_plugin_get(&self, args: PluginGetArgs) -> ScannerResult<()> {
        info!("Getting plugin: {}", args.id);
        if let Some(plugin) = self.plugin_manager.get_plugin(&args.id) {
            self.output_plugin(&plugin)?;
        } else {
            println!("Plugin not found: {}", args.id);
        }
        Ok(())
    }

    async fn cmd_plugin_enable(&self, args: PluginEnableArgs) -> ScannerResult<()> {
        info!("Enabling plugin: {}", args.id);
        self.plugin_manager.enable_plugin(&args.id).await?;
        println!("Plugin enabled: {}", args.id);
        Ok(())
    }

    async fn cmd_plugin_disable(&self, args: PluginDisableArgs) -> ScannerResult<()> {
        info!("Disabling plugin: {}", args.id);
        self.plugin_manager.disable_plugin(&args.id).await?;
        println!("Plugin disabled: {}", args.id);
        Ok(())
    }

    async fn cmd_plugin_config_get(&self, args: PluginConfigGetArgs) -> ScannerResult<()> {
        info!("Getting config for plugin: {}", args.id);
        if let Some(config) = self.plugin_manager.get_plugin_config(&args.id) {
            self.output_json(&config)?;
        } else {
            println!("Plugin not found or no config: {}", args.id);
        }
        Ok(())
    }

    async fn cmd_plugin_config_set(&self, args: PluginConfigSetArgs) -> ScannerResult<()> {
        info!("Setting config for plugin: {}", args.id);
        let config: crate::plugin::PluginConfig = serde_json::from_str(&args.config)?;
        self.plugin_manager.set_plugin_config(config).await?;
        println!("Plugin config updated: {}", args.id);
        Ok(())
    }

    async fn cmd_plugin_discover(&self, args: PluginDiscoverArgs) -> ScannerResult<()> {
        info!("Discovering plugins");
        let plugins = self.plugin_manager.discover_plugins().await?;
        println!("Discovered {} plugins", plugins.len());
        for plugin in plugins {
            println!("  - {} ({})", plugin.name, plugin.id);
        }
        Ok(())
    }

    async fn cmd_plugin_health(&self, args: PluginHealthArgs) -> ScannerResult<()> {
        info!("Health check for plugins");
        if let Some(id) = args.id {
            let status = self.plugin_manager.health_check(&id).await?;
            println!("Plugin {}: {:?}", id, status);
        } else {
            let results = self.plugin_manager.health_check_all().await?;
            for (id, status) in results {
                println!("Plugin {}: {:?}", id, status);
            }
        }
        Ok(())
    }

    // Finding command implementations
    async fn cmd_finding_list(&self, args: FindingListArgs) -> ScannerResult<()> {
        info!("Listing findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            confidence: args.confidence.map(|c| c.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: args.category.map(|c| c.into_iter().filter_map(|v| v.parse().ok()).collect()),
            target: args.target,
            plugin_source: args.plugin,
            search: args.search,
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, args.sort, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_finding_get(&self, args: FindingGetArgs) -> ScannerResult<()> {
        info!("Getting finding: {}", args.id);
        // Would need to search across all scans
        println!("Finding get not fully implemented (placeholder)");
        Ok(())
    }

    async fn cmd_finding_stats(&self, args: FindingStatsArgs) -> ScannerResult<()> {
        info!("Getting finding stats");
        let stats = self.storage.get_finding_stats(args.scan_id).await?;
        self.output_json(&stats)?;
        Ok(())
    }

    async fn cmd_finding_update(&self, args: FindingUpdateArgs) -> ScannerResult<()> {
        info!("Updating finding: {}", args.id);
        println!("Finding update not fully implemented (placeholder)");
        Ok(())
    }

    // Security finding command implementations
    async fn run_security_finding_command(&self, command: SecurityFindingCommands) -> ScannerResult<()> {
        match command {
            SecurityFindingCommands::Auth(args) => self.cmd_security_auth_findings(args).await,
            SecurityFindingCommands::Session(args) => self.cmd_security_session_findings(args).await,
            SecurityFindingCommands::Cookie(args) => self.cmd_security_cookie_findings(args).await,
            SecurityFindingCommands::Headers(args) => self.cmd_security_headers_findings(args).await,
            SecurityFindingCommands::Cors(args) => self.cmd_security_cors_findings(args).await,
            SecurityFindingCommands::RateLimit(args) => self.cmd_security_rate_limit_findings(args).await,
            SecurityFindingCommands::InfoDisclosure(args) => self.cmd_security_info_disclosure_findings(args).await,
            SecurityFindingCommands::Injection(args) => self.cmd_security_injection_findings(args).await,
            SecurityFindingCommands::InjectionStats(args) => self.cmd_security_injection_stats(args).await,
            SecurityFindingCommands::InjectionCategories => self.cmd_security_injection_categories().await,
            SecurityFindingCommands::DetectionMethods => self.cmd_security_detection_methods().await,
            SecurityFindingCommands::Api(args) => self.cmd_security_api_findings(args).await,
            SecurityFindingCommands::ApiStats(args) => self.cmd_security_api_stats(args).await,
            SecurityFindingCommands::Graphql(args) => self.cmd_security_graphql_findings(args).await,
            SecurityFindingCommands::GraphqlStats(args) => self.cmd_security_graphql_stats(args).await,
            SecurityFindingCommands::RateLimiting(args) => self.cmd_security_rate_limiting_findings(args).await,
            SecurityFindingCommands::RateLimitingStats(args) => self.cmd_security_rate_limiting_stats(args).await,
            SecurityFindingCommands::AccessControl(args) => self.cmd_security_access_control_findings(args).await,
            SecurityFindingCommands::AccessControlStats(args) => self.cmd_security_access_control_stats(args).await,
            SecurityFindingCommands::FileUpload(args) => self.cmd_security_file_upload_findings(args).await,
            SecurityFindingCommands::FileUploadStats(args) => self.cmd_security_file_upload_stats(args).await,
            SecurityFindingCommands::PathTraversal(args) => self.cmd_security_path_traversal_findings(args).await,
            SecurityFindingCommands::PathTraversalStats(args) => self.cmd_security_path_traversal_stats(args).await,
            SecurityFindingCommands::SensitiveInfo(args) => self.cmd_security_sensitive_info_findings(args).await,
            SecurityFindingCommands::SensitiveInfoStats(args) => self.cmd_security_sensitive_info_stats(args).await,
            SecurityFindingCommands::Summary(args) => self.cmd_security_summary(args).await,
        }
    }

    async fn cmd_security_auth_findings(&self, args: AuthFindingArgs) -> ScannerResult<()> {
        info!("Listing authentication findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::BrokenAuthentication]),
            plugin_source: Some("auth_discovery".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_session_findings(&self, args: SessionFindingArgs) -> ScannerResult<()> {
        info!("Listing session management findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::BrokenAuthentication]),
            plugin_source: Some("session_management".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_cookie_findings(&self, args: CookieFindingArgs) -> ScannerResult<()> {
        info!("Listing cookie security findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::SecurityMisconfiguration]),
            plugin_source: Some("cookie_security".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_headers_findings(&self, args: HeadersFindingArgs) -> ScannerResult<()> {
        info!("Listing security header findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::SecurityMisconfiguration]),
            plugin_source: Some("security_headers".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_cors_findings(&self, args: CorsFindingArgs) -> ScannerResult<()> {
        info!("Listing CORS findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::SecurityMisconfiguration]),
            plugin_source: Some("cors_analysis".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_rate_limit_findings(&self, args: RateLimitFindingArgs) -> ScannerResult<()> {
        info!("Listing rate limiting findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::SecurityMisconfiguration]),
            plugin_source: Some("rate_limiting".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_info_disclosure_findings(&self, args: InfoDisclosureFindingArgs) -> ScannerResult<()> {
        info!("Listing information disclosure findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::InformationDisclosure]),
            plugin_source: Some("information_disclosure".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_injection_findings(&self, args: InjectionFindingArgs) -> ScannerResult<()> {
        info!("Listing injection findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::Injection]),
            plugin_source: Some("injection_framework".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_injection_stats(&self, args: InjectionStatsArgs) -> ScannerResult<()> {
        info!("Getting injection statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            category: Some(vec![Category::Injection]),
            plugin_source: Some("injection_framework".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("Injection Findings Statistics");
        println!("=============================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        println!();
        println!("By Plugin:");
        for (plugin, count) in &stats.by_plugin {
            println!("  {}: {}", plugin, count);
        }
        Ok(())
    }

    async fn cmd_security_api_findings(&self, args: ApiFindingArgs) -> ScannerResult<()> {
        info!("Listing REST API findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("rest_api_security".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_api_stats(&self, args: ApiStatsArgs) -> ScannerResult<()> {
        info!("Getting REST API statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("rest_api_security".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("REST API Security Statistics");
        println!("==============================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_graphql_findings(&self, args: GraphqlFindingArgs) -> ScannerResult<()> {
        info!("Listing GraphQL findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("graphql_security".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_graphql_stats(&self, args: GraphqlStatsArgs) -> ScannerResult<()> {
        info!("Getting GraphQL statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("graphql_security".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("GraphQL Security Statistics");
        println!("===========================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_rate_limiting_findings(&self, args: RateLimitingFindingArgs) -> ScannerResult<()> {
        info!("Listing rate limiting findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("api_rate_limiting".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_rate_limiting_stats(&self, args: RateLimitingStatsArgs) -> ScannerResult<()> {
        info!("Getting rate limiting statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("api_rate_limiting".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("Rate Limiting Statistics");
        println!("========================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_access_control_findings(&self, args: AccessControlFindingArgs) -> ScannerResult<()> {
        info!("Listing access control findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("access_control".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_access_control_stats(&self, args: AccessControlStatsArgs) -> ScannerResult<()> {
        info!("Getting access control statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("access_control".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("Access Control Statistics");
        println!("=========================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_file_upload_findings(&self, args: FileUploadFindingArgs) -> ScannerResult<()> {
        info!("Listing file upload findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("file_upload".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_file_upload_stats(&self, args: FileUploadStatsArgs) -> ScannerResult<()> {
        info!("Getting file upload statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("file_upload".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("File Upload Statistics");
        println!("======================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_path_traversal_findings(&self, args: PathTraversalFindingArgs) -> ScannerResult<()> {
        info!("Listing path traversal findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("path_traversal".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_path_traversal_stats(&self, args: PathTraversalStatsArgs) -> ScannerResult<()> {
        info!("Getting path traversal statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("path_traversal".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("Path Traversal Statistics");
        println!("=========================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_sensitive_info_findings(&self, args: SensitiveInfoFindingArgs) -> ScannerResult<()> {
        info!("Listing sensitive info findings");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("sensitive_info".to_string()),
            ..Default::default()
        };
        let findings = self.storage.get_findings_filtered(filter, FindingSort::SeverityDesc, args.limit, args.offset).await?;
        self.output_findings(&findings)?;
        Ok(())
    }

    async fn cmd_security_sensitive_info_stats(&self, args: SensitiveInfoStatsArgs) -> ScannerResult<()> {
        info!("Getting sensitive info statistics");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            severity: args.severity.map(|s| s.into_iter().filter_map(|v| v.parse().ok()).collect()),
            plugin_source: Some("sensitive_info".to_string()),
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("Sensitive Information Statistics");
        println!("================================");
        println!("Total: {}", stats.total);
        println!("Verified: {}", stats.verified_count);
        println!("False Positives: {}", stats.false_positive_count);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Confidence:");
        for (confidence, count) in &stats.by_confidence {
            println!("  {}: {}", confidence, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        Ok(())
    }

    async fn cmd_security_injection_categories(&self) -> ScannerResult<()> {
        info!("Listing injection categories");
        println!("Available Injection Categories:");
        println!("===============================");
        println!("1. sql_injection - SQL Injection (CWE-89)");
        println!("2. nosql_injection - NoSQL Injection (CWE-943)");
        println!("3. xss - Cross-Site Scripting (CWE-79, CWE-80)");
        println!("4. ssti - Server-Side Template Injection (CWE-1336)");
        println!("5. command_injection - Command Injection (CWE-78)");
        println!("6. xxe - XML External Entity (CWE-611)");
        println!("7. ldap_injection - LDAP Injection (CWE-90)");
        println!("8. xpath_injection - XPath Injection (CWE-643)");
        println!("9. header_injection - HTTP Header Injection (CWE-113)");
        Ok(())
    }

    async fn cmd_security_detection_methods(&self) -> ScannerResult<()> {
        info!("Listing detection methods");
        println!("Available Detection Methods:");
        println!("============================");
        println!("1. error_based - Error-Based Detection (High reliability)");
        println!("2. boolean_based - Boolean-Based Blind (High reliability)");
        println!("3. time_based - Time-Based Blind (Medium reliability)");
        println!("4. reflection - Reflection-Based (Very High reliability)");
        println!("5. pattern_match - Pattern Matching (High reliability)");
        println!("6. differential - Differential Analysis (Medium reliability)");
        println!("7. out_of_band - Out-of-Band (Very High reliability)");
        println!("8. heuristic - Heuristic Analysis (Low reliability)");
        Ok(())
    }

    async fn cmd_security_summary(&self, args: SecuritySummaryArgs) -> ScannerResult<()> {
        info!("Getting security findings summary");
        let filter = FindingFilter {
            scan_id: args.scan_id,
            ..Default::default()
        };
        let stats = self.storage.get_finding_stats(filter).await?;
        
        println!("Security Findings Summary");
        println!("=========================");
        println!("Total Findings: {}", stats.total);
        println!("Verified: {}", stats.verified);
        println!("False Positives: {}", stats.false_positives);
        println!("Average Risk Score: {:.1}", stats.avg_risk_score);
        println!();
        println!("By Severity:");
        for (severity, count) in &stats.by_severity {
            println!("  {}: {}", severity, count);
        }
        println!();
        println!("By Category:");
        for (category, count) in &stats.by_category {
            println!("  {}: {}", category, count);
        }
        println!();
        println!("By Plugin:");
        for (plugin, count) in &stats.by_plugin {
            println!("  {}: {}", plugin, count);
        }
        Ok(())
    }

    // Config command implementations
    async fn cmd_config_show(&self) -> ScannerResult<()> {
        println!("Configuration show not implemented (placeholder)");
        Ok(())
    }

    async fn cmd_config_set(&self, args: ConfigSetArgs) -> ScannerResult<()> {
        println!("Config set: {} = {} (placeholder)", args.key, args.value);
        Ok(())
    }

    async fn cmd_config_get(&self, args: ConfigGetArgs) -> ScannerResult<()> {
        println!("Config get: {} (placeholder)", args.key);
        Ok(())
    }

    async fn cmd_config_reset(&self) -> ScannerResult<()> {
        println!("Config reset (placeholder)");
        Ok(())
    }

    // Server command implementations
    async fn cmd_server_start(&self, args: ServerStartArgs) -> ScannerResult<()> {
        info!("Starting server on {}:{}", args.host, args.port);
        println!("Server start not implemented (placeholder)");
        Ok(())
    }

    async fn cmd_server_status(&self) -> ScannerResult<()> {
        println!("Server status not implemented (placeholder)");
        Ok(())
    }

    // Output helpers
    fn output_scan(&self, scan: &ScanSession) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(scan),
            OutputFormat::Yaml => self.output_yaml(scan),
            OutputFormat::Table => {
                println!("Scan: {}", scan.id);
                println!("  Name: {}", scan.config.name);
                println!("  Status: {}", scan.status);
                println!("  Target: {}", scan.target.id);
                println!("  Progress: {:.1}%", scan.progress.progress_percent);
                println!("  Findings: {}", scan.findings.len());
                println!("  Created: {}", scan.created_at);
                Ok(())
            }
        }
    }

    fn output_scans(&self, scans: &[ScanSession]) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(scans),
            OutputFormat::Yaml => self.output_yaml(scans),
            OutputFormat::Table => {
                println!("{:<36} {:<30} {:<15} {:<10} {:<10}", "ID", "NAME", "STATUS", "PROGRESS", "FINDINGS");
                println!("{}", "-".repeat(101));
                for scan in scans {
                    println!("{:<36} {:<30} {:<15} {:<10.1} {:<10}",
                        scan.id.to_string(),
                        truncate(&scan.config.name, 30),
                        format!("{}", scan.status),
                        scan.progress.progress_percent,
                        scan.findings.len()
                    );
                }
                Ok(())
            }
        }
    }

    fn output_progress(&self, progress: &ScanProgress) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(progress),
            OutputFormat::Yaml => self.output_yaml(progress),
            OutputFormat::Table => {
                println!("Scan Progress: {}", progress.scan_id);
                println!("  Status: {}", progress.status);
                println!("  Plugins: {}/{}", progress.completed_plugins, progress.total_plugins);
                println!("  Current: {}", progress.current_plugin.as_deref().unwrap_or("none"));
                println!("  Findings: {}", progress.total_findings);
                println!("  Progress: {:.1}%", progress.progress_percent);
                println!("  Elapsed: {:?}", progress.elapsed);
                Ok(())
            }
        }
    }

    fn output_target(&self, target: &Target) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(target),
            OutputFormat::Yaml => self.output_yaml(target),
            OutputFormat::Table => {
                println!("Target: {}", target.id);
                println!("  Name: {}", target.metadata.name);
                println!("  Type: {}", target.target_type);
                println!("  URL: {}", target.metadata.base_url);
                println!("  Tags: {:?}", target.metadata.tags);
                println!("  Created: {}", target.created_at);
                Ok(())
            }
        }
    }

    fn output_targets(&self, targets: &[Target]) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(targets),
            OutputFormat::Yaml => self.output_yaml(targets),
            OutputFormat::Table => {
                println!("{:<36} {:<30} {:<20} {:<40}", "ID", "NAME", "TYPE", "URL");
                println!("{}", "-".repeat(126));
                for target in targets {
                    println!("{:<36} {:<30} {:<20} {:<40}",
                        target.id.to_string(),
                        truncate(&target.metadata.name, 30),
                        format!("{}", target.target_type),
                        truncate(&target.metadata.base_url.to_string(), 40)
                    );
                }
                Ok(())
            }
        }
    }

    fn output_plugin(&self, plugin: &PluginInfo) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(plugin),
            OutputFormat::Yaml => self.output_yaml(plugin),
            OutputFormat::Table => {
                println!("Plugin: {}", plugin.id);
                println!("  Name: {}", plugin.name);
                println!("  Version: {}", plugin.version);
                println!("  Status: {:?}", plugin.status);
                println!("  Capabilities: {}", plugin.capabilities.len());
                println!("  Tags: {:?}", plugin.tags);
                Ok(())
            }
        }
    }

    fn output_plugins(&self, plugins: &[PluginInfo]) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(plugins),
            OutputFormat::Yaml => self.output_yaml(plugins),
            OutputFormat::Table => {
                println!("{:<36} {:<30} {:<15} {:<15} {:<10}", "ID", "NAME", "VERSION", "STATUS", "CAPS");
                println!("{}", "-".repeat(106));
                for plugin in plugins {
                    println!("{:<36} {:<30} {:<15} {:<15} {:<10}",
                        plugin.id.to_string(),
                        truncate(&plugin.name, 30),
                        truncate(&plugin.version, 15),
                        format!("{:?}", plugin.status),
                        plugin.capabilities.len()
                    );
                }
                Ok(())
            }
        }
    }

    fn output_findings(&self, findings: &[Finding]) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(findings),
            OutputFormat::Yaml => self.output_yaml(findings),
            OutputFormat::Table => {
                println!("{:<36} {:<10} {:<10} {:<20} {:<40}", "ID", "SEVERITY", "CONFIDENCE", "CATEGORY", "TITLE");
                println!("{}", "-".repeat(116));
                for finding in findings {
                    println!("{:<36} {:<10} {:<10} {:<20} {:<40}",
                        finding.id.to_string(),
                        format!("{}", finding.severity),
                        format!("{}", finding.confidence),
                        truncate(&format!("{}", finding.category), 20),
                        truncate(&finding.title, 40)
                    );
                }
                Ok(())
            }
        }
    }

    fn output_logs(&self, logs: &[crate::scan::ScanLogEntry]) -> ScannerResult<()> {
        match self.format {
            OutputFormat::Json => self.output_json(logs),
            OutputFormat::Yaml => self.output_yaml(logs),
            OutputFormat::Table => {
                for log in logs {
                    println!("[{}] {} [{}] {}", log.timestamp.format("%H:%M:%S"), log.level, log.plugin.as_deref().unwrap_or("-"), log.message);
                }
                Ok(())
            }
        }
    }

    fn output_json<T: serde::Serialize>(&self, value: &T) -> ScannerResult<()> {
        println!("{}", serde_json::to_string_pretty(value)?);
        Ok(())
    }

    fn output_yaml<T: serde::Serialize>(&self, value: &T) -> ScannerResult<()> {
        println!("{}", serde_yaml::to_string(value)?);
        Ok(())
    }
}

/// Truncate string to max length
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Run the CLI application
pub async fn run_cli() -> ScannerResult<()> {
    let cli = Cli::parse();

    // Initialize tracing
    if cli.verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    // Create storage (in-memory for now)
    let storage = Arc::new(MemoryScanStorage::new());

    // Create target manager
    let target_manager = Arc::new(crate::target::TargetManager::new());

    // Create plugin manager (placeholder)
    // This would need a proper plugin directory
    let plugin_dir = std::path::PathBuf::from("./plugins");
    let plugin_manager = Arc::new(crate::plugin::PluginManager::new(plugin_dir)?);

    // Create scan manager (placeholder - needs queue manager)
    // For now, we'll use a mock
    // let scan_manager = Arc::new(ScanManager::new(...));

    // Create TUI app
    // let app = TuiApp::new(scan_manager, plugin_manager, storage, target_manager, cli.format);

    // Run command
    // app.run_command(cli.command).await?;

    println!("CLI structure ready - implementation pending core services");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_value() {
        assert_eq!(parse_key_value("key=value").unwrap(), ("key".to_string(), "value".to_string()));
        assert_eq!(parse_key_value("key=value=with=equals").unwrap(), ("key".to_string(), "value=with=equals".to_string()));
        assert!(parse_key_value("novalue").is_err());
    }

    #[test]
    fn test_truncate() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("very long string", 10), "very lon...");
        assert_eq!(truncate("exact", 5), "exact");
    }
}