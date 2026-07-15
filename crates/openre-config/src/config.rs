//! Configuration structures for open-re

use figment::{Figment, providers::{Toml, Env, Json, Serialized, Format}};
use once_cell::sync::Lazy;
use openre_core::error::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::Duration;

static CONFIG: Lazy<RwLock<Option<Config>>> = Lazy::new(|| RwLock::new(None));

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub storage: StorageConfig,
    pub plugins: PluginConfig,
    pub ai: AiConfig,
    pub queue: QueueConfig,
    pub telemetry: TelemetryConfig,
    pub security: SecurityConfig,
    pub auth: AuthConfig,
}

impl Config {
    /// Load configuration from multiple sources with precedence:
    /// 1. Defaults
    /// 2. config.toml
    /// 3. config.local.toml (gitignored)
    /// 4. Environment variables (OPENRE_*)
    /// 5. config.local.json (gitignored)
    pub fn load() -> Result<Self> {
        let figment = Figment::new()
            .merge(Serialized::defaults(Self::default()))
            .merge(Toml::file("config.toml"))
            .merge(Toml::file("config.local.toml"))
            .merge(Env::prefixed("OPENRE_").split("__"))
            .merge(Json::file("config.local.json"));

        let config: Config = figment.extract().map_err(|e| openre_core::Error::Config(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Load and set as global config
    pub fn load_global() -> Result<()> {
        let config = Self::load()?;
        let mut guard = CONFIG.write().unwrap();
        *guard = Some(config);
        Ok(())
    }

    /// Get global config (must be loaded first)
    pub fn global() -> Config {
        CONFIG.read().unwrap().as_ref().expect("Config not loaded. Call Config::load_global() first.").clone()
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        self.server.validate()?;
        self.database.validate()?;
        self.redis.validate()?;
        self.storage.validate()?;
        self.plugins.validate()?;
        self.ai.validate()?;
        self.queue.validate()?;
        self.telemetry.validate()?;
        self.security.validate()?;
        self.auth.validate()?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            redis: RedisConfig::default(),
            storage: StorageConfig::default(),
            plugins: PluginConfig::default(),
            ai: AiConfig::default(),
            queue: QueueConfig::default(),
            telemetry: TelemetryConfig::default(),
            security: SecurityConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub request_timeout_secs: u64,
    pub body_limit_mb: usize,
    pub enable_cors: bool,
    pub cors_origins: Vec<String>,
    pub tls: Option<TlsConfig>,
}

impl ServerConfig {
    fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(openre_core::Error::Config("Server port cannot be 0".into()));
        }
        if self.workers == 0 {
            return Err(openre_core::Error::Config("Server workers cannot be 0".into()));
        }
        Ok(())
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".into(),
            port: 8080,
            workers: num_cpus::get(),
            request_timeout_secs: 30,
            body_limit_mb: 100,
            enable_cors: true,
            cors_origins: vec!["http://localhost:3000".into(), "http://localhost:5173".into()],
            tls: None,
        }
    }
}

/// TLS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub ca_path: Option<PathBuf>,
    pub client_ca_path: Option<PathBuf>,
    pub verify_client: bool,
}

/// Database configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
    pub run_migrations: bool,
}

impl DatabaseConfig {
    fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            return Err(openre_core::Error::Config("Database URL cannot be empty".into()));
        }
        if self.max_connections == 0 {
            return Err(openre_core::Error::Config("Max connections cannot be 0".into()));
        }
        Ok(())
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://openre:openre@localhost:5432/openre".into(),
            max_connections: 20,
            min_connections: 5,
            connect_timeout_secs: 10,
            idle_timeout_secs: 600,
            max_lifetime_secs: 1800,
            run_migrations: true,
        }
    }
}

/// Redis configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout_secs: u64,
    pub command_timeout_secs: u64,
    pub cluster_mode: bool,
}

impl RedisConfig {
    fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            return Err(openre_core::Error::Config("Redis URL cannot be empty".into()));
        }
        Ok(())
    }
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://localhost:6379".into(),
            max_connections: 50,
            connection_timeout_secs: 5,
            command_timeout_secs: 30,
            cluster_mode: false,
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub local_path: PathBuf,
    pub s3: Option<S3Config>,
    pub max_file_size_mb: u64,
    pub temp_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Local,
    S3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    pub use_path_style: bool,
}

impl StorageConfig {
    fn validate(&self) -> Result<()> {
        if self.max_file_size_mb == 0 {
            return Err(openre_core::Error::Config("Max file size cannot be 0".into()));
        }
        Ok(())
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Local,
            local_path: PathBuf::from("./data/storage"),
            s3: None,
            max_file_size_mb: 10240, // 10 GB
            temp_dir: PathBuf::from("./data/tmp"),
        }
    }
}

/// Plugin configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginConfig {
    pub local_plugin_dir: PathBuf,
    pub remote_registry: Option<RemoteRegistryConfig>,
    pub allow_native: bool,
    pub trusted_keys: Vec<String>,
    pub max_memory_mb: u64,
    pub max_fuel: u64,
    pub max_execution_time_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteRegistryConfig {
    pub url: String,
    pub name: String,
    pub auth_token: Option<String>,
    pub priority: i32,
}

impl PluginConfig {
    fn validate(&self) -> Result<()> {
        if self.max_memory_mb == 0 {
            return Err(openre_core::Error::Config("Plugin max memory cannot be 0".into()));
        }
        Ok(())
    }
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            local_plugin_dir: PathBuf::from("./plugins"),
            remote_registry: None,
            allow_native: false,
            trusted_keys: vec![],
            max_memory_mb: 256,
            max_fuel: 10_000_000,
            max_execution_time_secs: 300,
        }
    }
}

/// AI configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AiConfig {
    pub enabled: bool,
    pub local_first: bool,
    pub allow_remote: bool,
    pub allowed_remote_providers: Vec<String>,
    pub models_dir: PathBuf,
    pub onnx: OnnxConfig,
    pub llama_cpp: LlamaCppConfig,
    pub cache: CacheConfig,
    pub privacy: PrivacyConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OnnxConfig {
    pub threads: usize,
    pub providers: Vec<String>, // "cpu", "cuda", "tensorrt"
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LlamaCppConfig {
    pub gpu_layers: i32,
    pub context_size: usize,
    pub use_mlock: bool,
    pub use_mmap: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub memory_max_entries: usize,
    pub disk_max_size_mb: u64,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PrivacyConfig {
    pub redact_sensitive: bool,
    pub sensitive_patterns: Vec<String>,
    pub max_context_tokens: usize,
    pub audit_log: bool,
    pub local_only_mode: bool,
}

impl AiConfig {
    fn validate(&self) -> Result<()> {
        if self.onnx.threads == 0 {
            return Err(openre_core::Error::Config("ONNX threads cannot be 0".into()));
        }
        Ok(())
    }
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            local_first: true,
            allow_remote: false,
            allowed_remote_providers: vec![],
            models_dir: PathBuf::from("./models"),
            onnx: OnnxConfig {
                threads: num_cpus::get(),
                providers: vec!["cpu".into()],
            },
            llama_cpp: LlamaCppConfig {
                gpu_layers: 0,
                context_size: 4096,
                use_mlock: false,
                use_mmap: true,
            },
            cache: CacheConfig {
                enabled: true,
                memory_max_entries: 1000,
                disk_max_size_mb: 100,
                ttl_secs: 3600,
            },
            privacy: PrivacyConfig {
                redact_sensitive: true,
                sensitive_patterns: vec![
                    r"(?i)(password|secret|key|token|api_key)".into(),
                    r"[A-Za-z0-9+/]{40,}".into(),
                    r"[0-9a-f]{32,}".into(),
                ],
                max_context_tokens: 8192,
                audit_log: true,
                local_only_mode: false,
            },
        }
    }
}

/// Queue configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueueConfig {
    pub streams: QueueStreamsConfig,
    pub worker: WorkerConfig,
    pub autoscaler: AutoscalerConfig,
    pub retry: RetryConfig,
    pub scheduler: SchedulerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueueStreamsConfig {
    pub high: String,
    pub default: String,
    pub low: String,
    pub scheduled: String,
    pub dlq: String,
    pub events: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WorkerConfig {
    pub min_workers: usize,
    pub max_workers: usize,
    pub max_concurrent_jobs: usize,
    pub max_memory_mb: u64,
    pub heartbeat_interval_secs: u64,
    pub graceful_shutdown_timeout_secs: u64,
    pub target_queue_depth_per_worker: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AutoscalerConfig {
    pub enabled: bool,
    pub scale_up_threshold: f64,
    pub scale_down_threshold: f64,
    pub scale_up_cooldown_secs: u64,
    pub scale_down_cooldown_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
    pub exponential_base: f64,
    pub jitter: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SchedulerConfig {
    pub enabled: bool,
    pub check_interval_secs: u64,
}

impl QueueConfig {
    fn validate(&self) -> Result<()> {
        if self.worker.min_workers > self.worker.max_workers {
            return Err(openre_core::Error::Config("Min workers cannot exceed max workers".into()));
        }
        Ok(())
    }
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            streams: QueueStreamsConfig {
                high: "queue:analysis:high".into(),
                default: "queue:analysis:default".into(),
                low: "queue:analysis:low".into(),
                scheduled: "queue:analysis:scheduled".into(),
                dlq: "queue:analysis:dlq".into(),
                events: "queue:analysis:events".into(),
            },
            worker: WorkerConfig {
                min_workers: 3,
                max_workers: 20,
                max_concurrent_jobs: 4,
                max_memory_mb: 4096,
                heartbeat_interval_secs: 10,
                graceful_shutdown_timeout_secs: 60,
                target_queue_depth_per_worker: 10,
            },
            autoscaler: AutoscalerConfig {
                enabled: true,
                scale_up_threshold: 1.5,
                scale_down_threshold: 0.5,
                scale_up_cooldown_secs: 60,
                scale_down_cooldown_secs: 300,
            },
            retry: RetryConfig {
                max_attempts: 3,
                base_delay_secs: 5,
                max_delay_secs: 300,
                exponential_base: 2.0,
                jitter: true,
            },
            scheduler: SchedulerConfig {
                enabled: true,
                check_interval_secs: 10,
            },
        }
    }
}

/// Telemetry configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub tracing: TracingConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: LogFormat,
    pub output: LogOutput,
    pub file_path: Option<PathBuf>,
    pub max_file_size_mb: u64,
    pub max_files: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Text,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogOutput {
    Stdout,
    File,
    Both,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    pub enabled: bool,
    pub otlp_endpoint: Option<String>,
    pub service_name: String,
    pub sample_rate: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditConfig {
    pub enabled: bool,
    pub file_path: PathBuf,
    pub max_file_size_mb: u64,
    pub max_files: u32,
}

impl TelemetryConfig {
    fn validate(&self) -> Result<()> {
        if self.metrics.enabled && self.metrics.port == 0 {
            return Err(openre_core::Error::Config("Metrics port cannot be 0".into()));
        }
        Ok(())
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            logging: LoggingConfig {
                level: "info".into(),
                format: LogFormat::Json,
                output: LogOutput::Stdout,
                file_path: None,
                max_file_size_mb: 100,
                max_files: 10,
            },
            metrics: MetricsConfig {
                enabled: true,
                port: 9090,
                path: "/metrics".into(),
            },
            tracing: TracingConfig {
                enabled: true,
                otlp_endpoint: None,
                service_name: "openre".into(),
                sample_rate: 1.0,
            },
            audit: AuditConfig {
                enabled: true,
                file_path: PathBuf::from("./data/audit.log"),
                max_file_size_mb: 100,
                max_files: 100,
            },
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    pub rate_limiting: RateLimitingConfig,
    pub headers: SecurityHeadersConfig,
    pub encryption: EncryptionConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitingConfig {
    pub enabled: bool,
    pub global_rps: u64,
    pub per_ip_rps: u64,
    pub per_user_rps: u64,
    pub per_api_key_rps: u64,
    pub burst_multiplier: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityHeadersConfig {
    pub hsts_max_age_secs: u64,
    pub csp: String,
    pub frame_options: String,
    pub content_type_options: String,
    pub referrer_policy: String,
    pub permissions_policy: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptionConfig {
    pub algorithm: String,
    pub key_rotation_days: u32,
}

impl SecurityConfig {
    fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limiting: RateLimitingConfig {
                enabled: true,
                global_rps: 1000,
                per_ip_rps: 100,
                per_user_rps: 200,
                per_api_key_rps: 500,
                burst_multiplier: 1.5,
            },
            headers: SecurityHeadersConfig {
                hsts_max_age_secs: 31536000,
                csp: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'".into(),
                frame_options: "DENY".into(),
                content_type_options: "nosniff".into(),
                referrer_policy: "strict-origin-when-cross-origin".into(),
                permissions_policy: "geolocation=(), microphone=(), camera=()".into(),
            },
            encryption: EncryptionConfig {
                algorithm: "AES-256-GCM".into(),
                key_rotation_days: 90,
            },
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub jwt: JwtConfig,
    pub oidc: Option<OidcConfig>,
    pub api_keys: ApiKeyConfig,
    pub session: SessionConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub algorithm: String,
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    pub access_token_ttl_secs: u64,
    pub refresh_token_ttl_secs: u64,
    pub issuer: String,
    pub audience: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKeyConfig {
    pub prefix: String,
    pub default_scopes: Vec<String>,
    pub max_keys_per_user: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionConfig {
    pub cookie_name: String,
    pub cookie_secure: bool,
    pub cookie_http_only: bool,
    pub cookie_same_site: String,
    pub ttl_secs: u64,
}

impl AuthConfig {
    fn validate(&self) -> Result<()> {
        if self.jwt.algorithm != "RS256" {
            return Err(openre_core::Error::Config("JWT algorithm must be RS256".into()));
        }
        Ok(())
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig {
                algorithm: "RS256".into(),
                private_key_path: PathBuf::from("./keys/private.pem"),
                public_key_path: PathBuf::from("./keys/public.pem"),
                access_token_ttl_secs: 86400, // 24 hours
                refresh_token_ttl_secs: 604800, // 7 days
                issuer: "openre".into(),
                audience: "openre-api".into(),
            },
            oidc: None,
            api_keys: ApiKeyConfig {
                prefix: "ore_".into(),
                default_scopes: vec!["read".into(), "write".into()],
                max_keys_per_user: 10,
            },
            session: SessionConfig {
                cookie_name: "openre_session".into(),
                cookie_secure: false,
                cookie_http_only: true,
                cookie_same_site: "lax".into(),
                ttl_secs: 86400,
            },
        }
    }
}