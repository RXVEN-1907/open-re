//! Scanner API types for openre-scan library

use openre_core::result::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;
use thiserror::Error;

mod url_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use url::Url;

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(url.as_str())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Scan target with configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTarget {
    /// Target URL
    #[serde(with = "url_serde")]
    pub url: Url,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirect depth
    pub max_redirects: usize,
    /// Custom headers
    pub headers: Vec<(String, String)>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Proxy URL
    pub proxy: Option<String>,
    /// Rate limit (requests per second)
    pub rate_limit: Option<f64>,
}

impl ScanTarget {
    pub fn new(url: &str) -> Result<Self, url::ParseError> {
        let url = if url.starts_with("http://") || url.starts_with("https://") {
            url.parse::<Url>()?
        } else {
            format!("https://{}", url).parse::<Url>()?
        };
        Ok(Self {
            url,
            timeout: 30,
            follow_redirects: true,
            max_redirects: 10,
            headers: Vec::new(),
            user_agent: None,
            proxy: None,
            rate_limit: None,
        })
    }

    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    pub fn with_max_redirects(mut self, max: usize) -> Self {
        self.max_redirects = max;
        self
    }

    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    pub fn with_user_agent(mut self, ua: String) -> Self {
        self.user_agent = Some(ua);
        self
    }

    pub fn with_proxy(mut self, proxy: String) -> Self {
        self.proxy = Some(proxy);
        self
    }

    pub fn with_rate_limit(mut self, rate: f64) -> Self {
        self.rate_limit = Some(rate);
        self
    }
}

/// Scan result containing findings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique scan ID
    pub scan_id: uuid::Uuid,
    /// Target URL
    pub target: String,
    /// Scan profile used
    pub profile: crate::profiles::ScanProfile,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Number of checks run
    pub checks_run: usize,
    /// Findings discovered
    pub findings: Vec<openre_core::result::Finding>,
    /// Severity counts
    pub severity_counts: HashMap<String, usize>,
}

impl ScanResult {
    pub fn new(target: String, profile: crate::profiles::ScanProfile, findings: Vec<openre_core::result::Finding>, duration_ms: u64) -> Self {
        let mut severity_counts = HashMap::new();
        for f in &findings {
            *severity_counts.entry(f.severity.to_string()).or_insert(0) += 1;
        }
        Self {
            scan_id: uuid::Uuid::new_v4(),
            target,
            profile,
            duration_ms,
            checks_run: 0, // Will be set by caller
            findings,
            severity_counts,
        }
    }
}

/// Scan error types
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
    #[error("Scan timeout after {0} seconds")]
    Timeout(u64),
    #[error("Too many redirects (max: {0})")]
    TooManyRedirects(usize),
    #[error("Scan failed: {0}")]
    Failed(String),
}

/// Scanner for running security scans
pub struct Scanner {
    profile: crate::profiles::ScanProfile,
}

impl Scanner {
    pub fn new(profile: crate::profiles::ScanProfile) -> Result<Self, ScanError> {
        Ok(Self { profile })
    }

    pub async fn scan(&mut self, target: ScanTarget) -> Result<ScanResult, ScanError> {
        let findings = crate::runner::run_scan_internal(
            target.url.to_string(),
            self.profile,
            crate::output::OutputFormat::Table,
            target.timeout,
            target.max_redirects,
            target.user_agent.clone().unwrap_or_default(),
        ).await?;

        Ok(ScanResult::new(
            target.url.to_string(),
            self.profile,
            findings,
            0, // duration will be calculated by caller
        ))
    }
}

impl Default for ScanResult {
    fn default() -> Self {
        Self {
            scan_id: uuid::Uuid::new_v4(),
            target: String::new(),
            profile: crate::profiles::ScanProfile::default(),
            duration_ms: 0,
            checks_run: 0,
            findings: Vec::new(),
            severity_counts: HashMap::new(),
        }
    }
}