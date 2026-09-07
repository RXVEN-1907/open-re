//! Scan configuration

use openre_config::ScannerConfig;
use std::path::PathBuf;
use url::Url;

#[derive(Debug)]
#[allow(dead_code)]
pub struct ScanConfig {
    pub target_str: String,
    pub profile: Option<crate::profiles::ScanProfile>,
    pub format: Option<crate::output::OutputFormat>,
    pub checks: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    #[allow(dead_code)]
    pub max_duration: Option<u64>,
    pub output: Option<PathBuf>,
    pub no_progress: bool,
    pub follow_redirects: Option<bool>,
    pub headers: Option<Vec<(String, String)>>,
    pub timeout: Option<u64>,
    pub max_redirects: Option<usize>,
    pub user_agent: Option<String>,
}

impl ScanConfig {
    pub fn resolve_target_url(&self) -> Result<Url, url::ParseError> {
        if self.target_str.starts_with("http://") || self.target_str.starts_with("https://") {
            self.target_str.parse::<Url>()
        } else {
            format!("https://{}", self.target_str).parse::<Url>()
        }
    }

    pub fn resolve_profile(
        &self,
        scanner_config: &ScannerConfig,
    ) -> crate::profiles::ScanProfile {
        self.profile.as_ref().cloned().unwrap_or_else(|| {
            match scanner_config.default_profile.as_str() {
                "quick" => crate::profiles::ScanProfile::Quick,
                "full" => crate::profiles::ScanProfile::Full,
                _ => crate::profiles::ScanProfile::Standard,
            }
        })
    }

    pub fn resolve_format(&self) -> crate::output::OutputFormat {
        self.format.clone().unwrap_or(crate::output::OutputFormat::Table)
    }
}