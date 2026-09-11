//! Scan profiles

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    Quick,
    #[default]
    Standard,
    Full,
}

impl std::fmt::Display for ScanProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanProfile::Quick => write!(f, "quick"),
            ScanProfile::Standard => write!(f, "standard"),
            ScanProfile::Full => write!(f, "full"),
        }
    }
}

impl std::str::FromStr for ScanProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "quick" => Ok(ScanProfile::Quick),
            "standard" => Ok(ScanProfile::Standard),
            "full" => Ok(ScanProfile::Full),
            _ => Err(format!("Invalid scan profile: {}", s)),
        }
    }
}
