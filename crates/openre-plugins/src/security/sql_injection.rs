//! Sql Injection Security Plugin

use crate::{Capability, CapabilitySet, PluginManifest, PluginMetadata};

pub fn manifest() -> PluginManifest {
    PluginManifest {
        metadata: PluginMetadata {
            name: "security-sql_injection".to_string(),
            version: "0.1.0".to_string(),
            description: "SQLi detection and exploitation".to_string(),
            author: "open-re team".to_string(),
            license: "MIT".to_string(),
            repository: "https://github.com/RXVEN-1907/open-re".to_string(),
            homepage: None,
            categories: vec!["security".to_string(), "analysis".to_string()],
            keywords: vec!["security".to_string(), "sql-injection".to_string()],
        },
        required_capabilities: CapabilitySet::from_iter(vec![
            Capability::NetworkAccess,
            Capability::CallAi,
        ]),
        optional_capabilities: CapabilitySet::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest() {
        let m = manifest();
        assert_eq!(m.metadata.name, "security-sql_injection");
        assert!(!m.required_capabilities.all().next().is_none());
    }
}
