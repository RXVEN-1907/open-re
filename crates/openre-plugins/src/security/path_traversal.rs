//! Directory traversal testing Security Plugin

use crate::{PluginManifest, SimplePluginMetadata};
use openre_core::Capability;

pub fn manifest() -> PluginManifest {
    let metadata = SimplePluginMetadata {
        name: "security-path_traversal".to_string(),
        version: "0.1.0".to_string(),
        description: "Directory traversal testing".to_string(),
        author: "open-re team".to_string(),
        license: "MIT".to_string(),
        repository: "https://github.com/RXVEN-1907/open-re".to_string(),
        homepage: None,
        categories: vec!["security".to_string(), "analysis".to_string()],
        keywords: vec!["security".to_string(), "path-traversal".to_string()],
    };

    PluginManifest::from_simple(
        metadata,
        vec![Capability::NetworkAccess, Capability::CallAi],
        vec![],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest() {
        let m = manifest();
        assert_eq!(m.name, "security-path_traversal");
        assert!(!m.plugin.capabilities.is_empty());
    }
}
