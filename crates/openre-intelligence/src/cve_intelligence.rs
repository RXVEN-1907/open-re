//! CVE Intelligence - Match software versions against vulnerability databases

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use async_trait::async_trait;
use openre_core::result::{Evidence, Finding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Trait for CVE data providers
#[async_trait]
pub trait CveProvider: Send + Sync {
    /// Get CVE information by ID
    async fn get_cve(&self, cve_id: &str) -> IntelligenceResult<Option<CveInfo>>;

    /// Search for CVEs affecting a specific software version
    async fn search_cves_for_software(
        &self,
        software_name: &str,
        version: &str,
    ) -> IntelligenceResult<Vec<CveInfo>>;

    /// Get provider name for logging/debugging
    fn provider_name(&self) -> &str;
}

/// Configuration for CVE intelligence
#[derive(Debug, Clone)]
pub struct CveIntelligenceConfig {
    /// Enable caching of CVE data
    pub enable_caching: bool,

    /// Cache TTL in seconds (default: 1 hour)
    pub cache_ttl_seconds: u64,

    /// Maximum number of concurrent requests
    pub max_concurrent_requests: usize,
}

impl Default for CveIntelligenceConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            cache_ttl_seconds: 3600, // 1 hour
            max_concurrent_requests: 5,
        }
    }
}

/// CVE Intelligence system
pub struct CveIntelligence {
    providers: Vec<Arc<dyn CveProvider>>,
    config: CveIntelligenceConfig,
    cache: Option<std::sync::RwLock<CveCache>>,
}

/// In-memory cache for CVE data
#[derive(Debug)]
struct CveCache {
    entries: HashMap<String, CachedCveEntry>,
    ttl_seconds: u64,
}

/// Cached CVE entry with timestamp
#[derive(Debug, Clone)]
struct CachedCveEntry {
    cve_info: CveInfo,
    cached_at: std::time::SystemTime,
}

impl CveCache {
    fn new(ttl_seconds: u64) -> Self {
        Self {
            entries: HashMap::new(),
            ttl_seconds,
        }
    }

    fn get(&self, key: &str) -> Option<&CveInfo> {
        if let Some(entry) = self.entries.get(key) {
            if let Ok(elapsed) = entry.cached_at.elapsed() {
                if elapsed.as_secs() < self.ttl_seconds {
                    return Some(&entry.cve_info);
                }
            }
        }
        None
    }

    fn insert(&mut self, key: String, cve_info: CveInfo) {
        self.entries.insert(
            key,
            CachedCveEntry {
                cve_info,
                cached_at: std::time::SystemTime::now(),
            },
        );
    }

    fn clear_expired(&mut self) {
        let ttl = self.ttl_seconds;
        self.entries.retain(|_, entry| {
            if let Ok(elapsed) = entry.cached_at.elapsed() {
                elapsed.as_secs() < ttl
            } else {
                false
            }
        });
    }
}

impl CveIntelligence {
    /// Create a new CVE intelligence system
    pub fn new(config: CveIntelligenceConfig) -> Self {
        let cache = if config.enable_caching {
            Some(std::sync::RwLock::new(CveCache::new(
                config.cache_ttl_seconds,
            )))
        } else {
            None
        };

        Self {
            providers: Vec::new(),
            config,
            cache,
        }
    }

    /// Add a CVE provider
    pub fn add_provider(&mut self, provider: Arc<dyn CveProvider>) {
        self.providers.push(provider);
    }

    /// Number of registered CVE providers
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Match findings against known CVEs based on evidence
    pub async fn match_findings_against_cves(
        &self,
        findings: &[Finding],
    ) -> IntelligenceResult<Vec<(Finding, Vec<CveInfo>)>> {
        let mut results = Vec::new();

        // Clear expired cache entries periodically
        if let Some(cache) = &self.cache {
            cache.write().unwrap().clear_expired();
        }

        for finding in findings {
            let cves = self.match_finding_against_cves(finding).await?;
            if !cves.is_empty() {
                results.push((finding.clone(), cves));
            }
        }

        Ok(results)
    }

    /// Match a single finding against known CVEs
    async fn match_finding_against_cves(
        &self,
        finding: &Finding,
    ) -> IntelligenceResult<Vec<CveInfo>> {
        let mut all_cves = Vec::new();

        // Extract software/version information from evidence
        let software_versions = self.extract_software_versions(finding);

        for (software_name, version) in software_versions {
            // Check cache first
            if let Some(cache) = &self.cache {
                let cache_key = format!("{}:{}", software_name, version);
                if let Some(cached_cves) = cache.read().unwrap().get(&cache_key) {
                    all_cves.push(cached_cves.clone());
                    continue;
                }
            }

            // Try each provider to find CVEs for this software/version
            for provider in &self.providers {
                match provider
                    .search_cves_for_software(&software_name, &version)
                    .await
                {
                    Ok(mut cves) => {
                        if !cves.is_empty() {
                            info!(
                                "Found {} CVEs for {} {} from {}",
                                cves.len(),
                                software_name,
                                version,
                                provider.provider_name()
                            );

                            // Cache the results
                            if let Some(cache) = &self.cache {
                                let mut cache = cache.write().unwrap();
                                for cve in &cves {
                                    cache.insert(format!("{}:{}", cve.cve_id, "info"), cve.clone());
                                }
                                cache.insert(
                                    format!("{}:{}", software_name, version),
                                    cves.first().unwrap().clone(),
                                ); // Cache first result as indicator
                            }

                            all_cves.append(&mut cves);
                            break; // Move to next software/version combination
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Error searching CVEs for {} {} from {}: {}",
                            software_name,
                            version,
                            provider.provider_name(),
                            e
                        );
                    }
                }
            }
        }

        // Remove duplicates by CVE ID
        all_cves.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
        all_cves.dedup_by(|a, b| a.cve_id == b.cve_id);

        Ok(all_cves)
    }

    /// Extract software and version information from finding evidence
    fn extract_software_versions(&self, finding: &Finding) -> Vec<(String, String)> {
        let mut software_versions = Vec::new();

        // Look through evidence for server headers, technology detection, etc.
        for evidence in &finding.evidence {
            if let Some(data) = &evidence.data {
                // Try to extract from JSON data
                if let Some(server_info) = data.get("server") {
                    if let Some(server_str) = server_info.as_str() {
                        if let Some((name, version)) = self.parse_software_version(server_str) {
                            software_versions.push((name, version));
                        }
                    }
                }

                if let Some(tech_info) = data.get("technology") {
                    if let Some(tech_str) = tech_info.as_str() {
                        if let Some((name, version)) = self.parse_software_version(tech_str) {
                            software_versions.push((name, version));
                        }
                    }
                }

                // Look for specific technology detection fields
                if let Some(framework) = data.get("framework") {
                    if let Some(version) = data.get("version") {
                        if let (Some(fw_str), Some(ver_str)) =
                            (framework.as_str(), version.as_str())
                        {
                            software_versions.push((fw_str.to_string(), ver_str.to_string()));
                        }
                    }
                }
            }

            // Also check description and location for version strings
            if let Some(location) = &evidence.location {
                if let Some((name, version)) = self.parse_software_version(location) {
                    software_versions.push((name, version));
                }
            }
        }

        // Check finding metadata for technology information
        for (key, value) in &finding.metadata {
            if key.starts_with("tech_") || key == "technology" || key == "framework" {
                if let Some(value_str) = value.as_str() {
                    if let Some((name, version)) = self.parse_software_version(value_str) {
                        software_versions.push((name, version));
                    }
                }
            }
        }

        software_versions
    }

    /// Parse software name and version from a string like "Apache/2.4.52" or "nginx/1.20.1"
    fn parse_software_version(&self, input: &str) -> Option<(String, String)> {
        // Common patterns: "Software/Version", "Software Version", etc.
        let patterns = [
            r#"^([a-zA-Z0-9_\-\.]+)/([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9]+)?)$"#,
            r#"^([a-zA-Z0-9_\-\.]+)\s+([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9]+)?)$"#,
        ];

        for pattern in &patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                if let Some(captures) = regex.captures(input.trim()) {
                    if captures.len() >= 3 {
                        let name = captures.get(1)?.as_str().to_string();
                        let version = captures.get(2)?.as_str().to_string();
                        return Some((name, version));
                    }
                }
            }
        }

        None
    }

    /// Get detailed CVE information by ID
    pub async fn get_cve_details(&self, cve_id: &str) -> IntelligenceResult<Option<CveInfo>> {
        // Check cache first
        if let Some(cache) = &self.cache {
            if let Some(cached_cve) = cache.read().unwrap().get(&format!("{}:{}", cve_id, "info")) {
                return Ok(Some(cached_cve.clone()));
            }
        }

        // Try each provider
        for provider in &self.providers {
            match provider.get_cve(cve_id).await {
                Ok(Some(cve_info)) => {
                    // Cache the result
                    if let Some(cache) = &self.cache {
                        cache
                            .write()
                            .unwrap()
                            .insert(format!("{}:{}", cve_id, "info"), cve_info.clone());
                    }
                    return Ok(Some(cve_info));
                }
                Ok(None) => continue,
                Err(e) => {
                    warn!(
                        "Error getting CVE {} from {}: {}",
                        cve_id,
                        provider.provider_name(),
                        e
                    );
                }
            }
        }

        Ok(None)
    }

    /// Enrich findings with CVE information
    pub async fn enrich_findings_with_cve_data(
        &self,
        findings: &mut [Finding],
    ) -> IntelligenceResult<()> {
        for finding in findings {
            let cves = self.match_finding_against_cves(finding).await?;

            if !cves.is_empty() {
                // Add CVE references to the finding
                for cve in &cves {
                    finding.references.push(openre_core::result::Reference {
                        reference_type: openre_core::result::ReferenceType::Cve,
                        title: format!("CVE-{}", cve.cve_id),
                        url: format!("https://nvd.nist.gov/vuln/detail/{}", cve.cve_id),
                        description: Some(cve.description.clone()),
                    });

                    // Add CWE IDs if not already present
                    for cwe_id in &cve.cwe_ids {
                        if !finding.cwe_ids.contains(cwe_id) {
                            finding.cwe_ids.push(cwe_id.clone());
                        }
                    }

                    // Update severity if CVE is more severe
                    if let Some(cvss_score) = cve.cvss_score {
                        let cve_severity = match cvss_score {
                            0.1..=3.9 => openre_core::result::Severity::Low,
                            4.0..=6.9 => openre_core::result::Severity::Medium,
                            7.0..=8.9 => openre_core::result::Severity::High,
                            9.0..=10.0 => openre_core::result::Severity::Critical,
                            _ => finding.severity,
                        };

                        if cve_severity.value() > finding.severity.value() {
                            finding.severity = cve_severity;
                        }

                        // Update risk score if higher
                        let cvss_risk_score = (cvss_score * 10.0) as u8;
                        if Some(cvss_risk_score) > finding.risk_score {
                            finding.risk_score = Some(cvss_risk_score);
                        }
                    }
                }

                // Add metadata about CVE matching
                finding.metadata.insert(
                    "cve_intelligence_matched".to_string(),
                    serde_json::Value::Bool(true),
                );
                finding.metadata.insert(
                    "cve_intelligence_count".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(cves.len())),
                );
            }
        }

        Ok(())
    }
}

/// Mock CVE provider for testing
#[derive(Debug)]
pub struct MockCveProvider {
    cve_database: HashMap<String, CveInfo>,
}

impl MockCveProvider {
    pub fn new() -> Self {
        let mut database = HashMap::new();

        // Add some test CVEs
        database.insert(
            "CVE-2023-12345".to_string(),
            CveInfo {
                cve_id: "CVE-2023-12345".to_string(),
                severity: openre_core::result::Severity::High,
                cvss_score: Some(7.5),
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                description:
                    "Apache HTTP Server 2.4.52 and earlier has a denial of service vulnerability."
                        .to_string(),
                affected_versions: vec![VersionRange {
                    start_version: Some("0.0.0".to_string()),
                    end_version: Some("2.4.53".to_string()),
                    is_vulnerable: true,
                }],
                fixed_versions: vec!["2.4.53".to_string()],
                references: vec![CveReference {
                    url: "https://httpd.apache.org/security/vulnerabilities_24.html".to_string(),
                    description: Some("Apache HTTP Server Security Vulnerabilities".to_string()),
                }],
                cwe_ids: vec!["CWE-400".to_string()],
                published_date: chrono::Utc::now(),
                last_modified_date: chrono::Utc::now(),
            },
        );

        Self {
            cve_database: database,
        }
    }
}

#[async_trait]
impl CveProvider for MockCveProvider {
    fn provider_name(&self) -> &str {
        "MockCVE"
    }

    async fn get_cve(&self, cve_id: &str) -> IntelligenceResult<Option<CveInfo>> {
        Ok(self.cve_database.get(cve_id).cloned())
    }

    async fn search_cves_for_software(
        &self,
        software_name: &str,
        version: &str,
    ) -> IntelligenceResult<Vec<CveInfo>> {
        let mut results = Vec::new();

        // Simple mock matching - in reality this would be more sophisticated
        if software_name.to_lowercase().contains("apache") && version.starts_with("2.4.") {
            // Parse version to check if it's vulnerable
            let version_parts: Vec<&str> = version.split('.').collect();
            if version_parts.len() >= 3 {
                if let Ok(minor_version) = version_parts[2].parse::<u32>() {
                    if minor_version <= 52 {
                        if let Some(cve) = self.cve_database.get("CVE-2023-12345") {
                            results.push(cve.clone());
                        }
                    }
                }
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Evidence, EvidenceType, Finding, Severity};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_cve_matching() {
        let mut cve_intel = CveIntelligence::new(CveIntelligenceConfig::default());
        cve_intel.add_provider(Arc::new(MockCveProvider::new()));

        // Create a finding with Apache evidence
        let mut metadata = HashMap::new();
        metadata.insert(
            "technology".to_string(),
            serde_json::Value::String("Apache/2.4.50".to_string()),
        );

        let evidence = Evidence {
            evidence_type: EvidenceType::HttpRequest,
            description: "HTTP response with Server header".to_string(),
            data: Some(serde_json::json!({
                "server": "Apache/2.4.50"
            })),
            location: Some("https://example.com".to_string()),
            metadata,
            http_request: None,
            http_response: None,
            timing: None,
            payload: None,
            reproduction_steps: None,
            plugin_source: Some("test".to_string()),
            timestamp: Utc::now(),
        };

        let finding = Finding {
            id: FindingId::new(),
            title: "Web Server Fingerprint".to_string(),
            description: "Identified web server technology".to_string(),
            severity: Severity::Info,
            confidence: Confidence::High,
            category: Category::InformationDisclosure,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            evidence: vec![evidence],
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(20),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: Some("test-fingerprint".to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        };

        let results = cve_intel
            .match_findings_against_cves(&[finding])
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        let (_, cves) = &results[0];
        assert_eq!(cves.len(), 1);
        assert_eq!(cves[0].cve_id, "CVE-2023-12345");
    }

    #[tokio::test]
    async fn test_cve_details() {
        let mut cve_intel = CveIntelligence::new(CveIntelligenceConfig::default());
        cve_intel.add_provider(Arc::new(MockCveProvider::new()));

        let cve_info = cve_intel.get_cve_details("CVE-2023-12345").await.unwrap();
        assert!(cve_info.is_some());
        assert_eq!(cve_info.unwrap().cve_id, "CVE-2023-12345");
    }
}
