//! Performance optimizations - Caching and incremental operation

use crate::{error::IntelligenceError, types::*, IntelligenceResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Configuration for performance optimizations
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable in-memory caching
    pub enable_caching: bool,

    /// Default cache TTL in seconds
    pub default_cache_ttl_seconds: u64,

    /// Maximum cache size (number of entries)
    pub max_cache_size: usize,

    /// Enable incremental processing
    pub enable_incremental_processing: bool,

    /// Minimum time between cache cleanups (seconds)
    pub cache_cleanup_interval_seconds: u64,

    /// Enable result deduplication
    pub enable_deduplication: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_caching: true,
            default_cache_ttl_seconds: 3600, // 1 hour
            max_cache_size: 10000,
            enable_incremental_processing: true,
            cache_cleanup_interval_seconds: 300, // 5 minutes
            enable_deduplication: true,
        }
    }
}

/// Cache entry with TTL
#[derive(Debug, Clone)]
pub struct CacheEntry<T> {
    pub value: T,
    pub created_at: Instant,
    pub ttl: Duration,
}

impl<T> CacheEntry<T> {
    pub fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            created_at: Instant::now(),
            ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.ttl
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Performance optimizer with caching and incremental processing
pub struct PerformanceOptimizer {
    config: PerformanceConfig,
    cache: HashMap<String, CacheEntry<serde_json::Value>>,
    last_cleanup: Instant,
    hit_count: usize,
    miss_count: usize,
}

impl PerformanceOptimizer {
    /// Create a new performance optimizer with default configuration
    pub fn new() -> Self {
        Self {
            config: PerformanceConfig::default(),
            cache: HashMap::new(),
            last_cleanup: Instant::now(),
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Create a new performance optimizer with custom configuration
    pub fn with_config(config: PerformanceConfig) -> Self {
        Self {
            config,
            cache: HashMap::new(),
            last_cleanup: Instant::now(),
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Get a value from cache
    pub fn get_from_cache<T>(&mut self, key: &str) -> IntelligenceResult<Option<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        if !self.config.enable_caching {
            return Ok(None);
        }

        // Clean up expired entries periodically
        if self.last_cleanup.elapsed()
            > Duration::from_secs(self.config.cache_cleanup_interval_seconds)
        {
            self.cleanup_expired_entries();
            self.last_cleanup = Instant::now();
        }

        match self.cache.get(key) {
            Some(entry) => {
                if entry.is_expired() {
                    // Remove expired entry
                    self.cache.remove(key);
                    self.miss_count += 1;
                    Ok(None)
                } else {
                    // Return cached value
                    self.hit_count += 1;
                    let value: T = serde_json::from_value(entry.value.clone())
                        .map_err(|e| IntelligenceError::CacheSerializationError(e.to_string()))?;
                    Ok(Some(value))
                }
            }
            None => {
                self.miss_count += 1;
                Ok(None)
            }
        }
    }

    /// Put a value in cache
    pub fn put_in_cache<T>(&mut self, key: String, value: T) -> IntelligenceResult<()>
    where
        T: Serialize,
    {
        if !self.config.enable_caching {
            return Ok(());
        }

        // Check cache size limit
        if self.cache.len() >= self.config.max_cache_size {
            // Remove oldest entries to make space
            self.evict_oldest_entries(self.config.max_cache_size / 10); // Remove 10%
        }

        let serialized_value = serde_json::to_value(value)
            .map_err(|e| IntelligenceError::CacheSerializationError(e.to_string()))?;

        let ttl = Duration::from_secs(self.config.default_cache_ttl_seconds);
        let entry = CacheEntry::new(serialized_value, ttl);

        self.cache.insert(key, entry);
        Ok(())
    }

    /// Remove expired cache entries
    fn cleanup_expired_entries(&mut self) {
        let initial_size = self.cache.len();
        self.cache.retain(|_, entry| !entry.is_expired());

        let removed_count = initial_size - self.cache.len();
        if removed_count > 0 {
            debug!("Cleaned up {} expired cache entries", removed_count);
        }
    }

    /// Evict oldest entries to make space
    fn evict_oldest_entries(&mut self, count: usize) {
        let mut entries: Vec<(String, Duration)> = self
            .cache
            .iter()
            .map(|(key, entry)| (key.clone(), entry.age()))
            .collect();

        // Sort by age (oldest first)
        entries.sort_by(|a, b| b.1.cmp(&a.1));

        // Remove oldest entries
        for (key, _) in entries.into_iter().take(count) {
            self.cache.remove(&key);
        }

        debug!(
            "Evicted {} oldest cache entries",
            count.min(self.cache.len())
        );
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> CacheStats {
        let total_requests = self.hit_count + self.miss_count;
        let hit_rate = if total_requests > 0 {
            (self.hit_count as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        CacheStats {
            cache_size: self.cache.len(),
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            hit_rate,
            total_requests,
        }
    }

    /// Clear all cache entries
    pub fn clear_cache(&mut self) {
        self.cache.clear();
        self.hit_count = 0;
        self.miss_count = 0;
    }

    /// Enable or disable caching
    pub fn set_caching_enabled(&mut self, enabled: bool) {
        self.config.enable_caching = enabled;
        if !enabled {
            self.clear_cache();
        }
    }

    /// Deduplicate findings based on fingerprint
    pub fn deduplicate_findings(&self, findings: &mut Vec<crate::Finding>) -> usize {
        if !self.config.enable_deduplication {
            return 0;
        }

        let initial_count = findings.len();
        let mut seen_fingerprints = HashSet::new();
        let mut deduplicated = Vec::new();

        for finding in findings.drain(..) {
            // Use fingerprint for deduplication if available
            if let Some(fingerprint) = &finding.fingerprint {
                if seen_fingerprints.insert(fingerprint.clone()) {
                    deduplicated.push(finding);
                }
            } else {
                // If no fingerprint, use a combination of key fields
                let key = format!(
                    "{}:{}:{}:{:?}",
                    finding.title, finding.target, finding.category, finding.severity
                );

                if seen_fingerprints.insert(key) {
                    deduplicated.push(finding);
                }
            }
        }

        *findings = deduplicated;
        initial_count - findings.len()
    }

    /// Perform incremental processing by comparing fingerprints
    pub fn incremental_process(
        &self,
        previous_findings: &[crate::Finding],
        current_findings: &mut Vec<crate::Finding>,
    ) -> IncrementalProcessingResult {
        if !self.config.enable_incremental_processing {
            return IncrementalProcessingResult {
                new_findings: current_findings.clone(),
                unchanged_findings: vec![],
                removed_findings: vec![],
            };
        }

        // Create sets of fingerprints
        let previous_fingerprints: HashSet<&str> = previous_findings
            .iter()
            .filter_map(|f| f.fingerprint.as_deref())
            .collect();

        let current_fingerprints: HashSet<&str> = current_findings
            .iter()
            .filter_map(|f| f.fingerprint.as_deref())
            .collect();

        // Identify new, unchanged, and removed findings
        let mut new_findings = Vec::new();
        let mut unchanged_findings = Vec::new();
        let mut removed_fingerprints = Vec::new();

        // Process current findings
        for finding in current_findings.drain(..) {
            if let Some(fingerprint) = &finding.fingerprint {
                if previous_fingerprints.contains(fingerprint.as_str()) {
                    unchanged_findings.push(finding);
                } else {
                    new_findings.push(finding);
                }
            } else {
                // No fingerprint, treat as new
                new_findings.push(finding);
            }
        }

        // Identify removed findings
        for finding in previous_findings {
            if let Some(fingerprint) = &finding.fingerprint {
                if !current_fingerprints.contains(fingerprint.as_str()) {
                    removed_fingerprints.push(fingerprint.clone());
                }
            }
        }

        *current_findings = new_findings.clone();

        IncrementalProcessingResult {
            new_findings,
            unchanged_findings,
            removed_findings: removed_fingerprints,
        }
    }

    /// Generate performance report
    pub fn generate_performance_report(&self) -> String {
        let stats = self.get_cache_stats();
        let mut report = String::new();

        report.push_str("# Performance Report\n\n");

        report.push_str("## Cache Statistics\n");
        report.push_str(&format!("- Current cache size: {}\n", stats.cache_size));
        report.push_str(&format!("- Total requests: {}\n", stats.total_requests));
        report.push_str(&format!("- Cache hits: {}\n", stats.hit_count));
        report.push_str(&format!("- Cache misses: {}\n", stats.miss_count));
        report.push_str(&format!("- Hit rate: {:.2}%\n\n", stats.hit_rate));

        if stats.total_requests > 0 {
            if stats.hit_rate > 90.0 {
                report.push_str("✅ Cache performance is excellent\n");
            } else if stats.hit_rate > 75.0 {
                report.push_str("⚠️  Cache performance is good but could be improved\n");
            } else {
                report.push_str("❌ Cache performance needs improvement - consider increasing cache size or TTL\n");
            }
        }

        report
    }
}

/// Statistics about cache performance
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub cache_size: usize,
    pub hit_count: usize,
    pub miss_count: usize,
    pub hit_rate: f64,
    pub total_requests: usize,
}

/// Result of incremental processing
#[derive(Debug, Clone)]
pub struct IncrementalProcessingResult {
    pub new_findings: Vec<crate::Finding>,
    pub unchanged_findings: Vec<crate::Finding>,
    pub removed_findings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use openre_core::ids::{FindingId, ScanId};
    use openre_core::result::{Category, Confidence, Finding, Severity};
    use std::collections::HashMap;
    use std::thread;

    fn create_test_finding(title: &str, fingerprint: Option<&str>) -> Finding {
        Finding {
            id: FindingId::new_v4(),
            title: title.to_string(),
            description: "Test finding".to_string(),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: Category::Injection,
            target: "https://example.com".to_string(),
            target_type: "web".to_string(),
            evidence: Vec::new(),
            references: Vec::new(),
            plugin_source: "test".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: chrono::Utc::now(),
            scan_id: ScanId::new_v4(),
            metadata: HashMap::new(),
            tags: Vec::new(),
            verified: false,
            false_positive: false,
            risk_score: Some(60),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: Vec::new(),
            capec_ids: Vec::new(),
            mitre_attack_ids: Vec::new(),
            owasp_category: None,
            fingerprint: fingerprint.map(|s| s.to_string()),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    #[test]
    fn test_cache_put_get() {
        let mut optimizer = PerformanceOptimizer::new();
        let key = "test_key".to_string();
        let value = "test_value".to_string();

        // Put value in cache
        assert!(optimizer.put_in_cache(key.clone(), value.clone()).is_ok());

        // Get value from cache
        let cached_value: Option<String> = optimizer.get_from_cache(&key).unwrap();
        assert_eq!(cached_value, Some(value));

        // Check stats
        let stats = optimizer.get_cache_stats();
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 0);
    }

    #[test]
    fn test_cache_expiration() {
        let mut optimizer = PerformanceOptimizer::with_config(PerformanceConfig {
            default_cache_ttl_seconds: 1, // 1 second TTL
            ..Default::default()
        });

        let key = "expiring_key".to_string();
        let value = "expiring_value".to_string();

        // Put value in cache
        assert!(optimizer.put_in_cache(key.clone(), value).is_ok());

        // Wait for expiration
        thread::sleep(Duration::from_secs(2));

        // Try to get expired value
        let cached_value: Option<String> = optimizer.get_from_cache(&key).unwrap();
        assert_eq!(cached_value, None);

        // Check stats
        let stats = optimizer.get_cache_stats();
        assert_eq!(stats.hit_count, 0);
        assert_eq!(stats.miss_count, 1);
    }

    #[test]
    fn test_cache_eviction() {
        let mut optimizer = PerformanceOptimizer::with_config(PerformanceConfig {
            max_cache_size: 5,
            ..Default::default()
        });

        // Add more entries than cache can hold
        for i in 0..10 {
            let key = format!("key_{}", i);
            let value = format!("value_{}", i);
            optimizer.put_in_cache(key, value).unwrap();
        }

        // Cache should be at max size
        assert!(optimizer.cache.len() <= 5);
    }

    #[test]
    fn test_finding_deduplication() {
        let optimizer = PerformanceOptimizer::new();

        let mut findings = vec![
            create_test_finding("SQL Injection 1", Some("fingerprint-1")),
            create_test_finding("SQL Injection 2", Some("fingerprint-1")), // Duplicate
            create_test_finding("XSS", Some("fingerprint-2")),
            create_test_finding("Path Traversal", Some("fingerprint-3")),
            create_test_finding("Command Injection", Some("fingerprint-3")), // Duplicate
        ];

        let deduplicated_count = optimizer.deduplicate_findings(&mut findings);

        // Should have removed 2 duplicates
        assert_eq!(deduplicated_count, 2);
        assert_eq!(findings.len(), 3); // 5 original - 2 duplicates = 3

        // Check that we kept one of each unique fingerprint
        let fingerprints: Vec<&str> = findings
            .iter()
            .filter_map(|f| f.fingerprint.as_deref())
            .collect();

        assert!(fingerprints.contains(&"fingerprint-1"));
        assert!(fingerprints.contains(&"fingerprint-2"));
        assert!(fingerprints.contains(&"fingerprint-3"));
    }

    #[test]
    fn test_incremental_processing() {
        let optimizer = PerformanceOptimizer::new();

        // Create previous findings
        let previous_findings = vec![
            create_test_finding("Existing Issue 1", Some("existing-1")),
            create_test_finding("Existing Issue 2", Some("existing-2")),
            create_test_finding("Fixed Issue", Some("fixed-1")),
        ];

        // Create current findings
        let mut current_findings = vec![
            create_test_finding("Existing Issue 1", Some("existing-1")), // Unchanged
            create_test_finding("Existing Issue 2", Some("existing-2")), // Unchanged
            create_test_finding("New Issue 1", Some("new-1")),           // New
            create_test_finding("New Issue 2", Some("new-2")),           // New
        ];

        let result = optimizer.incremental_process(&previous_findings, &mut current_findings);

        // Should have 2 unchanged findings
        assert_eq!(result.unchanged_findings.len(), 2);

        // Should have 2 new findings
        assert_eq!(result.new_findings.len(), 2);

        // Should have 1 removed finding
        assert_eq!(result.removed_findings.len(), 1);
        assert_eq!(result.removed_findings[0], "fixed-1");

        // Current findings should now only contain new findings
        assert_eq!(current_findings.len(), 2);
    }

    #[test]
    fn test_cache_stats() {
        let mut optimizer = PerformanceOptimizer::new();

        // Perform some cache operations
        optimizer
            .put_in_cache("key1".to_string(), "value1".to_string())
            .unwrap();
        optimizer
            .put_in_cache("key2".to_string(), "value2".to_string())
            .unwrap();

        let _val1: Option<String> = optimizer.get_from_cache("key1").unwrap();
        let _val2: Option<String> = optimizer.get_from_cache("key2").unwrap();
        let _val3: Option<String> = optimizer.get_from_cache("key3").unwrap(); // Miss

        let stats = optimizer.get_cache_stats();
        assert_eq!(stats.hit_count, 2);
        assert_eq!(stats.miss_count, 1);
        assert_eq!(stats.total_requests, 3);
        assert!((stats.hit_rate - 66.67).abs() < 0.01); // Approximately 66.67%
    }
}
