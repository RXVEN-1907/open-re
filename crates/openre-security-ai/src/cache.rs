//! Analysis cache for caching AI analysis results with fingerprint-based invalidation

use crate::{AiAnalystError, AiResult};
use dashmap::DashMap;
use openre_core::ids::{FindingId, ScanId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Task type for caching
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TaskType {
    ExplainFinding,
    GenerateRemediation,
    CorrelateFindings,
    PrioritizeFindings,
    ExecutiveSummary,
    NaturalLanguageQuery,
    CompareScans,
}

/// Cache key combining scan, finding, task type, and template version
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AnalysisKey {
    pub scan_id: ScanId,
    pub finding_id: Option<FindingId>, // None for cross-finding tasks like prioritize/correlation
    pub task_type: TaskType,
    pub template_version: String,
}

/// Cached entry with TTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedEntry {
    /// Serialized result data
    pub data: String,

    /// Timestamp when cached
    pub cached_at: SystemTime,

    /// Time-to-live duration
    pub ttl: Duration,

    /// Model information for reproducibility
    pub model_info: Option<String>,
}

impl CachedEntry {
    /// Check if entry is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        if let Ok(elapsed) = self.cached_at.elapsed() {
            elapsed < self.ttl
        } else {
            false
        }
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Option<Duration> {
        if let Ok(elapsed) = self.cached_at.elapsed() {
            self.ttl.checked_sub(elapsed)
        } else {
            None
        }
    }
}

/// Analysis cache for storing and retrieving AI analysis results
pub struct AnalysisCache {
    /// Cache entries keyed by AnalysisKey
    entries: Arc<DashMap<AnalysisKey, CachedEntry>>,

    /// Default TTL for cache entries
    default_ttl: Duration,

    /// Maximum number of entries
    max_entries: usize,
}

impl AnalysisCache {
    /// Create a new analysis cache
    pub fn new(max_entries: usize, default_ttl_seconds: u64) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            default_ttl: Duration::from_secs(default_ttl_seconds),
            max_entries,
        }
    }

    /// Get cached result if still valid
    pub async fn get(&self, key: &AnalysisKey) -> Option<String> {
        if let Some(entry) = self.entries.get(key) {
            if entry.is_valid() {
                Some(entry.data.clone())
            } else {
                // Remove expired entry
                self.entries.remove(key);
                None
            }
        } else {
            None
        }
    }

    /// Store a new result in cache
    pub async fn put(
        &self,
        key: AnalysisKey,
        data: String,
        model_info: Option<String>,
    ) -> AiResult<()> {
        // Check if we need to evict entries
        if self.entries.len() >= self.max_entries {
            self.evict_lru();
        }

        let entry = CachedEntry {
            data,
            cached_at: SystemTime::now(),
            ttl: self.default_ttl,
            model_info,
        };

        self.entries.insert(key, entry);
        Ok(())
    }

    /// Invalidate cache entries for a specific finding
    pub async fn invalidate_finding(&self, scan_id: ScanId, finding_id: FindingId) {
        let keys_to_remove: Vec<AnalysisKey> = self
            .entries
            .iter()
            .filter(|entry| {
                let key = entry.key();
                key.scan_id == scan_id && key.finding_id == Some(finding_id)
            })
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.entries.remove(&key);
        }
    }

    /// Invalidate all cache entries for a specific scan
    pub async fn invalidate_scan(&self, scan_id: ScanId) {
        let keys_to_remove: Vec<AnalysisKey> = self
            .entries
            .iter()
            .filter(|entry| entry.key().scan_id == scan_id)
            .map(|entry| entry.key().clone())
            .collect();

        for key in keys_to_remove {
            self.entries.remove(&key);
        }
    }

    /// Evict least recently used entries when cache is full
    fn evict_lru(&self) {
        // Simple approach: remove oldest entries
        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|entry| (entry.key().clone(), entry.cached_at))
            .collect();

        // Sort by timestamp (oldest first)
        entries.sort_by_key(|(_, timestamp)| *timestamp);

        // Remove oldest entries to make space
        let entries_to_remove = entries.len().saturating_sub(self.max_entries / 2);
        for (key, _) in entries.into_iter().take(entries_to_remove) {
            self.entries.remove(&key);
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let total_entries = self.entries.len();
        let mut expired_entries = 0;

        for entry in self.entries.iter() {
            if !entry.is_valid() {
                expired_entries += 1;
            }
        }

        CacheStats {
            total_entries,
            expired_entries,
            active_entries: total_entries.saturating_sub(expired_entries),
            max_entries: self.max_entries,
        }
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        self.entries.clear();
    }

    /// Get entry metadata without the data
    pub async fn get_metadata(&self, key: &AnalysisKey) -> Option<CacheEntryMetadata> {
        self.entries.get(key).map(|entry| CacheEntryMetadata {
            cached_at: entry.cached_at,
            ttl: entry.ttl,
            remaining_ttl: entry.remaining_ttl(),
            is_valid: entry.is_valid(),
            model_info: entry.model_info.clone(),
        })
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub active_entries: usize,
    pub max_entries: usize,
}

/// Metadata about a cache entry
#[derive(Debug, Clone)]
pub struct CacheEntryMetadata {
    pub cached_at: SystemTime,
    pub ttl: Duration,
    pub remaining_ttl: Option<Duration>,
    pub is_valid: bool,
    pub model_info: Option<String>,
}

impl Default for AnalysisCache {
    fn default() -> Self {
        Self::new(1000, 3600) // 1000 entries, 1 hour TTL
    }
}
