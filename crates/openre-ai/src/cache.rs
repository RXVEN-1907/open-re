//! AI response cache for open-re

use crate::providers::*;
use openre_core::error::Result;
use openre_config::CacheConfig;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use sha2::{Sha256, Digest};

/// Multi-level cache for AI responses
pub struct AiCache {
    memory_cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    disk_cache_path: Option<PathBuf>,
    config: CacheConfig,
    stats: Arc<RwLock<CacheStats>>,
}

impl AiCache {
    pub fn new(config: CacheConfig) -> Result<Self> {
        let disk_cache_path = if config.disk_cache_enabled {
            Some(config.disk_cache_path.clone())
        } else {
            None
        };

        let cache = Self {
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            disk_cache_path,
            config,
            stats: Arc::new(RwLock::new(CacheStats::default())),
        };

        // Load disk cache if enabled
        if let Some(path) = &cache.disk_cache_path {
            cache.load_disk_cache(path).await?;
        }

        Ok(cache)
    }

    /// Generate cache key from request
    pub fn generate_key(&self, request: &CompletionRequest) -> String {
        let mut hasher = Sha256::new();
        
        // Hash messages
        for msg in &request.messages {
            if let Some(content) = &msg.content {
                hasher.update(content.as_bytes());
            }
            if let Some(tool_calls) = &msg.tool_calls {
                for tc in tool_calls {
                    hasher.update(tc.name.as_bytes());
                    hasher.update(tc.arguments.to_string().as_bytes());
                }
            }
        }

        // Hash tools
        if let Some(tools) = &request.tools {
            for tool in tools {
                hasher.update(tool.name.as_bytes());
                hasher.update(tool.parameters.to_string().as_bytes());
            }
        }

        // Hash parameters
        hasher.update(request.temperature.unwrap_or(0.7).to_le_bytes());
        hasher.update(request.max_tokens.unwrap_or(2048).to_le_bytes());
        hasher.update(request.top_p.unwrap_or(0.95).to_le_bytes());

        format!("{:x}", hasher.finalize())
    }

    /// Get cached response
    pub async fn get(&self, key: &str) -> Option<CompletionResponse> {
        // Check memory cache first
        {
            let cache = self.memory_cache.read().await;
            if let Some(entry) = cache.get(key) {
                if !entry.is_expired() {
                    self.record_hit().await;
                    return Some(entry.response.clone());
                }
            }
        }

        // Check disk cache
        if let Some(path) = &self.disk_cache_path {
            if let Some(response) = self.load_from_disk(path, key).await {
                self.record_hit().await;
                // Promote to memory cache
                self.put_memory(key, response.clone()).await;
                return Some(response);
            }
        }

        self.record_miss().await;
        None
    }

    /// Put response in cache
    pub async fn put(&self, key: &str, response: CompletionResponse) {
        self.put_memory(key, response.clone()).await;
        
        if self.config.disk_cache_enabled {
            if let Some(path) = &self.disk_cache_path {
                let _ = self.save_to_disk(path, key, &response).await;
            }
        }
    }

    async fn put_memory(&self, key: &str, response: CompletionResponse) {
        let mut cache = self.memory_cache.write().await;
        
        // Evict if over capacity
        if cache.len() >= self.config.max_memory_entries {
            self.evict_lru(&mut cache).await;
        }

        let entry = CacheEntry {
            response,
            created_at: chrono::Utc::now(),
            access_count: 0,
            last_accessed: chrono::Utc::now(),
        };

        cache.insert(key.to_string(), entry);
    }

    async fn evict_lru(&self, cache: &mut HashMap<String, CacheEntry>) {
        if let Some((key, _)) = cache.iter()
            .min_by_key(|(_, v)| v.last_accessed)
            .map(|(k, v)| (k.clone(), v.clone())) {
            cache.remove(&key);
        }
    }

    async fn load_disk_cache(&self, path: &PathBuf) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let data = tokio::fs::read(path).await?;
        let entries: HashMap<String, CacheEntry> = serde_json::from_slice(&data)?;
        
        let mut cache = self.memory_cache.write().await;
        for (key, entry) in entries {
            if !entry.is_expired() {
                cache.insert(key, entry);
            }
        }

        Ok(())
    }

    async fn save_to_disk(&self, path: &PathBuf, key: &str, response: &CompletionResponse) -> Result<()> {
        let cache = self.memory_cache.read().await;
        let data = serde_json::to_vec(&*cache)?;
        tokio::fs::write(path, data).await?;
        Ok(())
    }

    async fn load_from_disk(&self, path: &PathBuf, key: &str) -> Option<CompletionResponse> {
        let data = tokio::fs::read(path).await.ok()?;
        let entries: HashMap<String, CacheEntry> = serde_json::from_slice(&data).ok()?;
        entries.get(key).and_then(|e| if e.is_expired() { None } else { Some(e.response.clone()) })
    }

    async fn record_hit(&self) {
        self.stats.write().await.hits += 1;
    }

    async fn record_miss(&self) {
        self.stats.write().await.misses += 1;
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        self.stats.read().await.clone()
    }

    /// Clear cache
    pub async fn clear(&self) {
        self.memory_cache.write().await.clear();
        if let Some(path) = &self.disk_cache_path {
            let _ = tokio::fs::remove_file(path).await;
        }
        *self.stats.write().await = CacheStats::default();
    }
}

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    response: CompletionResponse,
    created_at: chrono::DateTime<chrono::Utc>,
    access_count: u64,
    last_accessed: chrono::DateTime<chrono::Utc>,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        let ttl = chrono::Duration::hours(24); // Default TTL
        chrono::Utc::now() - self.created_at > ttl
    }
}

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub memory_entries: usize,
    pub disk_size_bytes: u64,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
}

/// Streaming response cache
pub struct StreamingCache {
    cache: Arc<RwLock<HashMap<String, Vec<StreamChunk>>>>,
}

impl StreamingCache {
    pub fn new() -> Self {
        Self { cache: Arc::new(RwLock::new(HashMap::new())) }
    }

    pub async fn get(&self, key: &str) -> Option<Vec<StreamChunk>> {
        self.cache.read().await.get(key).cloned()
    }

    pub async fn put(&self, key: &str, chunks: Vec<StreamChunk>) {
        self.cache.write().await.insert(key.to_string(), chunks);
    }

    pub async fn append(&self, key: &str, chunk: StreamChunk) {
        self.cache.write().await.entry(key.to_string()).or_default().push(chunk);
    }
}

impl Default for StreamingCache {
    fn default() -> Self {
        Self::new()
    }
}