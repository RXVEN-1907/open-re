//! Object storage (S3-compatible) for open-re

use openre_config::{StorageConfig, S3Config, StorageBackend};
use openre_core::error::Result;
use openre_core::ids::FileId;
use openre_telemetry::metrics;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

/// Object store for binary and artifact storage
#[derive(Clone)]
pub struct ObjectStore {
    config: StorageConfig,
    local_base: PathBuf,
}

impl ObjectStore {
    /// Create a new object store
    pub async fn new(config: &StorageConfig) -> Result<Self> {
        let local_base = config.local_path.clone();
        if let Some(parent) = local_base.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Object store initialized with backend: {:?}", config.backend);

        Ok(Self {
            config: config.clone(),
            local_base,
        })
    }

    /// Store a file stream with SHA256 hashing
    pub async fn put_stream(&self, file_id: FileId, stream: &mut (dyn AsyncRead + Unpin + Send)) -> Result<(u64, String)> {
        let start = std::time::Instant::now();
        
        let path = self.object_path(file_id);
        let hash = self.write_stream_to_path(stream, &path).await?;
        
        metrics::record_db_query(start.elapsed());
        Ok((hash.1, hash.0))
    }

    /// Get an object as a readable stream
    pub async fn get_object(&self, file_id: FileId) -> Result<Box<dyn AsyncRead + Unpin + Send>> {
        let path = self.object_path(file_id);
        let file_path = self.local_base.join(&path);
        let file = tokio::fs::File::open(&file_path).await?;
        Ok(Box::new(file))
    }

    /// Put raw data to a path
    pub async fn put(&self, path: &str, data: Vec<u8>) -> Result<()> {
        let start = std::time::Instant::now();
        
        let file_path = self.local_base.join(path);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&file_path, data).await?;
        
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Get raw data from a path
    pub async fn get(&self, path: &str) -> Result<Vec<u8>> {
        let start = std::time::Instant::now();
        
        let file_path = self.local_base.join(path);
        let data = tokio::fs::read(&file_path).await?;
        
        metrics::record_db_query(start.elapsed());
        Ok(data)
    }

    /// Delete an object
    pub async fn delete(&self, path: &str) -> Result<()> {
        let start = std::time::Instant::now();
        
        let file_path = self.local_base.join(path);
        tokio::fs::remove_file(&file_path).await?;
        
        metrics::record_db_query(start.elapsed());
        Ok(())
    }

    /// Delete a file by ID
    pub async fn delete_file(&self, file_id: FileId) -> Result<()> {
        self.delete(&self.object_path(file_id)).await
    }

    /// Generate object path for a file ID
    fn object_path(&self, file_id: FileId) -> String {
        let uuid_str = file_id.to_string();
        let (first, rest) = uuid_str.split_at(2);
        let (second, rest) = rest.split_at(2);
        format!("files/{}/{}/{}", first, second, uuid_str)
    }

    /// Write stream to path with SHA256 hashing
    async fn write_stream_to_path(&self, stream: &mut (dyn AsyncRead + Unpin + Send), path: &str) -> Result<(String, u64)> {
        use sha2::{Digest, Sha256};
        
        let mut hasher = Sha256::new();
        let mut total_bytes = 0u64;
        let mut buffer = vec![0u8; 8192];
        
        let file_path = self.local_base.join(path);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        let mut file = tokio::fs::File::create(&file_path).await?;
        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 { break; }
            hasher.update(&buffer[..n]);
            file.write_all(&buffer[..n]).await?;
            total_bytes += n as u64;
        }
        file.flush().await?;
        
        let hash = format!("{:x}", hasher.finalize());
        Ok((hash, total_bytes))
    }
}