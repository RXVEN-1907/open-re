//! Binary upload handling

use crate::binary::common::*;
use crate::binary::elf::ElfIdentifier;
use crate::binary::elf::ElfMetadataExtractor;
use crate::binary::pe::PeIdentifier;
use crate::binary::pe::PeMetadataExtractor;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_storage::ObjectStore;
use openre_telemetry::metrics;
use std::sync::Arc;
use tracing::{info, warn};

/// Binary upload service
pub struct BinaryUploadService {
    object_store: Arc<ObjectStore>,
    elf_identifier: ElfIdentifier,
    pe_identifier: PeIdentifier,
    elf_extractor: ElfMetadataExtractor,
    pe_extractor: PeMetadataExtractor,
}

impl BinaryUploadService {
    pub fn new(object_store: Arc<ObjectStore>) -> Self {
        Self {
            object_store,
            elf_identifier: ElfIdentifier,
            pe_identifier: PeIdentifier,
            elf_extractor: ElfMetadataExtractor,
            pe_extractor: PeMetadataExtractor,
        }
    }

    /// Upload and analyze a binary file
    pub async fn upload_binary(
        &self,
        request: BinaryUploadRequest,
    ) -> Result<BinaryUploadResponse> {
        let start = std::time::Instant::now();

        // Calculate hashes
        let hashes = calculate_hashes(&request.file_data);

        // Identify binary format
        let format = BinaryFormat::from_bytes(&request.file_data);

        // Validate format
        if format == BinaryFormat::Unknown {
            return Err(openre_core::Error::Validation("Unsupported binary format".to_string()));
        }

        // Store file in object storage
        let file_id = FileId::new();
        let object_path = format!("binaries/{}/{}.bin", request.project_id, hashes.sha256);
        self.object_store.put(&object_path, request.file_data.clone()).await?;

        // Identify binary format and extract basic info
        match self.identify_binary(&request.file_data).await {
            Ok(identification) => {
                info!(
                    file_id = %file_id,
                    format = ?identification.format,
                    "Binary identified"
                );
            }
            Err(e) => warn!(file_id = %file_id, error = %e, "Binary identification failed"),
        }

        // Create analysis session
        let analysis_id = AnalysisId::new();

        // Queue analysis job for processing
        self.queue_analysis(analysis_id, file_id, request.project_id).await?;

        metrics::record_http_request("POST", 201, start.elapsed());

        Ok(BinaryUploadResponse {
            file_id,
            analysis_id,
            status: AnalysisStatus::Pending,
            message: "Binary uploaded and analysis queued".to_string(),
        })
    }

    /// Identify binary format and extract basic info
    async fn identify_binary(&self, data: &[u8]) -> Result<BinaryIdentification> {
        let format = BinaryFormat::from_bytes(data);

        match format {
            BinaryFormat::Elf => self.elf_identifier.identify(data).await,
            BinaryFormat::Pe => self.pe_identifier.identify(data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    /// Queue analysis job
    async fn queue_analysis(
        &self,
        analysis_id: AnalysisId,
        file_id: FileId,
        project_id: ProjectId,
    ) -> Result<()> {
        let _ = project_id;

        let job = crate::orchestrator::AnalysisJob::new(
            project_id,
            file_id,
            crate::orchestrator::AnalysisConfig::default(),
            UserId::nil(), // System user
        );
        let _ = job.id;

        info!(
            analysis_id = %analysis_id,
            file_id = %file_id,
            "Analysis job queued"
        );

        Ok(())
    }

    /// Get binary metadata by file ID
    pub async fn get_binary_metadata(&self, file_id: FileId) -> Result<Option<BinaryMetadata>> {
        let data = match self.object_store.get_object(file_id).await {
            Ok(mut reader) => {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                match reader.read_to_end(&mut buf).await {
                    Ok(_) => buf,
                    Err(e) => return Err(openre_core::Error::Io(e)),
                }
            }
            Err(_) => return Ok(None),
        };

        self.extract_metadata(&data, file_id).await
    }

    /// Extract full metadata from binary data
    async fn extract_metadata(
        &self,
        data: &[u8],
        file_id: FileId,
    ) -> Result<Option<BinaryMetadata>> {
        let format = BinaryFormat::from_bytes(data);

        let metadata = match format {
            BinaryFormat::Elf => self.elf_extractor.extract_metadata(data).await?,
            BinaryFormat::Pe => self.pe_extractor.extract_metadata(data).await?,
            _ => return Ok(None),
        };

        Ok(Some(BinaryMetadata { file_id, ..metadata }))
    }
}

/// Calculate file hashes
fn calculate_hashes(data: &[u8]) -> FileHashes {
    use md5::{Digest, Md5};
    use sha1::{Digest as Sha1Digest, Sha1};
    use sha2::{Digest as Sha2Digest, Sha256};

    let md5_hash = {
        let mut hasher = Md5::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    let sha1_hash = {
        let mut hasher = Sha1::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };
    let sha256_hash = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };

    FileHashes { md5: md5_hash, sha1: sha1_hash, sha256: sha256_hash }
}
