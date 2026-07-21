//! Binary upload handling

use crate::binary::common::*;
use crate::binary::traits::*;
use crate::binary::elf::ElfIdentifier;
use crate::binary::elf::ElfMetadataExtractor;
use crate::binary::pe::PeIdentifier;
use crate::binary::pe::PeMetadataExtractor;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_storage::GlobalStore;
use openre_telemetry::metrics;
use std::sync::Arc;
use tracing::{info, warn};

/// Binary upload service
pub struct BinaryUploadService {
    global_store: Arc<GlobalStore>,
    elf_identifier: ElfIdentifier,
    pe_identifier: PeIdentifier,
    elf_extractor: ElfMetadataExtractor,
    pe_extractor: PeMetadataExtractor,
}

impl BinaryUploadService {
    pub fn new(global_store: Arc<GlobalStore>) -> Self {
        Self {
            global_store,
            elf_identifier: ElfIdentifier,
            pe_identifier: PeIdentifier,
            elf_extractor: ElfMetadataExtractor,
            pe_extractor: PeMetadataExtractor,
        }
    }

    /// Upload and analyze a binary file
    pub async fn upload_binary(&self, request: BinaryUploadRequest) -> Result<BinaryUploadResponse> {
        let start = std::time::Instant::now();
        
        // Calculate hashes
        let hashes = calculate_hashes(&request.file_data);
        
        // Identify binary format
        let format = BinaryFormat::from_bytes(&request.file_data);
        
        // Validate format
        if format == BinaryFormat::Unknown {
            return Err(openre_core::Error::Validation(
                "Unsupported binary format".to_string()
            ));
        }

        // Check if file already exists (by hash)
        if let Some(existing_file) = self.global_store.get_file_by_hash(&hashes.sha256).await? {
            info!(file_id = %existing_file.id, "Binary already exists, returning existing analysis");
            return Ok(BinaryUploadResponse {
                file_id: existing_file.id,
                analysis_id: AnalysisId::nil(),
                status: AnalysisStatus::Completed,
                message: "Binary already analyzed".to_string(),
            });
        }

        // Store file in object storage
        let object_path = format!("binaries/{}/{}.bin", request.project_id, hashes.sha256);
        self.global_store.object_store().put(&object_path, &request.file_data).await?;

        // Create file record
        let file_id = FileId::new();
        let identification = self.identify_binary(&request.file_data).await?;
        
        self.global_store.create_file(
            file_id,
            request.project_id,
            request.file_name,
            object_path.clone(),
            request.file_data.len() as u64,
            hashes.sha256.clone(),
            identification.format,
            identification.architecture,
            identification.bitness,
            identification.os,
            identification.entry_point,
            identification.compiler_info.map(|c| serde_json::to_value(c).unwrap_or_default()),
            "completed".to_string(),
            request.uploaded_by,
        ).await?;

        // Create analysis session
        let analysis_id = AnalysisId::new();
        self.global_store.create_analysis_session(
            analysis_id,
            file_id,
            request.project_id,
            AnalysisStatus::Pending,
        ).await?;

        // Queue analysis job
        self.queue_analysis(analysis_id, file_id, request.project_id, request.file_data).await?;

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
        file_data: Vec<u8>,
    ) -> Result<()> {
        // Store file data temporarily for analysis
        let object_path = format!("analysis/{}/input.bin", analysis_id);
        self.global_store.object_store().put(&object_path, &file_data).await?;

        // Create analysis job
        let job = crate::orchestrator::AnalysisJob::new(
            project_id,
            file_id,
            crate::orchestrator::AnalysisConfig::default(),
            UserId::nil(), // System user
        );

        self.global_store.create_job(&job).await?;
        
        // Queue the job
        self.global_store.queue_job(job.id, job.priority).await?;

        Ok(())
    }

    /// Get binary metadata by file ID
    pub async fn get_binary_metadata(&self, file_id: FileId) -> Result<Option<BinaryMetadata>> {
        let file = self.global_store.get_file(file_id).await?;
        if let Some(file) = file {
            let data = self.global_store.object_store().get(&file.object_path).await?;
            self.extract_metadata(&data, file_id).await
        } else {
            Ok(None)
        }
    }

    /// Extract full metadata from binary data
    async fn extract_metadata(&self, data: &[u8], file_id: FileId) -> Result<Option<BinaryMetadata>> {
        let format = BinaryFormat::from_bytes(data);
        
        let metadata = match format {
            BinaryFormat::Elf => self.elf_extractor.extract_metadata(data).await?,
            BinaryFormat::Pe => self.pe_extractor.extract_metadata(data).await?,
            _ => return Ok(None),
        };

        Ok(Some(BinaryMetadata {
            file_id,
            ..metadata
        }))
    }
}

/// Calculate file hashes
fn calculate_hashes(data: &[u8]) -> FileHashes {
    use md5::{Digest, Md5};
    use sha1::Sha1;
    use sha2::Sha256;

    let md5_hash = format!("{:x}", Md5::digest(data));
    let sha1_hash = format!("{:x}", Sha1::digest(data));
    let sha256_hash = format!("{:x}", Sha256::digest(data));

    FileHashes {
        md5: md5_hash,
        sha1: sha1_hash,
        sha256: sha256_hash,
    }
}