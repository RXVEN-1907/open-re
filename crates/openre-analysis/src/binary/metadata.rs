//! Metadata extraction service

use crate::binary::common::*;
use crate::binary::elf::ElfMetadataExtractor;
use crate::binary::pe::PeMetadataExtractor;
use crate::binary::traits::*;
use openre_core::error::OpenreResult as Result;
use openre_core::ids::*;
use openre_storage::ObjectStore;
use openre_telemetry::metrics;
use std::sync::Arc;
use tokio::io::AsyncReadExt;

/// Metadata extraction service
pub struct MetadataExtractionService {
    object_store: Arc<ObjectStore>,
    elf_extractor: ElfMetadataExtractor,
    pe_extractor: PeMetadataExtractor,
}

impl MetadataExtractionService {
    pub fn new(object_store: Arc<ObjectStore>) -> Self {
        Self {
            object_store,
            elf_extractor: ElfMetadataExtractor,
            pe_extractor: PeMetadataExtractor,
        }
    }

    /// Read the full contents of a stored binary
    async fn read_object(&self, file_id: FileId) -> Result<Vec<u8>> {
        let mut reader = self.object_store.get_object(file_id).await?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await?;
        Ok(data)
    }

    /// Extract metadata for a file
    pub async fn extract_metadata(&self, file_id: FileId) -> Result<BinaryMetadata> {
        let start = std::time::Instant::now();

        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        let mut metadata = match format {
            BinaryFormat::Elf => self.elf_extractor.extract_metadata(&data).await?,
            BinaryFormat::Pe => self.pe_extractor.extract_metadata(&data).await?,
            _ => {
                return Err(openre_core::Error::Validation(
                    "Unsupported format".to_string(),
                ))
            }
        };
        metadata.file_id = file_id;

        metrics::record_http_request("POST", 200, start.elapsed());

        Ok(metadata)
    }

    /// Get stored metadata for a file
    pub async fn get_metadata(&self, _file_id: FileId) -> Result<Option<BinaryMetadata>> {
        // Metadata persistence is not wired up yet
        Ok(None)
    }

    /// Extract specific metadata components
    pub async fn extract_sections(&self, file_id: FileId) -> Result<Vec<SectionInfo>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_sections(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_sections(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }

    pub async fn extract_symbols(&self, file_id: FileId) -> Result<Vec<SymbolInfo>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_symbols(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_symbols(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }

    pub async fn extract_imports(&self, file_id: FileId) -> Result<Vec<ImportInfo>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_imports(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_imports(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }

    pub async fn extract_exports(&self, file_id: FileId) -> Result<Vec<ExportInfo>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_exports(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_exports(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }

    pub async fn extract_strings(&self, file_id: FileId) -> Result<Vec<ExtractedString>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_strings(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_strings(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }

    pub async fn extract_resources(&self, file_id: FileId) -> Result<Vec<ResourceInfo>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_resources(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_resources(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }

    pub async fn extract_version_info(&self, file_id: FileId) -> Result<Option<VersionInfo>> {
        let data = self.read_object(file_id).await?;
        let format = BinaryFormat::from_bytes(&data);

        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_version_info(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_version_info(&data).await,
            _ => Err(openre_core::Error::Validation(
                "Unsupported format".to_string(),
            )),
        }
    }
}
