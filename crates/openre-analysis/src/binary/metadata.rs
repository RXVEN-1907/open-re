//! Metadata extraction service

use crate::binary::common::*;
use crate::binary::traits::*;
use crate::binary::elf::ElfMetadataExtractor;
use crate::binary::pe::PeMetadataExtractor;
use openre_core::error::Result;
use openre_core::ids::*;
use openre_storage::GlobalStore;
use openre_telemetry::metrics;
use std::sync::Arc;
use tracing::{info, warn};

/// Metadata extraction service
pub struct MetadataExtractionService {
    global_store: Arc<GlobalStore>,
    elf_extractor: ElfMetadataExtractor,
    pe_extractor: PeMetadataExtractor,
}

impl MetadataExtractionService {
    pub fn new(global_store: Arc<GlobalStore>) -> Self {
        Self {
            global_store,
            elf_extractor: ElfMetadataExtractor,
            pe_extractor: PeMetadataExtractor,
        }
    }

    /// Extract metadata for a file
    pub async fn extract_metadata(&self, file_id: FileId) -> Result<BinaryMetadata> {
        let start = std::time::Instant::now();
        
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        
        let format = BinaryFormat::from_bytes(&data);
        
        let metadata = match format {
            BinaryFormat::Elf => self.elf_extractor.extract_metadata(&data).await?,
            BinaryFormat::Pe => self.pe_extractor.extract_metadata(&data).await?,
            _ => return Err(openre_core::Error::Validation("Unsupported format".to_string())),
        };

        // Update file record with extracted metadata
        self.global_store.update_file_metadata(file_id, &metadata).await?;

        metrics::record_http_request("POST", 200, start.elapsed());

        Ok(BinaryMetadata {
            file_id,
            ..metadata
        })
    }

    /// Get stored metadata for a file
    pub async fn get_metadata(&self, file_id: FileId) -> Result<Option<BinaryMetadata>> {
        self.global_store.get_file_metadata(file_id).await
    }

    /// Extract specific metadata components
    pub async fn extract_sections(&self, file_id: FileId) -> Result<Vec<SectionInfo>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_sections(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_sections(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    pub async fn extract_symbols(&self, file_id: FileId) -> Result<Vec<SymbolInfo>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_symbols(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_symbols(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    pub async fn extract_imports(&self, file_id: FileId) -> Result<Vec<ImportInfo>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_imports(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_imports(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    pub async fn extract_exports(&self, file_id: FileId) -> Result<Vec<ExportInfo>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_exports(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_exports(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    pub async fn extract_strings(&self, file_id: FileId) -> Result<Vec<ExtractedString>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_strings(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_strings(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    pub async fn extract_resources(&self, file_id: FileId) -> Result<Vec<ResourceInfo>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_resources(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_resources(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }

    pub async fn extract_version_info(&self, file_id: FileId) -> Result<Option<VersionInfo>> {
        let file = self.global_store.get_file(file_id).await?
            .ok_or_else(|| openre_core::Error::NotFound(format!("File not found: {}", file_id)))?;

        let data = self.global_store.object_store().get(&file.object_path).await?;
        let format = BinaryFormat::from_bytes(&data);
        
        match format {
            BinaryFormat::Elf => self.elf_extractor.extract_version_info(&data).await,
            BinaryFormat::Pe => self.pe_extractor.extract_version_info(&data).await,
            _ => Err(openre_core::Error::Validation("Unsupported format".to_string())),
        }
    }
}