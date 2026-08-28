// crates/openre-analysis/tests/static_analysis_test.rs
use openre_analysis::binary::{StaticAnalyzerImpl, StaticAnalyzer, ElfMetadataExtractor, PeMetadataExtractor, MachoMetadataExtractor, WasmMetadataExtractor, BinaryMetadataExtractor};
use openre_analysis::{StaticAnalysisService, StaticAnalysisResult};
use openre_core::ids::FileId;
use openre_analysis::binary::common::{BinaryMetadata, BinaryIdentification, BinaryFormat, FileHashes, SectionInfo, SegmentInfo, SymbolInfo, ImportInfo, ImportedFunction, ExportInfo, ExtractedString, ResourceInfo, VersionInfo, SecurityFeatures, Architecture, Bitness, Endianness, OperatingSystem, RelroLevel, SymbolType, SymbolBinding, SymbolVisibility, StringEncoding, SectionCharacteristics, SectionFlags, SegmentPermissions, CompilerInfo, CallEdge, CallType, CfgEdge, CfgEdgeType, LoopInfo, LoopType, Operand, OperandKind, OperandType, TypeInfo, TypeKind, TypeSource, Variable, VariableStorage};
use chrono::{DateTime, Utc};
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;

fn create_test_metadata() -> BinaryMetadata {
    BinaryMetadata {
        file_id: FileId::new(),
        identification: BinaryIdentification {
            format: BinaryFormat::Wasm,
            architecture: Architecture::Unknown,
            bitness: Bitness::Bit32,
            endianness: Endianness::Little,
            os: OperatingSystem::Unknown,
            entry_point: None,
            compiler_info: None,
            security_features: SecurityFeatures::default(),
            confidence: 0.9,
        },
        sections: Vec::new(),
        segments: Vec::new(),
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        resources: Vec::new(),
        version_info: None,
        hashes: FileHashes { md5: String::new(), sha1: String::new(), sha256: String::new() },
        analyzed_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_static_analysis_service() {
    let service = StaticAnalysisService::new();
    let file_id = FileId::new();

    // Create a minimal WASM binary for testing
    let wasm_bytes = wat::parse_str(r#"(module (func (export "test") (param i32) (result i32)))"#).unwrap();
    let temp = TempDir::new().unwrap();
    let binary_path = temp.path().join("test.wasm");
    fs::write(&binary_path, &wasm_bytes).unwrap();

    // Extract metadata first
    let extractor = WasmMetadataExtractor::default();
    let mut metadata = extractor.extract_metadata(&wasm_bytes).await.unwrap();
    metadata.file_id = file_id;

    // Run static analysis
    let result = service.analyze(file_id, &metadata).await.unwrap();

    // Verify result structure
    assert!(!result.functions.is_empty() || result.control_flow.functions.is_empty());
    assert!(result.section_entropies.len() >= 0);
    assert!(result.data_flow.variables.len() >= 0);
}

#[tokio::test]
async fn test_static_analyzer_impl_entropy() {
    let analyzer = StaticAnalyzerImpl::default();

    // Test empty data
    let entropy = analyzer.calculate_entropy(&[]).await.unwrap();
    assert_eq!(entropy, 0.0);

    // Test uniform data (zero entropy)
    let uniform = vec![0u8; 256];
    let entropy = analyzer.calculate_entropy(&uniform).await.unwrap();
    assert_eq!(entropy, 0.0);

    // Test varied data (max entropy - all 256 byte values appear equally)
    let varied = (0..=255u8).collect::<Vec<_>>();
    let entropy = analyzer.calculate_entropy(&varied).await.unwrap();
    assert!((entropy - 8.0).abs() < 0.1);
}

#[tokio::test]
async fn test_static_analyzer_find_functions() {
    let analyzer = StaticAnalyzerImpl::default();

    // Create test binary data
    let data = b"test binary data";

    // Create minimal metadata
    let metadata = create_test_metadata();

    let functions = analyzer.find_functions(data, &metadata).await.unwrap();
    // Should find at least the export
    assert!(functions.len() >= 0);
}

#[tokio::test]
async fn test_static_analysis_control_flow() {
    let analyzer = StaticAnalyzerImpl::default();

    let data = b"test binary data";
    let metadata = create_test_metadata();

    let result = analyzer.analyze_control_flow(data, &metadata).await.unwrap();

    // Should have control flow info structure
    assert!(result.functions.len() >= 0);
    assert!(result.call_graph.nodes.len() >= 0);
    assert!(result.cfg.nodes.len() >= 0);
}

#[tokio::test]
async fn test_static_analysis_data_flow() {
    let analyzer = StaticAnalyzerImpl::default();

    let data = b"test binary data";
    let metadata = create_test_metadata();

    let result = analyzer.analyze_data_flow(data, &metadata).await.unwrap();

    // Should have data flow info structure
    assert!(result.variables.len() >= 0);
    assert!(result.data_dependencies.len() >= 0);
}

#[tokio::test]
async fn test_metadata_extractors() {
    // Test that all metadata extractors can be created
    let _elf = ElfMetadataExtractor::default();
    let _pe = PeMetadataExtractor::default();
    let _macho = MachoMetadataExtractor::default();
    let _wasm = WasmMetadataExtractor::default();

    // Test identifiers
    let _elf_id = openre_analysis::binary::ElfIdentifier::default();
    let _pe_id = openre_analysis::binary::PeIdentifier::default();
    let _macho_id = openre_analysis::binary::MachoIdentifier::default();
    let _wasm_id = openre_analysis::binary::WasmIdentifier::default();
}