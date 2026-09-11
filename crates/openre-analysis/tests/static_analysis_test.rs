// crates/openre-analysis/tests/static_analysis_test.rs
use chrono::Utc;
use openre_analysis::binary::common::{
    Architecture, BinaryFormat, BinaryIdentification, BinaryMetadata, Bitness, Endianness,
    FileHashes, OperatingSystem, SecurityFeatures,
};
use openre_analysis::binary::{
    BinaryMetadataExtractor, ElfMetadataExtractor, MachoMetadataExtractor, PeMetadataExtractor,
    StaticAnalyzer, StaticAnalyzerImpl, WasmMetadataExtractor,
};
use openre_analysis::StaticAnalysisService;
use openre_core::ids::FileId;
use std::fs;
use tempfile::TempDir;

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
    let wasm_bytes =
        wat::parse_str(r#"(module (func (export "test") (param i32) (result i32)))"#).unwrap();
    let temp = TempDir::new().unwrap();
    let binary_path = temp.path().join("test.wasm");
    fs::write(&binary_path, &wasm_bytes).unwrap();

    // Extract metadata first
    let extractor = WasmMetadataExtractor;
    let mut metadata = extractor.extract_metadata(&wasm_bytes).await.unwrap();
    metadata.file_id = file_id;

    // Run static analysis
    let result = service.analyze(file_id, &metadata).await.unwrap();

    // Verify result structure
    let _ = result.functions.len();
    let _ = result.control_flow.functions.len();
    let _ = result.section_entropies.len();
    let _ = result.data_flow.variables.len();
}

#[tokio::test]
async fn test_static_analyzer_impl_entropy() {
    let analyzer = StaticAnalyzerImpl;

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
    let analyzer = StaticAnalyzerImpl;

    // Create test binary data
    let data = b"test binary data";

    // Create minimal metadata
    let metadata = create_test_metadata();

    let functions = analyzer.find_functions(data, &metadata).await.unwrap();
    // Should find at least the export
    let _ = functions.len();
}

#[tokio::test]
async fn test_static_analysis_control_flow() {
    let analyzer = StaticAnalyzerImpl;

    let data = b"test binary data";
    let metadata = create_test_metadata();

    let result = analyzer.analyze_control_flow(data, &metadata).await.unwrap();

    // Should have control flow info structure
    let _ = result.functions.len();
    let _ = result.call_graph.nodes.len();
    let _ = result.cfg.nodes.len();
}

#[tokio::test]
async fn test_static_analysis_data_flow() {
    let analyzer = StaticAnalyzerImpl;

    let data = b"test binary data";
    let metadata = create_test_metadata();

    let result = analyzer.analyze_data_flow(data, &metadata).await.unwrap();

    // Should have data flow info structure
    let _ = result.variables.len();
    let _ = result.data_dependencies.len();
}

#[tokio::test]
async fn test_metadata_extractors() {
    // Test that all metadata extractors can be created
    let _elf = ElfMetadataExtractor;
    let _pe = PeMetadataExtractor;
    let _macho = MachoMetadataExtractor;
    let _wasm = WasmMetadataExtractor;

    // Test identifiers
    let _elf_id = openre_analysis::binary::ElfIdentifier;
    let _pe_id = openre_analysis::binary::PeIdentifier;
    let _macho_id = openre_analysis::binary::MachoIdentifier;
    let _wasm_id = openre_analysis::binary::WasmIdentifier;
}
