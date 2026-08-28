// crates/openre-analysis/tests/wasm_parser_test.rs
use openre_analysis::binary::{
    BinaryFormat, BinaryIdentifier, BinaryMetadataExtractor, WasmIdentifier, WasmMetadataExtractor,
    WasmParser,
};
use std::path::PathBuf;

#[test]
fn test_wasm_identification() {
    let wasm_bytes = wat::parse_str(r#"(module (func (export "test")))"#).unwrap();
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&temp, &wasm_bytes).unwrap();

    let identifier = WasmIdentifier::default();
    let result = tokio_test::block_on(identifier.identify(&wasm_bytes)).unwrap();

    assert_eq!(result.format, BinaryFormat::Wasm);
    assert!(result.confidence > 0.9);
}

#[test]
fn test_wasm_metadata_extraction() {
    let wasm_bytes =
        wat::parse_str(r#"(module (func (export "test") (param i32) (result i32)))"#).unwrap();
    let extractor = WasmMetadataExtractor::default();
    let metadata = tokio_test::block_on(extractor.extract_metadata(&wasm_bytes)).unwrap();

    assert_eq!(metadata.identification.format, BinaryFormat::Wasm);
    assert!(!metadata.exports.is_empty());
    assert_eq!(metadata.exports[0].name, "test");
}

#[test]
fn test_wasm_full_parse() {
    let wasm_bytes = wat::parse_str(r#"(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))"#).unwrap();
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&temp, &wasm_bytes).unwrap();

    let info = WasmParser::parse(temp.path()).unwrap();
    assert_eq!(info.format, BinaryFormat::Wasm);
    assert!(!info.symbols.is_empty());
}
