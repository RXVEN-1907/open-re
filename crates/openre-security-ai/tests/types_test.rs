use openre_security_ai::{AiResult, AiAnalystError};

#[test]
fn test_error_variants_exist() {
    let err = AiAnalystError::ProviderNotConfigured;
    assert!(err.to_string().contains("not configured"));
}