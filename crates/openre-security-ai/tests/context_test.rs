use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Finding, FindingConfig, Severity,
};
use openre_security_ai::context::{ContextBuilder, TokenBudget};

#[test]
fn test_token_budget() {
    let mut budget = TokenBudget::new(100);
    assert_eq!(budget.remaining(), 100);

    // Consume some tokens
    assert!(budget.consume(30).is_ok());
    assert_eq!(budget.used_tokens, 30);
    assert_eq!(budget.remaining(), 70);

    // Check capacity
    assert!(budget.has_capacity(50));
    assert!(!budget.has_capacity(80));

    // Consume more tokens
    assert!(budget.consume(40).is_ok());
    assert_eq!(budget.used_tokens, 70);
    assert_eq!(budget.remaining(), 30);

    // Try to consume too many tokens
    assert!(budget.consume(50).is_err());
}

#[test]
fn test_context_builder_creation() {
    let builder = ContextBuilder::new(2048);
    assert_eq!(builder.max_tokens(), 2048);
}

#[test]
fn test_finding_summary_creation() {
    let scan_id = ScanId::new();

    let finding = Finding::new(FindingConfig {
        title: "Test SQL Injection".to_string(),
        description: "User input is not properly sanitized in login form".to_string(),
        severity: Severity::High,
        confidence: Confidence::Medium,
        category: Category::Injection,
        target: "http://example.com/login".to_string(),
        target_type: "web_application".to_string(),
        plugin_source: "sql_injection_scanner".to_string(),
        plugin_version: "1.0.0".to_string(),
        scan_id,
    });

    let builder = ContextBuilder::new(2048);
    let context = builder.build_finding_context(&finding);

    assert!(context.is_ok());
    let context = context.unwrap();
    assert_eq!(context.finding.title, "Test SQL Injection");
    assert_eq!(context.finding.severity, "High");
    assert_eq!(context.finding.confidence, "Medium");
}
