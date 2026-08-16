//! Integration tests for injection testing framework

use openre_plugins::injection::{
    create_confidence_scorer, create_payload_engine, create_response_analyzer,
    BuiltinPayloadEngine, BuiltinResponseAnalyzer, ConfidenceConfig, ConfidenceScorer,
    DetectionMethod, InjectionCategory, ParameterLocation, PayloadContext, PayloadEngine,
    ResponseAnalyzer, SafetyConfig, Severity,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_payload_engine_sql_injection() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let context = PayloadContext {
        parameter_name: "id".to_string(),
        location: ParameterLocation::Query,
        expected_type: Some("integer".to_string()),
        technology_hints: vec![],
        database_type: Some("mysql".to_string()),
        template_engine: None,
        os_type: None,
        is_id_parameter: true,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::SqlInjection, &context);
    assert!(!payloads.is_empty());

    // Check for MySQL-specific payloads
    let has_mysql = payloads
        .iter()
        .any(|p| p.required_context.contains(&"mysql".to_string()));
    assert!(has_mysql);
}

#[tokio::test]
async fn test_payload_engine_xss() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let context = PayloadContext {
        parameter_name: "search".to_string(),
        location: ParameterLocation::Query,
        expected_type: Some("string".to_string()),
        technology_hints: vec![],
        database_type: None,
        template_engine: None,
        os_type: None,
        is_id_parameter: false,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::Xss, &context);
    assert!(!payloads.is_empty());

    // Check for reflection-based payloads
    let has_reflection = payloads
        .iter()
        .any(|p| p.detection_method == DetectionMethod::Reflection);
    assert!(has_reflection);
}

#[tokio::test]
async fn test_payload_engine_xxe() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let context = PayloadContext {
        parameter_name: "xml".to_string(),
        location: ParameterLocation::XmlBody,
        expected_type: Some("xml".to_string()),
        technology_hints: vec![],
        database_type: None,
        template_engine: None,
        os_type: None,
        is_id_parameter: false,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::Xxe, &context);
    assert!(!payloads.is_empty());

    // Check for file-read payloads
    let has_file_read = payloads
        .iter()
        .any(|p| p.tags.contains(&"file-read".to_string()));
    assert!(has_file_read);
}

#[tokio::test]
async fn test_payload_engine_ldap_injection() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let context = PayloadContext {
        parameter_name: "username".to_string(),
        location: ParameterLocation::Query,
        expected_type: None,
        technology_hints: vec!["ldap".to_string()],
        database_type: None,
        template_engine: None,
        os_type: None,
        is_id_parameter: false,
        is_auth_context: true,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::LdapInjection, &context);
    assert!(!payloads.is_empty());

    // Check for auth-bypass payloads
    let has_auth_bypass = payloads
        .iter()
        .any(|p| p.tags.contains(&"auth-bypass".to_string()));
    assert!(has_auth_bypass);
}

#[tokio::test]
async fn test_payload_engine_xpath_injection() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let context = PayloadContext {
        parameter_name: "id".to_string(),
        location: ParameterLocation::Query,
        expected_type: None,
        technology_hints: vec!["xpath".to_string()],
        database_type: None,
        template_engine: None,
        os_type: None,
        is_id_parameter: false,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::XPathInjection, &context);
    assert!(!payloads.is_empty());

    // Check for tautology payloads
    let has_tautology = payloads
        .iter()
        .any(|p| p.tags.contains(&"tautology".to_string()));
    assert!(has_tautology);
}

#[tokio::test]
async fn test_payload_engine_header_injection() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let context = PayloadContext {
        parameter_name: "X-Forwarded-For".to_string(),
        location: ParameterLocation::Header,
        expected_type: None,
        technology_hints: vec![],
        database_type: None,
        template_engine: None,
        os_type: None,
        is_id_parameter: false,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::HeaderInjection, &context);
    assert!(!payloads.is_empty());

    // Check for CRLF payloads
    let has_crlf = payloads
        .iter()
        .any(|p| p.tags.contains(&"crlf".to_string()));
    assert!(has_crlf);
}

#[tokio::test]
async fn test_payload_encoding() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let payload = "<script>alert(1)</script>";

    // Test URL encoding
    let url_encoded = engine.encode_payload(payload, openre_plugins::injection::Encoding::Url);
    assert!(url_encoded.contains("%3C"));
    assert!(url_encoded.contains("%3E"));

    // Test HTML entity encoding
    let html_encoded =
        engine.encode_payload(payload, openre_plugins::injection::Encoding::HtmlEntity);
    assert!(html_encoded.contains("&lt;"));
    assert!(html_encoded.contains("&gt;"));

    // Test double URL encoding
    let double_encoded =
        engine.encode_payload(payload, openre_plugins::injection::Encoding::DoubleUrl);
    assert!(double_encoded.contains("%253C"));
}

#[tokio::test]
async fn test_response_analyzer_sql_error_detection() {
    let analyzer = create_response_analyzer(InjectionCategory::SqlInjection);

    let test_result = create_test_result(
        InjectionCategory::SqlInjection,
        "id",
        ParameterLocation::Query,
        "' OR '1'='1",
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());

    let finding = &findings[0];
    assert_eq!(finding.detection_method, DetectionMethod::ErrorBased);
    assert_eq!(finding.severity, Severity::High);
    assert!(finding.confidence > 0.7);
}

#[tokio::test]
async fn test_response_analyzer_xss_reflection() {
    let analyzer = create_response_analyzer(InjectionCategory::Xss);

    let test_result = create_test_result(
        InjectionCategory::Xss,
        "search",
        ParameterLocation::Query,
        "<script>alert(1)</script>",
        "<html><body>Search results for <script>alert(1)</script></body></html>",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());

    let finding = &findings[0];
    assert_eq!(finding.detection_method, DetectionMethod::Reflection);
    assert_eq!(finding.severity, Severity::High);
}

#[tokio::test]
async fn test_response_analyzer_xxe_file_read() {
    let analyzer = create_response_analyzer(InjectionCategory::Xxe);

    let test_result = create_test_result(
        InjectionCategory::Xxe,
        "xml",
        ParameterLocation::XmlBody,
        r#"<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());

    let finding = &findings[0];
    assert_eq!(finding.detection_method, DetectionMethod::PatternMatch);
    assert_eq!(finding.severity, Severity::Critical);
}

#[tokio::test]
async fn test_response_analyzer_ldap_injection() {
    let analyzer = create_response_analyzer(InjectionCategory::LdapInjection);

    let test_result = create_test_result(
        InjectionCategory::LdapInjection,
        "username",
        ParameterLocation::Query,
        "*)(|(userPassword=*))",
        "cn=admin,ou=users,dc=example,dc=com\nuserPassword=secret123",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());

    let finding = &findings[0];
    assert_eq!(finding.detection_method, DetectionMethod::PatternMatch);
    assert_eq!(finding.severity, Severity::High);
}

#[tokio::test]
async fn test_response_analyzer_xpath_injection() {
    let analyzer = create_response_analyzer(InjectionCategory::XPathInjection);

    let test_result = create_test_result(
        InjectionCategory::XPathInjection,
        "id",
        ParameterLocation::Query,
        "' or '1'='1",
        "user1\nuser2\nadmin\npassword123",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());

    let finding = &findings[0];
    assert_eq!(finding.detection_method, DetectionMethod::PatternMatch);
    assert_eq!(finding.severity, Severity::High);
}

#[tokio::test]
async fn test_response_analyzer_header_injection() {
    let analyzer = create_response_analyzer(InjectionCategory::HeaderInjection);

    let test_result = create_test_result(
        InjectionCategory::HeaderInjection,
        "X-Forwarded-For",
        ParameterLocation::Header,
        "\r\nX-Injected: test",
        "HTTP/1.1 200 OK\r\nX-Injected: test\r\nContent-Type: text/html",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());

    let finding = &findings[0];
    assert_eq!(finding.detection_method, DetectionMethod::PatternMatch);
    assert_eq!(finding.severity, Severity::High);
}

#[tokio::test]
async fn test_confidence_scoring() {
    let scorer = create_confidence_scorer(ConfidenceConfig::default());

    // High confidence finding
    let finding = create_injection_test_result(
        InjectionCategory::SqlInjection,
        DetectionMethod::ErrorBased,
        Severity::High,
        0.8,
        true, // has baseline
        true, // has timing
        true, // has diff
        2,    // multiple patterns
    );

    let score = scorer.score(&finding);
    assert!(score > 0.7);

    // Low confidence finding
    let finding_low = create_injection_test_result(
        InjectionCategory::Xss,
        DetectionMethod::Heuristic,
        Severity::Low,
        0.4,
        false, // no baseline
        false, // no timing
        false, // no diff
        0,     // no patterns
    );

    let score_low = scorer.score(&finding_low);
    assert!(score_low < 0.5);
}

#[tokio::test]
async fn test_confidence_breakdown() {
    let scorer = create_confidence_scorer(ConfidenceConfig::default());

    let finding = create_injection_test_result(
        InjectionCategory::SqlInjection,
        DetectionMethod::TimeBased,
        Severity::High,
        0.85,
        true,
        true,
        true,
        3,
    );

    let breakdown = scorer.detailed_score(&finding);
    assert!(breakdown.final_score > 0.0);
    assert!(breakdown.final_score <= 1.0);
    assert!(!breakdown.label.is_empty());
    assert!(!breakdown.color.is_empty());
}

#[tokio::test]
async fn test_safety_controls_payload_blocking() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    // Test that dangerous payloads are blocked
    let context = PayloadContext {
        parameter_name: "test".to_string(),
        location: ParameterLocation::Query,
        expected_type: None,
        technology_hints: vec![],
        database_type: None,
        template_engine: None,
        os_type: None,
        is_id_parameter: false,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::SqlInjection, &context);

    // Check that DROP TABLE is not in payloads
    let has_drop = payloads
        .iter()
        .any(|p| p.raw.to_uppercase().contains("DROP TABLE"));
    assert!(!has_drop);

    let has_delete = payloads
        .iter()
        .any(|p| p.raw.to_uppercase().contains("DELETE FROM"));
    assert!(!has_delete);
}

#[tokio::test]
async fn test_payload_context_filtering() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    // Context without MySQL hint should not get MySQL-specific payloads
    let context_no_mysql = PayloadContext {
        parameter_name: "id".to_string(),
        location: ParameterLocation::Query,
        expected_type: Some("integer".to_string()),
        technology_hints: vec![],
        database_type: Some("postgresql".to_string()),
        template_engine: None,
        os_type: None,
        is_id_parameter: true,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::SqlInjection, &context_no_mysql);
    let has_mysql = payloads
        .iter()
        .any(|p| p.required_context.contains(&"mysql".to_string()));
    assert!(!has_mysql);

    // Context with MySQL hint should get MySQL-specific payloads
    let context_mysql = PayloadContext {
        parameter_name: "id".to_string(),
        location: ParameterLocation::Query,
        expected_type: Some("integer".to_string()),
        technology_hints: vec![],
        database_type: Some("mysql".to_string()),
        template_engine: None,
        os_type: None,
        is_id_parameter: true,
        is_auth_context: false,
        custom: HashMap::new(),
    };

    let payloads = engine.get_payloads(InjectionCategory::SqlInjection, &context_mysql);
    let has_mysql = payloads
        .iter()
        .any(|p| p.required_context.contains(&"mysql".to_string()));
    assert!(has_mysql);
}

#[tokio::test]
async fn test_parameter_mutation() {
    let safety = SafetyConfig::default();
    let engine = create_payload_engine(safety);

    let payloads = vec![openre_plugins::injection::Payload {
        id: "test_1".to_string(),
        category: InjectionCategory::SqlInjection,
        raw: "'".to_string(),
        description: "Test".to_string(),
        tags: vec![],
        risk_level: 1,
        is_safe: true,
        required_context: vec![],
        compatible_encodings: vec![openre_plugins::injection::Encoding::None],
        detection_method: DetectionMethod::ErrorBased,
    }];

    let mutated = engine.mutate_parameter("original", &payloads, ParameterLocation::Query);
    assert!(!mutated.is_empty());
    assert!(mutated.contains(&"'".to_string()));
    assert!(mutated.contains(&"original'".to_string()));
}

// Helper functions

fn create_test_result(
    category: InjectionCategory,
    parameter: &str,
    location: ParameterLocation,
    payload: &str,
    response_body: &str,
    status: u16,
) -> openre_plugins::injection::response_analyzer::TestResult {
    use chrono::Utc;
    use openre_plugins::injection::{HttpRequestSnapshot, HttpResponseSnapshot, Payload};
    use std::collections::HashMap;

    openre_plugins::injection::response_analyzer::TestResult {
        parameter: parameter.to_string(),
        location,
        payload: Some(Payload {
            id: "test".to_string(),
            category,
            raw: payload.to_string(),
            description: "Test".to_string(),
            tags: vec![],
            risk_level: 1,
            is_safe: true,
            required_context: vec![],
            compatible_encodings: vec![],
            detection_method: DetectionMethod::ErrorBased,
        }),
        request: HttpRequestSnapshot {
            method: "GET".to_string(),
            url: "http://example.com".to_string(),
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
        },
        response: HttpResponseSnapshot {
            status,
            headers: HashMap::new(),
            body: response_body.to_string(),
            body_length: response_body.len(),
            response_time_ms: 100,
            timestamp: Utc::now(),
        },
        baseline_response: None,
        category,
        timestamp: Utc::now(),
    }
}

fn create_injection_test_result(
    category: InjectionCategory,
    detection_method: DetectionMethod,
    severity: Severity,
    confidence: f64,
    has_baseline: bool,
    has_timing: bool,
    has_diff: bool,
    pattern_count: usize,
) -> openre_plugins::injection::InjectionTestResult {
    use chrono::Utc;
    use openre_plugins::injection::{
        HeaderChange, HttpRequestSnapshot, HttpResponseSnapshot, InjectionEvidence,
        ReproducibleRequest, ResponseDiff, TimingInfo,
    };
    use std::collections::HashMap;

    let mut evidence = InjectionEvidence {
        original_request: Some(HttpRequestSnapshot {
            method: "GET".to_string(),
            url: "http://example.com".to_string(),
            headers: HashMap::new(),
            body: None,
            timestamp: Utc::now(),
        }),
        triggering_response: HttpResponseSnapshot {
            status: 200,
            headers: HashMap::new(),
            body: "test".to_string(),
            body_length: 4,
            response_time_ms: 100,
            timestamp: Utc::now(),
        },
        baseline_response: if has_baseline {
            Some(HttpResponseSnapshot {
                status: 200,
                headers: HashMap::new(),
                body: "baseline".to_string(),
                body_length: 8,
                response_time_ms: 50,
                timestamp: Utc::now(),
            })
        } else {
            None
        },
        diff: if has_diff {
            Some(ResponseDiff {
                status_changed: false,
                length_diff: 0,
                header_changes: vec![],
                body_similarity: 1.0,
                new_patterns: vec![],
                removed_patterns: vec![],
            })
        } else {
            None
        },
        matched_patterns: (0..pattern_count)
            .map(|i| format!("pattern{}", i))
            .collect(),
        timing_info: if has_timing {
            Some(TimingInfo {
                baseline_ms: 50,
                test_ms: 5000,
                diff_ms: 4950,
                threshold_ms: 3000,
                is_significant: true,
            })
        } else {
            None
        },
    };

    openre_plugins::injection::InjectionTestResult {
        category,
        parameter: "test".to_string(),
        location: ParameterLocation::Query,
        payload: "test".to_string(),
        detection_method,
        confidence,
        severity,
        evidence,
        reproducible_request: ReproducibleRequest {
            method: "GET".to_string(),
            url: "http://example.com".to_string(),
            headers: HashMap::new(),
            body: None,
            parameter: "test".to_string(),
            payload: "test".to_string(),
            location: ParameterLocation::Query,
        },
        verification_steps: vec![],
        tags: vec![],
    }
}
