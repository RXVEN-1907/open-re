//! Unit tests for injection testing framework components

use openre_plugins::injection::{
    create_confidence_scorer, create_payload_engine, create_response_analyzer,
    BuiltinPayloadEngine, BuiltinResponseAnalyzer, ConfidenceConfig, ConfidenceScorer,
    DetectionMethod, Encoding, ErrorPattern, InjectionCategory, ParameterLocation, Payload,
    PayloadContext, PayloadEngine, ResponseAnalyzer, SafetyConfig, SafetyController, Severity,
};
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn test_payload_engine_creation() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    // Check all categories have payloads
    for category in [
        InjectionCategory::SqlInjection,
        InjectionCategory::NoSqlInjection,
        InjectionCategory::Xss,
        InjectionCategory::Ssti,
        InjectionCategory::CommandInjection,
        InjectionCategory::Xxe,
        InjectionCategory::LdapInjection,
        InjectionCategory::XPathInjection,
        InjectionCategory::HeaderInjection,
    ] {
        let payloads = engine.get_all_payloads(category);
        assert!(
            !payloads.is_empty(),
            "Category {:?} should have payloads",
            category
        );
    }
}

#[test]
fn test_payload_encoding_none() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "test payload";
    let encoded = engine.encode_payload(payload, Encoding::None);
    assert_eq!(encoded, payload);
}

#[test]
fn test_payload_encoding_url() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "<script>alert(1)</script>";
    let encoded = engine.encode_payload(payload, Encoding::Url);
    assert!(encoded.contains("%3C"));
    assert!(encoded.contains("%3E"));
    assert!(encoded.contains("%28"));
    assert!(encoded.contains("%29"));
}

#[test]
fn test_payload_encoding_double_url() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "<script>";
    let encoded = engine.encode_payload(payload, Encoding::DoubleUrl);
    // Double encoded: < -> %3C -> %253C
    assert!(encoded.contains("%253C"));
}

#[test]
fn test_payload_encoding_html_entity() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "<script>&\"'";
    let encoded = engine.encode_payload(payload, Encoding::HtmlEntity);
    assert!(encoded.contains("&lt;"));
    assert!(encoded.contains("&gt;"));
    assert!(encoded.contains("&amp;"));
    assert!(encoded.contains("&quot;"));
    assert!(encoded.contains("&#x27;"));
}

#[test]
fn test_payload_encoding_unicode() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "AB";
    let encoded = engine.encode_payload(payload, Encoding::Unicode);
    assert_eq!(encoded, "\\u0041\\u0042");
}

#[test]
fn test_payload_encoding_base64() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "test";
    let encoded = engine.encode_payload(payload, Encoding::Base64);
    assert_eq!(encoded, "dGVzdA==");
}

#[test]
fn test_payload_encoding_hex() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "AB";
    let encoded = engine.encode_payload(payload, Encoding::Hex);
    assert_eq!(encoded, "4142");
}

#[test]
fn test_payload_encoding_sql_comment() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "test";
    let encoded = engine.encode_payload(payload, Encoding::SqlComment);
    assert_eq!(encoded, "test--");
}

#[test]
fn test_payload_encoding_xml() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "<test>&\"'";
    let encoded = engine.encode_payload(payload, Encoding::Xml);
    assert!(encoded.contains("&lt;"));
    assert!(encoded.contains("&gt;"));
    assert!(encoded.contains("&amp;"));
    assert!(encoded.contains("&quot;"));
    assert!(encoded.contains("&apos;"));
}

#[test]
fn test_payload_encoding_json() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payload = "test\"value";
    let encoded = engine.encode_payload(payload, Encoding::Json);
    assert!(encoded.contains("\\\""));
}

#[test]
fn test_supported_encodings() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let encodings = engine.supported_encodings();
    assert!(encodings.contains(&Encoding::None));
    assert!(encodings.contains(&Encoding::Url));
    assert!(encodings.contains(&Encoding::DoubleUrl));
    assert!(encodings.contains(&Encoding::HtmlEntity));
    assert!(encodings.contains(&Encoding::Unicode));
    assert!(encodings.contains(&Encoding::Base64));
    assert!(encodings.contains(&Encoding::Hex));
    assert!(encodings.contains(&Encoding::SqlComment));
    assert!(encodings.contains(&Encoding::Xml));
    assert!(encodings.contains(&Encoding::Json));
}

#[test]
fn test_parameter_mutation_query() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payloads = vec![Payload {
        id: "test".to_string(),
        category: InjectionCategory::SqlInjection,
        raw: "'".to_string(),
        description: "Test".to_string(),
        tags: vec![],
        risk_level: 1,
        is_safe: true,
        required_context: vec![],
        compatible_encodings: vec![Encoding::None],
        detection_method: DetectionMethod::ErrorBased,
    }];

    let mutated = engine.mutate_parameter("original", &payloads, ParameterLocation::Query);
    assert!(mutated.contains(&"'".to_string()));
    assert!(mutated.contains(&"original'".to_string()));
}

#[test]
fn test_parameter_mutation_header() {
    let safety = SafetyConfig::default();
    let engine = BuiltinPayloadEngine::new(safety);

    let payloads = vec![Payload {
        id: "test".to_string(),
        category: InjectionCategory::HeaderInjection,
        raw: "\r\nX-Injected: test".to_string(),
        description: "Test".to_string(),
        tags: vec![],
        risk_level: 1,
        is_safe: true,
        required_context: vec![],
        compatible_encodings: vec![Encoding::None],
        detection_method: DetectionMethod::Reflection,
    }];

    let mutated = engine.mutate_parameter("original", &payloads, ParameterLocation::Header);
    assert!(mutated.contains(&"\r\nX-Injected: test".to_string()));
}

#[test]
fn test_response_analyzer_creation() {
    for category in [
        InjectionCategory::SqlInjection,
        InjectionCategory::NoSqlInjection,
        InjectionCategory::Xss,
        InjectionCategory::Ssti,
        InjectionCategory::CommandInjection,
        InjectionCategory::Xxe,
        InjectionCategory::LdapInjection,
        InjectionCategory::XPathInjection,
        InjectionCategory::HeaderInjection,
    ] {
        let analyzer = BuiltinResponseAnalyzer::new(category);
        assert_eq!(analyzer.category(), category);

        let methods = analyzer.supported_methods();
        assert!(!methods.is_empty());
    }
}

#[test]
fn test_error_patterns_sql_injection() {
    let analyzer = BuiltinResponseAnalyzer::new(InjectionCategory::SqlInjection);

    // Access private field through reflection-like test
    // We'll test via the analyze method instead
    let test_result = create_test_result(
        InjectionCategory::SqlInjection,
        "id",
        ParameterLocation::Query,
        "'",
        "You have an error in your SQL syntax",
        500,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].detection_method, DetectionMethod::ErrorBased);
}

#[test]
fn test_error_patterns_xss() {
    let analyzer = BuiltinResponseAnalyzer::new(InjectionCategory::Xss);

    let test_result = create_test_result(
        InjectionCategory::Xss,
        "search",
        ParameterLocation::Query,
        "<script>alert(1)</script>",
        "<html><body><script>alert(1)</script></body></html>",
        200,
    );

    let findings = analyzer.analyze(&test_result, None);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].detection_method, DetectionMethod::Reflection);
}

#[test]
fn test_confidence_scorer_creation() {
    let scorer = ConfidenceScorer::new();

    // Test method weights
    assert_eq!(
        scorer.method_weights.get(&DetectionMethod::ErrorBased),
        Some(&0.85)
    );
    assert_eq!(
        scorer.method_weights.get(&DetectionMethod::TimeBased),
        Some(&0.90)
    );
    assert_eq!(
        scorer.method_weights.get(&DetectionMethod::Reflection),
        Some(&0.95)
    );
    assert_eq!(
        scorer.method_weights.get(&DetectionMethod::OutOfBand),
        Some(&0.95)
    );
    assert_eq!(
        scorer.method_weights.get(&DetectionMethod::Heuristic),
        Some(&0.50)
    );

    // Test severity weights
    assert_eq!(scorer.severity_weights.get(&Severity::Critical), Some(&1.0));
    assert_eq!(scorer.severity_weights.get(&Severity::High), Some(&0.9));
    assert_eq!(scorer.severity_weights.get(&Severity::Medium), Some(&0.7));
    assert_eq!(scorer.severity_weights.get(&Severity::Low), Some(&0.5));
    assert_eq!(scorer.severity_weights.get(&Severity::Info), Some(&0.3));

    // Test category weights
    assert_eq!(
        scorer
            .category_weights
            .get(&InjectionCategory::SqlInjection),
        Some(&1.0)
    );
    assert_eq!(
        scorer.category_weights.get(&InjectionCategory::Ssti),
        Some(&0.98)
    );
    assert_eq!(
        scorer
            .category_weights
            .get(&InjectionCategory::CommandInjection),
        Some(&0.98)
    );
    assert_eq!(
        scorer.category_weights.get(&InjectionCategory::Xxe),
        Some(&0.97)
    );
}

#[test]
fn test_confidence_scoring_high() {
    let scorer = ConfidenceScorer::new();

    let finding = create_injection_test_result(
        InjectionCategory::SqlInjection,
        DetectionMethod::ErrorBased,
        Severity::High,
        0.8,
        true,
        true,
        true,
        2,
    );

    let score = scorer.score(&finding);
    assert!(score > 0.7);
    assert!(score <= 1.0);
}

#[test]
fn test_confidence_scoring_low() {
    let scorer = ConfidenceScorer::new();

    let finding = create_injection_test_result(
        InjectionCategory::Xss,
        DetectionMethod::Heuristic,
        Severity::Low,
        0.4,
        false,
        false,
        false,
        0,
    );

    let score = scorer.score(&finding);
    assert!(score < 0.5);
    assert!(score >= 0.0);
}

#[test]
fn test_confidence_labels() {
    let scorer = ConfidenceScorer::new();

    assert_eq!(scorer.confidence_label(0.95), "Very High");
    assert_eq!(scorer.confidence_label(0.8), "High");
    assert_eq!(scorer.confidence_label(0.65), "Medium");
    assert_eq!(scorer.confidence_label(0.45), "Low");
    assert_eq!(scorer.confidence_label(0.2), "Very Low");
}

#[test]
fn test_confidence_colors() {
    let scorer = ConfidenceScorer::new();

    assert_eq!(scorer.confidence_color(0.95), "green");
    assert_eq!(scorer.confidence_color(0.8), "light_green");
    assert_eq!(scorer.confidence_color(0.65), "yellow");
    assert_eq!(scorer.confidence_color(0.45), "orange");
    assert_eq!(scorer.confidence_color(0.2), "red");
}

#[test]
fn test_confidence_breakdown() {
    let scorer = ConfidenceScorer::new();

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
    assert_eq!(breakdown.base_confidence, 0.85);
    assert_eq!(breakdown.method_weight, 0.90);
    assert_eq!(breakdown.severity_weight, 0.9);
    assert_eq!(breakdown.category_weight, 1.0);
}

#[test]
fn test_safety_config_defaults() {
    let config = SafetyConfig::default();

    assert_eq!(config.max_requests_per_test, 100);
    assert_eq!(config.max_total_requests, 10000);
    assert_eq!(config.rate_limit_rps, 10.0);
    assert_eq!(config.max_payloads_per_param, 50);
    assert_eq!(config.max_concurrency, 5);
    assert_eq!(config.request_timeout_secs, 30);
    assert!(config.blocked_patterns.contains(&"DROP TABLE".to_string()));
    assert!(config.blocked_patterns.contains(&"DELETE FROM".to_string()));
    assert!(config.require_authorization);
}

#[test]
fn test_injection_plugin_config_defaults() {
    let config = openre_plugins::injection::InjectionPluginConfig::default();

    assert_eq!(config.request_timeout, 30);
    assert_eq!(config.max_concurrent_requests, 10);
    assert_eq!(config.user_agent, "open-re-injection-tester/1.0");
    assert!(config.follow_redirects);
    assert_eq!(config.max_redirects, 10);
    assert!(config.settings.contains_key("aggressive_mode"));
    assert!(config.settings.contains_key("verify_ssl"));
}

#[test]
fn test_payload_context_defaults() {
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

    assert_eq!(context.parameter_name, "test");
    assert_eq!(context.location, ParameterLocation::Query);
    assert!(!context.is_id_parameter);
    assert!(!context.is_auth_context);
}

#[test]
fn test_detection_method_serialization() {
    let method = DetectionMethod::ErrorBased;
    let json = serde_json::to_string(&method).unwrap();
    assert_eq!(json, "\"error_based\"");

    let method = DetectionMethod::TimeBased;
    let json = serde_json::to_string(&method).unwrap();
    assert_eq!(json, "\"time_based\"");
}

#[test]
fn test_severity_serialization() {
    let severity = Severity::Critical;
    let json = serde_json::to_string(&severity).unwrap();
    assert_eq!(json, "\"critical\"");

    let severity = Severity::High;
    let json = serde_json::to_string(&severity).unwrap();
    assert_eq!(json, "\"high\"");
}

#[test]
fn test_injection_category_serialization() {
    let category = InjectionCategory::SqlInjection;
    let json = serde_json::to_string(&category).unwrap();
    assert_eq!(json, "\"sql_injection\"");

    let category = InjectionCategory::Xss;
    let json = serde_json::to_string(&category).unwrap();
    assert_eq!(json, "\"xss\"");
}

#[test]
fn test_parameter_location_serialization() {
    let location = ParameterLocation::Query;
    let json = serde_json::to_string(&location).unwrap();
    assert_eq!(json, "\"query\"");

    let location = ParameterLocation::Header;
    let json = serde_json::to_string(&location).unwrap();
    assert_eq!(json, "\"header\"");
}

#[test]
fn test_encoding_serialization() {
    let encoding = Encoding::Url;
    let json = serde_json::to_string(&encoding).unwrap();
    assert_eq!(json, "\"url\"");

    let encoding = Encoding::HtmlEntity;
    let json = serde_json::to_string(&encoding).unwrap();
    assert_eq!(json, "\"html_entity\"");
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
