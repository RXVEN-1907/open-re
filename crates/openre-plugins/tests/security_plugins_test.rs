//! Tests for security plugins

use openre_core::result::{
    Category, Confidence, Evidence, EvidenceType, Reference, ReferenceType, Severity,
};
use openre_plugins::security::{
    detect_mfa_indicators, detect_sso_providers, extract_cookies, is_auth_page,
    standard_references, CookieInfo, HttpResponse, SecurityPluginConfig, SecurityReference,
};
use std::collections::HashMap;

#[test]
fn test_security_plugin_config_default() {
    let config = SecurityPluginConfig::default();
    assert_eq!(config.request_timeout, 30);
    assert_eq!(config.max_concurrent_requests, 10);
    assert_eq!(config.user_agent, "open-re-security-scanner/1.0");
    assert!(config.follow_redirects);
    assert_eq!(config.max_redirects, 10);
}

#[test]
fn test_standard_references() {
    let refs = standard_references();
    assert!(!refs.is_empty());

    // Check for expected references
    let has_owasp_a07 = refs
        .iter()
        .any(|r| r.id == "A07:2021" && r.ref_type == "OWASP");
    let has_owasp_a05 = refs
        .iter()
        .any(|r| r.id == "A05:2021" && r.ref_type == "OWASP");
    let has_cwe_384 = refs
        .iter()
        .any(|r| r.id == "CWE-384" && r.ref_type == "CWE");
    let has_cwe_614 = refs
        .iter()
        .any(|r| r.id == "CWE-614" && r.ref_type == "CWE");
    let has_cwe_1004 = refs
        .iter()
        .any(|r| r.id == "CWE-1004" && r.ref_type == "CWE");

    assert!(has_owasp_a07);
    assert!(has_owasp_a05);
    assert!(has_cwe_384);
    assert!(has_cwe_614);
    assert!(has_cwe_1004);
}

#[test]
fn test_extract_cookies() {
    let mut headers = HashMap::new();
    headers.insert(
        "set-cookie".to_string(),
        "sessionid=abc123; Secure; HttpOnly; SameSite=Lax; Path=/".to_string(),
    );
    headers.insert(
        "set-cookie".to_string(),
        "csrftoken=xyz789; Secure; HttpOnly; SameSite=Strict; Path=/".to_string(),
    );

    let cookies = extract_cookies(&headers, "https://example.com");

    assert_eq!(cookies.len(), 2);

    let session_cookie = cookies.iter().find(|c| c.name == "sessionid").unwrap();
    assert_eq!(session_cookie.value, "abc123");
    assert!(session_cookie.secure);
    assert!(session_cookie.http_only);
    assert_eq!(session_cookie.same_site, Some("Lax".to_string()));
    assert_eq!(session_cookie.path, Some("/".to_string()));

    let csrf_cookie = cookies.iter().find(|c| c.name == "csrftoken").unwrap();
    assert_eq!(csrf_cookie.value, "xyz789");
    assert!(csrf_cookie.secure);
    assert!(csrf_cookie.http_only);
    assert_eq!(csrf_cookie.same_site, Some("Strict".to_string()));
}

#[test]
fn test_extract_cookies_with_domain_and_expiry() {
    let mut headers = HashMap::new();
    headers.insert("set-cookie".to_string(), "sessionid=abc123; Domain=.example.com; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=3600".to_string());

    let cookies = extract_cookies(&headers, "https://example.com");

    assert_eq!(cookies.len(), 1);
    let cookie = &cookies[0];
    assert_eq!(cookie.domain, Some(".example.com".to_string()));
    assert_eq!(
        cookie.expires,
        Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string())
    );
    assert_eq!(cookie.max_age, Some(3600));
}

#[test]
fn test_is_auth_page_login() {
    let url = "https://example.com/login";
    let body = r#"<form><input type="password" name="password"><input type="submit" value="Login"></form>"#;
    assert!(is_auth_page(url, body));
}

#[test]
fn test_is_auth_page_registration() {
    let url = "https://example.com/register";
    let body = r#"<form><input type="password" name="password"><input type="password" name="confirm_password"><button type="submit">Register</button></form>"#;
    assert!(is_auth_page(url, body));
}

#[test]
fn test_is_auth_page_password_reset() {
    let url = "https://example.com/password/reset";
    let body = "Forgot your password? Enter your email to reset.";
    assert!(is_auth_page(url, body));
}

#[test]
fn test_is_auth_page_mfa() {
    let url = "https://example.com/mfa";
    let body = "Enter your TOTP code from authenticator app";
    assert!(is_auth_page(url, body));
}

#[test]
fn test_is_auth_page_sso() {
    let url = "https://example.com/sso";
    let body = "Sign in with Google, GitHub, or SAML";
    assert!(is_auth_page(url, body));
}

#[test]
fn test_is_auth_page_not_auth() {
    let url = "https://example.com/dashboard";
    let body = "Welcome to your dashboard";
    assert!(!is_auth_page(url, body));
}

#[test]
fn test_detect_sso_providers() {
    let body = r#"
        <div>Sign in with Google</div>
        <div>Continue with GitHub</div>
        <div>Microsoft Azure AD</div>
        <div>Okta SSO</div>
        <div>Auth0</div>
    "#;

    let providers = detect_sso_providers(body);
    assert!(providers.iter().any(|p| p.contains("Google")));
    assert!(providers.iter().any(|p| p.contains("GitHub")));
    assert!(providers.iter().any(|p| p.contains("Microsoft")));
    assert!(providers.iter().any(|p| p.contains("Okta")));
    assert!(providers.iter().any(|p| p.contains("Auth0")));
}

#[test]
fn test_detect_mfa_indicators() {
    let body = r#"
        <div>Enter TOTP code</div>
        <div>Google Authenticator</div>
        <div>YubiKey</div>
        <div>WebAuthn</div>
        <div>SMS code</div>
        <div>Backup codes</div>
    "#;

    let indicators = detect_mfa_indicators(body);
    assert!(indicators.iter().any(|i| i.contains("TOTP")));
    assert!(indicators.iter().any(|i| i.contains("Authenticator")));
    assert!(indicators.iter().any(|i| i.contains("YubiKey")));
    assert!(indicators.iter().any(|i| i.contains("WebAuthn")));
    assert!(indicators.iter().any(|i| i.contains("SMS")));
    assert!(indicators.iter().any(|i| i.contains("Backup")));
}

#[test]
fn test_cookie_info_serialization() {
    let cookie = CookieInfo {
        name: "test".to_string(),
        value: "value".to_string(),
        domain: Some("example.com".to_string()),
        path: Some("/".to_string()),
        secure: true,
        http_only: true,
        same_site: Some("Lax".to_string()),
        expires: Some("Wed, 21 Oct 2026 07:28:00 GMT".to_string()),
        max_age: Some(3600),
    };

    let json = serde_json::to_string(&cookie).unwrap();
    let deserialized: CookieInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(cookie.name, deserialized.name);
    assert_eq!(cookie.value, deserialized.value);
    assert_eq!(cookie.domain, deserialized.domain);
    assert_eq!(cookie.path, deserialized.path);
    assert_eq!(cookie.secure, deserialized.secure);
    assert_eq!(cookie.http_only, deserialized.http_only);
    assert_eq!(cookie.same_site, deserialized.same_site);
    assert_eq!(cookie.expires, deserialized.expires);
    assert_eq!(cookie.max_age, deserialized.max_age);
}

#[test]
fn test_http_response_structure() {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());
    headers.insert(
        "set-cookie".to_string(),
        "session=abc; Secure; HttpOnly".to_string(),
    );

    let response = HttpResponse {
        status: 200,
        headers,
        body: "<html>Test</html>".to_string(),
        url: "https://example.com".to_string(),
        cookies: vec![],
    };

    assert_eq!(response.status, 200);
    assert_eq!(response.url, "https://example.com");
    assert!(response.headers.contains_key("content-type"));
}

#[test]
fn test_finding_creation() {
    let finding = openre_core::result::Finding::new(
        "Test Finding".to_string(),
        "Test Description".to_string(),
        Severity::High,
        Confidence::High,
        Category::BrokenAuthentication,
        "https://example.com".to_string(),
        "web_application".to_string(),
        "test_plugin".to_string(),
        "1.0.0".to_string(),
        openre_core::ids::ScanId::new(),
    );

    assert_eq!(finding.title, "Test Finding");
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.confidence, Confidence::High);
    assert_eq!(finding.category, Category::BrokenAuthentication);
    assert!(!finding.verified);
    assert!(!finding.false_positive);
}

#[test]
fn test_finding_with_evidence() {
    let finding = openre_core::result::Finding::new(
        "Test Finding".to_string(),
        "Test Description".to_string(),
        Severity::High,
        Confidence::High,
        Category::BrokenAuthentication,
        "https://example.com".to_string(),
        "web_application".to_string(),
        "test_plugin".to_string(),
        "1.0.0".to_string(),
        openre_core::ids::ScanId::new(),
    )
    .with_evidence(Evidence {
        evidence_type: EvidenceType::HttpResponse,
        description: "Test evidence".to_string(),
        data: Some(serde_json::json!({"key": "value"})),
        location: Some("https://example.com".to_string()),
        metadata: HashMap::new(),
    });

    assert_eq!(finding.evidence.len(), 1);
    assert_eq!(
        finding.evidence[0].evidence_type,
        EvidenceType::HttpResponse
    );
}

#[test]
fn test_finding_with_reference() {
    let finding = openre_core::result::Finding::new(
        "Test Finding".to_string(),
        "Test Description".to_string(),
        Severity::High,
        Confidence::High,
        Category::BrokenAuthentication,
        "https://example.com".to_string(),
        "web_application".to_string(),
        "test_plugin".to_string(),
        "1.0.0".to_string(),
        openre_core::ids::ScanId::new(),
    )
    .with_reference(Reference {
        reference_type: ReferenceType::Cwe,
        title: "CWE-384".to_string(),
        url: "https://cwe.mitre.org/data/definitions/384.html".to_string(),
        description: Some("Session Fixation".to_string()),
    });

    assert_eq!(finding.references.len(), 1);
    assert_eq!(finding.references[0].reference_type, ReferenceType::Cwe);
}

#[test]
fn test_finding_risk_score_calculation() {
    let finding = openre_core::result::Finding::new(
        "Test Finding".to_string(),
        "Test Description".to_string(),
        Severity::Critical,
        Confidence::VeryHigh,
        Category::BrokenAuthentication,
        "https://example.com".to_string(),
        "web_application".to_string(),
        "test_plugin".to_string(),
        "1.0.0".to_string(),
        openre_core::ids::ScanId::new(),
    );

    let score = finding.calculate_risk_score();
    // Critical (4) * 20 + VeryHigh (4) * 5 = 80 + 20 = 100
    assert_eq!(score, 100);
}

#[test]
fn test_severity_ordering() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    assert!(Severity::Low > Severity::Info);
}

#[test]
fn test_confidence_ordering() {
    assert!(Confidence::VeryHigh > Confidence::High);
    assert!(Confidence::High > Confidence::Medium);
    assert!(Confidence::Medium > Confidence::Low);
    assert!(Confidence::Low > Confidence::VeryLow);
}

#[test]
fn test_category_owasp_mapping() {
    assert_eq!(
        Category::BrokenAuthentication.owasp_category(),
        Some("A07:2021 - Identification and Authentication Failures")
    );
    assert_eq!(
        Category::SecurityMisconfiguration.owasp_category(),
        Some("A05:2021 - Security Misconfiguration")
    );
    assert_eq!(
        Category::Injection.owasp_category(),
        Some("A03:2021 - Injection")
    );
    assert_eq!(Category::InformationDisclosure.owasp_category(), None);
}
