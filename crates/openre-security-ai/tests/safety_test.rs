use openre_security_ai::safety::SafetyGuard;

#[test]
fn test_safety_guard_creation() {
    let guard = SafetyGuard::new(true);
    assert_eq!(guard.strict_evidence_checking, true);

    let guard = SafetyGuard::new(false);
    assert_eq!(guard.strict_evidence_checking, false);
}

#[test]
fn test_claim_tagging() {
    let guard = SafetyGuard::new(false);
    let content = "This is a security finding explanation";
    let evidence_ids = vec!["evidence-1".to_string(), "evidence-2".to_string()];

    let claims = guard.tag_claims(content, &evidence_ids);
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].content, content);
}

#[test]
fn test_response_grounding_validation() {
    let guard = SafetyGuard::new(true);
    let response = "This response references finding-123 and finding-456";
    let available_ids = vec!["finding-123".to_string(), "finding-789".to_string()];

    // This should fail because finding-456 is not in available IDs
    let result = guard.validate_response_grounding(response, &available_ids);
    assert!(result.is_err());

    // This should pass because all referenced IDs are available
    let response2 = "This response references finding-123 only";
    let result2 = guard.validate_response_grounding(response2, &available_ids);
    assert!(result2.is_ok());
}

#[test]
fn test_hallucination_detection() {
    let guard = SafetyGuard::new(false);

    // Test detecting unsubstantiated impact claims
    let response = "This vulnerability will allow attackers to gain full system access";
    let context = "The finding shows improper input validation";

    let alerts = guard.detect_hallucination(response, context);
    assert!(!alerts.is_empty());
}