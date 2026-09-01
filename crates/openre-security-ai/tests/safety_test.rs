use openre_security_ai::safety::SafetyGuard;
use uuid::Uuid;

#[test]
fn test_safety_guard_creation() {
    let guard = SafetyGuard::new(true);
    assert!(guard.strict_evidence_checking());

    let guard = SafetyGuard::new(false);
    assert!(!guard.strict_evidence_checking());
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
    let finding_123 = Uuid::new_v4().to_string();
    let finding_456 = Uuid::new_v4().to_string();
    let finding_789 = Uuid::new_v4().to_string();
    let response = format!("This response references {} and {}", finding_123, finding_456);
    let available_ids = vec![finding_123.clone(), finding_789.clone()];

    // This should fail because finding-456 is not in available IDs
    let result = guard.validate_response_grounding(&response, &available_ids);
    assert!(result.is_err());

    // This should pass because all referenced IDs are available
    let response2 = format!("This response references {} only", finding_123);
    let result2 = guard.validate_response_grounding(&response2, &available_ids);
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
