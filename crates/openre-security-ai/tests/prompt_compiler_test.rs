use openre_security_ai::prompts::PromptCompiler;
use std::collections::HashMap;

#[test]
fn test_prompt_compiler_creation() {
    let compiler = PromptCompiler::new();
    assert!(!compiler.list_templates().is_empty());

    // Check that all expected templates are present
    let template_names: Vec<&str> = compiler
        .list_templates()
        .iter()
        .map(|t| t.name.as_str())
        .collect();

    assert!(template_names.contains(&"explain_finding_system"));
    assert!(template_names.contains(&"explain_finding_user"));
    assert!(template_names.contains(&"generate_remediation_system"));
    assert!(template_names.contains(&"generate_remediation_user"));
}

#[test]
fn test_template_rendering() {
    let compiler = PromptCompiler::new();

    // Test rendering a template with variables
    let mut variables = HashMap::new();
    variables.insert("finding_title".to_string(), "SQL Injection".to_string());
    variables.insert(
        "finding_description".to_string(),
        "User input is not properly sanitized".to_string(),
    );
    variables.insert("severity".to_string(), "High".to_string());
    variables.insert("confidence".to_string(), "Medium".to_string());
    variables.insert("category".to_string(), "Injection".to_string());
    variables.insert("target".to_string(), "http://example.com/login".to_string());
    variables.insert("evidence_count".to_string(), "3".to_string());

    let result = compiler.render_template("explain_finding_user", &variables);
    assert!(result.is_ok());

    let rendered = result.unwrap();
    assert!(rendered.contains("SQL Injection"));
    assert!(rendered.contains("User input is not properly sanitized"));
    assert!(rendered.contains("High"));
    assert!(rendered.contains("Medium"));
}

#[test]
fn test_missing_variables() {
    let compiler = PromptCompiler::new();

    // Test with missing required variables
    let variables = HashMap::new();
    let result = compiler.render_template("explain_finding_user", &variables);
    assert!(result.is_err());
}
