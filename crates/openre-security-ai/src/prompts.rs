//! Prompt compiler and template management for AI Security Analyst

use crate::AiAnalystError;
use std::collections::HashMap;

/// A prompt template with versioning
#[derive(Debug, Clone)]
pub struct PromptTemplate {
    /// Template name
    pub name: String,

    /// Semantic version
    pub version: String,

    /// System prompt text
    pub system_prompt: String,

    /// User prompt template
    pub user_template: String,

    /// Required variables for this template
    pub required_variables: Vec<String>,
}

/// Prompt compiler for assembling prompts from templates
pub struct PromptCompiler {
    templates: HashMap<String, PromptTemplate>,
}

impl PromptCompiler {
    /// Create a new prompt compiler
    pub fn new() -> Self {
        let mut compiler = Self { templates: HashMap::new() };

        // Register built-in templates
        compiler.register_builtin_templates();
        compiler
    }

    /// Register all built-in templates
    fn register_builtin_templates(&mut self) {
        // Explanation templates
        self.templates.insert(
            "explain_finding_system".to_string(),
            PromptTemplate {
                name: "explain_finding_system".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/explain_finding_system.txt").to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        self.templates.insert(
            "explain_finding_user".to_string(),
            PromptTemplate {
                name: "explain_finding_user".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: String::new(),
                user_template: include_str!("templates/explain_finding_user.txt").to_string(),
                required_variables: vec![
                    "finding_title".to_string(),
                    "finding_description".to_string(),
                    "severity".to_string(),
                    "confidence".to_string(),
                    "category".to_string(),
                    "target".to_string(),
                    "evidence_count".to_string(),
                ],
            },
        );

        // Remediation templates
        self.templates.insert(
            "generate_remediation_system".to_string(),
            PromptTemplate {
                name: "generate_remediation_system".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/generate_remediation_system.txt")
                    .to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        self.templates.insert(
            "generate_remediation_user".to_string(),
            PromptTemplate {
                name: "generate_remediation_user".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: String::new(),
                user_template: include_str!("templates/generate_remediation_user.txt").to_string(),
                required_variables: vec![
                    "finding_title".to_string(),
                    "finding_description".to_string(),
                    "category".to_string(),
                    "target".to_string(),
                    "evidence_summary".to_string(),
                ],
            },
        );

        // Correlation templates
        self.templates.insert(
            "correlate_findings_system".to_string(),
            PromptTemplate {
                name: "correlate_findings_system".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/correlate_findings_system.txt").to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        // Prioritization templates
        self.templates.insert(
            "prioritize_system".to_string(),
            PromptTemplate {
                name: "prioritize_system".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/prioritize_system.txt").to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        // Executive summary templates
        self.templates.insert(
            "executive_summary_developer".to_string(),
            PromptTemplate {
                name: "executive_summary_developer".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/executive_summary_developer.txt")
                    .to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        self.templates.insert(
            "executive_summary_manager".to_string(),
            PromptTemplate {
                name: "executive_summary_manager".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/executive_summary_manager.txt").to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        self.templates.insert(
            "executive_summary_security_engineer".to_string(),
            PromptTemplate {
                name: "executive_summary_security_engineer".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/executive_summary_security_engineer.txt")
                    .to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        self.templates.insert(
            "executive_summary_executive".to_string(),
            PromptTemplate {
                name: "executive_summary_executive".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/executive_summary_executive.txt")
                    .to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        // Query templates
        self.templates.insert(
            "natural_language_query_system".to_string(),
            PromptTemplate {
                name: "natural_language_query_system".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/natural_language_query_system.txt")
                    .to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );

        // Comparison templates
        self.templates.insert(
            "compare_scans_system".to_string(),
            PromptTemplate {
                name: "compare_scans_system".to_string(),
                version: "1.0.0".to_string(),
                system_prompt: include_str!("templates/compare_scans_system.txt").to_string(),
                user_template: String::new(),
                required_variables: vec![],
            },
        );
    }

    /// Get a template by name
    pub fn get_template(&self, name: &str) -> Option<&PromptTemplate> {
        self.templates.get(name)
    }

    /// List all available templates
    pub fn list_templates(&self) -> Vec<&PromptTemplate> {
        self.templates.values().collect()
    }

    /// Render a template with variables
    pub fn render_template(
        &self,
        name: &str,
        variables: &HashMap<String, String>,
    ) -> Result<String, AiAnalystError> {
        let template = self
            .get_template(name)
            .ok_or_else(|| AiAnalystError::TemplateNotFound(name.to_string()))?;

        // Check required variables
        for required_var in &template.required_variables {
            if !variables.contains_key(required_var) {
                return Err(AiAnalystError::Internal(format!(
                    "Missing required variable '{}' for template '{}'",
                    required_var, name
                )));
            }
        }

        // Simple variable substitution
        let mut result = template.user_template.clone();
        for (key, value) in variables {
            let placeholder = format!("{{{{{}}}}}", key);
            result = result.replace(&placeholder, value);
        }

        Ok(result)
    }
}

impl Default for PromptCompiler {
    fn default() -> Self {
        Self::new()
    }
}
