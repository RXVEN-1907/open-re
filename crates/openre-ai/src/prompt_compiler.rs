//! Prompt compiler for open-re AI

use crate::providers::*;
use openre_core::error::Result;
use openre_storage::ProjectStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Prompt compiler
pub struct PromptCompiler {
    templates: HashMap<String, PromptTemplate>,
    few_shot_examples: HashMap<String, Vec<FewShotExample>>,
}

impl PromptCompiler {
    pub fn new() -> Self {
        let mut compiler = Self {
            templates: HashMap::new(),
            few_shot_examples: HashMap::new(),
        };
        compiler.register_builtin_templates();
        compiler
    }

    fn register_builtin_templates(&mut self) {
        // Function analysis template
        self.register_template(PromptTemplate {
            name: "analyze_function".to_string(),
            description: "Analyze a function for reverse engineering".to_string(),
            system_prompt: include_str!("templates/analyze_function_system.txt").to_string(),
            user_template: include_str!("templates/analyze_function_user.txt").to_string(),
            variables: vec![
                "function_name".to_string(),
                "architecture".to_string(),
                "disassembly".to_string(),
                "pseudocode".to_string(),
                "cfg_info".to_string(),
                "xrefs".to_string(),
                "strings".to_string(),
            ],
            few_shot_key: Some("analyze_function".to_string()),
        });

        // Variable recovery template
        self.register_template(PromptTemplate {
            name: "recover_variables".to_string(),
            description: "Recover variable types and names".to_string(),
            system_prompt: include_str!("templates/recover_variables_system.txt").to_string(),
            user_template: include_str!("templates/recover_variables_user.txt").to_string(),
            variables: vec![
                "function_name".to_string(),
                "stack_frame".to_string(),
                "register_usage".to_string(),
                "calling_convention".to_string(),
            ],
            few_shot_key: Some("recover_variables".to_string()),
        });

        // Type inference template
        self.register_template(PromptTemplate {
            name: "infer_types".to_string(),
            description: "Infer types for variables and functions".to_string(),
            system_prompt: include_str!("templates/infer_types_system.txt").to_string(),
            user_template: include_str!("templates/infer_types_user.txt").to_string(),
            variables: vec![
                "function_signature".to_string(),
                "usage_patterns".to_string(),
                "data_flow".to_string(),
            ],
            few_shot_key: Some("infer_types".to_string()),
        });

        // Vulnerability detection template
        self.register_template(PromptTemplate {
            name: "detect_vulnerabilities".to_string(),
            description: "Detect potential vulnerabilities in code".to_string(),
            system_prompt: include_str!("templates/detect_vulnerabilities_system.txt").to_string(),
            user_template: include_str!("templates/detect_vulnerabilities_user.txt").to_string(),
            variables: vec![
                "function_name".to_string(),
                "pseudocode".to_string(),
                "taint_sources".to_string(),
                "taint_sinks".to_string(),
            ],
            few_shot_key: Some("detect_vulnerabilities".to_string()),
        });

        // Decompilation improvement template
        self.register_template(PromptTemplate {
            name: "improve_decompilation".to_string(),
            description: "Improve decompilation output".to_string(),
            system_prompt: include_str!("templates/improve_decompilation_system.txt").to_string(),
            user_template: include_str!("templates/improve_decompilation_user.txt").to_string(),
            variables: vec![
                "original_pseudocode".to_string(),
                "issues".to_string(),
                "context".to_string(),
            ],
            few_shot_key: Some("improve_decompilation".to_string()),
        });

        // Register few-shot examples
        self.register_few_shot_examples();
    }

    fn register_template(&mut self, template: PromptTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    fn register_few_shot_examples(&mut self) {
        // Analyze function examples
        self.few_shot_examples.insert("analyze_function".to_string(), vec![
            FewShotExample {
                input: r#"Function: main
Architecture: x86_64
Disassembly:
push rbp
mov rbp, rsp
sub rsp, 0x20
mov edi, 0x1
call puts
xor eax, eax
leave
ret"#.to_string(),
                output: r#"This is a simple main function that prints "Hello World" (or similar) using puts and returns 0. The function sets up a standard stack frame, allocates 32 bytes of stack space, calls puts with argument 1 (likely a string pointer in .rodata), then cleans up and returns."#.to_string(),
            },
        ]);

        // Recover variables examples
        self.few_shot_examples.insert("recover_variables".to_string(), vec![
            FewShotExample {
                input: r#"Function: process_data
Stack frame: 0x40 bytes
Register usage: rdi=ptr, rsi=len, rdx=flags
Calling convention: System V AMD64"#.to_string(),
                output: r#"Variables:
- arg1 (rdi): const char* data_ptr - input data pointer
- arg2 (rsi): size_t data_len - length of input data
- arg3 (rdx): uint32_t flags - processing flags
- var_10 (rbp-0x10): size_t i - loop counter
- var_8 (rbp-0x8): int result - return value"#.to_string(),
            },
        ]);
    }

    /// Compile a prompt from template
    pub fn compile(&self, template_name: &str, variables: HashMap<String, String>) -> Result<CompiledPrompt> {
        let template = self.templates.get(template_name)
            .ok_or_else(|| openre_core::Error::NotFound(format!("Template not found: {}", template_name)))?;

        // Validate required variables
        for var in &template.variables {
            if !variables.contains_key(var) {
                return Err(openre_core::Error::InvalidInput(format!("Missing required variable: {}", var)));
            }
        }

        // Build system prompt
        let system_prompt = self.render_template(&template.system_prompt, &variables)?;

        // Build user prompt
        let user_prompt = self.render_template(&template.user_template, &variables)?;

        // Get few-shot examples
        let few_shot = if let Some(key) = &template.few_shot_key {
            self.few_shot_examples.get(key).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };

        Ok(CompiledPrompt {
            system_prompt,
            user_prompt,
            few_shot_examples: few_shot,
            template_name: template_name.to_string(),
        })
    }

    /// Compile with context assembly from project data
    pub async fn compile_with_context(
        &self,
        template_name: &str,
        variables: HashMap<String, String>,
        project_store: &ProjectStore,
        function_id: openre_core::ids::FunctionId,
    ) -> Result<CompiledPrompt> {
        let mut enriched_vars = variables;

        // Enrich with project data
        if let Ok(Some(func)) = project_store.get_function(function_id).await {
            enriched_vars.insert("function_name".to_string(), func.name);
            enriched_vars.insert("function_address".to_string(), format!("0x{:x}", func.address));
        }

        if let Ok(blocks) = project_store.get_basic_blocks(function_id).await {
            let disassembly = blocks.iter()
                .flat_map(|b| &b.instructions)
                .map(|i| format!("0x{:x}: {}", i.address, i.mnemonic))
                .collect::<Vec<_>>()
                .join("\n");
            enriched_vars.insert("disassembly".to_string(), disassembly);
        }

        if let Ok(pseudocode) = project_store.get_pseudocode(function_id).await {
            enriched_vars.insert("pseudocode".to_string(), pseudocode);
        }

        self.compile(template_name, enriched_vars)
    }

    fn render_template(&self, template: &str, variables: &HashMap<String, String>) -> Result<String> {
        let mut result = template.to_string();
        for (key, value) in variables {
            result = result.replace(&format!("{{{{{}}}}}", key), value);
        }
        Ok(result)
    }

    /// Get available templates
    pub fn list_templates(&self) -> Vec<&PromptTemplate> {
        self.templates.values().collect()
    }

    /// Get template by name
    pub fn get_template(&self, name: &str) -> Option<&PromptTemplate> {
        self.templates.get(name)
    }
}

impl Default for PromptCompiler {
    fn default() -> Self {
        Self::new()
    }
}

/// Prompt template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    pub name: String,
    pub description: String,
    pub system_prompt: String,
    pub user_template: String,
    pub variables: Vec<String>,
    pub few_shot_key: Option<String>,
}

/// Few-shot example
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FewShotExample {
    pub input: String,
    pub output: String,
}

/// Compiled prompt ready for provider
#[derive(Debug, Clone)]
pub struct CompiledPrompt {
    pub system_prompt: String,
    pub user_prompt: String,
    pub few_shot_examples: Vec<FewShotExample>,
    pub template_name: String,
}

impl CompiledPrompt {
    /// Convert to completion request
    pub fn to_completion_request(&self, model: &str, temperature: Option<f32>) -> CompletionRequest {
        let mut messages = vec![Message::system(self.system_prompt.clone())];

        // Add few-shot examples
        for example in &self.few_shot_examples {
            messages.push(Message::user(example.input.clone()));
            messages.push(Message::assistant(example.output.clone()));
        }

        // Add actual user prompt
        messages.push(Message::user(self.user_prompt.clone()));

        CompletionRequest {
            messages,
            tools: None,
            tool_choice: None,
            temperature,
            max_tokens: Some(4096),
            top_p: Some(0.95),
            stop: None,
            response_format: None,
            stream: false,
            metadata: HashMap::new(),
        }
    }
}