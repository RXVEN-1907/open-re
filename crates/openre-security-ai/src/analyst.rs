//! Security Analyst service - main entry point for AI-powered security analysis

use crate::{
    cache::AnalysisCache, context::ContextBuilder, prompts::PromptCompiler, safety::SafetyGuard,
    types::*, AiAnalystError, AiResult, FindingProvider, ScanMetadata,
};
use async_trait::async_trait;
use openre_ai::providers::{
    CompletionRequest, CompletionResponse, Message, ModelProvider, StreamChunk, StreamingResponse,
};
use openre_core::ids::{FindingId, ScanId};
use openre_core::result::{Finding, FindingFilter};
use serde_json::Value;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, info, warn};

/// Audience for executive summaries
#[derive(Debug, Clone)]
pub enum SummaryAudience {
    Developer,
    SecurityEngineer,
    Manager,
    Executive,
}

/// Main AI Security Analyst service
#[async_trait]
pub trait SecurityAnalyst: Send + Sync {
    /// Explain why a finding exists and its security implications
    async fn explain_finding(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<FindingExplanation>;

    /// Stream explanation of a finding
    async fn stream_explain_finding(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;

    /// Generate remediation guidance for a finding
    async fn generate_remediation(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<RemediationPlan>;

    /// Stream generation of remediation guidance
    async fn stream_generate_remediation(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;

    /// Identify relationships between findings
    async fn correlate_findings(
        &self,
        scan_id: ScanId,
        filter: Option<&FindingFilter>,
    ) -> AiResult<CorrelationReport>;

    /// Stream correlation of findings
    async fn stream_correlate_findings(
        &self,
        scan_id: ScanId,
        filter: Option<&FindingFilter>,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;

    /// Generate prioritized remediation plan
    async fn prioritize_findings(&self, scan_id: ScanId) -> AiResult<PrioritizedFindings>;

    /// Stream prioritization of findings
    async fn stream_prioritize_findings(
        &self,
        scan_id: ScanId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;

    /// Generate executive summary for a specific audience
    async fn executive_summary(
        &self,
        scan_id: ScanId,
        audience: SummaryAudience,
    ) -> AiResult<ExecutiveSummary>;

    /// Stream generation of executive summary
    async fn stream_executive_summary(
        &self,
        scan_id: ScanId,
        audience: SummaryAudience,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;

    /// Answer natural language questions about findings
    async fn query_findings(&self, scan_id: ScanId, question: &str) -> AiResult<QueryResponse>;

    /// Stream querying of findings
    async fn stream_query_findings(
        &self,
        scan_id: ScanId,
        question: &str,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;

    /// Compare two scans for changes
    async fn compare_scans(
        &self,
        base_scan_id: ScanId,
        target_scan_id: ScanId,
    ) -> AiResult<ScanComparison>;

    /// Stream comparison of scans
    async fn stream_compare_scans(
        &self,
        base_scan_id: ScanId,
        target_scan_id: ScanId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>>;
}

/// Concrete implementation of SecurityAnalyst
pub struct SecurityAnalystImpl {
    finding_provider: Arc<dyn FindingProvider>,
    model_provider: Arc<dyn ModelProvider>,
    prompt_compiler: Arc<PromptCompiler>,
    context_builder: Arc<ContextBuilder>,
    cache: Arc<AnalysisCache>,
    safety_guard: Arc<SafetyGuard>,
    max_tokens: usize,
}

impl SecurityAnalystImpl {
    /// Create a new security analyst
    pub fn new(
        finding_provider: Arc<dyn FindingProvider>,
        model_provider: Arc<dyn ModelProvider>,
        max_context_tokens: usize,
    ) -> Self {
        Self {
            finding_provider,
            model_provider,
            prompt_compiler: Arc::new(PromptCompiler::new()),
            context_builder: Arc::new(ContextBuilder::new(max_context_tokens)),
            cache: Arc::new(AnalysisCache::default()),
            safety_guard: Arc::new(SafetyGuard::default()),
            max_tokens: max_context_tokens,
        }
    }

    /// Create a new security analyst with custom components
    pub fn with_components(
        finding_provider: Arc<dyn FindingProvider>,
        model_provider: Arc<dyn ModelProvider>,
        prompt_compiler: Arc<PromptCompiler>,
        context_builder: Arc<ContextBuilder>,
        cache: Arc<AnalysisCache>,
        safety_guard: Arc<SafetyGuard>,
    ) -> Self {
        let max_tokens = context_builder.max_tokens();
        Self {
            finding_provider,
            model_provider,
            prompt_compiler,
            context_builder,
            cache,
            safety_guard,
            max_tokens,
        }
    }

    /// Helper to get model info for responses
    fn get_model_info(&self) -> ModelInfo {
        ModelInfo {
            model: "unknown".to_string(), // In real implementation, this would come from the provider
            version: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Helper to create completion request
    async fn create_completion_request(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> AiResult<CompletionRequest> {
        Ok(CompletionRequest {
            messages: vec![
                Message::system(system_prompt.to_string()),
                Message::user(user_prompt.to_string()),
            ],
            temperature: Some(0.7),
            max_tokens: Some(self.max_tokens as u32),
            ..Default::default()
        })
    }

    /// Helper to execute completion and handle response
    async fn execute_completion<T>(&self, request: CompletionRequest) -> AiResult<T>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self.model_provider.complete(request).await?;

        if let Some(choice) = response.choices.first() {
            if let Some(content) = &choice.message.content {
                // Validate response grounding
                // In a real implementation, we'd pass available finding IDs for validation
                let available_ids: Vec<String> = vec![]; // Empty for now
                self.safety_guard.validate_response_grounding(content, &available_ids)?;

                // Parse the response
                let result: T = serde_json::from_str(content)?;
                return Ok(result);
            }
        }

        Err(AiAnalystError::Internal("No valid response from model".to_string()))
    }

    /// Helper to execute streaming completion and handle response
    async fn execute_streaming_completion(
        &self,
        request: CompletionRequest,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Check if the provider supports streaming
        if !self.model_provider.supports_streaming() {
            return Err(AiAnalystError::Internal(
                "Model provider does not support streaming".to_string(),
            ));
        }

        let response = self.model_provider.stream(request).await?;

        // Forward only content chunks to the caller
        let (tx, rx) = tokio::sync::mpsc::channel::<AiResult<String>>(64);
        tokio::spawn(async move {
            let mut source = response.stream;
            while let Some(chunk) = source.recv().await {
                match chunk {
                    StreamChunk::Content(content) => {
                        if tx.send(Ok(content)).await.is_err() {
                            break;
                        }
                    }
                    StreamChunk::Finish(_) | StreamChunk::ToolCall(_) => continue,
                }
            }
        });

        let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

        Ok(Box::pin(stream))
    }
}

#[async_trait]
impl SecurityAnalyst for SecurityAnalystImpl {
    async fn explain_finding(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<FindingExplanation> {
        // Try cache first
        // In a real implementation, we'd use proper cache keys with template versions

        // Get the finding
        let finding = self
            .finding_provider
            .get_finding(scan_id, finding_id)
            .await?
            .ok_or(AiAnalystError::FindingNotFound(finding_id))?;

        // Build context
        let context = self.context_builder.build_finding_context(&finding)?;

        // Get templates
        let system_template =
            self.prompt_compiler.get_template("explain_finding_system").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("explain_finding_system".to_string())
            })?;

        let user_template = self
            .prompt_compiler
            .get_template("explain_finding_user")
            .ok_or_else(|| AiAnalystError::TemplateNotFound("explain_finding_user".to_string()))?;

        // Prepare variables for user template
        let mut variables = std::collections::HashMap::new();
        variables.insert("finding_title".to_string(), finding.title.clone());
        variables.insert("finding_description".to_string(), finding.description.clone());
        variables.insert("severity".to_string(), format!("{:?}", finding.severity));
        variables.insert("confidence".to_string(), format!("{:?}", finding.confidence));
        variables.insert("category".to_string(), format!("{:?}", finding.category));
        variables.insert("target".to_string(), finding.target.clone());
        variables.insert("evidence_count".to_string(), context.evidence.len().to_string());

        // Render user prompt
        let user_prompt =
            self.prompt_compiler.render_template("explain_finding_user", &variables)?;

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut explanation: FindingExplanation = self.execute_completion(request).await?;

        // Add model info
        explanation.model_info = self.get_model_info();
        explanation.finding_id = finding_id;

        Ok(explanation)
    }

    async fn generate_remediation(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<RemediationPlan> {
        // Get the finding
        let finding = self
            .finding_provider
            .get_finding(scan_id, finding_id)
            .await?
            .ok_or(AiAnalystError::FindingNotFound(finding_id))?;

        // Build a simplified evidence summary for the prompt
        let evidence_summary: String = finding
            .evidence
            .iter()
            .take(5) // Limit to first 5 pieces of evidence
            .map(|e| format!("- {}: {}", e.evidence_type, e.description))
            .collect::<Vec<_>>()
            .join("\n");

        // Get templates
        let system_template =
            self.prompt_compiler.get_template("generate_remediation_system").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("generate_remediation_system".to_string())
            })?;

        let user_template =
            self.prompt_compiler.get_template("generate_remediation_user").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("generate_remediation_user".to_string())
            })?;

        // Prepare variables for user template
        let mut variables = std::collections::HashMap::new();
        variables.insert("finding_title".to_string(), finding.title.clone());
        variables.insert("finding_description".to_string(), finding.description.clone());
        variables.insert("category".to_string(), format!("{:?}", finding.category));
        variables.insert("target".to_string(), finding.target.clone());
        variables.insert("evidence_summary".to_string(), evidence_summary);

        // Render user prompt
        let user_prompt =
            self.prompt_compiler.render_template("generate_remediation_user", &variables)?;

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut plan: RemediationPlan = self.execute_completion(request).await?;

        // Add model info
        plan.model_info = self.get_model_info();
        plan.finding_id = finding_id;

        Ok(plan)
    }

    async fn correlate_findings(
        &self,
        scan_id: ScanId,
        filter: Option<&FindingFilter>,
    ) -> AiResult<CorrelationReport> {
        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, filter).await?;

        // Convert to references for context builder
        let finding_refs: Vec<&Finding> = findings.iter().collect();

        // Build correlation context
        let context = self.context_builder.build_correlation_context(&finding_refs)?;

        // Get template
        let system_template =
            self.prompt_compiler.get_template("correlate_findings_system").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("correlate_findings_system".to_string())
            })?;

        // Create a summary of findings for the prompt
        let findings_summary: String = context
            .findings
            .iter()
            .map(|f| format!("- {} ({}, {})", f.title, f.category, f.severity))
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with findings summary
        let user_prompt = format!(
            "Analyze the following security findings for correlations and relationships:\n\n{}",
            findings_summary
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut report: CorrelationReport = self.execute_completion(request).await?;

        // Add model info
        report.model_info = self.get_model_info();
        report.scan_id = scan_id;

        Ok(report)
    }

    async fn prioritize_findings(&self, scan_id: ScanId) -> AiResult<PrioritizedFindings> {
        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, None).await?;

        // Get template
        let system_template = self
            .prompt_compiler
            .get_template("prioritize_system")
            .ok_or_else(|| AiAnalystError::TemplateNotFound("prioritize_system".to_string()))?;

        // Create a summary of findings for the prompt
        let findings_summary: String = findings
            .iter()
            .map(|f| {
                format!(
                    "- {} (Severity: {:?}, Confidence: {:?}, Risk Score: {:?})",
                    f.title, f.severity, f.confidence, f.risk_score
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with findings summary
        let user_prompt = format!(
            "Prioritize the following security findings based on risk factors:\n\n{}",
            findings_summary
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut prioritized: PrioritizedFindings = self.execute_completion(request).await?;

        // Add model info
        prioritized.model_info = self.get_model_info();
        prioritized.scan_id = scan_id;

        Ok(prioritized)
    }

    async fn executive_summary(
        &self,
        scan_id: ScanId,
        audience: SummaryAudience,
    ) -> AiResult<ExecutiveSummary> {
        // Get scan metadata
        let metadata = self.finding_provider.get_scan_metadata(scan_id).await?;

        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, None).await?;

        // Determine which template to use based on audience
        let template_name = match audience {
            SummaryAudience::Developer => "executive_summary_developer",
            SummaryAudience::SecurityEngineer => "executive_summary_security_engineer",
            SummaryAudience::Manager => "executive_summary_manager",
            SummaryAudience::Executive => "executive_summary_executive",
        };

        // Get template
        let system_template = self
            .prompt_compiler
            .get_template(template_name)
            .ok_or_else(|| AiAnalystError::TemplateNotFound(template_name.to_string()))?;

        // Create a summary of key findings
        let key_findings: Vec<SummaryFinding> = findings
            .iter()
            .take(10) // Top 10 findings
            .map(|f| SummaryFinding {
                finding_id: f.id,
                title: f.title.clone(),
                severity: f.severity,
                brief: f.description.chars().take(100).collect::<String>(),
                priority: RemediationPriority::Medium, // Would be determined by actual prioritization
            })
            .collect();

        // Create user prompt with scan info and findings
        let audience_str = format!("{:?}", audience);
        let user_prompt = format!(
            "Create an executive summary for a {} audience about security scan {} targeting {}.\n\nKey findings:\n{}",
            audience_str,
            scan_id,
            metadata.target,
            key_findings.iter()
                .map(|f| format!("- {} ({:?})", f.title, f.severity))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut summary: ExecutiveSummary = self.execute_completion(request).await?;

        // Add model info and audience
        summary.model_info = self.get_model_info();
        summary.scan_id = scan_id;
        summary.audience = match audience {
            SummaryAudience::Developer => Audience::Developer,
            SummaryAudience::SecurityEngineer => Audience::SecurityEngineer,
            SummaryAudience::Manager => Audience::Manager,
            SummaryAudience::Executive => Audience::Executive,
        };

        Ok(summary)
    }

    async fn query_findings(&self, scan_id: ScanId, question: &str) -> AiResult<QueryResponse> {
        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, None).await?;

        // Get template
        let system_template =
            self.prompt_compiler.get_template("natural_language_query_system").ok_or_else(
                || AiAnalystError::TemplateNotFound("natural_language_query_system".to_string()),
            )?;

        // Create a summary of findings for context
        let findings_summary: String = findings
            .iter()
            .map(|f| {
                format!(
                    "- {} (ID: {}, Severity: {:?}, Category: {:?}): {}",
                    f.title, f.id, f.severity, f.category, f.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with question and findings context
        let user_prompt =
            format!("Question: {}\n\nAvailable findings:\n{}", question, findings_summary);

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut response: QueryResponse = self.execute_completion(request).await?;

        // Add model info and question
        response.model_info = self.get_model_info();
        response.question = question.to_string();

        Ok(response)
    }

    async fn compare_scans(
        &self,
        base_scan_id: ScanId,
        target_scan_id: ScanId,
    ) -> AiResult<ScanComparison> {
        // Get findings from both scans
        let base_findings = self.finding_provider.list_findings(base_scan_id, None).await?;
        let target_findings = self.finding_provider.list_findings(target_scan_id, None).await?;

        // Get template
        let system_template = self
            .prompt_compiler
            .get_template("compare_scans_system")
            .ok_or_else(|| AiAnalystError::TemplateNotFound("compare_scans_system".to_string()))?;

        // Create summaries of findings from both scans
        let base_summary: String = base_findings
            .iter()
            .map(|f| format!("- {} ({:?}, {:?})", f.title, f.severity, f.category))
            .collect::<Vec<_>>()
            .join("\n");

        let target_summary: String = target_findings
            .iter()
            .map(|f| format!("- {} ({:?}, {:?})", f.title, f.severity, f.category))
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with both scan summaries
        let user_prompt = format!(
            "Compare security scan results:\n\nBase Scan ({}):\n{}\n\nTarget Scan ({}):\n{}\n\nAnalyze the differences.",
            base_scan_id, base_summary, target_scan_id, target_summary
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute completion
        let mut comparison: ScanComparison = self.execute_completion(request).await?;

        // Add model info and scan IDs
        comparison.model_info = self.get_model_info();
        comparison.base_scan_id = base_scan_id;
        comparison.target_scan_id = target_scan_id;

        Ok(comparison)
    }

    async fn stream_explain_finding(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get the finding
        let finding = self
            .finding_provider
            .get_finding(scan_id, finding_id)
            .await?
            .ok_or(AiAnalystError::FindingNotFound(finding_id))?;

        // Build context
        let context = self.context_builder.build_finding_context(&finding)?;

        // Get templates
        let system_template =
            self.prompt_compiler.get_template("explain_finding_system").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("explain_finding_system".to_string())
            })?;

        let user_template = self
            .prompt_compiler
            .get_template("explain_finding_user")
            .ok_or_else(|| AiAnalystError::TemplateNotFound("explain_finding_user".to_string()))?;

        // Prepare variables for user template
        let mut variables = std::collections::HashMap::new();
        variables.insert("finding_title".to_string(), finding.title.clone());
        variables.insert("finding_description".to_string(), finding.description.clone());
        variables.insert("severity".to_string(), format!("{:?}", finding.severity));
        variables.insert("confidence".to_string(), format!("{:?}", finding.confidence));
        variables.insert("category".to_string(), format!("{:?}", finding.category));
        variables.insert("target".to_string(), finding.target.clone());
        variables.insert("evidence_count".to_string(), context.evidence.len().to_string());

        // Render user prompt
        let user_prompt =
            self.prompt_compiler.render_template("explain_finding_user", &variables)?;

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }

    async fn stream_generate_remediation(
        &self,
        scan_id: ScanId,
        finding_id: FindingId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get the finding
        let finding = self
            .finding_provider
            .get_finding(scan_id, finding_id)
            .await?
            .ok_or(AiAnalystError::FindingNotFound(finding_id))?;

        // Build a simplified evidence summary for the prompt
        let evidence_summary: String = finding
            .evidence
            .iter()
            .take(5) // Limit to first 5 pieces of evidence
            .map(|e| format!("- {}: {}", e.evidence_type, e.description))
            .collect::<Vec<_>>()
            .join("\n");

        // Get templates
        let system_template =
            self.prompt_compiler.get_template("generate_remediation_system").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("generate_remediation_system".to_string())
            })?;

        let user_template =
            self.prompt_compiler.get_template("generate_remediation_user").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("generate_remediation_user".to_string())
            })?;

        // Prepare variables for user template
        let mut variables = std::collections::HashMap::new();
        variables.insert("finding_title".to_string(), finding.title.clone());
        variables.insert("finding_description".to_string(), finding.description.clone());
        variables.insert("category".to_string(), format!("{:?}", finding.category));
        variables.insert("target".to_string(), finding.target.clone());
        variables.insert("evidence_summary".to_string(), evidence_summary);

        // Render user prompt
        let user_prompt =
            self.prompt_compiler.render_template("generate_remediation_user", &variables)?;

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }

    async fn stream_correlate_findings(
        &self,
        scan_id: ScanId,
        filter: Option<&FindingFilter>,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, filter).await?;

        // Convert to references for context builder
        let finding_refs: Vec<&Finding> = findings.iter().collect();

        // Build correlation context
        let context = self.context_builder.build_correlation_context(&finding_refs)?;

        // Get template
        let system_template =
            self.prompt_compiler.get_template("correlate_findings_system").ok_or_else(|| {
                AiAnalystError::TemplateNotFound("correlate_findings_system".to_string())
            })?;

        // Create a summary of findings for the prompt
        let findings_summary: String = context
            .findings
            .iter()
            .map(|f| format!("- {} ({}, {})", f.title, f.category, f.severity))
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with findings summary
        let user_prompt = format!(
            "Analyze the following security findings for correlations and relationships:\n\n{}",
            findings_summary
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }

    async fn stream_prioritize_findings(
        &self,
        scan_id: ScanId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, None).await?;

        // Get template
        let system_template = self
            .prompt_compiler
            .get_template("prioritize_system")
            .ok_or_else(|| AiAnalystError::TemplateNotFound("prioritize_system".to_string()))?;

        // Create a summary of findings for the prompt
        let findings_summary: String = findings
            .iter()
            .map(|f| {
                format!(
                    "- {} (Severity: {:?}, Confidence: {:?}, Risk Score: {:?})",
                    f.title, f.severity, f.confidence, f.risk_score
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with findings summary
        let user_prompt = format!(
            "Prioritize the following security findings based on risk factors:\n\n{}",
            findings_summary
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }

    async fn stream_executive_summary(
        &self,
        scan_id: ScanId,
        audience: SummaryAudience,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get scan metadata
        let metadata = self.finding_provider.get_scan_metadata(scan_id).await?;

        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, None).await?;

        // Determine which template to use based on audience
        let template_name = match audience {
            SummaryAudience::Developer => "executive_summary_developer",
            SummaryAudience::SecurityEngineer => "executive_summary_security_engineer",
            SummaryAudience::Manager => "executive_summary_manager",
            SummaryAudience::Executive => "executive_summary_executive",
        };

        // Get template
        let system_template = self
            .prompt_compiler
            .get_template(template_name)
            .ok_or_else(|| AiAnalystError::TemplateNotFound(template_name.to_string()))?;

        // Create a summary of key findings
        let key_findings: Vec<SummaryFinding> = findings
            .iter()
            .take(10) // Top 10 findings
            .map(|f| SummaryFinding {
                finding_id: f.id,
                title: f.title.clone(),
                severity: f.severity,
                brief: f.description.chars().take(100).collect::<String>(),
                priority: RemediationPriority::Medium, // Would be determined by actual prioritization
            })
            .collect();

        // Create user prompt with scan info and findings
        let audience_str = format!("{:?}", audience);
        let user_prompt = format!(
            "Create an executive summary for a {} audience about security scan {} targeting {}.\n\nKey findings:\n{}",
            audience_str,
            scan_id,
            metadata.target,
            key_findings.iter()
                .map(|f| format!("- {} ({:?})", f.title, f.severity))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }

    async fn stream_query_findings(
        &self,
        scan_id: ScanId,
        question: &str,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get all findings for the scan
        let findings = self.finding_provider.list_findings(scan_id, None).await?;

        // Get template
        let system_template =
            self.prompt_compiler.get_template("natural_language_query_system").ok_or_else(
                || AiAnalystError::TemplateNotFound("natural_language_query_system".to_string()),
            )?;

        // Create a summary of findings for context
        let findings_summary: String = findings
            .iter()
            .map(|f| {
                format!(
                    "- {} (ID: {}, Severity: {:?}, Category: {:?}): {}",
                    f.title, f.id, f.severity, f.category, f.description
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with question and findings context
        let user_prompt =
            format!("Question: {}\n\nAvailable findings:\n{}", question, findings_summary);

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }

    async fn stream_compare_scans(
        &self,
        base_scan_id: ScanId,
        target_scan_id: ScanId,
    ) -> AiResult<Pin<Box<dyn Stream<Item = AiResult<String>> + Send>>> {
        // Get findings from both scans
        let base_findings = self.finding_provider.list_findings(base_scan_id, None).await?;
        let target_findings = self.finding_provider.list_findings(target_scan_id, None).await?;

        // Get template
        let system_template = self
            .prompt_compiler
            .get_template("compare_scans_system")
            .ok_or_else(|| AiAnalystError::TemplateNotFound("compare_scans_system".to_string()))?;

        // Create summaries of findings from both scans
        let base_summary: String = base_findings
            .iter()
            .map(|f| format!("- {} ({:?}, {:?})", f.title, f.severity, f.category))
            .collect::<Vec<_>>()
            .join("\n");

        let target_summary: String = target_findings
            .iter()
            .map(|f| format!("- {} ({:?}, {:?})", f.title, f.severity, f.category))
            .collect::<Vec<_>>()
            .join("\n");

        // Create user prompt with both scan summaries
        let user_prompt = format!(
            "Compare security scan results:\n\nBase Scan ({}):\n{}\n\nTarget Scan ({}):\n{}\n\nAnalyze the differences.",
            base_scan_id, base_summary, target_scan_id, target_summary
        );

        // Create completion request
        let request =
            self.create_completion_request(&system_template.system_prompt, &user_prompt).await?;

        // Execute streaming completion
        self.execute_streaming_completion(request).await
    }
}
