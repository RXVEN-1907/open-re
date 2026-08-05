//! Context builder for assembling token-budgeted structured context for AI prompts

use crate::{AiResult, AiAnalystError};
use openre_core::result::{Finding, Evidence};
use serde::{Deserialize, Serialize};

/// Token budget for context assembly
#[derive(Debug, Clone)]
pub struct TokenBudget {
    /// Maximum tokens allowed
    pub max_tokens: usize,

    /// Tokens used so far
    pub used_tokens: usize,
}

impl TokenBudget {
    /// Create a new token budget
    pub fn new(max_tokens: usize) -> Self {
        Self {
            max_tokens,
            used_tokens: 0,
        }
    }

    /// Check if we have enough tokens for additional content
    pub fn has_capacity(&self, tokens: usize) -> bool {
        self.used_tokens + tokens <= self.max_tokens
    }

    /// Consume tokens from the budget
    pub fn consume(&mut self, tokens: usize) -> Result<(), AiAnalystError> {
        if self.has_capacity(tokens) {
            self.used_tokens += tokens;
            Ok(())
        } else {
            Err(AiAnalystError::ContextTooLarge)
        }
    }

    /// Get remaining tokens
    pub fn remaining(&self) -> usize {
        self.max_tokens.saturating_sub(self.used_tokens)
    }
}

/// Context for explaining a finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingExplanationContext {
    /// The finding being explained
    pub finding: FindingSummary,

    /// Supporting evidence (truncated if necessary)
    pub evidence: Vec<EvidenceSummary>,

    /// Available token budget
    pub token_budget: TokenBudgetInfo,
}

/// Summary of a finding for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub title: String,
    pub description: String,
    pub severity: String,
    pub confidence: String,
    pub category: String,
    pub target: String,
    pub risk_score: Option<u8>,
}

/// Summary of evidence for context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    pub evidence_type: String,
    pub description: String,
    pub location: Option<String>,
    pub content_preview: String,
    pub truncated: bool,
}

/// Token budget information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBudgetInfo {
    pub max_tokens: usize,
    pub used_tokens: usize,
    pub remaining_tokens: usize,
}

/// Context builder for assembling AI contexts within token budgets
pub struct ContextBuilder {
    max_tokens: usize,
}

impl ContextBuilder {
    /// Create a new context builder
    pub fn new(max_tokens: usize) -> Self {
        Self { max_tokens }
    }

    /// Build context for explaining a finding
    pub fn build_finding_context(&self, finding: &Finding) -> AiResult<FindingExplanationContext> {
        let mut budget = TokenBudget::new(self.max_tokens);

        // Add basic finding info (estimate ~100 tokens)
        let finding_summary = FindingSummary {
            title: finding.title.clone(),
            description: finding.description.clone(),
            severity: format!("{:?}", finding.severity),
            confidence: format!("{:?}", finding.confidence),
            category: format!("{:?}", finding.category),
            target: finding.target.clone(),
            risk_score: finding.risk_score,
        };

        budget.consume(100)?;

        // Process evidence within remaining budget
        let evidence_summaries = self.process_evidence(&finding.evidence, &mut budget)?;

        Ok(FindingExplanationContext {
            finding: finding_summary,
            evidence: evidence_summaries,
            token_budget: TokenBudgetInfo {
                max_tokens: self.max_tokens,
                used_tokens: budget.used_tokens,
                remaining_tokens: budget.remaining(),
            },
        })
    }

    /// Process evidence within token budget
    fn process_evidence(&self, evidence: &[Evidence], budget: &mut TokenBudget) -> AiResult<Vec<EvidenceSummary>> {
        let mut summaries = Vec::new();

        for ev in evidence {
            // Estimate tokens needed for this evidence (rough estimate)
            let base_tokens = 50; // Base overhead
            let content_tokens = self.estimate_content_tokens(ev);
            let total_tokens = base_tokens + content_tokens;

            if budget.has_capacity(total_tokens) {
                // Include full evidence
                budget.consume(total_tokens)?;

                summaries.push(EvidenceSummary {
                    evidence_type: format!("{:?}", ev.evidence_type),
                    description: ev.description.clone(),
                    location: ev.location.clone(),
                    content_preview: self.extract_content_preview(ev, 500),
                    truncated: false,
                });
            } else {
                // Check if we can include a truncated version
                let truncated_tokens = base_tokens + 100; // Truncated content estimate
                if budget.has_capacity(truncated_tokens) {
                    budget.consume(truncated_tokens)?;

                    summaries.push(EvidenceSummary {
                        evidence_type: format!("{:?}", ev.evidence_type),
                        description: ev.description.clone(),
                        location: ev.location.clone(),
                        content_preview: self.extract_content_preview(ev, 100),
                        truncated: true,
                    });
                } else {
                    // Can't include this evidence at all
                    break;
                }
            }
        }

        Ok(summaries)
    }

    /// Estimate tokens needed for evidence content
    fn estimate_content_tokens(&self, evidence: &Evidence) -> usize {
        let mut total = 0;

        // HTTP request evidence
        if let Some(http_req) = &evidence.http_request {
            total += http_req.method.len() / 4;
            total += http_req.url.len() / 4;
            for (k, v) in &http_req.headers {
                total += (k.len() + v.len()) / 4;
            }
            if let Some(body) = &http_req.body {
                total += body.len() / 4;
            }
        }

        // HTTP response evidence
        if let Some(http_resp) = &evidence.http_response {
            total += 10; // Status code
            for (k, v) in &http_resp.headers {
                total += (k.len() + v.len()) / 4;
            }
            if let Some(body) = &http_resp.body {
                total += body.len() / 4;
            }
        }

        // Raw data
        if let Some(data) = &evidence.data {
            total += format!("{:?}", data).len() / 4;
        }

        total
    }

    /// Extract content preview from evidence
    fn extract_content_preview(&self, evidence: &Evidence, max_length: usize) -> String {
        let mut preview = String::new();

        // HTTP request
        if let Some(http_req) = &evidence.http_request {
            preview.push_str(&format!("{} {} HTTP/1.1\n", http_req.method, http_req.url));
            for (k, v) in &http_req.headers {
                preview.push_str(&format!("{}: {}\n", k, v));
            }
            if let Some(body) = &http_req.body {
                preview.push_str("\n");
                preview.push_str(body);
            }
        }

        // HTTP response
        else if let Some(http_resp) = &evidence.http_response {
            preview.push_str(&format!("HTTP/1.1 {}\n", http_resp.status_code));
            for (k, v) in &http_resp.headers {
                preview.push_str(&format!("{}: {}\n", k, v));
            }
            if let Some(body) = &http_resp.body {
                preview.push_str("\n");
                preview.push_str(body);
            }
        }

        // Raw data
        else if let Some(data) = &evidence.data {
            preview.push_str(&format!("{:.200}", format!("{:?}", data)));
        }

        // Fallback to description
        if preview.is_empty() {
            preview.push_str(&evidence.description);
        }

        // Truncate if too long
        if preview.len() > max_length {
            preview.truncate(max_length - 3);
            preview.push_str("...");
        }

        preview
    }

    /// Build context for correlation analysis
    pub fn build_correlation_context(&self, findings: &[&Finding]) -> AiResult<CorrelationContext> {
        let mut budget = TokenBudget::new(self.max_tokens);

        // Create summaries of all findings
        let finding_summaries: Result<Vec<FindingSummary>, AiAnalystError> = findings
            .iter()
            .map(|f| {
                if budget.has_capacity(100) {
                    budget.consume(100)?;
                    Ok(FindingSummary {
                        title: f.title.clone(),
                        description: f.description.clone(),
                        severity: format!("{:?}", f.severity),
                        confidence: format!("{:?}", f.confidence),
                        category: format!("{:?}", f.category),
                        target: f.target.clone(),
                        risk_score: f.risk_score,
                    })
                } else {
                    Err(AiAnalystError::ContextTooLarge)
                }
            })
            .collect();

        Ok(CorrelationContext {
            findings: finding_summaries?,
            token_budget: TokenBudgetInfo {
                max_tokens: self.max_tokens,
                used_tokens: budget.used_tokens,
                remaining_tokens: budget.remaining(),
            },
        })
    }

    /// Build context for scan comparison
    pub fn build_comparison_context(
        &self,
        base_findings: &[Finding],
        target_findings: &[Finding],
    ) -> AiResult<ComparisonContext> {
        let mut budget = TokenBudget::new(self.max_tokens);

        // Process both sets of findings
        let base_summaries = self.process_findings_for_comparison(base_findings, "base", &mut budget)?;
        let target_summaries = self.process_findings_for_comparison(target_findings, "target", &mut budget)?;

        Ok(ComparisonContext {
            base_findings: base_summaries,
            target_findings: target_summaries,
            token_budget: TokenBudgetInfo {
                max_tokens: self.max_tokens,
                used_tokens: budget.used_tokens,
                remaining_tokens: budget.remaining(),
            },
        })
    }

    /// Process findings for comparison context
    fn process_findings_for_comparison(
        &self,
        findings: &[Finding],
        source: &str,
        budget: &mut TokenBudget,
    ) -> AiResult<Vec<FindingSummary>> {
        findings
            .iter()
            .filter_map(|f| {
                if budget.has_capacity(100) {
                    match budget.consume(100) {
                        Ok(_) => Some(Ok(FindingSummary {
                            title: f.title.clone(),
                            description: f.description.clone(),
                            severity: format!("{:?}", f.severity),
                            confidence: format!("{:?}", f.confidence),
                            category: format!("{:?}", f.category),
                            target: f.target.clone(),
                            risk_score: f.risk_score,
                        })),
                        Err(e) => Some(Err(e)),
                    }
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Context for correlation analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationContext {
    pub findings: Vec<FindingSummary>,
    pub token_budget: TokenBudgetInfo,
}

/// Context for scan comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonContext {
    pub base_findings: Vec<FindingSummary>,
    pub target_findings: Vec<FindingSummary>,
    pub token_budget: TokenBudgetInfo,
}