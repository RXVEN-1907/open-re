//! Confidence Scoring
//!
//! Implements confidence scoring for injection findings based on:
//! - Detection method reliability
//! - Evidence quality
//! - Reproducibility
//! - Context factors

use crate::injection::{DetectionMethod, InjectionCategory, InjectionTestResult, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Confidence scorer for injection findings
pub struct ConfidenceScorer {
    method_weights: HashMap<DetectionMethod, f64>,
    severity_weights: HashMap<Severity, f64>,
    category_weights: HashMap<InjectionCategory, f64>,
}

impl ConfidenceScorer {
    /// Create a new confidence scorer with default weights
    pub fn new() -> Self {
        let mut method_weights = HashMap::new();
        method_weights.insert(DetectionMethod::ErrorBased, 0.85);
        method_weights.insert(DetectionMethod::BooleanBased, 0.80);
        method_weights.insert(DetectionMethod::TimeBased, 0.90);
        method_weights.insert(DetectionMethod::Reflection, 0.95);
        method_weights.insert(DetectionMethod::PatternMatch, 0.85);
        method_weights.insert(DetectionMethod::Differential, 0.70);
        method_weights.insert(DetectionMethod::OutOfBand, 0.95);
        method_weights.insert(DetectionMethod::Heuristic, 0.50);
        
        let mut severity_weights = HashMap::new();
        severity_weights.insert(crate::injection::Severity::Critical, 1.0);
        severity_weights.insert(crate::injection::Severity::High, 0.9);
        severity_weights.insert(crate::injection::Severity::Medium, 0.7);
        severity_weights.insert(crate::injection::Severity::Low, 0.5);
        severity_weights.insert(crate::injection::Severity::Info, 0.3);
        
        let mut category_weights = HashMap::new();
        category_weights.insert(crate::injection::InjectionCategory::SqlInjection, 1.0);
        category_weights.insert(crate::injection::InjectionCategory::NoSqlInjection, 0.95);
        category_weights.insert(crate::injection::InjectionCategory::Xss, 0.95);
        category_weights.insert(crate::injection::InjectionCategory::Ssti, 0.98);
        category_weights.insert(crate::injection::InjectionCategory::CommandInjection, 0.98);
        category_weights.insert(crate::injection::InjectionCategory::Xxe, 0.97);
        category_weights.insert(crate::injection::InjectionCategory::LdapInjection, 0.9);
        category_weights.insert(crate::injection::InjectionCategory::XPathInjection, 0.9);
        category_weights.insert(crate::injection::InjectionCategory::HeaderInjection, 0.85);
        category_weights.insert(crate::injection::InjectionCategory::Custom, 0.5);
        
        Self {
            method_weights,
            severity_weights,
            category_weights,
        }
    }
    
    /// Score a finding's confidence
    pub fn score(&self, finding: &InjectionTestResult) -> f64 {
        let mut score = finding.confidence; // Base confidence from analyzer
        
        // Apply method weight
        if let Some(weight) = self.method_weights.get(&finding.detection_method) {
            score *= weight;
        }
        
        // Apply severity weight
        if let Some(weight) = self.severity_weights.get(&finding.severity) {
            score *= weight;
        }
        
        // Apply category weight
        if let Some(weight) = self.category_weights.get(&finding.category) {
            score *= weight;
        }
        
        // Boost for multiple detection methods
        let method_count = self.count_detection_methods(finding);
        if method_count > 1 {
            score = (score + 0.1 * (method_count as f64 - 1.0)).min(1.0);
        }
        
        // Boost for high-quality evidence
        score *= self.evidence_quality_multiplier(finding);
        
        // Boost for reproducibility
        if finding.evidence.timing_info.is_some() && finding.evidence.timing_info.as_ref().unwrap().is_significant {
            score = (score + 0.05).min(1.0);
        }
        
        // Penalize for lack of baseline
        if finding.evidence.baseline_response.is_none() {
            score *= 0.9;
        }
        
        // Clamp to [0, 1]
        score.clamp(0.0, 1.0)
    }
    
    /// Count unique detection methods in evidence
    fn count_detection_methods(&self, finding: &InjectionTestResult) -> usize {
        let mut methods = std::collections::HashSet::new();
        methods.insert(finding.detection_method);
        
        // Check for additional methods in evidence
        for pattern in &finding.evidence.matched_patterns {
            if pattern.contains("time") || pattern.contains("sleep") || pattern.contains("delay") {
                methods.insert(crate::injection::DetectionMethod::TimeBased);
            }
            if pattern.contains("union") || pattern.contains("select") {
                methods.insert(crate::injection::DetectionMethod::ErrorBased);
            }
        }
        
        methods.len()
    }
    
    /// Calculate evidence quality multiplier
    fn evidence_quality_multiplier(&self, finding: &InjectionTestResult) -> f64 {
        let mut multiplier = 1.0;
        
        // Has baseline for comparison
        if finding.evidence.baseline_response.is_some() {
            multiplier += 0.05;
        }
        
        // Has timing info
        if finding.evidence.timing_info.is_some() {
            multiplier += 0.05;
        }
        
        // Has diff analysis
        if finding.evidence.diff.is_some() {
            multiplier += 0.05;
        }
        
        // Multiple matched patterns
        if finding.evidence.matched_patterns.len() > 1 {
            multiplier += 0.05 * (finding.evidence.matched_patterns.len() as f64 - 1.0).min(3.0);
        }
        
        // Has reproducible request
        if !finding.reproducible_request.payload.is_empty() {
            multiplier += 0.05;
        }
        
        multiplier.min(1.2)
    }
    
    /// Get confidence level label
    pub fn confidence_label(&self, score: f64) -> &'static str {
        match score {
            s if s >= 0.9 => "Very High",
            s if s >= 0.75 => "High",
            s if s >= 0.6 => "Medium",
            s if s >= 0.4 => "Low",
            _ => "Very Low",
        }
    }
    
    /// Get confidence color for display
    pub fn confidence_color(&self, score: f64) -> &'static str {
        match score {
            s if s >= 0.9 => "green",
            s if s >= 0.75 => "light_green",
            s if s >= 0.6 => "yellow",
            s if s >= 0.4 => "orange",
            _ => "red",
        }
    }
}

/// Detailed confidence breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    pub base_confidence: f64,
    pub method_weight: f64,
    pub severity_weight: f64,
    pub category_weight: f64,
    pub evidence_multiplier: f64,
    pub method_bonus: f64,
    pub final_score: f64,
    pub label: String,
    pub color: String,
}

impl ConfidenceScorer {
    /// Get detailed confidence breakdown
    pub fn detailed_score(&self, finding: &InjectionTestResult) -> ConfidenceBreakdown {
        let base = finding.confidence;
        let method_weight = self.method_weights.get(&finding.detection_method).copied().unwrap_or(1.0);
        let severity_weight = self.severity_weights.get(&finding.severity).copied().unwrap_or(1.0);
        let category_weight = self.category_weights.get(&finding.category).copied().unwrap_or(1.0);
        let evidence_multiplier = self.evidence_quality_multiplier(finding);
        let method_bonus = if self.count_detection_methods(finding) > 1 { 0.1 } else { 0.0 };
        
        let final_score = (base * method_weight * severity_weight * category_weight * evidence_multiplier + method_bonus).clamp(0.0, 1.0);
        
        ConfidenceBreakdown {
            base_confidence: base,
            method_weight,
            severity_weight,
            category_weight,
            evidence_multiplier,
            method_bonus,
            final_score,
            label: self.confidence_label(final_score).to_string(),
            color: self.confidence_color(final_score).to_string(),
        }
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Confidence scoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceConfig {
    pub method_weights: HashMap<DetectionMethod, f64>,
    pub severity_weights: HashMap<Severity, f64>,
    pub category_weights: HashMap<InjectionCategory, f64>,
    pub evidence_quality_bonus: f64,
    pub multi_method_bonus: f64,
    pub baseline_penalty: f64,
}

impl Default for ConfidenceConfig {
    fn default() -> Self {
        let mut method_weights = HashMap::new();
        method_weights.insert(DetectionMethod::ErrorBased, 0.85);
        method_weights.insert(DetectionMethod::BooleanBased, 0.80);
        method_weights.insert(DetectionMethod::TimeBased, 0.90);
        method_weights.insert(DetectionMethod::Reflection, 0.95);
        method_weights.insert(DetectionMethod::PatternMatch, 0.85);
        method_weights.insert(DetectionMethod::Differential, 0.70);
        method_weights.insert(DetectionMethod::OutOfBand, 0.95);
        method_weights.insert(DetectionMethod::Heuristic, 0.50);
        
        let mut severity_weights = HashMap::new();
        severity_weights.insert(crate::injection::Severity::Critical, 1.0);
        severity_weights.insert(crate::injection::Severity::High, 0.9);
        severity_weights.insert(crate::injection::Severity::Medium, 0.7);
        severity_weights.insert(crate::injection::Severity::Low, 0.5);
        severity_weights.insert(crate::injection::Severity::Info, 0.3);
        
        let mut category_weights = HashMap::new();
        category_weights.insert(crate::injection::InjectionCategory::SqlInjection, 1.0);
        category_weights.insert(crate::injection::InjectionCategory::NoSqlInjection, 0.95);
        category_weights.insert(crate::injection::InjectionCategory::Xss, 0.95);
        category_weights.insert(crate::injection::InjectionCategory::Ssti, 0.98);
        category_weights.insert(crate::injection::InjectionCategory::CommandInjection, 0.98);
        category_weights.insert(crate::injection::InjectionCategory::Xxe, 0.97);
        category_weights.insert(crate::injection::InjectionCategory::LdapInjection, 0.9);
        category_weights.insert(crate::injection::InjectionCategory::XPathInjection, 0.9);
        category_weights.insert(crate::injection::InjectionCategory::HeaderInjection, 0.85);
        category_weights.insert(crate::injection::InjectionCategory::Custom, 0.5);
        
        Self {
            method_weights,
            severity_weights,
            category_weights,
            evidence_quality_bonus: 0.15,
            multi_method_bonus: 0.1,
            baseline_penalty: 0.1,
        }
    }
}

/// Create a confidence scorer from config
pub fn create_confidence_scorer(config: ConfidenceConfig) -> ConfidenceScorer {
    ConfidenceScorer {
        method_weights: config.method_weights,
        severity_weights: config.severity_weights,
        category_weights: config.category_weights,
    }
}