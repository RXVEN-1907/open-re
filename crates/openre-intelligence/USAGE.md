# OpenRE Intelligence Layer Usage Guide

This guide demonstrates how to use the intelligence layer components in your security scanning workflows.

## Quick Start

### Basic Setup

```rust
use openre_intelligence::*;

// Create intelligence components with default configurations
let correlation_engine = CorrelationEngine::new();
let cve_intelligence = CveIntelligence::new(CveIntelligenceConfig::default());
let dependency_analyzer = DependencyAnalyzer::new(DependencyAnalysisConfig::default());
let knowledge_base = KnowledgeBase::new();
let root_cause_analyzer = RootCauseAnalyzer::new();
let scan_diff_analyzer = ScanDiffAnalyzer::new();
let workflow_manager = WorkflowManager::new();
let performance_optimizer = PerformanceOptimizer::new();
let tui_enhancer = TuiEnhancer::new();
```

### Processing Security Findings

```rust
// Assume you have a vector of findings from your scanners
let mut findings: Vec<Finding> = get_scanner_findings();

// 1. Correlate findings to identify relationships
let correlations = correlation_engine.correlate_findings(&findings)?;

// 2. Enrich findings with CVE data
cve_intelligence.enrich_findings_with_cve_data(&mut findings).await?;

// 3. Analyze dependencies for vulnerabilities
let dependencies = dependency_analyzer.analyze_dependencies_file("Cargo.lock").await?;

// 4. Link findings to security standards
let kb_entries = knowledge_base.enrich_findings(&mut findings)?;

// 5. Identify root causes
let root_causes = root_cause_analyzer.analyze_root_causes(&findings)?;
root_cause_analyzer.correlate_findings_with_root_causes(&mut findings, &root_causes)?;

// 6. Apply workflow filters
workflow_manager.process_findings(&mut findings)?;

// 7. Format output for display
for finding in &findings {
    println!("{}", tui_enhancer.format_finding(finding, true));
}
```

## Detailed Component Usage

### 1. Correlation Engine

#### Basic Correlation

```rust
use openre_intelligence::correlation::{CorrelationEngine, CorrelationConfig};

// Default configuration
let engine = CorrelationEngine::new();

// Custom configuration
let config = CorrelationConfig {
    enable_csp_xss: true,
    enable_directory_git: true,
    enable_strengthening_weakening: true,
    enable_root_cause: true,
    min_confidence_threshold: 0.3,
    max_correlations_per_finding: 10,
};
let engine = CorrelationEngine::with_config(config);

// Correlate findings
let correlations = engine.correlate_findings(&findings)?;

// Process results
for correlation in &correlations {
    match correlation.correlation_type {
        CorrelationType::CspXssChain => {
            println!("CSP + XSS chain detected with {:.1}% confidence", 
                     correlation.confidence * 100.0);
        }
        CorrelationType::InfoDisclosureChain => {
            println!("Information disclosure chain detected");
        }
        _ => {}
    }
}
```

#### Custom Correlation Patterns

```rust
impl CorrelationEngine {
    fn correlate_custom_pattern(&self, findings: &[Finding]) -> IntelligenceResult<Vec<EnhancedCorrelation>> {
        let mut correlations = Vec::new();
        
        // Implement your custom correlation logic here
        // Example: Correlate authentication bypass with privilege escalation
        
        Ok(correlations)
    }
}
```

### 2. CVE Intelligence

#### Setting up CVE Providers

```rust
use openre_intelligence::cve_intelligence::{CveIntelligence, CveIntelligenceConfig, MockCveProvider};
use std::sync::Arc;

let config = CveIntelligenceConfig {
    enable_caching: true,
    cache_ttl_seconds: 3600, // 1 hour
    max_concurrent_requests: 5,
};

let mut cve_intel = CveIntelligence::new(config);

// Add providers (mock for testing, real ones for production)
cve_intel.add_provider(Arc::new(MockCveProvider::new()));

// For production, you might add:
// cve_intel.add_provider(Arc::new(NvdCveProvider::new(api_key)));
// cve_intel.add_provider(Arc::new(GithubAdvisoryProvider::new(token)));
```

#### Matching Findings Against CVEs

```rust
// Match findings against known CVEs
let cve_matches = cve_intel.match_findings_against_cves(&findings).await?;

for (finding, cves) in &cve_matches {
    println!("Finding '{}' matches {} CVEs:", finding.title, cves.len());
    for cve in cves {
        println!("  - {}: {}", cve.cve_id, cve.description);
    }
}

// Enrich findings with CVE data
cve_intel.enrich_findings_with_cve_data(&mut findings).await?;

// Check if a finding was enriched
for finding in &findings {
    if let Some(true) = finding.metadata.get("cve_intelligence_matched")
        .and_then(|v| v.as_bool()) {
        println!("Finding '{}' was enriched with CVE data", finding.title);
    }
}
```

### 3. Dependency Analysis

#### Analyzing Different Package Ecosystems

```rust
use openre_intelligence::dependency_analysis::{DependencyAnalyzer, DependencyAnalysisConfig};

let config = DependencyAnalysisConfig {
    enable_caching: true,
    cache_ttl_seconds: 86400, // 1 day
    check_vulnerabilities: true,
    check_outdated: true,
};

let mut dep_analyzer = DependencyAnalyzer::new(config);

// Add registry clients for different ecosystems
dep_analyzer.add_registry_client("npm", Box::new(NpmRegistryClient::new()));
dep_analyzer.add_registry_client("Cargo", Box::new(CratesIoRegistryClient::new()));
dep_analyzer.add_registry_client("pypi", Box::new(PyPiRegistryClient::new()));

// Analyze different dependency files
let npm_deps = dep_analyzer.analyze_dependencies_file("package-lock.JSON").await?;
let cargo_deps = dep_analyzer.analyze_dependencies_file("Cargo.lock").await?;
let python_deps = dep_analyzer.analyze_dependencies_file("requirements.txt").await?;

// Combine and analyze all dependencies
let mut all_deps = Vec::new();
all_deps.extend(npm_deps);
all_deps.extend(cargo_deps);
all_deps.extend(python_deps);

// Generate comprehensive report
let report = dep_analyzer.generate_analysis_report(&all_deps);
println!("{}", report);
```

### 4. Security Knowledge Base

#### Enriching Findings with Security Standards

```rust
use openre_intelligence::knowledge_base::{KnowledgeBase, KnowledgeBaseConfig};

let config = KnowledgeBaseConfig {
    enable_caching: true,
    cache_ttl_seconds: 86400, // 1 day
    auto_enrich_findings: true,
};

let knowledge_base = KnowledgeBase::with_config(config);

// Enrich findings with security standards
let kb_entries = knowledge_base.enrich_findings(&mut findings)?;

// Access specific CWE information
if let Some(cwe_info) = knowledge_base.get_cwe_info("CWE-79") {
    println!("CWE-79: {}", cwe_info.name);
    println!("Description: {}", cwe_info.description);
}

// Generate compliance report
let kb_report = knowledge_base.generate_knowledge_report(&kb_entries);
println!("{}", kb_report);
```

### 5. Root Cause Analysis

#### Identifying Systemic Issues

```rust
use openre_intelligence::root_cause::{RootCauseAnalyzer, RootCauseConfig};

let config = RootCauseConfig {
    enable_common_patterns: true,
    enable_misconfig_patterns: true,
    enable_auth_patterns: true,
    enable_input_validation_patterns: true,
    min_related_findings: 3,
    confidence_threshold: 0.6,
};

let root_cause_analyzer = RootCauseAnalyzer::with_config(config);

// Analyze findings for root causes
let root_causes = root_cause_analyzer.analyze_root_causes(&findings)?;

// Correlate findings with identified root causes
root_cause_analyzer.correlate_findings_with_root_causes(&mut findings, &root_causes)?;

// Generate detailed root cause report
let root_cause_report = root_cause_analyzer.generate_root_cause_report(&root_causes, &findings);
println!("{}", root_cause_report);
```

### 6. Scan Diff Intelligence

#### Comparing Scans Over Time

```rust
use openre_intelligence::scan_diff::{ScanDiffAnalyzer, ScanDiffConfig, ScanData};

let config = ScanDiffConfig {
    enable_new_critical_detection: true,
    enable_resolved_detection: true,
    enable_trend_analysis: true,
    min_severity_for_significant_change: SeverityLevel::High,
    time_window_hours: 24,
    significance_threshold_percent: 10.0,
};

let scan_diff_analyzer = ScanDiffAnalyzer::with_config(config);

// Create scan data from previous and current scans
let previous_scan = ScanData::new(previous_metadata, previous_findings);
let current_scan = ScanData::new(current_metadata, current_findings);

// Compare scans
let diff_analysis = scan_diff_analyzer.compare_scans(&previous_scan, &current_scan)?;

// Generate detailed diff report
let diff_report = scan_diff_analyzer.generate_diff_report(&diff_analysis, &previous_scan, &current_scan);
println!("{}", diff_report);

// Identify priority findings that need immediate attention
let priority_findings = scan_diff_analyzer.identify_priority_findings(&diff_analysis, &current_scan);
```

### 7. Workflow Management

#### Managing Finding Lifecycle

```rust
use openre_intelligence::workflow::{WorkflowManager, WorkflowConfig};

let config = WorkflowConfig {
    enable_acknowledgment: true,
    enable_false_positive: true,
    enable_ignore_rules: true,
    default_temp_ignore_days: 30,
    max_ignore_rules: 1000,
};

let mut workflow_manager = WorkflowManager::with_config(config);

// Acknowledge a finding
workflow_manager.acknowledge_finding(finding_id, "john_doe", Some("Reviewed during triage meeting"))?;

// Mark a finding as false positive
workflow_manager.mark_false_positive(finding_id, "jane_smith", 
    "This is a test environment artifact, not a real vulnerability")?;

// Add an ignore rule for a pattern
let ignore_rule = IgnoreRule {
    id: uuid::Uuid::new_v4().to_string(),
    pattern: r"title:.*Test Environment.*".to_string(),
    reason: "Known test environment noise",
    created_by: "admin".to_string(),
    created_at: Utc::now(),
    expires_at: Some(Utc::now() + chrono::Duration::days(7)),
    severity_threshold: Some(SeverityLevel::Medium),
    target_pattern: Some(r"HTTPS://test\..*".to_string()),
};

workflow_manager.add_ignore_rule(ignore_rule)?;

// Process findings through workflow filters
let workflow_result = workflow_manager.process_findings(&mut findings)?;

println!("Workflow processing results:");
println!("  Total findings: {}", workflow_result.total_findings);
println!("  Acknowledged: {}", workflow_result.acknowledged_count);
println!("  False positives: {}", workflow_result.false_positive_count);
println!("  Ignored: {}", workflow_result.ignored_count);
println!("  Remaining: {}", workflow_result.remaining_count);

// Generate workflow status report
let workflow_report = workflow_manager.generate_workflow_report();
println!("{}", workflow_report);
```

### 8. Performance Optimization

#### Caching and Deduplication

```rust
use openre_intelligence::performance::{PerformanceOptimizer, PerformanceConfig};

let config = PerformanceConfig {
    enable_caching: true,
    default_cache_ttl_seconds: 3600,
    max_cache_size: 10000,
    enable_incremental_processing: true,
    cache_cleanup_interval_seconds: 300,
    enable_deduplication: true,
};

let mut perf_optimizer = PerformanceOptimizer::with_config(config);

// Use caching for expensive operations
if let Some(cached_result) = perf_optimizer.get_from_cache("expensive_operation_key")? {
    // Use cached result
    println!("Using cached result");
} else {
    // Perform expensive operation
    let result = perform_expensive_operation();
    
    // Cache the result
    perf_optimizer.put_in_cache("expensive_operation_key".to_string(), result)?;
}

// Deduplicate findings based on fingerprints
let duplicate_count = perf_optimizer.deduplicate_findings(&mut findings);
println!("Removed {} duplicate findings", duplicate_count);

// Perform incremental processing
let incremental_result = perf_optimizer.incremental_process(&previous_findings, &mut current_findings);

println!("Incremental processing results:");
println!("  New findings: {}", incremental_result.new_findings.len());
println!("  Unchanged findings: {}", incremental_result.unchanged_findings.len());
println!("  Removed findings: {}", incremental_result.removed_findings.len());

// Check cache statistics
let cache_stats = perf_optimizer.get_cache_stats();
println!("Cache hit rate: {:.1}%", cache_stats.hit_rate);
```

### 9. TUI Enhancements

#### Enhanced Terminal Output

```rust
use openre_intelligence::tui_enhancements::{TuiEnhancer, TuiConfig};

let config = TuiConfig {
    enable_colors: true,
    enable_emojis: true,
    show_detailed_descriptions: true,
    max_width: 120,
    enable_filtering: true,
    show_confidence_indicators: true,
    enable_progress_indicators: true,
};

let tui_enhancer = TuiEnhancer::with_config(config);

// Format individual findings
for finding in &findings {
    println!("{}", tui_enhancer.format_finding(finding, true));
}

// Format correlations
for correlation in &correlations {
    println!("{}", tui_enhancer.format_correlation_result(correlation));
}

// Format CVE information
for (_, cves) in &cve_matches {
    for cve in cves {
        println!("{}", tui_enhancer.format_cve_result(cve));
    }
}

// Format dependency analysis results
for DEP in &dependencies {
    println!("{}", tui_enhancer.format_dependency_result(DEP));
}

// Generate comprehensive dashboard
let dashboard = tui_enhancer.format_dashboard(&findings, &correlations);
println!("{}", dashboard);

// Create progress indicator for long operations
let progress = tui_enhancer.create_progress_indicator("Processing findings");
for (i, finding) in findings.iter().enumerate() {
    process_finding(finding)?;
    progress.update(i + 1, findings.len());
}
progress.finish();
```

## Advanced Integration Examples

### Complete Security Pipeline

```rust
use openre_intelligence::*;
use std::sync::Arc;

async fn run_complete_security_pipeline(
    scan_metadata: ScanMetadata,
    mut findings: Vec<Finding>
) -> Result<SecurityAnalysisReport, IntelligenceError> {
    // Initialize all intelligence components
    let correlation_engine = CorrelationEngine::new();
    let cve_config = CveIntelligenceConfig {
        enable_caching: true,
        cache_ttl_seconds: 3600,
        max_concurrent_requests: 5,
    };
    let mut cve_intel = CveIntelligence::new(cve_config);
    cve_intel.add_provider(Arc::new(MockCveProvider::new()));
    
    let dep_config = DependencyAnalysisConfig {
        enable_caching: true,
        cache_ttl_seconds: 86400,
        check_vulnerabilities: true,
        check_outdated: true,
    };
    let mut dep_analyzer = DependencyAnalyzer::new(dep_config);
    dep_analyzer.add_registry_client("npm", Box::new(MockRegistryClient::new("npm")));
    
    let knowledge_base = KnowledgeBase::new();
    let root_cause_config = RootCauseConfig {
        min_related_findings: 2,
        confidence_threshold: 0.5,
        ..Default::default()
    };
    let root_cause_analyzer = RootCauseAnalyzer::with_config(root_cause_config);
    let scan_diff_analyzer = ScanDiffAnalyzer::new();
    let workflow_manager = WorkflowManager::new();
    let perf_optimizer = PerformanceOptimizer::new();
    let tui_enhancer = TuiEnhancer::new();

    // 1. Correlation Analysis
    println!("🔍 Performing correlation analysis...");
    let correlations = correlation_engine.correlate_findings(&findings)?;

    // 2. CVE Intelligence Enrichment
    println!("🛡️  Enriching findings with CVE intelligence...");
    cve_intel.enrich_findings_with_cve_data(&mut findings).await?;

    // 3. Dependency Analysis
    println!("📦 Analyzing project dependencies...");
    let dependencies = if std::path::Path::new("package-lock.JSON").exists() {
        dep_analyzer.analyze_dependencies_file("package-lock.JSON").await?
    } else {
        Vec::new()
    };

    // 4. Knowledge Base Enrichment
    println!("📚 Linking findings to security standards...");
    let kb_entries = knowledge_base.enrich_findings(&mut findings)?;

    // 5. Root Cause Analysis
    println!("🌱 Identifying root causes...");
    let root_causes = root_cause_analyzer.analyze_root_causes(&findings)?;
    root_cause_analyzer.correlate_findings_with_root_causes(&mut findings, &root_causes)?;

    // 6. Workflow Processing
    println!("✅ Applying workflow filters...");
    workflow_manager.process_findings(&mut findings)?;

    // 7. Performance Optimization
    println!("⚡ Optimizing performance...");
    let duplicate_count = perf_optimizer.deduplicate_findings(&mut findings);
    if duplicate_count > 0 {
        println!("   Removed {} duplicate findings", duplicate_count);
    }

    // 8. Generate Reports
    println!("📋 Generating comprehensive reports...");
    
    let correlation_report = format!("Found {} correlations\n", correlations.len());
    for correlation in &correlations {
        correlation_report.push_str(&format!("- {:?} ({:.1}% confidence)\n", 
            correlation.correlation_type, correlation.confidence * 100.0));
    }

    let dependency_report = dep_analyzer.generate_analysis_report(&dependencies);
    let root_cause_report = root_cause_analyzer.generate_root_cause_report(&root_causes, &findings);
    let workflow_report = workflow_manager.generate_workflow_report();
    let performance_report = perf_optimizer.generate_performance_report();
    let kb_report = knowledge_base.generate_knowledge_report(&kb_entries);

    // 9. Generate Dashboard
    let dashboard = tui_enhancer.format_dashboard(&findings, &correlations);

    Ok(SecurityAnalysisReport {
        scan_metadata,
        findings,
        correlations,
        dependencies,
        kb_entries,
        root_causes,
        correlation_report,
        dependency_report,
        root_cause_report,
        workflow_report,
        performance_report,
        kb_report,
        dashboard,
    })
}

#[derive(Debug)]
pub struct SecurityAnalysisReport {
    pub scan_metadata: ScanMetadata,
    pub findings: Vec<Finding>,
    pub correlations: Vec<EnhancedCorrelation>,
    pub dependencies: Vec<DependencyInfo>,
    pub kb_entries: Vec<KnowledgeBaseEntry>,
    pub root_causes: Vec<RootCauseAnalysis>,
    pub correlation_report: String,
    pub dependency_report: String,
    pub root_cause_report: String,
    pub workflow_report: String,
    pub performance_report: String,
    pub kb_report: String,
    pub dashboard: String,
}
```

### Custom Intelligence Module

```rust
// Example of creating a custom intelligence module
use openre_intelligence::{types::*, error::IntelligenceError, IntelligenceResult};
use openre_core::result::Finding;
use std::collections::HashMap;

pub struct BusinessImpactAnalyzer {
    config: BusinessImpactConfig,
    impact_database: HashMap<String, BusinessImpactData>,
}

#[derive(Debug, Clone)]
pub struct BusinessImpactConfig {
    pub enable_financial_impact: bool,
    pub enable_compliance_impact: bool,
    pub enable_reputation_impact: bool,
}

impl Default for BusinessImpactConfig {
    fn default() -> Self {
        Self {
            enable_financial_impact: true,
            enable_compliance_impact: true,
            enable_reputation_impact: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BusinessImpactData {
    pub financial_impact: Option<u32>, // Estimated financial impact in USD
    pub compliance_risk: Option<String>, // Compliance framework at risk
    pub reputation_risk: Option<u8>, // 1-10 scale
    pub customer_impact: Option<u32>, // Number of potentially affected customers
}

impl BusinessImpactAnalyzer {
    pub fn new(config: BusinessImpactConfig) -> Self {
        Self {
            config,
            impact_database: HashMap::new(),
        }
    }

    pub fn analyze_business_impact(&self, findings: &[Finding]) -> IntelligenceResult<Vec<(Finding, BusinessImpactData)>> {
        let mut results = Vec::new();

        for finding in findings {
            let impact_data = self.calculate_impact(finding)?;
            results.push((finding.clone(), impact_data));
        }

        Ok(results)
    }

    fn calculate_impact(&self, finding: &Finding) -> IntelligenceResult<BusinessImpactData> {
        // Implement your business impact calculation logic here
        // This is a simplified example
        
        let financial_impact = match finding.severity {
            openre_core::result::Severity::Critical => Some(100000),
            openre_core::result::Severity::High => Some(50000),
            openre_core::result::Severity::Medium => Some(10000),
            _ => None,
        };

        let compliance_risk = match finding.category {
            openre_core::result::Category::SensitiveDataExposure => Some("GDPR, CCPA".to_string()),
            openre_core::result::Category::BrokenAuthentication => Some("PCI DSS".to_string()),
            _ => None,
        };

        let reputation_risk = match finding.severity {
            openre_core::result::Severity::Critical => Some(9),
            openre_core::result::Severity::High => Some(7),
            openre_core::result::Severity::Medium => Some(4),
            _ => Some(1),
        };

        Ok(BusinessImpactData {
            financial_impact,
            compliance_risk,
            reputation_risk,
            customer_impact: None, // Would require additional context
        })
    }
}
```

This usage guide provides comprehensive examples of how to leverage all the intelligence layer components effectively in your security scanning workflows.
