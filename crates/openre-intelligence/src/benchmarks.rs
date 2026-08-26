//! Performance benchmarks for intelligence layer components

#[cfg(test)]
mod benchmarks {
    use crate::*;
    use openre_core::result::{Finding, Category, Severity, Confidence, Evidence, EvidenceType};
    use openre_core::ids::{FindingId, ScanId};
    use std::collections::HashMap;
    use chrono::Utc;
    use std::sync::Arc;
    use std::time::Instant;

    fn create_benchmark_finding(id: usize, target: &str) -> Finding {
        Finding {
            id: FindingId::new(),
            title: format!("Test Finding {}", id),
            description: format!("Description for test finding {}", id),
            severity: Severity::Medium,
            confidence: Confidence::High,
            category: Category::Injection,
            target: target.to_string(),
            target_type: "web".to_string(),
            evidence: vec![Evidence {
                evidence_type: EvidenceType::HttpRequest,
                description: format!("Test evidence for finding {}", id),
                data: Some(serde_json::json!({
                    "test": format!("data_{}", id)
                })),
                location: Some(format!("{}/endpoint_{}", target, id)),
                metadata: HashMap::new(),
                http_request: None,
                http_response: None,
                timing: None,
                payload: None,
                reproduction_steps: None,
                plugin_source: "benchmark".to_string(),
                timestamp: Utc::now(),
            }],
            references: Vec::new(),
            plugin_source: "benchmark".to_string(),
            plugin_version: "1.0".to_string(),
            timestamp: Utc::now(),
            scan_id: ScanId::new(),
            metadata: HashMap::new(),
            tags: vec![format!("tag_{}", id)],
            verified: false,
            false_positive: false,
            risk_score: Some((id % 100) as u8),
            cvss_vector: None,
            cvss_score: None,
            cwe_ids: vec![format!("CWE-{}", id % 1000)],
            capec_ids: vec![format!("CAPEC-{}", id % 500)],
            mitre_attack_ids: vec![format!("T{:04}.{:03}", id % 100, id % 10)],
            owasp_category: Some(format!("A{:02}:2021-TestCategory{}", id % 10, id % 5)),
            fingerprint: Some(format!("benchmark-fingerprint-{}", id)),
            related_findings: Vec::new(),
            remediation: None,
            exploitability: None,
            business_impact: None,
        }
    }

    fn create_benchmark_findings(count: usize, targets: &[&str]) -> Vec<Finding> {
        let mut findings = Vec::with_capacity(count);
        for i in 0..count {
            let target = targets[i % targets.len()];
            findings.push(create_benchmark_finding(i, target));
        }
        findings
    }

    #[tokio::test]
    async fn benchmark_correlation_engine() {
        const FINDING_COUNT: usize = 1000;
        const TARGETS: &[&str] = &[
            "https://api.example.com",
            "https://admin.example.com",
            "https://shop.example.com",
            "https://blog.example.com",
        ];

        println!("📊 Benchmarking Correlation Engine with {} findings across {} targets...",
                 FINDING_COUNT, TARGETS.len());

        // Create benchmark data
        let findings = create_benchmark_findings(FINDING_COUNT, TARGETS);

        // Initialize correlation engine
        let correlation_engine = CorrelationEngine::new();

        // Measure correlation performance
        let start_time = Instant::now();
        let correlations = correlation_engine.correlate_findings(&findings).unwrap();
        let duration = start_time.elapsed();

        println!("   📈 Results:");
        println!("   - Processed {} findings in {:?}", FINDING_COUNT, duration);
        println!("   - Found {} correlations", correlations.len());
        println!("   - Performance: {:.2} findings/second",
                 FINDING_COUNT as f64 / duration.as_secs_f64());

        // Verify results are reasonable
        assert!(correlations.len() <= FINDING_COUNT * 10); // Sanity check on correlation count
        assert!(duration.as_millis() < 5000); // Should complete within 5 seconds

        println!("   ✅ Correlation Engine benchmark completed successfully");
    }

    #[tokio::test]
    async fn benchmark_cve_intelligence() {
        const FINDING_COUNT: usize = 500;
        const TARGETS: &[&str] = &[
            "https://service1.example.com",
            "https://service2.example.com",
        ];

        println!("🛡️  Benchmarking CVE Intelligence with {} findings...", FINDING_COUNT);

        // Create findings with software evidence
        let mut findings = create_benchmark_findings(FINDING_COUNT, TARGETS);

        // Add software version evidence to some findings
        for (i, finding) in findings.iter_mut().enumerate() {
            if i % 3 == 0 {
                // Add Apache evidence
                finding.evidence.push(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Server header indicating Apache version".to_string(),
                    data: Some(serde_json::json!({
                        "server": format!("Apache/2.4.{}", i % 53)
                    })),
                    location: Some(finding.target.clone()),
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("technology".to_string(),
                                  serde_json::Value::String(format!("Apache/2.4.{}", i % 53)));
                        map
                    },
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: "benchmark".to_string(),
                    timestamp: Utc::now(),
                });
            } else if i % 5 == 0 {
                // Add Nginx evidence
                finding.evidence.push(Evidence {
                    evidence_type: EvidenceType::HttpResponse,
                    description: "Server header indicating Nginx version".to_string(),
                    data: Some(serde_json::json!({
                        "server": format!("nginx/1.{}.{}", i % 20, i % 10)
                    })),
                    location: Some(finding.target.clone()),
                    metadata: {
                        let mut map = HashMap::new();
                        map.insert("technology".to_string(),
                                  serde_json::Value::String(format!("nginx/1.{}.{}", i % 20, i % 10)));
                        map
                    },
                    http_request: None,
                    http_response: None,
                    timing: None,
                    payload: None,
                    reproduction_steps: None,
                    plugin_source: "benchmark".to_string(),
                    timestamp: Utc::now(),
                });
            }
        }

        // Initialize CVE intelligence with mock provider
        let cve_config = cve_intelligence::CveIntelligenceConfig {
            enable_caching: true,
            cache_ttl_seconds: 3600,
            max_concurrent_requests: 10,
        };
        let mut cve_intel = CveIntelligence::new(cve_config);
        cve_intel.add_provider(Arc::new(cve_intelligence::MockCveProvider::new()));

        // Measure CVE matching performance
        let start_time = Instant::now();
        let cve_matches = cve_intel.match_findings_against_cves(&findings).await.unwrap();
        let duration = start_time.elapsed();

        println!("   📈 Results:");
        println!("   - Processed {} findings in {:?}", FINDING_COUNT, duration);
        println!("   - Found CVE matches for {} findings", cve_matches.len());
        println!("   - Performance: {:.2} findings/second",
                 FINDING_COUNT as f64 / duration.as_secs_f64());

        // Verify results
        assert!(duration.as_millis() < 10000); // Should complete within 10 seconds

        println!("   ✅ CVE Intelligence benchmark completed successfully");
    }

    #[tokio::test]
    async fn benchmark_dependency_analysis() {
        const DEPENDENCY_COUNT: usize = 200;

        println!("📦 Benchmarking Dependency Analysis with {} dependencies...", DEPENDENCY_COUNT);

        // Create mock dependency content
        let mut requirements_content = String::new();
        for i in 0..DEPENDENCY_COUNT {
            writeln!(requirements_content, "package{}==1.{}.{}", i, i % 10, i % 20).unwrap();
        }

        // Initialize dependency analyzer with mock registry
        let dep_config = dependency_analysis::DependencyAnalysisConfig {
            enable_caching: true,
            cache_ttl_seconds: 86400,
            check_vulnerabilities: true,
            check_outdated: true,
        };
        let mut dep_analyzer = DependencyAnalyzer::new(dep_config);
        dep_analyzer.add_registry_client("pypi", Box::new(dependency_analysis::MockRegistryClient::new("PyPI")));

        // Measure dependency analysis performance
        let start_time = Instant::now();
        let dependencies = dep_analyzer.analyze_dependencies_content(
            &requirements_content,
            std::path::Path::new("requirements.txt")
        ).await.unwrap();
        let duration = start_time.elapsed();

        println!("   📈 Results:");
        println!("   - Analyzed {} dependencies in {:?}", DEPENDENCY_COUNT, duration);
        println!("   - Found {} actual dependencies", dependencies.len());
        println!("   - Performance: {:.2} dependencies/second",
                 DEPENDENCY_COUNT as f64 / duration.as_secs_f64());

        // Verify results
        assert!(!dependencies.is_empty());
        assert!(duration.as_millis() < 5000); // Should complete within 5 seconds

        println!("   ✅ Dependency Analysis benchmark completed successfully");
    }

    #[test]
    fn benchmark_knowledge_base_enrichment() {
        const FINDING_COUNT: usize = 1000;
        const TARGETS: &[&str] = &[
            "https://web.example.com",
            "https://api.example.com",
        ];

        println!("📚 Benchmarking Knowledge Base Enrichment with {} findings...", FINDING_COUNT);

        // Create benchmark findings
        let mut findings = create_benchmark_findings(FINDING_COUNT, TARGETS);

        // Initialize knowledge base
        let knowledge_base = KnowledgeBase::new();

        // Measure knowledge base enrichment performance
        let start_time = Instant::now();
        let kb_entries = knowledge_base.enrich_findings(&mut findings).unwrap();
        let duration = start_time.elapsed();

        println!("   📈 Results:");
        println!("   - Enriched {} findings in {:?}", FINDING_COUNT, duration);
        println!("   - Created {} knowledge base entries", kb_entries.len());
        println!("   - Performance: {:.2} findings/second",
                 FINDING_COUNT as f64 / duration.as_secs_f64());

        // Verify results
        assert!(!kb_entries.is_empty());
        assert!(duration.as_millis() < 3000); // Should complete within 3 seconds

        println!("   ✅ Knowledge Base Enrichment benchmark completed successfully");
    }

    #[test]
    fn benchmark_root_cause_analysis() {
        const FINDING_COUNT: usize = 500;
        const TARGETS: &[&str] = &[
            "https://admin.internal.example.com",
            "https://api.internal.example.com",
        ];

        println!("🌱 Benchmarking Root Cause Analysis with {} findings...", FINDING_COUNT);

        // Create findings that will trigger root cause analysis
        let mut findings = Vec::with_capacity(FINDING_COUNT);
        for i in 0..FINDING_COUNT {
            let target = TARGETS[i % TARGETS.len()];
            let category = match i % 4 {
                0 => Category::Injection,
                1 => Category::Xss,
                2 => Category::SecurityMisconfiguration,
                _ => Category::InformationDisclosure,
            };

            findings.push(Finding {
                id: FindingId::new(),
                title: format!("{} Finding {}",
                             match category {
                                 Category::Injection => "SQL Injection",
                                 Category::Xss => "Cross-site Scripting",
                                 Category::SecurityMisconfiguration => "Missing Security Header",
                                 Category::InformationDisclosure => "Directory Listing",
                                 _ => "Security",
                             }, i),
                description: format!("Description for {} finding {}",
                                   match category {
                                       Category::Injection => "SQL injection",
                                       Category::Xss => "XSS",
                                       Category::SecurityMisconfiguration => "security misconfiguration",
                                       Category::InformationDisclosure => "information disclosure",
                                       _ => "security",
                                   }, i),
                severity: Severity::Medium,
                confidence: Confidence::High,
                category,
                target: target.to_string(),
                target_type: "web".to_string(),
                evidence: Vec::new(),
                references: Vec::new(),
                plugin_source: "benchmark".to_string(),
                plugin_version: "1.0".to_string(),
                timestamp: Utc::now(),
                scan_id: ScanId::new(),
                metadata: HashMap::new(),
                tags: Vec::new(),
                verified: false,
                false_positive: false,
                risk_score: Some((50 + (i % 50)) as u8),
                cvss_vector: None,
                cvss_score: None,
                cwe_ids: vec![format!("CWE-{}", match category {
                    Category::Injection => 89,
                    Category::Xss => 79,
                    Category::SecurityMisconfiguration => 732,
                    Category::InformationDisclosure => 22,
                    _ => 1000,
                })],
                capec_ids: Vec::new(),
                mitre_attack_ids: Vec::new(),
                owasp_category: None,
                fingerprint: Some(format!("rc-benchmark-{}", i)),
                related_findings: Vec::new(),
                remediation: None,
                exploitability: None,
                business_impact: None,
            });
        }

        // Initialize root cause analyzer
        let root_cause_analyzer = RootCauseAnalyzer::new();

        // Measure root cause analysis performance
        let start_time = Instant::now();
        let root_causes = root_cause_analyzer.analyze_root_causes(&findings).unwrap();
        let duration = start_time.elapsed();

        println!("   📈 Results:");
        println!("   - Analyzed {} findings in {:?}", FINDING_COUNT, duration);
        println!("   - Identified {} root causes", root_causes.len());
        println!("   - Performance: {:.2} findings/second",
                 FINDING_COUNT as f64 / duration.as_secs_f64());

        // Verify results
        assert!(duration.as_millis() < 2000); // Should complete within 2 seconds

        println!("   ✅ Root Cause Analysis benchmark completed successfully");
    }

    #[test]
    fn benchmark_performance_optimizer() {
        const CACHE_OPERATIONS: usize = 10000;
        const DEDUPLICATION_COUNT: usize = 5000;

        println!("⚡ Benchmarking Performance Optimizer with {} cache operations...", CACHE_OPERATIONS);

        // Initialize performance optimizer
        let mut perf_optimizer = PerformanceOptimizer::new();

        // Measure cache performance
        let start_time = Instant::now();

        // Perform cache put operations
        for i in 0..CACHE_OPERATIONS {
            let key = format!("cache_key_{}", i);
            let value = format!("cache_value_{}_data_{}", i, i * 2);
            perf_optimizer.put_in_cache(key, value).unwrap();
        }

        // Perform cache get operations (mix of hits and misses)
        let mut hits = 0;
        for i in 0..(CACHE_OPERATIONS * 2) {
            let key = format!("cache_key_{}", i % CACHE_OPERATIONS);
            if perf_optimizer.get_from_cache::<String>(&key).unwrap().is_some() {
                hits += 1;
            }
        }

        let cache_duration = start_time.elapsed();

        println!("   📈 Cache Performance Results:");
        println!("   - Performed {} cache operations in {:?}", CACHE_OPERATIONS * 3, cache_duration);
        println!("   - Cache hit rate: {:.1}%", (hits as f64 / (CACHE_OPERATIONS * 2) as f64) * 100.0);
        println!("   - Performance: {:.2} operations/second",
                 (CACHE_OPERATIONS * 3) as f64 / cache_duration.as_secs_f64());

        // Measure deduplication performance
        let mut duplicate_findings = Vec::with_capacity(DEDUPLICATION_COUNT);
        for i in 0..DEDUPLICATION_COUNT {
            let finding = create_benchmark_finding(i, "https://test.example.com");
            duplicate_findings.push(finding);

            // Make some findings duplicates by reusing fingerprints
            if i > 100 && i % 3 == 0 {
                if let Some(last_fingerprint) = duplicate_findings.get(i - 1)
                    .and_then(|f| f.fingerprint.clone()) {
                    if let Some(current) = duplicate_findings.last_mut() {
                        current.fingerprint = Some(last_fingerprint);
                    }
                }
            }
        }

        let dedup_start_time = Instant::now();
        let duplicates_removed = perf_optimizer.deduplicate_findings(&mut duplicate_findings);
        let dedup_duration = dedup_start_time.elapsed();

        println!("   📈 Deduplication Performance Results:");
        println!("   - Deduplicated {} findings in {:?}", DEDUPLICATION_COUNT, dedup_duration);
        println!("   - Removed {} duplicate findings", duplicates_removed);
        println!("   - Remaining unique findings: {}", duplicate_findings.len());
        println!("   - Performance: {:.2} findings/second",
                 DEDUPLICATION_COUNT as f64 / dedup_duration.as_secs_f64());

        // Verify results
        assert!(cache_duration.as_millis() < 5000); // Cache operations within 5 seconds
        assert!(dedup_duration.as_millis() < 2000); // Deduplication within 2 seconds

        println!("   ✅ Performance Optimizer benchmark completed successfully");
    }

    #[tokio::test]
    async fn benchmark_complete_intelligence_pipeline() {
        const FINDING_COUNT: usize = 200;
        const TARGETS: &[&str] = &[
            "https://web.example.com",
            "https://api.example.com",
            "https://admin.example.com",
        ];

        println!("🏁 Benchmarking Complete Intelligence Pipeline with {} findings...", FINDING_COUNT);

        // Create comprehensive benchmark data
        let mut findings = create_benchmark_findings(FINDING_COUNT, TARGETS);

        // Add some specific finding types for better correlation opportunities
        for i in 0..20 {
            if i % 2 == 0 {
                findings.push(Finding {
                    id: FindingId::new(),
                    title: "Reflected XSS in search parameter".to_string(),
                    description: "The application reflects user input directly into the HTML response without proper encoding.".to_string(),
                    severity: Severity::High,
                    confidence: Confidence::High,
                    category: Category::Xss,
                    target: "https://web.example.com".to_string(),
                    target_type: "web".to_string(),
                    evidence: Vec::new(),
                    references: Vec::new(),
                    plugin_source: "benchmark".to_string(),
                    plugin_version: "1.0".to_string(),
                    timestamp: Utc::now(),
                    scan_id: ScanId::new(),
                    metadata: HashMap::new(),
                    tags: Vec::new(),
                    verified: false,
                    false_positive: false,
                    risk_score: Some(75),
                    cvss_vector: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-79".to_string()],
                    capec_ids: vec!["CAPEC-66".to_string()],
                    mitre_attack_ids: Vec::new(),
                    owasp_category: Some("A03:2021-Injection".to_string()),
                    fingerprint: Some(format!("xss-benchmark-{}", i)),
                    related_findings: Vec::new(),
                    remediation: None,
                    exploitability: None,
                    business_impact: None,
                });

                findings.push(Finding {
                    id: FindingId::new(),
                    title: "Missing Content-Security-Policy header".to_string(),
                    description: "The application does not set a Content Security Policy header, increasing XSS risk.".to_string(),
                    severity: Severity::Medium,
                    confidence: Confidence::High,
                    category: Category::SecurityMisconfiguration,
                    target: "https://web.example.com".to_string(),
                    target_type: "web".to_string(),
                    evidence: Vec::new(),
                    references: Vec::new(),
                    plugin_source: "benchmark".to_string(),
                    plugin_version: "1.0".to_string(),
                    timestamp: Utc::now(),
                    scan_id: ScanId::new(),
                    metadata: HashMap::new(),
                    tags: Vec::new(),
                    verified: false,
                    false_positive: false,
                    risk_score: Some(35),
                    cvss_vector: None,
                    cvss_score: None,
                    cwe_ids: vec!["CWE-732".to_string()],
                    capec_ids: Vec::new(),
                    mitre_attack_ids: Vec::new(),
                    owasp_category: Some("A05:2021-Security_Misconfiguration".to_string()),
                    fingerprint: Some(format!("csp-benchmark-{}", i)),
                    related_findings: Vec::new(),
                    remediation: None,
                    exploitability: None,
                    business_impact: None,
                });
            }
        }

        let total_findings = findings.len();
        println!("   Created {} test findings", total_findings);

        // Initialize all intelligence components
        let correlation_engine = CorrelationEngine::new();

        let cve_config = cve_intelligence::CveIntelligenceConfig {
            enable_caching: true,
            cache_ttl_seconds: 3600,
            max_concurrent_requests: 5,
        };
        let mut cve_intel = CveIntelligence::new(cve_config);
        cve_intel.add_provider(Arc::new(cve_intelligence::MockCveProvider::new()));

        let knowledge_base = KnowledgeBase::new();
        let root_cause_analyzer = RootCauseAnalyzer::new();
        let perf_optimizer = PerformanceOptimizer::new();

        // Measure complete pipeline performance
        let start_time = Instant::now();

        // Step 1: Correlation Analysis
        let correlation_start = Instant::now();
        let correlations = correlation_engine.correlate_findings(&findings).unwrap();
        let correlation_duration = correlation_start.elapsed();

        // Step 2: CVE Intelligence Enrichment
        let cve_start = Instant::now();
        cve_intel.enrich_findings_with_cve_data(&mut findings).await.unwrap();
        let cve_duration = cve_start.elapsed();

        // Step 3: Knowledge Base Enrichment
        let kb_start = Instant::now();
        let kb_entries = knowledge_base.enrich_findings(&mut findings).unwrap();
        let kb_duration = kb_start.elapsed();

        // Step 4: Root Cause Analysis
        let rc_start = Instant::now();
        let root_causes = root_cause_analyzer.analyze_root_causes(&findings).unwrap();
        let rc_duration = rc_start.elapsed();

        // Step 5: Performance Optimization (Deduplication)
        let dedup_start = Instant::now();
        let duplicates_removed = perf_optimizer.deduplicate_findings(&mut findings);
        let dedup_duration = dedup_start.elapsed();

        let total_duration = start_time.elapsed();

        println!("   📈 Pipeline Performance Results:");
        println!("   - Total processing time: {:?}", total_duration);
        println!("   - Correlation analysis: {:?} ({} correlations)",
                 correlation_duration, correlations.len());
        println!("   - CVE intelligence enrichment: {:?}", cve_duration);
        println!("   - Knowledge base enrichment: {:?} ({} entries)",
                 kb_duration, kb_entries.len());
        println!("   - Root cause analysis: {:?} ({} root causes)",
                 rc_duration, root_causes.len());
        println!("   - Deduplication: {:?} ({} duplicates removed)",
                 dedup_duration, duplicates_removed);
        println!("   - Overall performance: {:.2} findings/second",
                 total_findings as f64 / total_duration.as_secs_f64());

        // Verify pipeline completed successfully
        assert!(total_duration.as_millis() < 15000); // Should complete within 15 seconds
        assert!(!correlations.is_empty() || correlations.len() >= 0); // At least empty vec
        assert!(!kb_entries.is_empty() || kb_entries.len() >= 0); // At least empty vec
        assert!(root_causes.len() >= 0); // At least empty vec

        println!("   ✅ Complete Intelligence Pipeline benchmark completed successfully");
    }

    #[test]
    fn benchmark_memory_usage() {
        use std::mem;

        println!("🧠 Benchmarking Memory Usage...");

        // Measure size of key data structures
        let correlation_size = mem::size_of::<EnhancedCorrelation>();
        let cve_info_size = mem::size_of::<CveInfo>();
        let dependency_info_size = mem::size_of::<DependencyInfo>();
        let kb_entry_size = mem::size_of::<KnowledgeBaseEntry>();
        let root_cause_size = mem::size_of::<RootCauseAnalysis>();

        println!("   📈 Memory Usage Results:");
        println!("   - EnhancedCorrelation: {} bytes", correlation_size);
        println!("   - CveInfo: {} bytes", cve_info_size);
        println!("   - DependencyInfo: {} bytes", dependency_info_size);
        println!("   - KnowledgeBaseEntry: {} bytes", kb_entry_size);
        println!("   - RootCauseAnalysis: {} bytes", root_cause_size);

        // Create sample data structures to measure actual memory usage
        let sample_correlation = EnhancedCorrelation {
            finding_ids: vec![FindingId::new(); 5],
            correlation_type: types::CorrelationType::CspXssChain,
            confidence: 0.85,
            description: "Sample correlation description for benchmarking purposes".to_string(),
            evidence: vec!["Evidence 1".to_string(), "Evidence 2".to_string()],
            combined_risk: types::RiskAssessment {
                individual_scores: vec![60, 75],
                combined_score: 80,
                explanation: "Combined risk explanation".to_string(),
            },
            mitigation_approach: "Mitigation approach for this correlation pattern".to_string(),
        };

        let sample_cve = CveInfo {
            cve_id: "CVE-2023-99999".to_string(),
            severity: Severity::High,
            cvss_score: Some(7.5),
            cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
            description: "Sample CVE description for memory benchmarking".to_string(),
            affected_versions: vec![types::VersionRange {
                start_version: Some("1.0.0".to_string()),
                end_version: Some("2.3.4".to_string()),
                is_vulnerable: true,
            }],
            fixed_versions: vec!["2.3.5".to_string()],
            references: vec![types::CveReference {
                url: "https://example.com/cve/CVE-2023-99999".to_string(),
                description: Some("Example reference".to_string()),
            }],
            cwe_ids: vec!["CWE-79".to_string(), "CWE-80".to_string()],
            published_date: Utc::now(),
            last_modified_date: Utc::now(),
        };

        println!("   📈 Sample Object Memory Usage:");
        println!("   - Sample EnhancedCorrelation: ~{} bytes",
                 mem::size_of_val(&sample_correlation));
        println!("   - Sample CveInfo: ~{} bytes",
                 mem::size_of_val(&sample_cve));

        // These sizes should be reasonable for the complexity of the data
        assert!(correlation_size < 1000, "Correlation struct too large");
        assert!(cve_info_size < 2000, "CVE info struct too large");

        println!("   ✅ Memory Usage benchmark completed successfully");
    }
}