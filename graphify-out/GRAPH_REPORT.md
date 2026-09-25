# Graph Report - open-re  (2026-09-14)

## Corpus Check
- cluster-only mode — file stats not available

## Summary
- 8943 nodes · 20888 edges · 415 communities (392 shown, 23 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 123 edges (avg confidence: 0.86)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a6034b6f`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- FindingRelationship
- state.rs
- app_map.rs
- reporting.rs
- common.rs
- ScanContext
- checks.rs
- openre-core/src/plugin.rs
- openre-core/src/attack_path.rs
- stages.rs
- risk_knowledge.rs
- Target
- api.rs
- ScanSession
- AgentCoordinator
- OpenREClient
- TuiApp
- history.rs
- agents/context.rs
- deduplication.rs
- openre-config/src/config.rs
- intelligence_stubs.rs
- evidence.rs
- openre-intelligence/src/types.rs
- PluginManager
- AppState
- Orchestrator
- ScannerResult
- DependencyAnalyzer
- InvestigationContext
- Services
- VerificationMethod
- Frame
- HeaderAnalysisPlugin
- InvestigationStage
- agent_trait.rs
- ContextBuilder
- AgentType
- SafetyController
- ProviderId
- manifest.rs
- InjectionCategory
- .new
- StageContext
- analysis_stubs.rs
- GroundedLlmService
- CveIntelligence
- PerformanceOptimizer
- InjectionTestResult
- TechDetectionPlugin
- Node<'a>
- AiCache
- grounded.rs
- ids.rs
- KnowledgeBase
- Event
- audit.rs
- orchestrator.rs
- app.py
- analyze.rs
- components.rs
- ResultAggregator
- models.py
- Context
- WorkflowManager
- openre-security-ai/src/types.rs
- openre-core/src/result.rs
- AuthDiscoveryPlugin
- Option
- CliError
- .new
- MockScanStorage
- Node
- architecture.rs
- .new
- PluginLifecycleManager
- GraphqlPlugin
- client.py
- .extract_metadata
- JobProgress
- remediate.rs
- openre-core/src/remediation.rs
- workflow_engine.rs
- RestApiPlugin
- properties
- properties
- properties
- properties
- properties
- properties
- CapstoneWrapper
- PluginRegistry
- RobotsSitemapPlugin
- tui.rs
- BinaryMetadata
- Result
- EndpointDiscoveryPlugin
- ScanTarget
- properties
- binary/traits.rs
- PrivacyController
- AiService
- ElfMetadataExtractor
- function.rs
- max_concurrent_requests
- String
- CookieAnalysisPlugin
- PeMetadataExtractor
- Finding
- ReconAgent
- App
- AnalysisCache
- Result
- BinaryUploadService
- Config
- HttpFingerprintPlugin
- ReconPluginConfig
- utils.rs
- openre-telemetry/src/metrics.rs
- Disassembler
- RootCauseAnalyzer
- BuiltinPayloadEngine
- burst_test_size
- exploit.rs
- FindingFilter
- PyOpenREClient
- RemoteProvider
- PromptCompiler
- OnnxProvider
- ai_stubs.rs
- .new
- App
- properties
- properties
- String
- predicate.rs
- SafetyGuard
- InjectionPluginConfig
- ScanResponse
- MetadataExtractionService
- commands/config.rs
- VerificationResult
- ReportingAgent
- verification.rs
- BaseInjectionPlugin
- ReconType
- MockModelProvider
- cfg.rs
- Job
- ScanManager
- Capability
- ScanProfile
- Error
- LlamaCppProvider
- lifter.rs
- RemediationVerifier
- setup-dev.sh
- Value
- create_response_analyzer
- storage.rs
- Document
- default
- CompletionRequest
- ConfidenceScorer
- LdapInjectionPlugin
- MockFindingProvider
- properties
- PyAnalysisManager
- PluginManager
- StageId
- openre-cli/src/main.rs
- .run_scan_command
- PromptCompiler
- tracing.rs
- properties
- AnalysisManager
- Selection
- AiTool
- .new
- ScheduledRecheck
- src/traits.rs
- HeaderInjectionPlugin
- openre-scan/src/main.rs
- openre-tui/src/lib.rs
- stubs.rs
- output_results
- AnalysisJob
- ApiAnalysisAgent
- CorrelationAgent
- WebAnalysisAgent
- CommandInjectionPlugin
- NoSqlInjectionPlugin
- SqlInjectionPlugin
- SstiPlugin
- XPathInjectionPlugin
- XssPlugin
- XxePlugin
- sdk.rs
- openre-scan/src/output.rs
- default
- allowed_scopes
- CliConfig
- incremental.rs
- RemediationAgent
- VerificationAgent
- ScanStorageFindingProvider
- openre-core
- openre-ai/src/lib.rs
- PipelineMetrics
- TargetType
- properties
- ._extract_evidence_ids
- AnalysisJob
- print_output
- .reload_config
- PluginType
- ResearchAgent
- AiResult
- allowed_scopes
- tools.rs
- .new
- benchmarks.rs
- SecurityAnalystImpl
- properties
- properties
- properties
- required
- properties
- allowed_scopes
- JobType
- default
- default
- AudienceArg
- .with_templates
- properties
- properties
- properties
- properties
- sustained_requests
- properties
- properties
- allowed_scopes
- RemediationVerifierConfig
- default
- default
- properties
- default
- PipelineContext
- ProjectStore
- src/integration_tests.rs
- aggressive_mode
- default
- properties
- properties
- ExecutiveSummary
- Arc
- static_analysis_test.rs
- max_concurrent_requests
- main
- default
- default
- default
- properties
- LlmRemediation
- request_timeout
- max_redirects
- comprehensive_test.rs
- logging.rs
- test_origins
- .explain_finding
- .compare_scans
- max_payloads_per_param
- openre-plugins-macros/src/lib.rs
- Iter<'sel, 'doc>
- auth_endpoint_test_requests
- max_redirects
- max_test_requests
- request_timeout
- sustained_requests_per_second
- sustained_test_duration_seconds
- test_requests_per_endpoint
- max_concurrent_requests
- max_depth
- max_redirects
- request_timeout
- max_concurrent_requests
- max_redirects
- request_timeout
- enabled_checks
- max_concurrent_requests
- max_redirects
- request_timeout
- max_concurrency
- max_payloads_per_param
- max_redirects
- max_requests_per_test
- max_total_requests
- request_timeout
- request_timeout_secs
- max_concurrent_requests
- max_redirects
- request_timeout
- max_concurrency
- max_redirects
- max_total_requests
- rate_limit_rps
- burst_size
- max_concurrent_requests
- max_redirects
- request_timeout
- sustained_delay_ms
- max_requests_per_test
- max_concurrent_requests
- max_redirects
- request_timeout
- max_concurrent_requests
- max_redirects
- request_timeout
- request_timeout
- max_redirects
- max_total_requests
- properties
- request_timeout_secs
- default
- max_concurrency
- max_concurrent_requests
- max_payloads_per_param
- max_redirects
- max_requests_per_test
- max_total_requests
- rate_limit_rps
- request_timeout
- request_timeout_secs
- AiService
- TelemetryHandle
- FindingChanges
- api_rate_limiting/config_schema.json
- user_agent
- Descendants
- enabled_checks
- enabled_checks
- enabled_checks
- openre_bindings
- GetBasicBlocksTool
- GetCFGTool
- GetFunctionInfoTool
- GetInstructionsTool
- GetStringsTool
- GetXrefsTool
- QueryDatabaseTool
- ReadBinaryTool
- SearchTool
- WriteAnnotationTool
- binary/metrics.rs
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- builtin_security_plugins
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- manifest
- &'sel Selection<'doc>
- user_agent
- user_agent
- verify_ssl
- information_disclosure/config_schema.json
- aggressive_mode
- check_sensitive_files
- user_agent
- verify_ssl
- user_agent
- check_cache_control
- check_cross_origin
- check_hsts
- check_permissions
- check_referrer
- check_xcto
- check_xfo
- verify_ssl
- aggressive_mode
- follow_redirects
- test_session_fixation
- verify_ssl
- aggressive_mode
- Theme
- .stream_compare_scans
- .stream_correlate_findings
- .stream_executive_summary
- .stream_explain_finding
- benchmark.sh
- build.sh
- benchmark-checkpoint.sh
- build-checkpoint.sh
- openre-plugins-macros
- openre-plugins-macros
- sentinel

## God Nodes (most connected - your core abstractions)
1. `TuiApp` - 92 edges
2. `OpenREClient` - 79 edges
3. `Config` - 70 edges
4. `StageId` - 65 edges
5. `AppState` - 61 edges
6. `CliError` - 61 edges
7. `Event` - 56 edges
8. `Context` - 55 edges
9. `Action` - 54 edges
10. `Capability` - 47 edges

## Surprising Connections (you probably didn't know these)
- `test_logging_init()` --calls--> `init_logging()`  [INFERRED]
  tests/unit_tests.rs → crates/openre-telemetry/src/logging.rs
- `PyOpenREClient` --references--> `AppState`  [EXTRACTED]
  python/openre-bindings/src/client.rs → crates/openre-tui/src/state.rs
- `TestServer` --references--> `Child`  [EXTRACTED]
  crates/openre-scan/tests/integration.rs → .patched-crates/select-patched/src/predicate.rs
- `parse_html()` --references--> `Document`  [EXTRACTED]
  crates/openre-recon/src/lib.rs → .patched-crates/select-patched/src/document.rs
- `openre-recon` --depends_on--> `select`  [EXTRACTED]
  crates/openre-recon/Cargo.toml → .patched-crates/select-patched/Cargo.toml

## Import Cycles
- 2-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/document.rs`
- 2-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/document.rs`
- 2-file cycle: `.patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/predicate.rs -> .patched-crates/select-patched/src/node.rs`
- 2-file cycle: `.patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/node.rs`
- 2-file cycle: `crates/openre-analysis/src/orchestrator.rs -> crates/openre-analysis/src/stages.rs -> crates/openre-analysis/src/orchestrator.rs`
- 3-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/document.rs`
- 3-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/predicate.rs -> .patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/document.rs`
- 3-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/document.rs`
- 3-file cycle: `.patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/predicate.rs -> .patched-crates/select-patched/src/node.rs`
- 4-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/predicate.rs -> .patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/document.rs`
- 4-file cycle: `.patched-crates/select-patched/src/document.rs -> .patched-crates/select-patched/src/selection.rs -> .patched-crates/select-patched/src/predicate.rs -> .patched-crates/select-patched/src/node.rs -> .patched-crates/select-patched/src/document.rs`

## Communities (415 total, 23 thin omitted)

### Community 0 - "FindingRelationship"
Cohesion: 0.05
Nodes (72): EvidenceSource, EvidenceType, FindingRelationship, FindingRelationshipGraph, FindingRelationshipType, RelationshipEvidence, RelationshipFilter, RelationshipGraphMetadata (+64 more)

### Community 1 - "state.rs"
Cohesion: 0.04
Nodes (65): ActiveScanInfo, AIAnalysis, AIState, AIViewMode, ChatMessage, ChatRole, DisplayFinding, EvidenceDetail (+57 more)

### Community 2 - "app_map.rs"
Cohesion: 0.05
Nodes (74): AuthEndpointId, ApplicationMap, AppMapMetadata, AppMapOutputFormat, AppMapRelationship, AppMapRelationshipType, AuthEndpoint, AuthInfo (+66 more)

### Community 3 - "reporting.rs"
Cohesion: 0.06
Nodes (59): Appendix, AppendixType, BrandingInfo, ColorScheme, ComparisonSummary, create_test_finding(), create_test_scan(), DateRange (+51 more)

### Community 4 - "common.rs"
Cohesion: 0.05
Nodes (89): BasicBlockId, CallEdgeId, CfgEdgeId, AnalysisSession, AnalysisStageStatus, AnalysisStatus, Architecture, BasicBlock (+81 more)

### Community 5 - "ScanContext"
Cohesion: 0.05
Nodes (52): AuthState, CacheEntry, DiscoveredEndpoint, DiscoveredParameter, RateLimiter, Arc, CacheEntry, CancellationToken (+44 more)

### Community 6 - "checks.rs"
Cohesion: 0.07
Nodes (75): Check, check_cookie_security(), check_cors(), check_csp(), check_directory_listing(), check_forms(), check_http_headers(), check_http_methods() (+67 more)

### Community 7 - "openre-core/src/plugin.rs"
Cohesion: 0.06
Nodes (61): BuildConfig, BuildTarget, CapabilityRequest, CapabilityResponse, CommandContext, CommandRegistration, CommandResult, ConfigSchema (+53 more)

### Community 8 - "openre-core/src/attack_path.rs"
Cohesion: 0.06
Nodes (60): AssetId, AttackPathId, AttackNodeType, AttackPath, AttackPathCollection, AttackPathCollectionMetadata, AttackPathEdge, AttackPathNode (+52 more)

### Community 9 - "stages.rs"
Cohesion: 0.06
Nodes (25): StageExecutor, AiEnrichmentStage, AiService, AnalyzerPlugin, ControlFlowStage, DataFlowStage, DecompilationStage, DecompilerPlugin (+17 more)

### Community 10 - "risk_knowledge.rs"
Cohesion: 0.06
Nodes (73): AffectedProduct, AssetCriticality, AttackLikelihood, AuthContext, AuthStrength, BusinessContext, BusinessCriticality, calculate_risk_score() (+65 more)

### Community 11 - "Target"
Cohesion: 0.08
Nodes (33): Builder, AuthConfig, ProxyAuth, ProxyConfig, RateLimitConfig, RetryConfig, AuthConfig, DashMap (+25 more)

### Community 12 - "api.rs"
Cohesion: 0.21
Nodes (41): ApiDoc, ApiState, cancel_scan(), create_router(), create_scan(), create_target(), delete_target(), disable_plugin() (+33 more)

### Community 13 - "ScanSession"
Cohesion: 0.11
Nodes (23): PluginExecutionRecord, PluginExecutionStatus, CancellationToken, DateTime, Display, Duration, Formatter, FromStr (+15 more)

### Community 14 - "AgentCoordinator"
Cohesion: 0.08
Nodes (37): AgentCoordinator, AgentDependencyGraph, AgentTask, AgentTaskResult, AgentWorkflowBuilder, CoordinatorConfig, CoordinatorStats, create_investigation_workflow() (+29 more)

### Community 15 - "OpenREClient"
Cohesion: 0.04
Nodes (23): AuthTokens, OpenREClient, Response, Generate remediation plan for a security finding., Stream generation of remediation plan for a security finding., Client for interacting with the open-re API. Example: client =…, Prioritize findings for remediation., Stream prioritization of findings for remediation. (+15 more)

### Community 16 - "TuiApp"
Cohesion: 0.09
Nodes (7): parse_finding_sort(), Finding, PluginInfo, ScannerResult, ScanProgress, T, TuiApp

### Community 17 - "history.rs"
Cohesion: 0.10
Nodes (46): create_test_scan_summary(), DiscoverConfig, HistoryError, HistoryManager, InvestigationStageConfig, PluginExecutionSummary, PrioritizeConfig, ReportArtifact (+38 more)

### Community 18 - "agents/context.rs"
Cohesion: 0.09
Nodes (65): AgentInput, AgentOutput, Serialize, ApiAnalysisInput, ApiAnalysisOutput, ApiEndpoint, AttackPath, AttackPathEdge (+57 more)

### Community 19 - "deduplication.rs"
Cohesion: 0.11
Nodes (35): CorrelationConfig, ChainType, CorrelationAttackPath, CorrelationAttackStep, CorrelationChain, CorrelationConfig, CorrelationEngine, CorrelationResult (+27 more)

### Community 20 - "openre-config/src/config.rs"
Cohesion: 0.08
Nodes (43): ApiKeyConfig, AuthConfig, AutoscalerConfig, default_config_dir(), default_config_path(), EncryptionConfig, JwtConfig, LogFormat (+35 more)

### Community 21 - "intelligence_stubs.rs"
Cohesion: 0.06
Nodes (49): Category, ComplianceFramework, Confidence, Correlation, CorrelationEngine, CorrelationType, Environment, Exploit (+41 more)

### Community 22 - "evidence.rs"
Cohesion: 0.08
Nodes (56): AuthBypassMethod, CertificateInfo, ChangeImpact, ChangeType, CloudProviderInfo, ConfigSource, ConfigType, ConfigurationEvidence (+48 more)

### Community 23 - "openre-intelligence/src/types.rs"
Cohesion: 0.08
Nodes (56): Acknowledgment, AcknowledgmentStatus, ConfidenceChange, ConfidenceChangeType, CorrelationType, CveReference, DependencyUpgradeRisk, DependencyVulnerability (+48 more)

### Community 24 - "PluginManager"
Cohesion: 0.10
Nodes (39): HealthStatus, Manifest, ManifestCapability, ManifestDependency, plugin_id_from_name(), PluginCapability, PluginConfig, PluginDependency (+31 more)

### Community 25 - "AppState"
Cohesion: 0.06
Nodes (38): Action, Category, Confidence, JobId, JobStatus, Option, Priority, ProjectId (+30 more)

### Community 26 - "Orchestrator"
Cohesion: 0.08
Nodes (29): AnalysisConfig, CancellationToken, default_pipeline_stages(), ExecutorConfig, IsolatedBinary, Orchestrator, PipelineContext, PluginRegistry (+21 more)

### Community 27 - "ScannerResult"
Cohesion: 0.11
Nodes (16): FindingSort, MemoryScanStorage, DashMap, Default, Finding, FindingId, Option, ProjectId (+8 more)

### Community 28 - "DependencyAnalyzer"
Cohesion: 0.11
Nodes (23): DependencyAnalysisConfig, DependencyAnalyzer, DependencyFileType, MockRegistryClient, RegistryClient, Box, Default, HashMap (+15 more)

### Community 29 - "InvestigationContext"
Cohesion: 0.09
Nodes (20): InvestigationContext, InvestigationWorkflow, InvestigationWorkflowEngine, ReportStageHandler, DateTime, Finding, IntelligenceResult, RwLock (+12 more)

### Community 30 - "Services"
Cohesion: 0.10
Nodes (25): DataFetcher, InvestigationWorkflowEngine, KnowledgeBase, Arc, Debug, Formatter, HashMap, Option (+17 more)

### Community 31 - "VerificationMethod"
Cohesion: 0.05
Nodes (22): AuthVerifier, DirectoryListingVerifier, FindingVerifier, get_all_verifiers(), InfoDisclosureVerifier, RateLimitVerifier, Display, Formatter (+14 more)

### Community 32 - "Frame"
Cohesion: 0.14
Nodes (16): render_empty_state(), JobStatus, Option, status_badge(), AIPanel, PluginsPanel, render_finding_detail(), render_scan_list() (+8 more)

### Community 33 - "HeaderAnalysisPlugin"
Cohesion: 0.12
Nodes (27): CacheControlAnalysis, CrossOriginPoliciesAnalysis, CspAnalysis, HeaderAnalysisPlugin, HeaderAnalysisResult, HstsAnalysis, PermissionsPolicyAnalysis, plugin_init() (+19 more)

### Community 34 - "InvestigationStage"
Cohesion: 0.07
Nodes (20): AnalyzeConfig, CorrelateConfig, VerifyConfig, AnalyzeStageHandler, CorrelateStageHandler, InvestigationStage, InvestigationStageConfig, ReportConfig (+12 more)

### Community 35 - "agent_trait.rs"
Cohesion: 0.08
Nodes (34): AgentContext, AiService, CancellationToken, DynamicAgentInput, DynamicAgentOutput, Arc, Box, DateTime (+26 more)

### Community 36 - "ContextBuilder"
Cohesion: 0.19
Nodes (16): ComparisonContext, ContextBuilder, CorrelationContext, EvidenceSummary, FindingExplanationContext, FindingSummary, AiResult, Evidence (+8 more)

### Community 37 - "AgentType"
Cohesion: 0.07
Nodes (27): BaseAgent, AgentId, String, Vec, Vec, AgentCapability, AgentHealth, AgentMetadata (+19 more)

### Community 38 - "SafetyController"
Cohesion: 0.09
Nodes (25): PayloadValidator, RateLimiter, RequestPermit, RequestValidator, Arc, Clone, Default, Drop (+17 more)

### Community 39 - "ProviderId"
Cohesion: 0.15
Nodes (13): ProviderId, Display, Formatter, Result, ModelRouter, ProviderStats, Arc, HashMap (+5 more)

### Community 40 - "manifest.rs"
Cohesion: 0.07
Nodes (42): BuildConfig, BuildTarget, ConfigSchema, EntryConfig, MenuExtension, PanelExtension, PanelPosition, PluginConfig (+34 more)

### Community 41 - "InjectionCategory"
Cohesion: 0.07
Nodes (33): Self, InjectionCategory, SafetyConfig, create_payload_engine(), PayloadEngine, Box, Self, Send (+25 more)

### Community 42 - ".new"
Cohesion: 0.17
Nodes (14): CookieSecurityVerifier, empty_verification_evidence(), Box, Client, Finding, Future, IntelligenceResult, Output (+6 more)

### Community 43 - "StageContext"
Cohesion: 0.08
Nodes (28): ControlFlowOutput, StageContext, AiEnrichmentConfig, CFG, DecompilationFunctionResult, DecompilationOutput, DisassemblyFunctionResult, ExportResult (+20 more)

### Community 44 - "analysis_stubs.rs"
Cohesion: 0.11
Nodes (29): BinaryAnalyzer, BinaryFormat, BinaryInfo, detect_format(), Disassembly, Export, Function, Import (+21 more)

### Community 45 - "GroundedLlmService"
Cohesion: 0.24
Nodes (9): create_test_evidence(), create_test_finding(), GroundedLlmService, ExecutiveSummary, Finding, FindingEvidence, ScanComparison, test_validate_grounding_extracts_ids() (+1 more)

### Community 46 - "CveIntelligence"
Cohesion: 0.13
Nodes (23): CachedCveEntry, CveCache, CveIntelligence, CveIntelligenceConfig, CveProvider, MockCveProvider, Arc, Default (+15 more)

### Community 47 - "PerformanceOptimizer"
Cohesion: 0.11
Nodes (26): CacheEntry, CacheEntry<T>, CacheStats, create_test_finding(), IncrementalProcessingResult, PerformanceConfig, PerformanceOptimizer, CacheStats (+18 more)

### Community 48 - "InjectionTestResult"
Cohesion: 0.16
Nodes (21): HttpResponseSnapshot, InjectionTestResult, DetectionMethod, ParameterLocation, Severity, BuiltinResponseAnalyzer, ErrorPattern, ReproducibleRequest (+13 more)

### Community 49 - "TechDetectionPlugin"
Cohesion: 0.10
Nodes (21): plugin_init(), Client, CommandRegistration, Confidence, Finding, HashMap, Option, Plugin (+13 more)

### Community 50 - "Node<'a>"
Cohesion: 0.10
Nodes (16): Children, Children<'a>, Descendants<'a>, Find<'a, P>, Node<'a>, Debug, Find, Formatter (+8 more)

### Community 51 - "AiCache"
Cohesion: 0.11
Nodes (21): AiCache, CacheEntry, CacheStats, Arc, CacheEntry, CacheStats, DateTime, Default (+13 more)

### Community 52 - "grounded.rs"
Cohesion: 0.07
Nodes (45): Audience, CorrelationType, ExecutiveSummary, ExplanationConfidence, GroundedAttackScenario, GroundedClaim, GroundedCodeExample, GroundedCorrelationGroup (+37 more)

### Community 53 - "ids.rs"
Cohesion: 0.06
Nodes (16): Architecture, CapabilityRequest, CapabilityResponse, JobStatus, Priority, DateTime, Option, String (+8 more)

### Community 54 - "KnowledgeBase"
Cohesion: 0.11
Nodes (20): CapecEntry, create_test_finding(), CweEntry, KnowledgeBase, KnowledgeBaseConfig, CapecEntry, Category, CweEntry (+12 more)

### Community 55 - "Event"
Cohesion: 0.07
Nodes (35): Event, EventBus, EventHandler, REProject, Category, ChatMessage, Clone, Confidence (+27 more)

### Community 56 - "audit.rs"
Cohesion: 0.12
Nodes (32): BufWriter, AuditConfig, audit_auth(), audit_data_access(), audit_logger(), audit_security(), AuditEntry, AuditEventType (+24 more)

### Community 57 - "orchestrator.rs"
Cohesion: 0.08
Nodes (37): AnalysisJob, AnalysisResult, AnalysisStatistics, AnalysisStatus, AnnotationInfo, Artifact, BasicBlockInfo, CallEdgeInfo (+29 more)

### Community 58 - "app.py"
Cohesion: 0.07
Nodes (39): get, post, add_comment(), api_login(), cors_test(), debug_info(), get_comments(), health_check() (+31 more)

### Community 59 - "analyze.rs"
Cohesion: 0.16
Nodes (31): AnalyzeArgs, AnalyzeCommands, BinaryFormatArg, crate::analysis_stubs::BinaryFormat, crate::analysis_stubs::PipelineStage, DecompileArgs, DisasmArgs, FunctionRow (+23 more)

### Community 60 - "components.rs"
Cohesion: 0.12
Nodes (38): Constraint, cell(), centered_rect(), header_cell(), log_level_badge(), priority_badge(), progress_line(), render_block() (+30 more)

### Community 61 - "ResultAggregator"
Cohesion: 0.12
Nodes (20): make_finding(), ResultAggregator, Arc, Category, Confidence, DashMap, Default, Finding (+12 more)

### Community 62 - "models.py"
Cohesion: 0.11
Nodes (36): Enum, Analysis manager for open-re Python bindings., open-re Python bindings for reverse engineering. This package provides Python…, AnalysisJob, AnalysisResult, AnalyzeFunctionResponse, AnnotationInfo, AnnotationsResponse (+28 more)

### Community 63 - "Context"
Cohesion: 0.09
Nodes (44): AiClient, AsRef, cancel_job(), CancelArgs, create_queue_manager(), get_job_logs(), get_job_status(), JobStatus (+36 more)

### Community 64 - "WorkflowManager"
Cohesion: 0.13
Nodes (21): create_test_finding(), Arc, Default, Finding, FindingId, HashMap, IntelligenceResult, Option (+13 more)

### Community 65 - "openre-security-ai/src/types.rs"
Cohesion: 0.11
Nodes (38): Audience, CodeExample, CorrelationGroup, CorrelationReport, EvidenceReference, ExecutiveSummary, ExplanationConfidence, FindingExplanation (+30 more)

### Community 66 - "openre-core/src/result.rs"
Cohesion: 0.14
Nodes (24): ExploitabilityInfo, AssetCriticality, AttackComplexity, AttackVector, BusinessImpactAssessment, CodeExample, ExploitabilityAssessment, HttpRequestEvidence (+16 more)

### Community 67 - "AuthDiscoveryPlugin"
Cohesion: 0.12
Nodes (21): AuthDiscoveryPlugin, AuthDiscoveryResult, AuthHeaderInfo, BasicAuthInfo, BearerAuthInfo, LoginFormInfo, OAuthIndicator, plugin_init() (+13 more)

### Community 68 - "Option"
Cohesion: 0.20
Nodes (38): AccessControlFindingArgs, AccessControlStatsArgs, ApiFindingArgs, ApiStatsArgs, AuthFindingArgs, Cli, CookieFindingArgs, CorsFindingArgs (+30 more)

### Community 69 - "CliError"
Cohesion: 0.14
Nodes (32): AiCommands, AnalyzeArgs, ChatArgs, CorrelateArgs, CorrelationRow, ExplainArgs, load_finding(), load_findings_from_path() (+24 more)

### Community 70 - ".new"
Cohesion: 0.12
Nodes (26): create_test_finding(), create_test_scan_data(), DateTime, Default, Finding, FindingId, HashMap, IntelligenceResult (+18 more)

### Community 71 - "MockScanStorage"
Cohesion: 0.15
Nodes (16): create_test_finding(), MockScanStorage, Category, DateTime, Default, Finding, FindingEvidence, FindingId (+8 more)

### Community 72 - "Node"
Cohesion: 0.08
Nodes (20): JoinHandle, R, spawn_blocking(), Node, And<A, B>, Any, Attr<&'a str, ()>, Attr<&'a str, &'a str> (+12 more)

### Community 73 - "architecture.rs"
Cohesion: 0.10
Nodes (22): Arch, Architecture, BasicBlock, CallingConvention, CfgEdge, CfgEdgeType, ControlFlowGraph, DominatorTree (+14 more)

### Community 74 - ".new"
Cohesion: 0.14
Nodes (18): create_test_finding(), ProgressIndicator, Confidence, Default, Finding, Instant, Self, Severity (+10 more)

### Community 75 - "PluginLifecycleManager"
Cohesion: 0.15
Nodes (20): PluginConfig, PluginLifecycleManager, PluginRuntimeInfo, PluginState, Arc, DateTime, Default, HashMap (+12 more)

### Community 76 - "GraphqlPlugin"
Cohesion: 0.12
Nodes (20): GraphqlConfig, GraphqlEndpoint, GraphqlPlugin, Arc, CapabilityRequest, CapabilityResponse, Category, Client (+12 more)

### Community 77 - "client.py"
Cohesion: 0.08
Nodes (35): Audience, CorrelationType, ExplanationConfidence, GroundedAttackScenario, GroundedClaim, GroundedCodeExample, GroundedCorrelationGroup, GroundedEvidenceReference (+27 more)

### Community 78 - ".extract_metadata"
Cohesion: 0.12
Nodes (17): calculate_entropy(), calculate_hashes(), extract_fat_metadata(), MachoIdentifier, MachoMetadataExtractor, MachoParser, Architecture, BinaryFormat (+9 more)

### Community 79 - "JobProgress"
Cohesion: 0.11
Nodes (22): JobProgress, JobStatus, ProgressTracker, QueueManager, Arc, DateTime, HashMap, JobId (+14 more)

### Community 80 - "remediate.rs"
Cohesion: 0.13
Nodes (29): ComplianceArg, crate::intelligence_stubs::ComplianceFramework, crate::intelligence_stubs::Environment, crate::intelligence_stubs::GroupBy, crate::intelligence_stubs::Language, EnvironmentArg, GroupByArg, LanguageArg (+21 more)

### Community 81 - "openre-core/src/remediation.rs"
Cohesion: 0.11
Nodes (28): AuthChanges, AuthMethodChange, EndpointChange, EndpointChanges, EndpointChangeType, EndpointInfo, EvidenceChange, FindingEvidence (+20 more)

### Community 82 - "workflow_engine.rs"
Cohesion: 0.09
Nodes (24): create_test_finding(), DefaultRiskScorer, DiscoverStageHandler, InvestigationReport, InvestigationStageHandler, PrioritizationLevel, PrioritizedFinding, PrioritizeStageHandler (+16 more)

### Community 83 - "RestApiPlugin"
Cohesion: 0.12
Nodes (20): ApiEndpoint, RestApiConfig, RestApiPlugin, ApiEndpoint, Arc, CapabilityRequest, CapabilityResponse, Category (+12 more)

### Community 84 - "properties"
Cohesion: 0.06
Nodes (34): default, description, type, default, description, maximum, minimum, type (+26 more)

### Community 85 - "properties"
Cohesion: 0.06
Nodes (34): default, description, type, default, description, maximum, minimum, type (+26 more)

### Community 86 - "properties"
Cohesion: 0.07
Nodes (28): default, description, type, default, description, maximum, minimum, type (+20 more)

### Community 87 - "properties"
Cohesion: 0.07
Nodes (28): default, description, type, default, description, maximum, minimum, type (+20 more)

### Community 88 - "properties"
Cohesion: 0.06
Nodes (34): default, description, type, default, description, maximum, minimum, type (+26 more)

### Community 89 - "properties"
Cohesion: 0.06
Nodes (34): default, description, type, default, description, maximum, minimum, type (+26 more)

### Community 90 - "CapstoneWrapper"
Cohesion: 0.13
Nodes (21): Capstone, Syntax, CapstoneWrapper, Insn, InsnGroup, InsnId, MemDetail, OpDetail (+13 more)

### Community 91 - "PluginRegistry"
Cohesion: 0.07
Nodes (34): PluginRegistry, PluginSource, RegistryConfig, RegistryEntry, Arc, DateTime, Default, HashMap (+26 more)

### Community 92 - "RobotsSitemapPlugin"
Cohesion: 0.12
Nodes (19): ParsedRobots, ParsedSitemap, plugin_init(), RobotsResult, RobotsSitemapPlugin, Client, CommandRegistration, Finding (+11 more)

### Community 93 - "tui.rs"
Cohesion: 0.11
Nodes (30): AuthType, Commands, ConfigCommands, ConfigGetArgs, ConfigSetArgs, ExportFormat, parse_key_value(), PluginCommands (+22 more)

### Community 94 - "BinaryMetadata"
Cohesion: 0.16
Nodes (18): AnyResult, BinaryMetadata, Default, Elf, FileId, FunctionInfo, PE, Result (+10 more)

### Community 95 - "Result"
Cohesion: 0.11
Nodes (14): VersionInfo, calculate_hashes(), BinaryFormat, BinaryInfo, FunctionInfo, Option, Path, Result (+6 more)

### Community 96 - "EndpointDiscoveryPlugin"
Cohesion: 0.12
Nodes (17): DiscoveredEndpoint, EndpointDiscoveryPlugin, EndpointDiscoveryResult, plugin_init(), Client, CommandRegistration, DiscoveredEndpoint, Finding (+9 more)

### Community 97 - "ScanTarget"
Cohesion: 0.22
Nodes (9): Default, Finding, Option, Self, String, Uuid, Vec, ScanResult (+1 more)

### Community 98 - "properties"
Cohesion: 0.08
Nodes (26): description, type, default, description, maximum, minimum, type, default (+18 more)

### Community 99 - "binary/traits.rs"
Cohesion: 0.11
Nodes (31): CfgNode, BasicBlockInfo, BinaryMetadataExtractor, CallEdgeType, CallGraph, CallGraphEdge, CallGraphNode, CfgEdge (+23 more)

### Community 100 - "PrivacyController"
Cohesion: 0.12
Nodes (18): DataClassification, PrivacyAction, PrivacyAuditEntry, PrivacyController, PrivacyDecision, Arc, DataClassification, DateTime (+10 more)

### Community 101 - "AiService"
Cohesion: 0.13
Nodes (16): AiService, Arc, CacheStats, FunctionId, HashMap, HealthStatus, Option, ProjectStore (+8 more)

### Community 102 - "ElfMetadataExtractor"
Cohesion: 0.14
Nodes (15): Symbol, SymbolBinding, SymbolType, calculate_entropy(), ElfMetadataExtractor, ElfParser, Architecture, BinaryInfo (+7 more)

### Community 103 - "function.rs"
Cohesion: 0.16
Nodes (21): Function, FunctionDetector, FunctionSignature, LocalVariable, Parameter, ParameterLocation, Architecture, ControlFlowGraph (+13 more)

### Community 104 - "max_concurrent_requests"
Cohesion: 0.20
Nodes (32): required, required, required, required, required, required, follow_redirects, max_concurrent_requests (+24 more)

### Community 105 - "String"
Cohesion: 0.18
Nodes (17): PyAnalysisJob, PyAnalysisResult, PyAPIKey, PyFile, PyFileStatus, PyFunction, PyFunctionParameter, PyJobPriority (+9 more)

### Community 106 - "CookieAnalysisPlugin"
Cohesion: 0.12
Nodes (17): Cookie, CookieAnalysis, CookieAnalysisPlugin, CookieAnalysisResult, JsCookie, plugin_init(), Client, CommandRegistration (+9 more)

### Community 107 - "PeMetadataExtractor"
Cohesion: 0.13
Nodes (16): FileHashes, calculate_hashes(), calculate_entropy(), calculate_hashes(), PeMetadataExtractor, PeParser, Architecture, BinaryInfo (+8 more)

### Community 108 - "Finding"
Cohesion: 0.09
Nodes (21): Evidence, Finding, Reference, ReferenceType, RegulatoryImpact, RemediationGuidance, ReproductionSteps, CodeExample (+13 more)

### Community 109 - "ReconAgent"
Cohesion: 0.15
Nodes (16): DiscoveredUrl, ReconAgent, AgentId, Arc, AuthEndpoint, Client, DiscoveredEndpoint, Duration (+8 more)

### Community 110 - "App"
Cohesion: 0.09
Nodes (52): App, centered_rect(), count_severities(), FilterMode, handle_key_event(), handle_settings_enter(), handle_settings_keys(), render_banner() (+44 more)

### Community 111 - "AnalysisCache"
Cohesion: 0.14
Nodes (18): AnalysisCache, AnalysisKey, CachedEntry, CacheEntryMetadata, CacheStats, AiResult, Arc, CacheStats (+10 more)

### Community 112 - "Result"
Cohesion: 0.16
Nodes (14): BlockId, Arc<dyn ProjectStore>, BasicBlockInfo, InstructionInfo, BasicBlockInfo, FunctionId, FunctionInfo, InstructionInfo (+6 more)

### Community 113 - "BinaryUploadService"
Cohesion: 0.14
Nodes (16): ElfIdentifier, BinaryFormat, PeIdentifier, BinaryFormat, BinaryIdentifier, BinaryUploadService, calculate_hashes(), ObjectStore (+8 more)

### Community 114 - "Config"
Cohesion: 0.11
Nodes (10): Config, DatabaseConfig, RedisConfig, AuthConfig, Path, PluginConfig, Result, Self (+2 more)

### Community 115 - "HttpFingerprintPlugin"
Cohesion: 0.12
Nodes (16): HttpFingerprintPlugin, HttpFingerprintResult, plugin_init(), Client, CommandRegistration, Finding, HashMap, Option (+8 more)

### Community 116 - "ReconPluginConfig"
Cohesion: 0.11
Nodes (18): ReconPluginConfig, Self, oid_name(), ParsedCertificate, plugin_init(), Client, CommandRegistration, Finding (+10 more)

### Community 117 - "utils.rs"
Cohesion: 0.09
Nodes (32): debounce(), format_bytes(), format_duration_ms(), format_relative_time(), get_theme_colors(), job_status_color(), job_status_icon(), key_to_action() (+24 more)

### Community 118 - "openre-telemetry/src/metrics.rs"
Cohesion: 0.09
Nodes (14): MetricsConfig, init_metrics(), MetricsGuard, record_ai_request(), record_db_query(), record_http_request(), record_job_completed(), record_job_failed() (+6 more)

### Community 119 - "Disassembler"
Cohesion: 0.14
Nodes (21): Disassembler, DisassemblyConfig, Instruction, InstructionDetail, MemDetail, Operand, OperandAccess, OperandDetail (+13 more)

### Community 120 - "RootCauseAnalyzer"
Cohesion: 0.21
Nodes (16): create_test_finding(), RootCauseAnalyzer, RootCauseConfig, Category, Default, Finding, IntelligenceResult, Self (+8 more)

### Community 121 - "BuiltinPayloadEngine"
Cohesion: 0.21
Nodes (11): BuiltinPayloadEngine, Encoding, Payload, PayloadContext, DetectionMethod, HashMap, Option, ParameterLocation (+3 more)

### Community 122 - "burst_test_size"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, burst_test_size

### Community 123 - "exploit.rs"
Cohesion: 0.15
Nodes (24): CategoryArg, crate::intelligence_stubs::Language, crate::intelligence_stubs::VulnCategory, ExploitCommands, GenerateArgs, LanguageArg, ListTemplatesArgs, load_finding() (+16 more)

### Community 124 - "FindingFilter"
Cohesion: 0.13
Nodes (17): Category, CertificateInfo, Confidence, EvidenceType, FindingConfig, FindingFilter, FindingStats, RemediationPriority (+9 more)

### Community 125 - "PyOpenREClient"
Cohesion: 0.26
Nodes (12): PyOpenREClient, Arc, Bound, Mutex, Option, PyDict, PyObject, PyResult (+4 more)

### Community 126 - "RemoteProvider"
Cohesion: 0.13
Nodes (12): Bytes, parse_sse_chunk(), RemoteProvider, Client, HealthStatus, Option, Result, Self (+4 more)

### Community 127 - "PromptCompiler"
Cohesion: 0.18
Nodes (14): CompiledPrompt, FewShotExample, PromptCompiler, PromptTemplate, Default, FunctionId, HashMap, Option (+6 more)

### Community 128 - "OnnxProvider"
Cohesion: 0.14
Nodes (12): OnnxProvider, HealthStatus, Option, Path, Result, Self, String, Vec (+4 more)

### Community 129 - "ai_stubs.rs"
Cohesion: 0.17
Nodes (19): AiClient, AiError, AiProvider, AnalysisRequest, AnalysisResult, AnalysisType, Audience, ConnectionTestResult (+11 more)

### Community 130 - ".new"
Cohesion: 0.11
Nodes (17): FindingCommands, FindingCompareArgs, FindingEvidenceArgs, FindingExportArgs, FindingGetArgs, FindingRiskScoreArgs, FindingStatsArgs, FindingUpdateArgs (+9 more)

### Community 131 - "App"
Cohesion: 0.14
Nodes (17): App, Arc, Box, Duration, Instant, KeyEvent, Option, Result (+9 more)

### Community 132 - "properties"
Cohesion: 0.07
Nodes (26): default, description, type, default, description, maximum, minimum, type (+18 more)

### Community 133 - "properties"
Cohesion: 0.10
Nodes (20): default, description, type, default, description, maximum, minimum, type (+12 more)

### Community 134 - "String"
Cohesion: 0.24
Nodes (11): PyPluginManager, PyPluginSource, Bound, Option, PyDict, PyObject, PyResult, Python (+3 more)

### Community 135 - "predicate.rs"
Cohesion: 0.13
Nodes (18): A, N, main(), Data, Raw, StrTendril, Vec, And (+10 more)

### Community 136 - "SafetyGuard"
Cohesion: 0.13
Nodes (16): ClaimSource, HallucinationAlert, HallucinationType, AiResult, DateTime, Default, Option, Self (+8 more)

### Community 137 - "InjectionPluginConfig"
Cohesion: 0.14
Nodes (22): DetectionMethod, HeaderChange, HttpRequestSnapshot, InjectionEvidence, InjectionPluginConfig, ParameterLocation, ReproducibleRequest, ResponseDiff (+14 more)

### Community 138 - "ScanResponse"
Cohesion: 0.16
Nodes (27): CreateScanRequest, CreateTargetRequest, ErrorResponse, FindingQueryParams, FindingResponse, PluginResponse, AuthConfig, DateTime (+19 more)

### Community 140 - "MetadataExtractionService"
Cohesion: 0.24
Nodes (10): MetadataExtractionService, ObjectStore, Arc, FileId, Option, Result, Self, SymbolInfo (+2 more)

### Community 141 - "commands/config.rs"
Cohesion: 0.21
Nodes (22): ConfigCommands, ConfigRow, format_value(), GetArgs, InitArgs, print_full_config(), print_section(), ResetArgs (+14 more)

### Community 142 - "VerificationResult"
Cohesion: 0.30
Nodes (12): Box<dyn FindingVerifier>, CorsVerifier, Box, Client, Finding, FindingId, Future, Output (+4 more)

### Community 143 - "ReportingAgent"
Cohesion: 0.15
Nodes (11): ReportingAgent, AgentId, Default, Finding, HashMap, Input, Output, Result (+3 more)

### Community 144 - "verification.rs"
Cohesion: 0.12
Nodes (18): create_test_finding(), InfoDisclosureVerifier, Category, HashMap, Severity, String, TechnologyVerifier, test_auth_verifier_can_verify() (+10 more)

### Community 145 - "BaseInjectionPlugin"
Cohesion: 0.14
Nodes (17): BaseInjectionPlugin, HttpResponse, ParameterTestConfig, Arc, Box, Client, Finding, HashMap (+9 more)

### Community 146 - "ReconType"
Cohesion: 0.09
Nodes (15): internal_err(), parse_html(), ReconMetadata, ReconPlugin, ReconType, DateTime, Display, Formatter (+7 more)

### Community 147 - "MockModelProvider"
Cohesion: 0.11
Nodes (8): ProviderCapabilities, MockModelProvider, HealthStatus, Self, String, Vec, test_security_analyst_basic_functionality(), OpenreResult

### Community 148 - "cfg.rs"
Cohesion: 0.19
Nodes (17): BasicBlock, CfgBuilder, CfgEdge, CfgEdgeType, compute_dominators(), ControlFlowGraph, DominatorTree, find_loops() (+9 more)

### Community 149 - "Job"
Cohesion: 0.17
Nodes (15): Job, JobStatus, JobType, Priority, QueueManager, QueueStats, DateTime, Default (+7 more)

### Community 150 - "ScanManager"
Cohesion: 0.24
Nodes (10): Clone, DashMap, Err, Finding, PluginInfo, ScanConfig, ScanId, ScannerResult (+2 more)

### Community 151 - "Capability"
Cohesion: 0.09
Nodes (22): Capability, CapabilitySet, RiskLevel, HashSet, Item, Iterator, RiskLevel, Vec (+14 more)

### Community 152 - "ScanProfile"
Cohesion: 0.11
Nodes (16): Option, OutputFormat, ParseError, PathBuf, Result, String, Url, Vec (+8 more)

### Community 153 - "Error"
Cohesion: 0.08
Nodes (26): GroundedError, AnalysisError, IntelligenceError, Error, String, DisasmError, From, Self (+18 more)

### Community 154 - "LlamaCppProvider"
Cohesion: 0.17
Nodes (9): LlamaCppProvider, HealthStatus, Path, Result, Self, String, Vec, LlamaCppConfig (+1 more)

### Community 155 - "lifter.rs"
Cohesion: 0.23
Nodes (16): IrInstruction, IrMemory, IrOp, IrOperand, IrOperandType, IrSideEffect, Lifter, Architecture (+8 more)

### Community 156 - "RemediationVerifier"
Cohesion: 0.13
Nodes (14): RemediationVerifier, Arc, HashMap, RecheckId, RwLock, ScanStorage, Send, String (+6 more)

### Community 157 - "setup-dev.sh"
Cohesion: 0.32
Nodes (21): build_core_crates(), command_exists(), create_dev_configs(), detect_os(), install_cargo_tools(), install_docker(), install_node(), install_rust() (+13 more)

### Community 158 - "Value"
Cohesion: 0.30
Nodes (6): FileId, ProjectId, Self, Value, ToolContext, ToolResult

### Community 159 - "create_response_analyzer"
Cohesion: 0.12
Nodes (14): Box, Box, Box, Box, create_response_analyzer(), ResponseAnalyzer, Box, Send (+6 more)

### Community 160 - "storage.rs"
Cohesion: 0.17
Nodes (18): FindingRecord, PluginExecutionRecord, Arc, DateTime, Duration, PluginId, ScanConfig, ScanProgress (+10 more)

### Community 161 - "Document"
Cohesion: 0.12
Nodes (14): Document, Find, Find<'a, P>, Debug, Find, Formatter, From, Iterator (+6 more)

### Community 162 - "default"
Cohesion: 0.15
Nodes (21): default, mkfs, REBOOT, rm -rf, default, mkfs, REBOOT, rm -rf (+13 more)

### Community 163 - "CompletionRequest"
Cohesion: 0.11
Nodes (24): Choice, CompletionRequest, FinishReason, HealthStatus, Message, MessageRole, ModelProvider, ProviderRegistry (+16 more)

### Community 164 - "ConfidenceScorer"
Cohesion: 0.20
Nodes (10): ConfidenceBreakdown, ConfidenceConfig, ConfidenceScorer, create_confidence_scorer(), Default, DetectionMethod, HashMap, Self (+2 more)

### Community 165 - "LdapInjectionPlugin"
Cohesion: 0.16
Nodes (8): LdapInjectionPlugin, CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec

### Community 166 - "MockFindingProvider"
Cohesion: 0.19
Nodes (13): matches_filter(), MockFindingProvider, AiResult, Arc, Finding, FindingId, HashMap, Option (+5 more)

### Community 167 - "properties"
Cohesion: 0.10
Nodes (20): description, type, default, description, maximum, minimum, type, blocked_patterns (+12 more)

### Community 168 - "PyAnalysisManager"
Cohesion: 0.27
Nodes (10): PyAnalysisManager, Bound, Option, PyDict, PyObject, PyResult, Python, Self (+2 more)

### Community 169 - "PluginManager"
Cohesion: 0.13
Nodes (6): PluginManager, PluginSource, Plugin, Get all enabled plugins., Plugin installation source., High-level manager for plugin operations. Example: async with OpenREClient() as…

### Community 170 - "StageId"
Cohesion: 0.17
Nodes (6): FinalizationStage, IdentificationStage, HashMap, PipelineContext, StageResult, StageId

### Community 171 - "openre-cli/src/main.rs"
Cohesion: 0.14
Nodes (17): AiProviderArg, Cli, Commands, crate::ai_stubs::AiProvider, main(), print_version(), Commands, ConfigCommands (+9 more)

### Community 172 - ".run_scan_command"
Cohesion: 0.15
Nodes (10): ScanStatus, ScanCancelArgs, ScanCommands, ScanDeleteArgs, ScanListArgs, ScanLogsArgs, ScanPauseArgs, ScanProgressArgs (+2 more)

### Community 173 - "PromptCompiler"
Cohesion: 0.14
Nodes (15): AiAnalystError, FindingId, From, ScanId, Self, String, PromptCompiler, PromptTemplate (+7 more)

### Community 174 - "tracing.rs"
Cohesion: 0.12
Nodes (18): TracingConfig, init_telemetry(), Debug, Result, Span, TelemetryGuards, TelemetryHandle, ai_span() (+10 more)

### Community 175 - "properties"
Cohesion: 0.11
Nodes (18): default, description, type, default, description, maximum, minimum, type (+10 more)

### Community 176 - "AnalysisManager"
Cohesion: 0.15
Nodes (10): AnalysisManager, AnalysisProgress, AnalysisJob, AnalysisResult, Wait for analysis to complete, yielding progress updates. Yields:…, High-level manager for binary analysis operations. Example: async with…, Start analysis on a file., Get analysis job status. (+2 more)

### Community 177 - "Selection"
Cohesion: 0.21
Nodes (5): BitSet, Iter, P, Selection, Selection<'a>

### Community 178 - "AiTool"
Cohesion: 0.17
Nodes (7): AiTool, ExecuteScriptTool, GetSymbolsTool, Box, Default, HashMap, ToolRegistry

### Community 179 - ".new"
Cohesion: 0.15
Nodes (11): CancellationToken, Arc, Default, Mutex, PluginManager, QueueManager, Receiver, ScanStorage (+3 more)

### Community 180 - "ScheduledRecheck"
Cohesion: 0.20
Nodes (18): EnhancedScanDiff, EvidenceComparison, RemediationResult, RemediationStatus, RemediationStatusType, DateTime, FindingEvidence, FindingId (+10 more)

### Community 181 - "src/traits.rs"
Cohesion: 0.09
Nodes (31): AiService, AnalysisService, Annotation, AnnotationSource, AnnotationType, ControlFlowOutput, CreateProjectRequest, DataFlowOutput (+23 more)

### Community 182 - "HeaderInjectionPlugin"
Cohesion: 0.15
Nodes (9): HeaderInjectionPlugin, CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec (+1 more)

### Community 183 - "openre-scan/src/main.rs"
Cohesion: 0.20
Nodes (16): apply_cli_overrides(), Cli, Commands, main(), parse_header(), print_banner(), print_compact_banner(), print_smart_banner() (+8 more)

### Community 184 - "openre-tui/src/lib.rs"
Cohesion: 0.15
Nodes (12): App, ActionDispatcher, ActionHandler, Clone, Result, Self, Send, SendError (+4 more)

### Community 185 - "stubs.rs"
Cohesion: 0.12
Nodes (16): AnalysisStatistics, AnnotationInfo, BasicBlockInfo, CallEdgeInfo, CfgEdgeInfo, ConstantInfo, FunctionId, FunctionInfo (+8 more)

### Community 186 - "output_results"
Cohesion: 0.28
Nodes (15): CustomScanArgs, output_results(), print_scan_summary(), Option, PathBuf, Result, ScanResult, String (+7 more)

### Community 187 - "AnalysisJob"
Cohesion: 0.18
Nodes (23): FileFormat, AnalysisJob, AnalysisResult, CollaboratorInvite, FileRecord, IdentificationOutput, Project, AnalysisConfig (+15 more)

### Community 188 - "ApiAnalysisAgent"
Cohesion: 0.15
Nodes (8): ApiAnalysisAgent, AgentId, Default, Input, Output, Result, Self, Vec

### Community 189 - "CorrelationAgent"
Cohesion: 0.16
Nodes (9): CorrelationAgent, AgentId, Arc, CorrelationEngine, Input, Output, Result, Self (+1 more)

### Community 190 - "WebAnalysisAgent"
Cohesion: 0.15
Nodes (8): AgentId, Default, Input, Output, Result, Self, Vec, WebAnalysisAgent

### Community 191 - "CommandInjectionPlugin"
Cohesion: 0.16
Nodes (8): CommandInjectionPlugin, CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec

### Community 192 - "NoSqlInjectionPlugin"
Cohesion: 0.16
Nodes (8): NoSqlInjectionPlugin, CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec

### Community 193 - "SqlInjectionPlugin"
Cohesion: 0.16
Nodes (8): CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec, SqlInjectionPlugin

### Community 194 - "SstiPlugin"
Cohesion: 0.16
Nodes (8): CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec, SstiPlugin

### Community 195 - "XPathInjectionPlugin"
Cohesion: 0.16
Nodes (8): CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec, XPathInjectionPlugin

### Community 196 - "XssPlugin"
Cohesion: 0.16
Nodes (8): CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec, XssPlugin

### Community 197 - "XxePlugin"
Cohesion: 0.16
Nodes (8): CapabilityRequest, CapabilityResponse, Plugin, Result, Self, String, Vec, XxePlugin

### Community 198 - "sdk.rs"
Cohesion: 0.18
Nodes (16): CommandContext, CommandRegistration, CommandResult, Plugin, PluginInitInfo, PluginMetadata, CommandContext, CommandResult (+8 more)

### Community 199 - "openre-scan/src/output.rs"
Cohesion: 0.31
Nodes (16): display_results(), FindingRow, format_severity(), OutputFormat, print_json_results(), print_sarif_results(), print_severity_summary(), print_table_results() (+8 more)

### Community 200 - "default"
Cohesion: 0.19
Nodes (17): default, description, items, type, enum, type, enabled_checks, cache_control (+9 more)

### Community 201 - "allowed_scopes"
Cohesion: 0.18
Nodes (11): default, description, items, type, items, description, items, type (+3 more)

### Community 202 - "CliConfig"
Cohesion: 0.17
Nodes (9): CoreConfig, CliConfig, Option, Path, PathBuf, Result, Self, Deref (+1 more)

### Community 203 - "incremental.rs"
Cohesion: 0.22
Nodes (10): AnalysisChanges, AnalysisResult, IncrementalAnalyzer, AnalysisResult, Arc, PipelineContext, ProjectId, Result (+2 more)

### Community 204 - "RemediationAgent"
Cohesion: 0.16
Nodes (8): RemediationAgent, AgentId, Default, Input, Output, Result, Self, Vec

### Community 205 - "VerificationAgent"
Cohesion: 0.16
Nodes (8): AgentId, Arc, Input, Output, Result, Self, Vec, VerificationAgent

### Community 206 - "ScanStorageFindingProvider"
Cohesion: 0.21
Nodes (11): AiResult, Arc, Finding, FindingId, Option, ScanId, ScanMetadata, ScanStorage (+3 more)

### Community 207 - "openre-core"
Cohesion: 0.38
Nodes (16): openre-ai, openre-analysis, openre_bindings, openre-cli, openre-config, openre-core, openre-disasm, openre-intelligence (+8 more)

### Community 208 - "openre-ai/src/lib.rs"
Cohesion: 0.28
Nodes (7): AiClient, AiProvider, Option, Result, Self, String, Router

### Community 209 - "PipelineMetrics"
Cohesion: 0.22
Nodes (10): PipelineMetrics, PipelineSummary, Arc, Default, Duration, HashMap, RwLock, Self (+2 more)

### Community 210 - "TargetType"
Cohesion: 0.20
Nodes (5): Display, Formatter, FromStr, Result, TargetType

### Community 211 - "properties"
Cohesion: 0.13
Nodes (14): default, description, type, properties, follow_redirects, safety, user_agent, type (+6 more)

### Community 212 - "._extract_evidence_ids"
Cohesion: 0.15
Nodes (10): LlmCorrelation, LlmRemediation, Validate that correlation claims are grounded in evidence references., Validate that remediation claims are grounded in evidence references., Extract evidence IDs from text in [Evidence: <id>] format., LLM Remediation grounded in evidence + technology context., Correlate findings to identify relationships., Correlate findings based on shared evidence. Args: finding_ids: List of finding… (+2 more)

### Community 213 - "AnalysisJob"
Cohesion: 0.18
Nodes (14): AnalysisConfig, AnalysisJob, AnalysisConfig, DateTime, FileId, JobId, Option, StageStatus (+6 more)

### Community 214 - "print_output"
Cohesion: 0.40
Nodes (12): OutputFormat, print_output(), Default, Option, Path, Result, Self, T (+4 more)

### Community 215 - ".reload_config"
Cohesion: 0.22
Nodes (9): ConfigWatcher, Arc, Option, PathBuf, Result, RwLock, Self, Sender (+1 more)

### Community 216 - "PluginType"
Cohesion: 0.14
Nodes (10): PluginType, Display, Err, Formatter, FromStr, Result, Self, T (+2 more)

### Community 217 - "ResearchAgent"
Cohesion: 0.21
Nodes (8): ResearchAgent, AgentId, Arc, Input, KnowledgeBase, Output, Result, Self

### Community 218 - "AiResult"
Cohesion: 0.42
Nodes (10): AiResult, Box, FindingId, Item, Pin, RemediationPlan, ScanId, Send (+2 more)

### Community 219 - "allowed_scopes"
Cohesion: 0.14
Nodes (14): default, description, items, type, description, items, type, description (+6 more)

### Community 220 - "tools.rs"
Cohesion: 0.26
Nodes (12): FunctionInfo, GlobalStore, ObjectStore, ProjectStore, Arc, Send, String, Sync (+4 more)

### Community 221 - ".new"
Cohesion: 0.21
Nodes (10): HistoryStorage, RiskTrends, Box, Default, Self, Send, Sync, TrendDirection (+2 more)

### Community 222 - "benchmarks.rs"
Cohesion: 0.24
Nodes (9): benchmark_complete_intelligence_pipeline(), benchmark_correlation_engine(), benchmark_cve_intelligence(), benchmark_knowledge_base_enrichment(), benchmark_performance_optimizer(), create_benchmark_finding(), create_benchmark_findings(), Finding (+1 more)

### Community 223 - "SecurityAnalystImpl"
Cohesion: 0.14
Nodes (15): Arc, ExecutiveSummary, ModelInfo, Option, PromptCompiler, ScanComparison, Self, Sync (+7 more)

### Community 224 - "properties"
Cohesion: 0.15
Nodes (13): default, description, type, default, description, type, default, description (+5 more)

### Community 225 - "properties"
Cohesion: 0.15
Nodes (12): default, description, type, properties, follow_redirects, user_agent, $schema, title (+4 more)

### Community 226 - "properties"
Cohesion: 0.15
Nodes (13): rate_limit_rps, require_authorization, safety, default, description, maximum, minimum, type (+5 more)

### Community 227 - "required"
Cohesion: 0.46
Nodes (13): required, required, required, allowed_scopes, blocked_patterns, max_concurrency, max_payloads_per_param, max_requests_per_test (+5 more)

### Community 228 - "properties"
Cohesion: 0.15
Nodes (12): default, description, type, properties, follow_redirects, user_agent, $schema, title (+4 more)

### Community 229 - "allowed_scopes"
Cohesion: 0.18
Nodes (11): default, description, items, type, items, description, items, type (+3 more)

### Community 230 - "JobType"
Cohesion: 0.12
Nodes (12): AnalysisConfig, CollaboratorRole, JobType, Default, Display, Err, Formatter, FromStr (+4 more)

### Community 231 - "default"
Cohesion: 0.30
Nodes (12): default, enum, backup_files, comments, debug_pages, directory_listing, framework_versions, sensitive_data (+4 more)

### Community 232 - "default"
Cohesion: 0.24
Nodes (12): default, description, items, type, enum, type, enabled_checks, api_endpoints (+4 more)

### Community 233 - "AudienceArg"
Cohesion: 0.27
Nodes (8): AudienceArg, crate::ai_stubs::Audience, crate::ai_stubs::ExplainDetail, crate::ai_stubs::FixType, ExplainDetailArg, FixTypeArg, From, Self

### Community 234 - ".with_templates"
Cohesion: 0.25
Nodes (6): MockAiService, PromptTemplates, AiService, Arc, Default, Self

### Community 235 - "properties"
Cohesion: 0.18
Nodes (10): default, description, type, properties, follow_redirects, settings, $schema, type (+2 more)

### Community 236 - "properties"
Cohesion: 0.18
Nodes (10): default, description, type, properties, follow_redirects, settings, $schema, type (+2 more)

### Community 237 - "properties"
Cohesion: 0.18
Nodes (11): default, description, type, aggressive_mode, settings, verify_ssl, properties, type (+3 more)

### Community 238 - "properties"
Cohesion: 0.18
Nodes (11): default, description, type, default, description, type, check_api_docs, check_debug_endpoints (+3 more)

### Community 239 - "sustained_requests"
Cohesion: 0.15
Nodes (13): settings, sustained_requests, verify_ssl, properties, type, default, description, maximum (+5 more)

### Community 240 - "properties"
Cohesion: 0.18
Nodes (11): default, description, type, default, description, type, aggressive_mode, check_csp (+3 more)

### Community 241 - "properties"
Cohesion: 0.18
Nodes (11): settings, test_session_rotation, verify_ssl, properties, type, default, description, type (+3 more)

### Community 242 - "allowed_scopes"
Cohesion: 0.18
Nodes (11): default, description, items, type, items, description, items, type (+3 more)

### Community 243 - "RemediationVerifierConfig"
Cohesion: 0.20
Nodes (8): RecheckFrequency, RemediationExportFormat, RemediationVerifierConfig, Default, Err, FromStr, Result, Self

### Community 244 - "default"
Cohesion: 0.36
Nodes (10): default, enum, cookie_prefixes, domain_scope, expiration, httponly_flag, path_scope, samesite (+2 more)

### Community 245 - "default"
Cohesion: 0.20
Nodes (10): test_methods, default, description, items, type, CONNECT, DELETE, PATCH (+2 more)

### Community 246 - "properties"
Cohesion: 0.20
Nodes (10): description, items, type, default, description, type, type, properties (+2 more)

### Community 247 - "default"
Cohesion: 0.27
Nodes (12): default, enum, auth_bypass, basic, blind, default, enum, basic (+4 more)

### Community 248 - "PipelineContext"
Cohesion: 0.22
Nodes (7): CancellationToken, PipelineContext, HashMap, IsolatedBinary, PluginRegistry, RwLock, WorkerId

### Community 249 - "ProjectStore"
Cohesion: 0.25
Nodes (6): ProjectStore, QueueManager, AnalysisJob, IdentificationOutput, ProjectId, Result

### Community 250 - "src/integration_tests.rs"
Cohesion: 0.25
Nodes (5): create_test_finding(), Category, Finding, Severity, test_component_interoperability()

### Community 251 - "aggressive_mode"
Cohesion: 0.22
Nodes (9): default, description, type, aggressive_mode, verify_ssl, properties, default, description (+1 more)

### Community 252 - "default"
Cohesion: 0.39
Nodes (9): default, enum, login_forms, mfa, oauth, oidc, password_reset, registration (+1 more)

### Community 253 - "properties"
Cohesion: 0.22
Nodes (8): default, description, type, properties, follow_redirects, $schema, title, type

### Community 254 - "properties"
Cohesion: 0.22
Nodes (8): properties, user_agent, $schema, title, type, default, description, type

### Community 255 - "ExecutiveSummary"
Cohesion: 0.25
Nodes (6): main(), ExecutiveSummary, Validate that executive summary claims are grounded in evidence references., Executive summary for different audiences., Generate executive summary for different audiences., Generate executive summary with evidence grounding. Args: scan_id: The ID of…

### Community 257 - "Arc"
Cohesion: 0.50
Nodes (3): ObjectStore, Arc, Self

### Community 258 - "static_analysis_test.rs"
Cohesion: 0.36
Nodes (4): create_test_metadata(), test_static_analysis_control_flow(), test_static_analysis_data_flow(), test_static_analyzer_find_functions()

### Community 259 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 260 - "main"
Cohesion: 0.25
Nodes (7): Cli, Commands, main(), Box, Commands, Result, String

### Community 261 - "default"
Cohesion: 0.43
Nodes (8): default, enum, allow_headers, credentials, origin_reflection, preflight, unsafe_methods, wildcard_origin

### Community 262 - "default"
Cohesion: 0.43
Nodes (8): default, enum, cache_poisoning, crlf, host_header, referer, response_splitting, xff

### Community 263 - "default"
Cohesion: 0.43
Nodes (8): default, enum, cookie_security, session_cookies, session_expiration, session_fixation, session_invalidation, session_rotation

### Community 264 - "properties"
Cohesion: 0.25
Nodes (8): description, type, blocked_patterns, require_authorization, default, description, type, properties

### Community 265 - "LlmRemediation"
Cohesion: 0.29
Nodes (7): LlmRemediation, RemediationEffort, RemediationPriority, GroundedCodeExample, GroundedRemediationStep, GroundedVerificationStep, TechnologyGuidance

### Community 266 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 267 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 268 - "comprehensive_test.rs"
Cohesion: 0.29
Nodes (4): create_test_finding(), Category, Finding, Option

### Community 269 - "logging.rs"
Cohesion: 0.43
Nodes (6): create_log_file(), init_logging(), Option, PathBuf, Result, test_logging_init()

### Community 270 - "test_origins"
Cohesion: 0.29
Nodes (7): test_origins, default, description, type, https://evil.com, https://sub.evil.com, null

### Community 271 - ".explain_finding"
Cohesion: 0.33
Nodes (5): LlmExplanation, Validate that explanation claims are grounded in evidence references., LLM Explanation grounded in evidence., Explain a security finding., Explain a security finding with evidence grounding. Args: finding_id: The ID of…

### Community 272 - ".compare_scans"
Cohesion: 0.33
Nodes (5): Compare two scans for changes with evidence grounding. Args: baseline_id: The…, Validate that scan comparison claims are grounded in evidence references., Scan comparison result., Compare two scans for changes., ScanComparison

### Community 273 - "max_payloads_per_param"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_payloads_per_param

### Community 274 - "openre-plugins-macros/src/lib.rs"
Cohesion: 0.60
Nodes (5): derive_plugin_manifest(), plugin_capability(), plugin_command(), plugin_init(), TokenStream

### Community 275 - "Iter<'sel, 'doc>"
Cohesion: 0.33
Nodes (5): Iter<'sel, 'doc>, Debug, Formatter, Iterator, Result

### Community 276 - "auth_endpoint_test_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, auth_endpoint_test_requests

### Community 277 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 278 - "max_test_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_test_requests

### Community 279 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 280 - "sustained_requests_per_second"
Cohesion: 0.33
Nodes (6): sustained_requests_per_second, default, description, maximum, minimum, type

### Community 281 - "sustained_test_duration_seconds"
Cohesion: 0.33
Nodes (6): sustained_test_duration_seconds, default, description, maximum, minimum, type

### Community 282 - "test_requests_per_endpoint"
Cohesion: 0.33
Nodes (6): test_requests_per_endpoint, default, description, maximum, minimum, type

### Community 283 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 284 - "max_depth"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_depth

### Community 285 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 286 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 287 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 288 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 289 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 290 - "enabled_checks"
Cohesion: 0.33
Nodes (6): description, items, type, type, enabled_checks, items

### Community 291 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 292 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 293 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 294 - "max_concurrency"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrency

### Community 295 - "max_payloads_per_param"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_payloads_per_param

### Community 296 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 297 - "max_requests_per_test"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_requests_per_test

### Community 298 - "max_total_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_total_requests

### Community 299 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 300 - "request_timeout_secs"
Cohesion: 0.33
Nodes (6): request_timeout_secs, default, description, maximum, minimum, type

### Community 301 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 302 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 303 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 304 - "max_concurrency"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrency

### Community 305 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 306 - "max_total_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_total_requests

### Community 307 - "rate_limit_rps"
Cohesion: 0.33
Nodes (6): rate_limit_rps, default, description, maximum, minimum, type

### Community 308 - "burst_size"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, burst_size

### Community 309 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 310 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 311 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 312 - "sustained_delay_ms"
Cohesion: 0.33
Nodes (6): sustained_delay_ms, default, description, maximum, minimum, type

### Community 313 - "max_requests_per_test"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_requests_per_test

### Community 314 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 315 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 316 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 317 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 318 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 319 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 320 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 321 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 322 - "max_total_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_total_requests

### Community 323 - "properties"
Cohesion: 0.40
Nodes (5): default, description, type, properties, follow_redirects

### Community 324 - "request_timeout_secs"
Cohesion: 0.33
Nodes (6): request_timeout_secs, default, description, maximum, minimum, type

### Community 325 - "default"
Cohesion: 0.53
Nodes (6): default, enum, basic, blind, parameter_entity, ssrf

### Community 326 - "max_concurrency"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrency

### Community 327 - "max_concurrent_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_concurrent_requests

### Community 328 - "max_payloads_per_param"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_payloads_per_param

### Community 329 - "max_redirects"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_redirects

### Community 330 - "max_requests_per_test"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_requests_per_test

### Community 331 - "max_total_requests"
Cohesion: 0.33
Nodes (6): default, description, maximum, minimum, type, max_total_requests

### Community 332 - "rate_limit_rps"
Cohesion: 0.33
Nodes (6): rate_limit_rps, default, description, maximum, minimum, type

### Community 333 - "request_timeout"
Cohesion: 0.33
Nodes (6): request_timeout, default, description, maximum, minimum, type

### Community 334 - "request_timeout_secs"
Cohesion: 0.33
Nodes (6): request_timeout_secs, default, description, maximum, minimum, type

### Community 335 - "AiService"
Cohesion: 0.50
Nodes (5): AiService, NoopAiService, PipelineStage, Send, Sync

### Community 337 - "FindingChanges"
Cohesion: 0.50
Nodes (5): FindingChanges, PersistentFinding, EvidenceChange, Finding, SeverityChange

### Community 338 - "api_rate_limiting/config_schema.json"
Cohesion: 0.50
Nodes (3): $schema, title, type

### Community 339 - "user_agent"
Cohesion: 0.50
Nodes (4): user_agent, default, description, type

### Community 340 - "Descendants"
Cohesion: 0.40
Nodes (3): Descendants, Find, P

### Community 341 - "enabled_checks"
Cohesion: 0.40
Nodes (5): description, items, type, type, enabled_checks

### Community 342 - "enabled_checks"
Cohesion: 0.40
Nodes (5): description, items, type, type, enabled_checks

### Community 343 - "enabled_checks"
Cohesion: 0.40
Nodes (5): description, items, type, type, enabled_checks

### Community 344 - "openre_bindings"
Cohesion: 0.40
Nodes (4): PyModule, openre_bindings(), Bound, PyResult

### Community 355 - "binary/metrics.rs"
Cohesion: 0.83
Nodes (3): record_http_request(), record_stage_completed(), Duration

### Community 357 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 358 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 359 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 360 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 361 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 362 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 363 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 364 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 365 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 366 - "builtin_security_plugins"
Cohesion: 0.67
Nodes (3): builtin_security_plugins(), PluginManifest, Vec

### Community 367 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 368 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 369 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 370 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 371 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 372 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 373 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 374 - "manifest"
Cohesion: 0.67
Nodes (3): manifest(), PluginManifest, test_manifest()

### Community 376 - "&'sel Selection<'doc>"
Cohesion: 0.50
Nodes (3): IntoIter, IntoIterator, &'sel Selection<'doc>

### Community 377 - "user_agent"
Cohesion: 0.50
Nodes (4): user_agent, default, description, type

### Community 378 - "user_agent"
Cohesion: 0.50
Nodes (4): user_agent, default, description, type

### Community 379 - "verify_ssl"
Cohesion: 0.50
Nodes (4): verify_ssl, default, description, type

### Community 380 - "information_disclosure/config_schema.json"
Cohesion: 0.50
Nodes (3): $schema, title, type

### Community 381 - "aggressive_mode"
Cohesion: 0.50
Nodes (4): default, description, type, aggressive_mode

### Community 382 - "check_sensitive_files"
Cohesion: 0.50
Nodes (4): default, description, type, check_sensitive_files

### Community 383 - "user_agent"
Cohesion: 0.50
Nodes (4): user_agent, default, description, type

### Community 384 - "verify_ssl"
Cohesion: 0.50
Nodes (4): verify_ssl, default, description, type

### Community 385 - "user_agent"
Cohesion: 0.50
Nodes (4): user_agent, default, description, type

### Community 386 - "check_cache_control"
Cohesion: 0.50
Nodes (4): default, description, type, check_cache_control

### Community 387 - "check_cross_origin"
Cohesion: 0.50
Nodes (4): default, description, type, check_cross_origin

### Community 388 - "check_hsts"
Cohesion: 0.50
Nodes (4): default, description, type, check_hsts

### Community 389 - "check_permissions"
Cohesion: 0.50
Nodes (4): default, description, type, check_permissions

### Community 390 - "check_referrer"
Cohesion: 0.50
Nodes (4): default, description, type, check_referrer

### Community 391 - "check_xcto"
Cohesion: 0.50
Nodes (4): default, description, type, check_xcto

### Community 392 - "check_xfo"
Cohesion: 0.50
Nodes (4): default, description, type, check_xfo

### Community 393 - "verify_ssl"
Cohesion: 0.50
Nodes (4): verify_ssl, default, description, type

### Community 394 - "aggressive_mode"
Cohesion: 0.50
Nodes (4): default, description, type, aggressive_mode

### Community 395 - "follow_redirects"
Cohesion: 0.50
Nodes (4): default, description, type, follow_redirects

### Community 396 - "test_session_fixation"
Cohesion: 0.50
Nodes (4): test_session_fixation, default, description, type

### Community 397 - "verify_ssl"
Cohesion: 0.50
Nodes (4): verify_ssl, default, description, type

### Community 398 - "aggressive_mode"
Cohesion: 0.50
Nodes (4): default, description, type, aggressive_mode

## Knowledge Gaps
- **914 isolated node(s):** `AssetCriticality`, `DataClassification`, `auth_endpoint_test_requests`, `burst_test_size`, `max_test_requests` (+909 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **23 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Error` connect `Error` to `main`, `CliError`, `InjectionCategory`, `analysis_stubs.rs`, `PromptCompiler`, `history.rs`, `ReconType`, `Node<'a>`, `grounded.rs`, `intelligence_stubs.rs`, `ids.rs`, `RemoteProvider`?**
  _High betweenness centrality (0.050) - this node is a cross-community bridge._
- **Why does `Config` connect `Config` to `NoSqlInjectionPlugin`, `CommandInjectionPlugin`, `SqlInjectionPlugin`, `SstiPlugin`, `XPathInjectionPlugin`, `AiService`, `LdapInjectionPlugin`, `XssPlugin`, `XxePlugin`, `GraphqlPlugin`, `commands/config.rs`, `tracing.rs`, `RestApiPlugin`, `openre-config/src/config.rs`, `HeaderInjectionPlugin`, `.reload_config`, `Services`, `Context`?**
  _High betweenness centrality (0.045) - this node is a cross-community bridge._
- **Why does `Target` connect `Target` to `storage.rs`, `ScanContext`, `CliConfig`, `ScanResponse`, `api.rs`, `ScanSession`, `TuiApp`, `TargetType`, `ScanManager`, `ScannerResult`, `tui.rs`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **Are the 2 inferred relationships involving `OpenREClient` (e.g. with `AnalysisManager` and `PluginManager`) actually correct?**
  _`OpenREClient` has 2 INFERRED edges - model-reasoned connections that need verification._
- **What connects `AssetCriticality`, `DataClassification`, `auth_endpoint_test_requests` to the rest of the system?**
  _914 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `FindingRelationship` be split into smaller, more focused modules?**
  _Cohesion score 0.05455063381284717 - nodes in this community are weakly interconnected._
- **Should `state.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.037571805620245306 - nodes in this community are weakly interconnected._