//! Unit tests for open-re crates

#[cfg(test)]
mod core_tests {
    use openre_core::ids::*;
    use openre_core::error::*;
    use openre_core::traits::*;

    #[test]
    fn test_id_generation() {
        let user_id = UserId::new();
        let project_id = ProjectId::new();
        let file_id = FileId::new();
        let job_id = JobId::new();
        let function_id = FunctionId::new();
        
        assert_ne!(user_id.to_string(), "");
        assert_ne!(project_id.to_string(), "");
        assert_ne!(file_id.to_string(), "");
        assert_ne!(job_id.to_string(), "");
        assert_ne!(function_id.to_string(), "");
    }

    #[test]
    fn test_id_parsing() {
        let user_id = UserId::new();
        let parsed = user_id.to_string().parse::<UserId>().unwrap();
        assert_eq!(user_id, parsed);
    }

    #[test]
    fn test_error_types() {
        let err = Error::NotFound("test".to_string());
        assert_eq!(err.to_string(), "Not found: test");
        
        let err = Error::InvalidInput("bad input".to_string());
        assert_eq!(err.to_string(), "Invalid input: bad input");
        
        let err = Error::PermissionDenied("access denied".to_string());
        assert_eq!(err.to_string(), "Permission denied: access denied");
    }

    #[test]
    fn test_job_type_serialization() {
        let job_type = JobType::FileAnalysis;
        let json = serde_json::to_string(&job_type).unwrap();
        assert_eq!(json, "\"file_analysis\"");
        
        let parsed: JobType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, JobType::FileAnalysis);
    }
}

#[cfg(test)]
mod config_tests {
    use openre_config::*;
    use std::collections::HashMap;

    #[test]
    fn test_config_defaults() {
        let config = Config::default();
        assert_eq!(config.server.host, "0.0.0.0");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.database.max_connections, 10);
        assert_eq!(config.redis.max_connections, 10);
    }

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .server_host("127.0.0.1")
            .server_port(9090)
            .database_url("postgresql://user:pass@localhost/db")
            .redis_url("redis://localhost:6379")
            .build()
            .unwrap();
        
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9090);
    }

    #[test]
    fn test_config_layers() {
        let mut env_vars = HashMap::new();
        env_vars.insert("OPENRE_SERVER_PORT".to_string(), "9090".to_string());
        
        let config = Config::from_layers(
            Config::default(),
            env_vars,
        ).unwrap();
        
        assert_eq!(config.server.port, 9090);
    }
}

#[cfg(test)]
mod telemetry_tests {
    use openre_telemetry::*;
    use std::time::Duration;

    #[test]
    fn test_logging_init() {
        let config = LoggingConfig::default();
        let _guard = init_logging(&config).unwrap();
    }

    #[test]
    fn test_metrics_registry() {
        let registry = MetricsRegistry::new();
        let counter = registry.counter("test_counter", "Test counter");
        counter.inc();
        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_histogram() {
        let registry = MetricsRegistry::new();
        let histogram = registry.histogram("test_histogram", "Test histogram");
        histogram.observe(1.0);
        histogram.observe(2.0);
        histogram.observe(3.0);
        
        let stats = histogram.get_stats();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.sum, 6.0);
    }

    #[test]
    fn test_audit_logger() {
        let logger = AuditLogger::new("test".to_string());
        logger.log(AuditEvent {
            event_type: "test_event".to_string(),
            user_id: Some("user123".to_string()),
            resource: "test_resource".to_string(),
            action: "test_action".to_string(),
            details: serde_json::json!({"key": "value"}),
            result: AuditResult::Success,
        }).unwrap();
    }
}

#[cfg(test)]
mod storage_tests {
    use openre_storage::*;
    use openre_core::ids::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_sqlite_store_creation() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        
        let store = ProjectStore::new(&db_path.to_string_lossy()).await.unwrap();
        
        // Test basic operations
        let function_id = store.create_function(Function {
            id: FunctionId::new(),
            file_id: FileId::new(),
            name: "test_func".to_string(),
            address: 0x1000,
            size: 100,
            is_entry: false,
            is_thunk: false,
            calling_convention: None,
            return_type: None,
            parameters: vec![],
            stack_frame_size: None,
            cyclomatic_complexity: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }).await.unwrap();
        
        let func = store.get_function(function_id).await.unwrap().unwrap();
        assert_eq!(func.name, "test_func");
    }

    #[tokio::test]
    async fn test_migration_manager() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        
        let manager = MigrationManager::new(&db_path.to_string_lossy()).await.unwrap();
        manager.run_migrations().await.unwrap();
        
        // Verify tables exist
        let conn = sqlx::SqliteConnection::connect(&db_path.to_string_lossy()).await.unwrap();
        let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table'")
            .fetch_all(&mut conn.clone())
            .await
            .unwrap();
        
        assert!(tables.contains(&"functions".to_string()));
        assert!(tables.contains(&"basic_blocks".to_string()));
        assert!(tables.contains(&"instructions".to_string()));
    }
}

#[cfg(test)]
mod plugin_tests {
    use openre_plugins::*;
    use openre_core::traits::*;
    use std::collections::HashMap;

    #[test]
    fn test_capability_validation() {
        let caps = CapabilitySet::new();
        assert!(caps.has(Capability::ReadFile));
        assert!(!caps.has(Capability::NetworkAccess));
        
        let mut caps = CapabilitySet::new();
        caps.add(Capability::NetworkAccess);
        assert!(caps.has(Capability::NetworkAccess));
    }

    #[test]
    fn test_manifest_parsing() {
        let toml = r#"
            name = "test-plugin"
            version = "1.0.0"
            description = "Test plugin"
            author = "Test Author"
            plugin_type = "analyzer"
            capabilities = ["read_file", "write_annotation"]
        "#;
        
        let manifest: PluginManifest = toml::from_str(toml).unwrap();
        assert_eq!(manifest.name, "test-plugin");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.capabilities.len(), 2);
    }

    #[test]
    fn test_plugin_registry() {
        let mut registry = PluginRegistry::new();
        
        let plugin = PluginInfo {
            id: PluginId::new(),
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test".to_string(),
            author: "Test".to_string(),
            plugin_type: "analyzer".to_string(),
            capabilities: vec!["read_file".to_string()],
            enabled: true,
            config: None,
            installed_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        
        registry.register(plugin.clone()).unwrap();
        let found = registry.get(plugin.id).unwrap();
        assert_eq!(found.name, "test");
    }
}

#[cfg(test)]
mod analysis_tests {
    use openre_analysis::*;
    use openre_core::ids::*;
    use openre_core::traits::*;

    #[test]
    fn test_stage_dag() {
        let mut dag = StageDag::new();
        
        dag.add_stage(StageName::Identification, vec![]);
        dag.add_stage(StageName::Loading, vec![StageName::Identification]);
        dag.add_stage(StageName::Disassembly, vec![StageName::Loading]);
        
        let order = dag.topological_order().unwrap();
        assert_eq!(order.len(), 3);
        assert_eq!(order[0], StageName::Identification);
        assert_eq!(order[1], StageName::Loading);
        assert_eq!(order[2], StageName::Disassembly);
    }

    #[test]
    fn test_stage_dag_cycle_detection() {
        let mut dag = StageDag::new();
        
        dag.add_stage(StageName::Identification, vec![StageName::Disassembly]);
        dag.add_stage(StageName::Loading, vec![StageName::Identification]);
        dag.add_stage(StageName::Disassembly, vec![StageName::Loading]);
        
        assert!(dag.topological_order().is_err());
    }

    #[test]
    fn test_incremental_analyzer() {
        let analyzer = IncrementalAnalyzer::new();
        
        let changes = AnalysisChanges {
            added_functions: vec![FunctionId::new()],
            modified_functions: vec![],
            removed_functions: vec![],
            added_blocks: vec![],
            modified_blocks: vec![],
            removed_blocks: vec![],
        };
        
        let affected = analyzer.compute_affected_stages(&changes);
        assert!(affected.contains(&StageName::Disassembly));
        assert!(affected.contains(&StageName::ControlFlow));
    }
}

#[cfg(test)]
mod ai_tests {
    use openre_ai::*;
    use std::collections::HashMap;

    #[test]
    fn test_prompt_compiler() {
        let compiler = PromptCompiler::new();
        
        let mut vars = HashMap::new();
        vars.insert("function_name".to_string(), "main".to_string());
        vars.insert("architecture".to_string(), "x86_64".to_string());
        vars.insert("disassembly".to_string(), "push rbp\nmov rbp, rsp".to_string());
        vars.insert("pseudocode".to_string(), "int main() {}".to_string());
        vars.insert("cfg_info".to_string(), "Simple CFG".to_string());
        vars.insert("xrefs".to_string(), "None".to_string());
        vars.insert("strings".to_string(), "None".to_string());
        
        let compiled = compiler.compile("analyze_function", vars).unwrap();
        assert!(compiled.system_prompt.contains("reverse engineer"));
        assert!(compiled.user_prompt.contains("main"));
    }

    #[test]
    fn test_tool_registry() {
        let registry = ToolRegistry::new();
        let tools = registry.all();
        assert!(!tools.is_empty());
        
        let read_binary = registry.get("read_binary").unwrap();
        assert_eq!(read_binary.name(), "read_binary");
    }

    #[test]
    fn test_cache_key_generation() {
        let config = CacheConfig::default();
        let cache = AiCache::new(config).unwrap();
        
        let request = CompletionRequest {
            messages: vec![Message::user("test".to_string())],
            temperature: Some(0.7),
            max_tokens: Some(100),
            ..Default::default()
        };
        
        let key1 = cache.generate_key(&request);
        let key2 = cache.generate_key(&request);
        assert_eq!(key1, key2);
    }
}

#[cfg(test)]
mod queue_tests {
    use openre_queue::*;
    use openre_core::ids::*;
    use openre_core::traits::*;

    #[test]
    fn test_job_creation() {
        let job = Job::new(JobType::FileAnalysis)
            .with_priority(Priority::High)
            .with_payload(serde_json::json!({"file_id": "123"}));
        
        assert_eq!(job.priority, Priority::High);
        assert_eq!(job.job_type, JobType::FileAnalysis);
    }

    #[test]
    fn test_retry_policy() {
        let config = RetryConfig::default();
        let policy = RetryPolicy::new(config);
        
        let delay1 = policy.calculate_delay(1);
        let delay2 = policy.calculate_delay(2);
        let delay3 = policy.calculate_delay(3);
        
        assert!(delay2 > delay1);
        assert!(delay3 > delay2);
    }

    #[test]
    fn test_job_retry_config() {
        let config = JobRetryConfig {
            max_retries: 5,
            base_delay_ms: 1000,
            max_delay_ms: 60000,
            multiplier: 2.0,
            jitter: true,
            retryable_errors: vec!["timeout".to_string()],
        };
        
        let error = openre_core::Error::Timeout("connection timeout".to_string());
        assert!(config.should_retry(&error));
        
        let error = openre_core::Error::NotFound("not found".to_string());
        assert!(!config.should_retry(&error));
    }
}