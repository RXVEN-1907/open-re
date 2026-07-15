//! Integration tests for open-re

use openre_core::ids::*;
use openre_config::Config;
use openre_storage::{GlobalStore, ObjectStore};
use openre_queue::{QueueManager, Job, Priority};
use openre_ai::{AiService, PromptCompiler};
use openre_plugins::PluginRegistry;
use tempfile::tempdir;
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_full_analysis_pipeline() {
    // Setup test environment
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let storage_path = dir.path().join("storage");
    std::fs::create_dir_all(&storage_path).unwrap();
    
    // Create config
    let config = Config {
        database: openre_config::DatabaseConfig {
            url: format!("sqlite://{}", db_path.display()),
            max_connections: 5,
            ..Default::default()
        },
        storage: openre_config::StorageConfig {
            local_path: storage_path.to_string_lossy().to_string(),
            ..Default::default()
        },
        queue: openre_config::QueueConfig {
            redis_url: "redis://localhost:6379".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    // Initialize stores
    let global_store = GlobalStore::new(&config.database).await.unwrap();
    let object_store = ObjectStore::new(&config.storage).await.unwrap();
    
    // Create test project
    let user_id = UserId::new();
    let project = global_store.create_project(
        user_id,
        "Test Project".to_string(),
        Some("Test description".to_string()),
        false,
        None,
    ).await.unwrap();
    
    // Upload test file
    let test_data = b"test binary content";
    let object_id = object_store.store_bytes(test_data).await.unwrap();
    
    let file = global_store.create_file(
        user_id,
        Some(project.id),
        "test.bin".to_string(),
        "application/octet-stream".to_string(),
        test_data.len() as u64,
        object_id,
    ).await.unwrap();
    
    // Verify file was created
    let retrieved = global_store.get_file(file.id).await.unwrap().unwrap();
    assert_eq!(retrieved.filename, "test.bin");
    assert_eq!(retrieved.size, test_data.len() as u64);
    
    // Test project store
    let project_store = global_store.get_project_store(project.id).await.unwrap();
    
    // Create a test function
    let function_id = project_store.create_function(openre_storage::Function {
        id: FunctionId::new(),
        file_id: file.id,
        name: "test_function".to_string(),
        address: 0x1000,
        size: 50,
        is_entry: true,
        is_thunk: false,
        calling_convention: Some("SystemV".to_string()),
        return_type: Some("int".to_string()),
        parameters: vec![],
        stack_frame_size: Some(32),
        cyclomatic_complexity: Some(3),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }).await.unwrap();
    
    let func = project_store.get_function(function_id).await.unwrap().unwrap();
    assert_eq!(func.name, "test_function");
    assert_eq!(func.address, 0x1000);
}

#[tokio::test]
async fn test_queue_job_processing() {
    // This test requires Redis - skip if not available
    if std::env::var("REDIS_URL").is_err() {
        eprintln!("Skipping queue test - REDIS_URL not set");
        return;
    }
    
    let redis_url = std::env::var("REDIS_URL").unwrap();
    let config = openre_config::QueueConfig {
        redis_url,
        ..Default::default()
    };
    
    let metrics = openre_telemetry::metrics::QueueMetrics::new(&openre_telemetry::MetricsRegistry::new());
    let queue_manager = QueueManager::new(config, metrics).await.unwrap();
    
    // Create test job
    let job = Job::new(openre_core::traits::JobType::FileAnalysis)
        .with_payload(serde_json::json!({"file_id": "test"}))
        .with_priority(Priority::High);
    
    // Enqueue job
    let job_id = queue_manager.enqueue(job.clone()).await.unwrap();
    assert_eq!(job_id, job.id);
    
    // Dequeue job
    let dequeued = queue_manager.dequeue("test-worker", &[Priority::High]).await.unwrap();
    assert!(dequeued.is_some());
    let dequeued_job = dequeued.unwrap();
    assert_eq!(dequeued_job.id, job.id);
    assert_eq!(dequeued_job.status, openre_queue::JobStatus::Running);
    
    // Complete job
    queue_manager.complete(job.id, serde_json::json!({"result": "success"})).await.unwrap();
    
    // Verify completion
    let result = queue_manager.get_job_result(job.id).await.unwrap().unwrap();
    assert_eq!(result.status, openre_queue::JobStatus::Completed);
}

#[tokio::test]
async fn test_ai_service_integration() {
    // This test requires AI models - skip if not available
    if std::env::var("OPENAI_API_KEY").is_err() && !std::path::Path::new("/models").exists() {
        eprintln!("Skipping AI test - no API key or local models");
        return;
    }
    
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let storage_path = dir.path().join("storage");
    std::fs::create_dir_all(&storage_path).unwrap();
    
    let config = Config {
        database: openre_config::DatabaseConfig {
            url: format!("sqlite://{}", db_path.display()),
            max_connections: 5,
            ..Default::default()
        },
        storage: openre_config::StorageConfig {
            local_path: storage_path.to_string_lossy().to_string(),
            ..Default::default()
        },
        ai: openre_config::AiConfig {
            openai_api_key: std::env::var("OPENAI_API_KEY").ok(),
            ..Default::default()
        },
        ..Default::default()
    };
    
    let global_store = GlobalStore::new(&config.database).await.unwrap();
    let object_store = ObjectStore::new(&config.storage).await.unwrap();
    
    let ai_service = AiService::new(config.ai, global_store, object_store).await.unwrap();
    
    // Test chat completion
    let request = openre_ai::providers::CompletionRequest {
        messages: vec![openre_ai::providers::Message::user("Hello".to_string())],
        temperature: Some(0.7),
        max_tokens: Some(100),
        ..Default::default()
    };
    
    let response = timeout(Duration::from_secs(30), ai_service.complete(request)).await;
    assert!(response.is_ok());
    let response = response.unwrap().unwrap();
    assert!(!response.choices.is_empty());
}

#[tokio::test]
async fn test_plugin_system() {
    let dir = tempdir().unwrap();
    let plugins_dir = dir.path().join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    
    let config = openre_config::PluginsConfig {
        plugins_dir: plugins_dir.to_string_lossy().to_string(),
        ..Default::default()
    };
    
    let registry = PluginRegistry::new(&config).await.unwrap();
    
    // List plugins (should be empty initially)
    let plugins = registry.list_plugins(None, None, 0, 10).await.unwrap();
    assert!(plugins.is_empty());
    
    // Test plugin source parsing
    let source = openre_plugins::PluginSource::Registry { name: "test-plugin".to_string() };
    assert_eq!(source.to_string(), "registry:test-plugin");
}

#[tokio::test]
async fn test_incremental_analysis() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    
    let project_store = openre_storage::ProjectStore::new(&db_path.to_string_lossy()).await.unwrap();
    
    let analyzer = openre_analysis::IncrementalAnalyzer::new();
    
    // Create initial function
    let file_id = FileId::new();
    let function_id = project_store.create_function(openre_storage::Function {
        id: FunctionId::new(),
        file_id,
        name: "func1".to_string(),
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
    
    // Simulate changes
    let changes = openre_analysis::AnalysisChanges {
        added_functions: vec![],
        modified_functions: vec![function_id],
        removed_functions: vec![],
        added_blocks: vec![],
        modified_blocks: vec![],
        removed_blocks: vec![],
    };
    
    let affected = analyzer.compute_affected_stages(&changes);
    assert!(affected.contains(&openre_analysis::StageName::Disassembly));
    assert!(affected.contains(&openre_analysis::StageName::ControlFlow));
    assert!(affected.contains(&openre_analysis::StageName::DataFlow));
}

#[tokio::test]
async fn test_prompt_compilation_with_context() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    
    let project_store = openre_storage::ProjectStore::new(&db_path.to_string_lossy()).await.unwrap();
    
    let compiler = PromptCompiler::new();
    
    // Create function with context
    let file_id = FileId::new();
    let function_id = project_store.create_function(openre_storage::Function {
        id: FunctionId::new(),
        file_id,
        name: "main".to_string(),
        address: 0x401000,
        size: 200,
        is_entry: true,
        is_thunk: false,
        calling_convention: Some("SystemV".to_string()),
        return_type: Some("int".to_string()),
        parameters: vec![],
        stack_frame_size: Some(64),
        cyclomatic_complexity: Some(5),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }).await.unwrap();
    
    // Add some basic blocks and instructions
    let block_id = project_store.create_basic_block(openre_storage::BasicBlock {
        id: openre_core::ids::BlockId::new(),
        function_id,
        start_address: 0x401000,
        end_address: 0x401050,
        instructions: vec![
            openre_storage::Instruction {
                id: openre_core::ids::InstructionId::new(),
                block_id: openre_core::ids::BlockId::new(),
                address: 0x401000,
                mnemonic: "push".to_string(),
                operands: "rbp".to_string(),
                bytes: vec![0x55],
                size: 1,
            },
            openre_storage::Instruction {
                id: openre_core::ids::InstructionId::new(),
                block_id: openre_core::ids::BlockId::new(),
                address: 0x401001,
                mnemonic: "mov".to_string(),
                operands: "rbp, rsp".to_string(),
                bytes: vec![0x48, 0x89, 0xe5],
                size: 3,
            },
        ],
        predecessors: vec![],
        successors: vec![],
        loop_header: false,
        loop_depth: 0,
    }).await.unwrap();
    
    // Compile with context
    let mut vars = std::collections::HashMap::new();
    vars.insert("function_name".to_string(), "main".to_string());
    vars.insert("architecture".to_string(), "x86_64".to_string());
    
    let compiled = compiler.compile_with_context(
        "analyze_function",
        vars,
        &project_store,
        function_id,
    ).await.unwrap();
    
    assert!(compiled.user_prompt.contains("main"));
    assert!(compiled.user_prompt.contains("x86_64"));
}

#[tokio::test]
async fn test_audit_logging() {
    let logger = openre_telemetry::AuditLogger::new("test".to_string());
    
    logger.log(openre_telemetry::AuditEvent {
        event_type: "file_upload".to_string(),
        user_id: Some("user123".to_string()),
        resource: "file:abc123".to_string(),
        action: "upload".to_string(),
        details: serde_json::json!({
            "filename": "test.bin",
            "size": 1024
        }),
        result: openre_telemetry::AuditResult::Success,
    }).unwrap();
    
    logger.log(openre_telemetry::AuditEvent {
        event_type: "analysis_start".to_string(),
        user_id: Some("user123".to_string()),
        resource: "job:xyz789".to_string(),
        action: "start_analysis".to_string(),
        details: serde_json::json!({
            "file_id": "abc123",
            "stages": ["disassembly", "decompilation"]
        }),
        result: openre_telemetry::AuditResult::Success,
    }).unwrap();
    
    // Verify audit log integrity
    let entries = logger.get_entries(10).await;
    assert_eq!(entries.len(), 2);
    
    // Verify hash chain
    for i in 1..entries.len() {
        assert_eq!(entries[i].previous_hash, entries[i-1].hash);
    }
}

#[tokio::test]
async fn test_config_hot_reload() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    
    // Write initial config
    std::fs::write(&config_path, r#"
        [server]
        host = "0.0.0.0"
        port = 8080
        
        [database]
        url = "sqlite://test.db"
        max_connections = 10
    "#).unwrap();
    
    let config = Config::from_file(&config_path).unwrap();
    assert_eq!(config.server.port, 8080);
    
    // Create watcher
    let mut watcher = ConfigWatcher::new(&config_path).unwrap();
    
    // Modify config
    std::fs::write(&config_path, r#"
        [server]
        host = "0.0.0.0"
        port = 9090
        
        [database]
        url = "sqlite://test.db"
        max_connections = 10
    "#).unwrap();
    
    // Wait for reload
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let reloaded = watcher.get_config().unwrap();
    assert_eq!(reloaded.server.port, 9090);
}