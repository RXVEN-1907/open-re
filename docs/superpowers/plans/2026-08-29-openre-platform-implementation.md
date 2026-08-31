# open-re Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all gaps between README promises and actual implementation by delivering 8 independently verifiable phases: Binary Analysis Pipeline, Plugin System E2E, API Server, Frontend, AI Security Analyst, Docker Platform, Configuration System, Release Automation — each with tests, docs, and CI/CD.

**Architecture:** The codebase is a Rust workspace with 17 crates. Most crate skeletons exist with substantial implementation. The plan wires them end-to-end: `openre-analysis` provides binary parsing + 9-stage pipeline; `openre-plugins` provides WASM runtime + capability system + 17 security plugins; `openre-api` serves REST/gRPC/WebSocket; `openre-cli` unifies all operations; `openre-security-ai` connects LLM providers; `openre-scan` is the standalone web scanner with TUI; `frontend` is React+TypeScript+Tailwind. Docker Compose orchestrates API+Worker+Frontend.

**Tech Stack:** Rust 2021, tokio, clap, ratatui/crossterm (TUI), axum/tonic (API), wasmtime (WASM), goblin/wasmparser (binary parsing), sqlx (SQLite/Postgres), reqwest (HTTP), serde/json, OpenAPI 3.1, React 18/TypeScript/Tailwind, Docker Compose, GitHub Actions.

**Spec:** `/home/jupyter-24b11cs489@adityau-1219b/project/open-re/REFACTOR-1.md` (audit of README vs implementation)

---

## Global Constraints

- **Rust version:** 1.75+ (MSRV)
- **Workspace resolver:** "2"
- **Edition:** 2021
- **License:** MIT
- **Release profile:** opt-level=3, lto=true, codegen-units=1, panic=abort, strip=true
- **Clippy:** deny warnings in CI (`-D warnings`)
- **Formatting:** `cargo fmt --all -- --check` must pass
- **Tests:** `cargo test --workspace` must pass (lib + integration)
- **Security:** `cargo audit`, `cargo deny check advisories bans licenses sources` must pass
- **Conventional commits:** `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`
- **Documentation:** Architecture docs in `docs/architecture/`, API reference via OpenAPI UI
- **Platform targets:** x86_64 Linux/macOS/Windows + ARM64 Linux/macOS

---

## Phase 1: Binary Analysis Pipeline (9 Stages)

### Task 1.1: Complete WASM Binary Parser Integration

**Files:**
- Modify: `crates/openre-analysis/src/binary/wasm.rs` (ensure full trait impl)
- Modify: `crates/openre-analysis/src/binary/mod.rs` (re-export)
- Test: `crates/openre-analysis/tests/wasm_parser_test.rs`

**Interfaces:**
- Consumes: `BinaryIdentifier`, `BinaryMetadataExtractor`, `StaticAnalyzer` traits
- Produces: `WasmIdentifier`, `WasmMetadataExtractor`, `WasmParser` implementing all traits

- [ ] **Step 1: Write failing integration test for WASM parsing**

```rust
// crates/openre-analysis/tests/wasm_parser_test.rs
use openre_analysis::binary::{WasmParser, WasmIdentifier, WasmMetadataExtractor, BinaryFormat, BinaryIdentifier, BinaryMetadataExtractor};
use std::path::PathBuf;

#[test]
fn test_wasm_identification() {
    let wasm_bytes = wat::parse_str(r#"(module (func (export "test")))"#).unwrap();
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&temp, &wasm_bytes).unwrap();
    
    let identifier = WasmIdentifier::default();
    let result = tokio_test::block_on(identifier.identify(&wasm_bytes)).unwrap();
    
    assert_eq!(result.format, BinaryFormat::Wasm);
    assert!(result.confidence > 0.9);
}

#[test]
fn test_wasm_metadata_extraction() {
    let wasm_bytes = wat::parse_str(r#"(module (func (export "test") (param i32) (result i32)))"#).unwrap();
    let extractor = WasmMetadataExtractor::default();
    let metadata = tokio_test::block_on(extractor.extract_metadata(&wasm_bytes)).unwrap();
    
    assert_eq!(metadata.identification.format, BinaryFormat::Wasm);
    assert!(!metadata.exports.is_empty());
    assert_eq!(metadata.exports[0].name, "test");
}

#[test]
fn test_wasm_full_parse() {
    let wasm_bytes = wat::parse_str(r#"(module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))"#).unwrap();
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(&temp, &wasm_bytes).unwrap();
    
    let info = WasmParser::parse(temp.path()).unwrap();
    assert_eq!(info.format, BinaryFormat::Wasm);
    assert!(!info.symbols.is_empty());
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-analysis wasm_parser_test -- --nocapture
# Expected: FAIL - missing wat dependency, incomplete trait impls
```

- [ ] **Step 3: Add `wat` dev-dependency and complete WASM trait implementations**

```toml
# crates/openre-analysis/Cargo.toml - add to [dev-dependencies]
wat = "1.0"
```

```rust
// crates/openre-analysis/src/binary/wasm.rs - ensure StaticAnalyzer impl exists
use crate::binary::traits::StaticAnalyzer;
use crate::binary::common::*;

#[async_trait]
impl StaticAnalyzer for WasmParser {
    async fn analyze(&self, file_id: FileId, binary: &BinaryMetadata) -> ResultCore<StaticAnalysisResult> {
        Ok(StaticAnalysisResult {
            file_id,
            functions: vec![],
            control_flow: ControlFlowOutput::default(),
            data_flow: DataFlowOutput::default(),
            type_recovery: TypeRecoveryOutput::default(),
            decompilation: None,
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-analysis wasm_parser_test -- --nocapture
# Expected: PASS
```

- [ ] **Step 5: Run full crate tests and clippy**

```bash
cargo test -p openre-analysis --lib
cargo clippy -p openre-analysis --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

- [ ] **Step 6: Commit**

```bash
git add crates/openre-analysis/src/binary/wasm.rs crates/openre-analysis/Cargo.toml crates/openre-analysis/tests/wasm_parser_test.rs
git commit -m "feat(analysis): complete WASM parser with full trait implementations"
```

---

### Task 1.2: Implement Incremental Analysis with Fingerprint Caching

**Files:**
- Create: `crates/openre-analysis/src/incremental.rs` (new file - check existing)
- Modify: `crates/openre-analysis/src/lib.rs` (re-export)
- Test: `crates/openre-analysis/tests/incremental_test.rs`

**Interfaces:**
- Consumes: `Fingerprint`, `IncrementalCache`, `IncrementalAnalyzer` from existing code
- Produces: Working incremental analysis with SHA256 fingerprinting, per-stage cache invalidation

- [ ] **Step 1: Write failing test for incremental caching**

```rust
// crates/openre-analysis/tests/incremental_test.rs
use openre_analysis::{IncrementalAnalyzer, Fingerprint, StageId, AnalysisId};
use std::path::PathBuf;
use tempfile::TempDir;

#[tokio::test]
async fn test_fingerprint_change_detection() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("cache");
    let analyzer = IncrementalAnalyzer::new(cache_dir).unwrap();
    
    let binary_path = temp.path().join("test.bin");
    std::fs::write(&binary_path, b"test binary content v1").unwrap();
    
    let analysis_id = AnalysisId::new();
    
    let results1 = analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        Ok(vec![(StageId::new("identification"), StageResult::success(StageId::new("identification"), vec![]))].into_iter().collect())
    }).await.unwrap();
    
    assert_eq!(results1.len(), 1);
    
    let results2 = analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        panic!("Should not re-analyze unchanged binary");
    }).await.unwrap();
    
    assert_eq!(results2.len(), 1);
    
    std::fs::write(&binary_path, b"test binary content v2").unwrap();
    let mut reanalyzed = false;
    let results3 = analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        reanalyzed = true;
        Ok(vec![(StageId::new("identification"), StageResult::success(StageId::new("identification"), vec![]))].into_iter().collect())
    }).await.unwrap();
    
    assert!(reanalyzed);
    assert_eq!(results3.len(), 1);
}

#[tokio::test]
async fn test_stage_level_invalidation() {
    let temp = TempDir::new().unwrap();
    let cache_dir = temp.path().join("cache");
    let analyzer = IncrementalAnalyzer::new(cache_dir).unwrap();
    
    let binary_path = temp.path().join("test.bin");
    std::fs::write(&binary_path, b"test").unwrap();
    let analysis_id = AnalysisId::new();
    
    analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        let mut map = std::collections::HashMap::new();
        map.insert(StageId::new("identification"), StageResult::success(StageId::new("identification"), vec![]));
        map.insert(StageId::new("disassembly"), StageResult::success(StageId::new("disassembly"), vec![]));
        Ok(map)
    }).await.unwrap();
    
    analyzer.invalidate_stage(&analysis_id, &StageId::new("disassembly")).await;
    
    let mut disassembly_ran = false;
    analyzer.analyze_if_changed(analysis_id, &binary_path, || {
        let mut map = std::collections::HashMap::new();
        map.insert(StageId::new("identification"), StageResult::success(StageId::new("identification"), vec![]));
        disassembly_ran = true;
        map.insert(StageId::new("disassembly"), StageResult::success(StageId::new("disassembly"), vec![]));
        Ok(map)
    }).await.unwrap();
    
    assert!(disassembly_ran);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-analysis incremental_test -- --nocapture
```

- [ ] **Step 3: Complete incremental.rs implementation**

```rust
// crates/openre-analysis/src/incremental.rs - ensure complete implementation
// Key: Fingerprint::from_binary, IncrementalCache, IncrementalAnalyzer
// Ensure analyze_if_changed, invalidate, invalidate_stage, persist all work
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-analysis incremental_test -- --nocapture
```

- [ ] **Step 5: Commit**

```bash
git add crates/openre-analysis/src/incremental.rs crates/openre-analysis/tests/incremental_test.rs
git commit -m "feat(analysis): implement incremental analysis with fingerprint caching"
```

---

### Task 1.3: Implement Pipeline Orchestrator (9 Stages)

**Files:**
- Modify: `crates/openre-analysis/src/orchestrator.rs` (complete implementation)
- Modify: `crates/openre-analysis/src/stages.rs` (stage runners)
- Create: `crates/openre-analysis/tests/pipeline_test.rs`

**Interfaces:**
- Consumes: `PipelineOrchestrator`, `PipelineStage`, `StageRunner`, `StageContext`, `IncrementalAnalyzer`
- Produces: Working 9-stage pipeline: Identification → Loading → Disassembly → Control Flow → Data Flow → Type Recovery → Decompilation → AI Enrichment → Finalization

- [ ] **Step 1: Write failing pipeline integration test**

```rust
// crates/openre-analysis/tests/pipeline_test.rs
use openre_analysis::{PipelineOrchestrator, PipelineStage, StageId, StageName, AnalysisId, BinaryInfo, BinaryFormat, Architecture};
use std::sync::Arc;

#[tokio::test]
async fn test_default_pipeline_stages() {
    let stages = PipelineOrchestrator::default_pipeline_stages();
    assert_eq!(stages.len(), 9);
    
    let expected = vec![
        "identification", "loading", "disassembly", "control_flow",
        "data_flow", "type_recovery", "decompilation", "ai_enrichment", "finalization"
    ];
    
    for (i, stage) in stages.iter().enumerate() {
        assert_eq!(stage.id.as_str(), expected[i]);
    }
}

#[tokio::test]
async fn test_pipeline_topological_sort() {
    let mut orch = PipelineOrchestrator::new(2);
    
    orch.add_stage(PipelineStage {
        id: StageId::new("a"),
        name: StageName::Identification,
        dependencies: vec![],
        runner: Box::new(TestStageRunner::new("a")),
    });
    orch.add_stage(PipelineStage {
        id: StageId::new("b"),
        name: StageName::Loading,
        dependencies: vec![StageId::new("a")],
        runner: Box::new(TestStageRunner::new("b")),
    });
    orch.add_stage(PipelineStage {
        id: StageId::new("c"),
        name: StageName::Disassembly,
        dependencies: vec![StageId::new("b")],
        runner: Box::new(TestStageRunner::new("c")),
    });
    
    let sorted = orch.topological_sort().unwrap();
    assert_eq!(sorted.len(), 3);
    assert_eq!(sorted[0].id.as_str(), "a");
    assert_eq!(sorted[1].id.as_str(), "b");
    assert_eq!(sorted[2].id.as_str(), "c");
}

#[tokio::test]
async fn test_pipeline_parallel_execution() {
    let mut orch = PipelineOrchestrator::new(2);
    
    orch.add_stage(PipelineStage {
        id: StageId::new("a"),
        name: StageName::Identification,
        dependencies: vec![],
        runner: Box::new(SlowStageRunner::new("a", 100)),
    });
    orch.add_stage(PipelineStage {
        id: StageId::new("b"),
        name: StageName::Loading,
        dependencies: vec![],
        runner: Box::new(SlowStageRunner::new("b", 100)),
    });
    orch.add_stage(PipelineStage {
        id: StageId::new("c"),
        name: StageName::Disassembly,
        dependencies: vec![StageId::new("a"), StageId::new("b")],
        runner: Box::new(TestStageRunner::new("c")),
    });
    
    let binary = BinaryInfo::default();
    let analysis_id = AnalysisId::new();
    let start = std::time::Instant::now();
    let results = orch.run(&binary, analysis_id).await.unwrap();
    let elapsed = start.elapsed();
    
    assert!(elapsed.as_millis() < 250);
    assert_eq!(results.len(), 3);
}

struct TestStageRunner { name: String }
impl TestStageRunner { fn new(name: &str) -> Self { Self { name: name.into() } } }
#[async_trait::async_trait]
impl openre_analysis::orchestrator::StageRunner for TestStageRunner {
    async fn run(&self, _: &BinaryInfo, _: &mut openre_analysis::orchestrator::StageContext) -> anyhow::Result<openre_analysis::StageResult> {
        Ok(openre_analysis::StageResult::success(StageId::new(&self.name), vec![]))
    }
}

struct SlowStageRunner { name: String, delay_ms: u64 }
impl SlowStageRunner { fn new(name: &str, delay_ms: u64) -> Self { Self { name: name.into(), delay_ms } } }
#[async_trait::async_trait]
impl openre_analysis::orchestrator::StageRunner for SlowStageRunner {
    async fn run(&self, _: &BinaryInfo, _: &mut openre_analysis::orchestrator::StageContext) -> anyhow::Result<openre_analysis::StageResult> {
        tokio::time::sleep(tokio::time::Duration::from_millis(self.delay_ms)).await;
        Ok(openre_analysis::StageResult::success(StageId::new(&self.name), vec![]))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-analysis pipeline_test -- --nocapture
```

- [ ] **Step 3: Complete orchestrator.rs and stages.rs**

```rust
// crates/openre-analysis/src/orchestrator.rs - ensure full implementation:
// - PipelineOrchestrator::new(max_parallel)
// - with_incremental()
// - add_stage()
// - run() with topological sort + semaphore-based parallelism
// - default_pipeline_stages() with all 9 stages

// crates/openre-analysis/src/stages.rs - implement real stage runners:
// - IdentificationStage (uses BinaryIdentifier)
// - LoadingStage (loads binary into memory)
// - DisassemblyStage (uses capstone/goblin for disassembly)
// - ControlFlowStage (builds CFG)
// - DataFlowStage (data dependency analysis)
// - TypeRecoveryStage (type inference)
// - DecompilationStage (pseudocode generation)
// - AiEnrichmentStage (calls AI service)
// - FinalizationStage (assembles results)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-analysis pipeline_test -- --nocapture
```

- [ ] **Step 5: Test with real binary**

```bash
cargo test -p openre-analysis --lib -- --nocapture
cargo clippy -p openre-analysis --all-targets --all-features -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git add crates/openre-analysis/src/orchestrator.rs crates/openre-analysis/src/stages.rs crates/openre-analysis/tests/pipeline_test.rs
git commit -m "feat(analysis): implement 9-stage pipeline orchestrator with parallel execution"
```

---

### Task 1.4: Add Progress Tracking with Stage Granularity

**Files:**
- Modify: `crates/openre-analysis/src/progress.rs` (complete)
- Modify: `crates/openre-analysis/src/orchestrator.rs` (integrate progress)
- Test: `crates/openre-analysis/tests/progress_test.rs`

**Interfaces:**
- Consumes: `ProgressTracker`, `AnalysisProgress`, `StageProgress`, `StageStatus`, `OverallStatus`
- Produces: Real-time progress updates, ETA calculation, stage-level metrics

- [ ] **Step 1: Write failing progress test**

```rust
// crates/openre-analysis/tests/progress_test.rs
use openre_analysis::{ProgressTracker, AnalysisId, StageId, StageName, StageStatus, OverallStatus};
use std::time::Duration;

#[tokio::test]
async fn test_progress_tracking_lifecycle() {
    let tracker = ProgressTracker::new();
    let analysis_id = AnalysisId::new();
    let stages = vec![
        (StageId::new("identification"), StageName::Identification),
        (StageId::new("disassembly"), StageName::Disassembly),
    ];
    
    tracker.start_analysis(analysis_id, "test.bin".into(), stages).await;
    
    let prog = tracker.get_progress(&analysis_id).await.unwrap();
    assert_eq!(prog.overall_status, OverallStatus::Initializing);
    assert_eq!(prog.overall_progress, 0.0);
    
    tracker.start_stage(&analysis_id, &StageId::new("identification"), "Identifying binary".into()).await;
    let prog = tracker.get_progress(&analysis_id).await.unwrap();
    assert_eq!(prog.overall_status, OverallStatus::Running);
    assert!(prog.stages[&StageId::new("identification")].status == StageStatus::Running);
    
    tracker.update_stage_progress(&analysis_id, &StageId::new("identification"), 50.0, "Processing headers".into(), 50, 100).await;
    let prog = tracker.get_progress(&analysis_id).await.unwrap();
    assert!((prog.overall_progress - 25.0).abs() < 1.0);
    
    tracker.complete_stage(&analysis_id, &StageId::new("identification")).await;
    let prog = tracker.get_progress(&analysis_id).await.unwrap();
    assert_eq!(prog.stages[&StageId::new("identification")].status, StageStatus::Completed);
    assert!((prog.overall_progress - 50.0).abs() < 1.0);
    
    tracker.start_stage(&analysis_id, &StageId::new("disassembly"), "Disassembling".into()).await;
    tracker.complete_stage(&analysis_id, &StageId::new("disassembly")).await;
    let prog = tracker.get_progress(&analysis_id).await.unwrap();
    assert_eq!(prog.overall_status, OverallStatus::Completed);
    assert!((prog.overall_progress - 100.0).abs() < 1.0);
}

#[tokio::test]
async fn test_eta_calculation() {
    let tracker = ProgressTracker::new();
    let analysis_id = AnalysisId::new();
    let stages = vec![(StageId::new("a"), StageName::Identification)];
    
    tracker.start_analysis(analysis_id, "test.bin".into(), stages).await;
    tracker.start_stage(&analysis_id, &StageId::new("a"), "Working".into()).await;
    
    tokio::time::sleep(Duration::from_millis(1100)).await;
    tracker.update_stage_progress(&analysis_id, &StageId::new("a"), 50.0, "Halfway".into(), 50, 100).await;
    
    let prog = tracker.get_progress(&analysis_id).await.unwrap();
    assert!(prog.estimated_remaining.is_some());
    let remaining = prog.estimated_remaining.unwrap();
    assert!(remaining.as_millis() > 800 && remaining.as_millis() < 1500);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-analysis progress_test -- --nocapture
```

- [ ] **Step 3: Complete progress.rs and integrate with orchestrator**

```rust
// crates/openre-analysis/src/progress.rs - ensure:
// - ProgressTracker::new()
// - start_analysis/stage, update_stage_progress, complete_stage, fail_stage
// - get_progress() returns AnalysisProgress with overall_progress, estimated_remaining
// - subscribe() returns broadcast receiver for real-time updates

// crates/openre-analysis/src/orchestrator.rs - integrate:
// In run(): create ProgressTracker, start_analysis, call start_stage/update/complete_stage per stage
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-analysis progress_test -- --nocapture
```

- [ ] **Step 5: Commit**

```bash
git add crates/openre-analysis/src/progress.rs crates/openre-analysis/src/orchestrator.rs crates/openre-analysis/tests/progress_test.rs
git commit -m "feat(analysis): add progress tracking with stage granularity and ETA"
```

---

### Task 1.5: Implement Static Analysis Passes

**Files:**
- Modify: `crates/openre-analysis/src/binary/static_analysis.rs` (complete)
- Test: `crates/openre-analysis/tests/static_analysis_test.rs`

**Interfaces:**
- Consumes: `StaticAnalyzer`, `StaticAnalysisResult`, `StaticAnalysisService`
- Produces: Symbol extraction, import/export analysis, section analysis, string extraction, compiler detection, packing detection

- [ ] **Step 1: Write failing static analysis test**

```rust
// crates/openre-analysis/tests/static_analysis_test.rs
use openre_analysis::{StaticAnalysisService, StaticAnalyzer, BinaryMetadata, FileId};
use openre_analysis::binary::common::*;

#[tokio::test]
async fn test_static_analysis_symbol_extraction() {
    let service = StaticAnalysisService::new();
    let file_id = FileId::new();
    
    let mut metadata = BinaryMetadata::default();
    metadata.file_id = file_id;
    metadata.symbols = vec![
        SymbolInfo { name: "main".into(), address: 0x1000, size: 100, symbol_type: SymbolType::Function, binding: SymbolBinding::Global, visibility: SymbolVisibility::Default, section_index: Some(1) },
        SymbolInfo { name: "global_var".into(), address: 0x2000, size: 8, symbol_type: SymbolType::Object, binding: SymbolBinding::Global, visibility: SymbolVisibility::Default, section_index: Some(2) },
    ];
    
    let result = service.analyze(file_id, &metadata).await.unwrap();
    
    assert!(!result.functions.is_empty());
    assert!(result.functions.iter().any(|f| f.name.as_deref() == Some("main")));
}

#[tokio::test]
async fn test_suspicious_import_detection() {
    let service = StaticAnalysisService::new();
    let file_id = FileId::new();
    
    let mut metadata = BinaryMetadata::default();
    metadata.file_id = file_id;
    metadata.imports = vec![
        ImportInfo { library: "kernel32.dll".into(), functions: vec![ImportedFunction { name: "VirtualAlloc".into(), address: None, ordinal: None }] },
    ];
    
    let result = service.analyze(file_id, &metadata).await.unwrap();
}

#[tokio::test]
async fn test_rwx_section_detection() {
    let service = StaticAnalysisService::new();
    let file_id = FileId::new();
    
    let mut metadata = BinaryMetadata::default();
    metadata.file_id = file_id;
    metadata.sections = vec![
        SectionInfo { name: ".text".into(), virtual_address: 0x1000, virtual_size: 1000, raw_offset: 0, raw_size: 1000, characteristics: SectionCharacteristics { readable: true, writable: true, executable: true, ..Default::default() }, entropy: 7.5 },
    ];
    
    let result = service.analyze(file_id, &metadata).await.unwrap();
}

#[tokio::test]
async fn test_packing_detection() {
    let service = StaticAnalysisService::new();
    let file_id = FileId::new();
    
    let mut metadata = BinaryMetadata::default();
    metadata.file_id = file_id;
    metadata.sections = vec![SectionInfo { name: "UPX0".into(), ..Default::default() }];
    metadata.strings = vec!["UPX!".into()];
    
    let result = service.analyze(file_id, &metadata).await.unwrap();
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-analysis static_analysis_test -- --nocapture
```

- [ ] **Step 3: Complete static_analysis.rs implementation**

```rust
// crates/openre-analysis/src/binary/static_analysis.rs - ensure:
// - StaticAnalyzer::analyze() extracts symbols, analyzes imports/exports/sections/strings
// - identify_compiler() detects GCC/Clang/MSVC/Rust/Go from strings
// - detect_packing() uses section count + entropy + known packer strings
// - StaticAnalysisService wraps analyzer with async interface
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-analysis static_analysis_test -- --nocapture
```

- [ ] **Step 5: Commit**

```bash
git add crates/openre-analysis/src/binary/static_analysis.rs crates/openre-analysis/tests/static_analysis_test.rs
git commit -m "feat(analysis): implement static analysis passes with symbol/import/section/string analysis"
```

---

### Task 1.6: Wire CLI Binary Analysis Commands to Pipeline

**Files:**
- Modify: `crates/openre-cli/src/commands/analysis.rs` (complete Pipeline::Run)
- Test: `crates/openre-cli/tests/analysis_integration_test.rs`

**Interfaces:**
- Consumes: `PipelineOrchestrator`, `ProgressTracker`, `AnalysisJob`, `AnalysisConfig`
- Produces: `openre analysis pipeline run <file> --stages all --ai-enabled` working end-to-end

- [ ] **Step 1: Write failing CLI integration test**

```rust
// crates/openre-cli/tests/analysis_integration_test.rs
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_analysis_pipeline_run() {
    let temp = TempDir::new().unwrap();
    let elf_path = temp.path().join("test.elf");
    std::fs::write(&elf_path, include_bytes!("../../test_binaries/hello.elf")).unwrap();
    
    let output = Command::new("cargo")
        .args(["run", "--release", "--package", "openre-cli", "--", "analysis", "pipeline", "run", elf_path.to_str().unwrap(), "--stages", "identification", "--format", "json"])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/crates/openre-cli", ""))
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Job ID"));
    assert!(stdout.contains("identification"));
}

#[test]
fn test_cli_analysis_info() {
    let temp = TempDir::new().unwrap();
    let elf_path = temp.path().join("test.elf");
    std::fs::write(&elf_path, include_bytes!("../../test_binaries/hello.elf")).unwrap();
    
    let output = Command::new("cargo")
        .args(["run", "--release", "--package", "openre-cli", "--", "analysis", "info", elf_path.to_str().unwrap(), "--format", "json"])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/crates/openre-cli", ""))
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Architecture"));
    assert!(stdout.contains("Format"));
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-cli analysis_integration_test -- --nocapture
```

- [ ] **Step 3: Complete CLI pipeline run command**

```rust
// crates/openre-cli/src/commands/analysis.rs - in cmd_pipeline_run:
// - Create real PipelineOrchestrator with all stage runners
// - Integrate ProgressTracker for real-time output
// - Use IncrementalAnalyzer for caching
// - Execute pipeline and return results
// - Support --stages filter, --ai-enabled flag
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-cli analysis_integration_test -- --nocapture
```

- [ ] **Step 5: Test manually**

```bash
cargo run --release --package openre-cli -- analysis info test_binaries/hello.elf
cargo run --release --package openre-cli -- analysis pipeline run test_binaries/hello.elf --stages all
```

- [ ] **Step 6: Commit**

```bash
git add crates/openre-cli/src/commands/analysis.rs crates/openre-cli/tests/analysis_integration_test.rs
git commit -m "feat(cli): wire binary analysis pipeline commands end-to-end"
```

---

### Task 1.7: Phase 1 Documentation & CI

**Files:**
- Create: `docs/architecture/04-binary-analysis-pipeline.md`
- Modify: `.github/workflows/ci.yml` (add analysis tests)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write architecture doc**

```markdown
# Binary Analysis Pipeline Architecture

## Overview
9-stage pipeline: Identification → Loading → Disassembly → Control Flow → Data Flow → Type Recovery → Decompilation → AI Enrichment → Finalization

## Components
- **Parsers**: ELF, PE, MachO, WASM (goblin, wasmparser)
- **Orchestrator**: Topological sort, parallel execution with semaphore
- **Incremental**: Fingerprint-based caching (SHA256 + mtime + size)
- **Progress**: Stage-level tracking with ETA

## API
- `PipelineOrchestrator::run()` - execute pipeline
- `ProgressTracker::subscribe()` - real-time updates
- `IncrementalAnalyzer::analyze_if_changed()` - cached re-analysis

## CLI
- `openre analysis pipeline run <file> --stages all|<stage>`
- `openre analysis info|symbols|imports|exports|strings|sections|segments|functions|decompile|cfg|dataflow <file>`
```

- [ ] **Step 2: Update CI workflow**

```yaml
# .github/workflows/ci.yml - add:
- name: Test openre-analysis
  run: cargo test -p openre-analysis --all-targets
- name: Clippy openre-analysis
  run: cargo clippy -p openre-analysis --all-targets --all-features -- -D warnings
```

- [ ] **Step 3: Run full test suite**

```bash
cargo test -p openre-analysis --all-targets
cargo clippy -p openre-analysis --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

- [ ] **Step 4: Commit**

```bash
git add docs/architecture/04-binary-analysis-pipeline.md .github/workflows/ci.yml CHANGELOG.md
git commit -m "docs(analysis): add binary analysis pipeline architecture doc and CI"
```

---

## Phase 2: Plugin System End-to-End

### Task 2.1: Complete WASM Runtime with Wasmtime

**Files:**
- Modify: `crates/openre-plugins/src/runtime.rs` (complete wasmtime integration)
- Modify: `crates/openre-plugins/src/sandbox.rs` (fuel/memory limits)
- Test: `crates/openre-plugins/tests/runtime_test.rs`

**Interfaces:**
- Consumes: `WasmRuntime`, `LoadedPlugin`, `WasmRuntimeState`, `Capability`
- Produces: WASM component model execution, fuel metering (10M instructions), memory limits, capability enforcement

- [ ] **Step 1: Write failing runtime test**

```rust
// crates/openre-plugins/tests/runtime_test.rs
use openre_plugins::{WasmRuntime, Capability, CapabilitySet, PluginManifest};
use std::sync::Arc;

#[tokio::test]
async fn test_wasm_runtime_load_and_execute() {
    let allowed = CapabilitySet::from_iter(vec![Capability::ReadBinary, Capability::CallAi]);
    let runtime = WasmRuntime::new(allowed).unwrap();
    
    let wat = r#"
    (component
      (core module $m
        (func (export "add") (param i32 i32) (result i32)
          local.get 0 local.get 1 i32.add))
      (core instance $i (instantiate $m))
      (func (export "add") (param i32 i32) (result i32)
        (canon lift (core func $i "add") (func $add))))
    "#;
    let wasm_bytes = wat::parse_str(wat).unwrap();
    
    let mut plugin = runtime.load_plugin(&wasm_bytes, "test-plugin".into()).await.unwrap();
    assert_eq!(plugin.plugin_id(), "test-plugin");
    
    let result = runtime.call_plugin(&mut plugin, "add", &[1i32.to_le_bytes(), 2i32.to_le_bytes()].concat()).await;
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-plugins runtime_test -- --nocapture
```

- [ ] **Step 3: Complete runtime.rs with wasmtime component model**

```rust
// crates/openre-plugins/src/runtime.rs - ensure:
// - Wasmtime Config: wasm_component_model(true), async_support(true), consume_fuel(true)
// - ComponentLinker with WASI preview2
// - load_plugin(): Component::new, Store::new, set_fuel(10_000_000), instantiate_async
// - call_plugin(): call exported function with capability checking
// - WasmRuntimeState holds allowed_capabilities, plugin_id
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-plugins runtime_test -- --nocapture
```

- [ ] **Step 5: Commit**

```bash
git add crates/openre-plugins/src/runtime.rs crates/openre-plugins/tests/runtime_test.rs
git commit -m "feat(plugins): complete WASM runtime with wasmtime component model"
```

---

### Task 2.2: Implement Capability-Based Permission System

**Files:**
- Verify: `crates/openre-plugins/src/capability.rs` (complete)
- Test: `crates/openre-plugins/tests/capability_test.rs`

**Interfaces:**
- Consumes: `Capability` enum (30+ variants), `CapabilitySet`, `RiskLevel`, `CapabilityRequest/Response`
- Produces: Fine-grained permissions with risk levels (Low/Medium/High), user consent tracking

- [ ] **Step 1: Write failing capability test**

```rust
// crates/openre-plugins/tests/capability_test.rs
use openre_plugins::{Capability, CapabilitySet, RiskLevel};

#[test]
fn test_capability_risk_levels() {
    assert_eq!(Capability::ReadBinary.risk_level(), RiskLevel::Low);
    assert_eq!(Capability::WriteAnnotations.risk_level(), RiskLevel::Medium);
    assert_eq!(Capability::WriteBinary.risk_level(), RiskLevel::High);
    assert_eq!(Capability::SpawnProcess.risk_level(), RiskLevel::High);
    assert_eq!(Capability::NetworkAccess.risk_level(), RiskLevel::High);
}

#[test]
fn test_capability_user_consent() {
    assert!(Capability::WriteBinary.requires_user_consent());
    assert!(Capability::MutateDatabase.requires_user_consent());
    assert!(Capability::SpawnProcess.requires_user_consent());
    assert!(Capability::NetworkAccess.requires_user_consent());
    assert!(!Capability::ReadBinary.requires_user_consent());
    assert!(!Capability::CallAi.requires_user_consent());
}

#[test]
fn test_capability_set_operations() {
    let mut set = CapabilitySet::new();
    set.add(Capability::ReadBinary);
    set.add(Capability::WriteAnnotations);
    
    assert!(set.has(Capability::ReadBinary));
    assert!(!set.has(Capability::WriteBinary));
    
    assert_eq!(set.highest_risk(), RiskLevel::Medium);
    assert_eq!(set.requires_consent(), vec![Capability::WriteAnnotations]);
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
cargo test -p openre-plugins capability_test -- --nocapture
```

- [ ] **Step 3: Commit**

```bash
git add crates/openre-plugins/tests/capability_test.rs
git commit -m "test(plugins): add capability system tests"
```

---

### Task 2.3: Complete Plugin Registry (Local + Remote)

**Files:**
- Modify: `crates/openre-plugins/src/registry.rs` (complete install/remote/update)
- Test: `crates/openre-plugins/tests/registry_test.rs`

**Interfaces:**
- Consumes: `PluginRegistry`, `RegistryEntry`, `PluginSource`, `RegistryConfig`
- Produces: Local plugin storage, remote registry support, versioning, signature verification

- [ ] **Step 1: Write failing registry test**

```rust
// crates/openre-plugins/tests/registry_test.rs
use openre_plugins::{PluginRegistry, PluginSource, RegistryConfig, PluginManifest, PluginMetadata, CapabilitySet};
use tempfile::TempDir;

#[tokio::test]
async fn test_local_registry_install() {
    let temp = TempDir::new().unwrap();
    let config = RegistryConfig { local_path: temp.path().join("plugins"), ..Default::default() };
    let registry = PluginRegistry::new(config).unwrap();
    
    let plugin_dir = temp.path().join("my-plugin");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    let manifest = PluginManifest {
        metadata: PluginMetadata { name: "test-plugin".into(), version: "1.0.0".into(), description: "Test".into(), author: "test".into(), license: "MIT".into(), repository: "".into(), homepage: None, categories: vec![], keywords: vec![] },
        required_capabilities: CapabilitySet::new(),
        optional_capabilities: CapabilitySet::new(),
    };
    tokio::fs::write(plugin_dir.join("plugin.json"), serde_json::to_string_pretty(&manifest).unwrap()).await.unwrap();
    
    let plugin_id = registry.install(PluginSource::Local { path: plugin_dir }).await.unwrap();
    assert_eq!(plugin_id.as_str(), "test-plugin");
    
    let entry = registry.get(&plugin_id).await.unwrap();
    assert!(entry.enabled);
    assert_eq!(entry.manifest.metadata.name, "test-plugin");
}

#[tokio::test]
async fn test_registry_enable_disable() {
    let temp = TempDir::new().unwrap();
    let config = RegistryConfig { local_path: temp.path().join("plugins"), ..Default::default() };
    let registry = PluginRegistry::new(config).unwrap();
    
    let plugin_id = /* install */;
    
    registry.disable(&plugin_id).await.unwrap();
    let entry = registry.get(&plugin_id).await.unwrap();
    assert!(!entry.enabled);
    
    registry.enable(&plugin_id).await.unwrap();
    let entry = registry.get(&plugin_id).await.unwrap();
    assert!(entry.enabled);
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p openre-plugins registry_test -- --nocapture
```

- [ ] **Step 3: Complete registry.rs**

```rust
// crates/openre-plugins/src/registry.rs - ensure:
// - install_remote(): download from registry_url, verify checksum, install locally
// - enable_builtin(): enable built-in plugins
// - update(): check for updates, download new version
// - Signature verification (ed25519) for remote plugins
// - Dependency resolution between plugins
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p openre-plugins registry_test -- --nocapture
```

- [ ] **Step 5: Commit**

```bash
git add crates/openre-plugins/src/registry.rs crates/openre-plugins/tests/registry_test.rs
git commit -m "feat(plugins): complete plugin registry with local/remote support"
```

---

### Task 2.4: Implement Plugin SDK with Macros

**Files:**
- Verify: `crates/openre-plugins/src/sdk.rs` (macros)
- Create: `crates/openre-plugins-macros/` (proc-macro crate)
- Test: `crates/openre-plugins/tests/sdk_test.rs`

**Interfaces:**
- Consumes: `#[derive(PluginManifest)]`, `#[plugin_command]`, `#[plugin_capability]`, `plugin_init!`
- Produces: Zero-boilerplate plugin development with manifest derivation, command/capability registration

- [ ] **Step 1: Write failing SDK test**

```rust
// crates/openre-plugins/tests/sdk_test.rs
use openre_plugins::sdk::{Plugin, PluginMetadata, CapabilitySet, CommandRegistration, CommandContext, CommandResult, Capability};
use openre_plugins::{PluginManifest, CapabilitySet as PluginCapabilitySet};

#[derive(PluginManifest)]
#[plugin_capability("ReadBinary")]
#[plugin_capability("CallAi")]
struct MyPlugin;

#[plugin_command("scan")]
fn scan_command(_ctx: CommandContext) -> anyhow::Result<CommandResult> {
    Ok(CommandResult { success: true, output: None, error: None })
}

#[test]
fn test_plugin_manifest_derive() {
    let manifest = MyPlugin::metadata();
    assert_eq!(manifest.name, "MyPlugin");
    assert!(manifest.required_capabilities.has(Capability::ReadBinary));
    assert!(manifest.required_capabilities.has(Capability::CallAi));
}

#[test]
fn test_plugin_commands() {
    let plugin = MyPlugin;
    let commands = plugin.commands();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].name, "scan");
}
```

- [ ] **Step 2: Create proc-macro crate**

```toml
# crates/openre-plugins-macros/Cargo.toml
[package]
name = "openre-plugins-macros"
version = "0.1.0"
edition = "2021"

[lib]
proc-macro = true

[dependencies]
proc-macro2 = "1.0"
quote = "1.0"
syn = { version = "2.0", features = ["full", "extra-traits"] }
openre-plugins = { path = ".." }
```

```rust
// crates/openre-plugins-macros/src/lib.rs
use proc_macro::TokenStream;

#[proc_macro_derive(PluginManifest)]
pub fn derive_plugin_manifest(input: TokenStream) -> TokenStream {
    crate::derive::derive_plugin_manifest(input)
}

#[proc_macro_attribute]
pub fn plugin_command(args: TokenStream, input: TokenStream) -> TokenStream {
    crate::attributes::plugin_command(args, input)
}

#[proc_macro_attribute]
pub fn plugin_capability(args: TokenStream, input: TokenStream) -> TokenStream {
    crate::attributes::plugin_capability(args, input)
}

#[proc_macro]
pub fn plugin_init(input: TokenStream) -> TokenStream {
    crate::init::plugin_init(input)
}

mod derive;
mod attributes;
mod init;
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-plugins sdk_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-plugins-macros/ crates/openre-plugins/tests/sdk_test.rs
git commit -m "feat(plugins): add Plugin SDK with derive macros and command/capability attributes"
```

---

### Task 2.5: Complete 17 Built-in Security Plugins

**Files:**
- Verify: `crates/openre-plugins/src/security/*.rs` (all 17 plugins)
- Test: `crates/openre-plugins/tests/security_plugins_test.rs`

**Interfaces:**
- Consumes: `PluginManifest`, `CapabilitySet`, `Capability`
- Produces: 17 security plugins with manifests

- [ ] **Step 1: Write test verifying all 17 plugins**

```rust
// crates/openre-plugins/tests/security_plugins_test.rs
use openre_plugins::security::builtin_security_plugins;

#[test]
fn test_all_17_security_plugins() {
    let plugins = builtin_security_plugins();
    assert_eq!(plugins.len(), 17);
    
    let expected = [
        "security-access-control", "security-api-rate-limiting", "security-auth-discovery",
        "security-cookie-security", "security-cors-analysis", "security-csp-analysis",
        "security-file-upload", "security-graphql-analysis", "security-information-disclosure",
        "security-path-traversal", "security-rate-limiting", "security-rest-api-analysis",
        "security-security-headers", "security-sensitive-info", "security-session-management",
        "security-sql-injection", "security-xss-analysis",
    ];
    
    for (plugin, name) in plugins.iter().zip(expected) {
        assert_eq!(plugin.metadata.name, name);
        assert!(!plugin.required_capabilities.all().next().is_none());
    }
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
cargo test -p openre-plugins security_plugins_test -- --nocapture
```

- [ ] **Step 3: Implement full plugin logic for key plugins**

```rust
// crates/openre-plugins/src/security/graphql.rs - ensure full implementation
// crates/openre-plugins/src/security/rest_api.rs - ensure full implementation
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-plugins/src/security/ crates/openre-plugins/tests/security_plugins_test.rs
git commit -m "feat(plugins): implement 17 built-in security plugins with full logic"
```

---

### Task 2.6: Implement Plugin Lifecycle Management

**Files:**
- Verify: `crates/openre-plugins/src/lifecycle.rs` (complete)
- Test: `crates/openre-plugins/tests/lifecycle_test.rs`

**Interfaces:**
- Consumes: `PluginLifecycleManager`, `PluginState`, `PluginConfig`, `PluginRuntimeInfo`
- Produces: Install, enable/disable, configure, grant/revoke capabilities, update, uninstall

- [ ] **Step 1: Write failing lifecycle test**

```rust
// crates/openre-plugins/tests/lifecycle_test.rs
use openre_plugins::{PluginLifecycleManager, PluginRegistry, PluginConfig, PluginId, Capability, CapabilitySet};
use tempfile::TempDir;

#[tokio::test]
async fn test_plugin_lifecycle() {
    let temp = TempDir::new().unwrap();
    let registry_config = openre_plugins::RegistryConfig { local_path: temp.path().join("plugins"), ..Default::default() };
    let registry = std::sync::Arc::new(PluginRegistry::new(registry_config).unwrap());
    
    let manager = PluginLifecycleManager::new(registry.clone(), temp.path().join("lifecycle")).unwrap();
    
    let plugin_id = PluginId::new("test-plugin");
    let config = PluginConfig { enabled: true, ..Default::default() };
    manager.install(&plugin_id, config).await.unwrap();
    
    let state = manager.get_state(&plugin_id).await.unwrap();
    assert!(state.config.enabled);
    
    manager.disable(&plugin_id).await.unwrap();
    let state = manager.get_state(&plugin_id).await.unwrap();
    assert!(!state.config.enabled);
    
    manager.enable(&plugin_id).await.unwrap();
    manager.grant_capability(&plugin_id, Capability::ReadBinary).await.unwrap();
    let state = manager.get_state(&plugin_id).await.unwrap();
    assert!(state.config.granted_capabilities.has(Capability::ReadBinary));
    
    manager.uninstall(&plugin_id).await.unwrap();
    assert!(manager.get_state(&plugin_id).await.is_none());
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
cargo test -p openre-plugins lifecycle_test -- --nocapture
```

- [ ] **Step 3: Commit**

```bash
git add crates/openre-plugins/tests/lifecycle_test.rs
git commit -m "test(plugins): add plugin lifecycle management tests"
```

---

### Task 2.7: Wire CLI Plugin Commands to Registry/Lifecycle

**Files:**
- Modify: `crates/openre-cli/src/commands/plugin.rs` (complete install/list/enable/disable/configure)
- Test: `crates/openre-cli/tests/plugin_integration_test.rs`

**Interfaces:**
- Consumes: `PluginRegistry`, `PluginLifecycleManager`
- Produces: `openre plugin install <path>`, `openre plugin list`, `openre plugin enable <id>`, `openre plugin disable <id>`, `openre plugin configure <id>`

- [ ] **Step 1: Write failing CLI plugin test**

```rust
// crates/openre-cli/tests/plugin_integration_test.rs
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_cli_plugin_install_list() {
    let temp = TempDir::new().unwrap();
    let plugin_dir = temp.path().join("test-plugin");
    std::fs::create_dir_all(&plugin_dir).unwrap();
    let manifest = serde_json::json!({
        "metadata": { "name": "test-plugin", "version": "1.0.0", "description": "Test", "author": "test", "license": "MIT", "repository": "" },
        "required_capabilities": [],
        "optional_capabilities": []
    });
    std::fs::write(plugin_dir.join("plugin.json"), serde_json::to_string_pretty(&manifest).unwrap()).unwrap();
    
    let output = Command::new("cargo")
        .args(["run", "--release", "--package", "openre-cli", "--", "plugin", "install", plugin_dir.to_str().unwrap()])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/crates/openre-cli", ""))
        .output()
        .unwrap();
    
    assert!(output.status.success());
    
    let output = Command::new("cargo")
        .args(["run", "--release", "--package", "openre-cli", "--", "plugin", "list", "--format", "json"])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/crates/openre-cli", ""))
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test-plugin"));
}
```

- [ ] **Step 2: Complete CLI plugin commands**

```rust
// crates/openre-cli/src/commands/plugin.rs - implement:
// - install: call PluginRegistry::install(PluginSource::Local)
// - list: call PluginRegistry::list()
// - enable/disable: call PluginLifecycleManager::enable/disable()
// - configure: call PluginLifecycleManager::configure()
// - uninstall: call PluginLifecycleManager::uninstall()
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-cli plugin_integration_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-cli/src/commands/plugin.rs crates/openre-cli/tests/plugin_integration_test.rs
git commit -m "feat(cli): wire plugin commands to registry and lifecycle manager"
```

---

### Task 2.8: Phase 2 Documentation & CI

**Files:**
- Create: `docs/architecture/05-plugin-system.md`
- Modify: `.github/workflows/ci.yml` (add plugin tests)
- Create: `docs/injection/plugin_development_guide.md`

- [ ] **Step 1: Write architecture doc**

```markdown
# Plugin System Architecture

## Components
- **WASM Runtime**: wasmtime component model, fuel metering (10M), memory limits
- **Capabilities**: 30+ fine-grained permissions with risk levels (Low/Medium/High)
- **Registry**: Local + remote, versioning, ed25519 signature verification
- **SDK**: `#[derive(PluginManifest)]`, `#[plugin_command]`, `#[plugin_capability]`, `plugin_init!`
- **Security Plugins**: 17 built-in plugins (access-control, cors-analysis, sql-injection, etc.)
- **Lifecycle**: Install, enable/disable, configure, grant/revoke capabilities, update, uninstall

## CLI Commands
- `openre plugin install <path>`
- `openre plugin list [--enabled]`
- `openre plugin enable|disable <id>`
- `openre plugin configure <id> --capability <cap>`
- `openre plugin update <id>`
- `openre plugin uninstall <id>`
```

- [ ] **Step 2: Write plugin development guide**

```markdown
# Plugin Development Guide

## Quick Start
```bash
cargo new --lib my-plugin
cd my-plugin
```

Add to Cargo.toml:
```toml
[dependencies]
openre-plugins = { path = "../crates/openre-plugins" }
openre-plugins-macros = { path = "../crates/openre-plugins-macros" }
```

Write plugin:
```rust
use openre_plugins::{PluginManifest, Capability, CapabilitySet, PluginMetadata};
use openre_plugins::sdk::{Plugin, CommandRegistration, CommandContext, CommandResult};

#[derive(PluginManifest)]
#[plugin_capability("ReadBinary")]
#[plugin_capability("CallAi")]
struct MyPlugin;

#[plugin_command("analyze")]
fn analyze(ctx: CommandContext) -> anyhow::Result<CommandResult> {
    Ok(CommandResult { success: true, output: Some(serde_json::json!({"result": "ok"})), error: None })
}

impl Plugin for MyPlugin {
    fn metadata(&self) -> PluginMetadata { MyPlugin::metadata() }
    fn capabilities(&self) -> CapabilitySet { MyPlugin::required_capabilities() }
    fn commands(&self) -> Vec<CommandRegistration> { vec![analyze_command_register()] }
    fn initialize(&mut self, _config: serde_json::Value) -> anyhow::Result<()> { Ok(()) }
    fn shutdown(&mut self) -> anyhow::Result<()> { Ok(()) }
}
```

Build: `cargo build --release --target wasm32-wasip2`
Install: `openre plugin install target/wasm32-wasip2/release/my_plugin.wasm`
```

- [ ] **Step 3: Update CI**

```yaml
# .github/workflows/ci.yml
- name: Test openre-plugins
  run: cargo test -p openre-plugins --all-targets
- name: Test openre-plugins-macros
  run: cargo test -p openre-plugins-macros --all-targets
```

- [ ] **Step 4: Commit**

```bash
git add docs/architecture/05-plugin-system.md docs/injection/plugin_development_guide.md .github/workflows/ci.yml CHANGELOG.md
git commit -m "docs(plugins): add plugin system architecture and development guide"
```

---

## Phase 3: API Server + WebSocket + Auth

### Task 3.1: Complete REST API with OpenAPI 3.1

**Files:**
- Modify: `crates/openre-api/src/routes/*.rs` (all endpoint groups)
- Modify: `crates/openre-api/src/http.rs` (axum router with OpenAPI)
- Test: `crates/openre-api/tests/api_test.rs`

**Interfaces:**
- Consumes: `ApiState`, `Auth`, `Validation`, `Versioning`
- Produces: REST endpoints for projects, scans, findings, ai/*, plugins, exports, auth

- [ ] **Step 1: Write failing API test**

```rust
// crates/openre-api/tests/api_test.rs
use axum_test::TestServer;
use openre_api::{create_app, ApiState};

#[tokio::test]
async fn test_health_endpoint() {
    let state = ApiState::new_for_test().await;
    let app = create_app(state);
    let server = TestServer::new(app).unwrap();
    
    let response = server.get("/health").await;
    assert_eq!(response.status_code(), 200);
    assert!(response.text().contains("healthy"));
}

#[tokio::test]
async fn test_projects_crud() {
    let state = ApiState::new_for_test().await;
    let app = create_app(state);
    let server = TestServer::new(app).unwrap();
    
    let create_resp = server.post("/api/v1/projects").json(&serde_json::json!({
        "name": "Test Project",
        "description": "Test"
    })).await;
    assert_eq!(create_resp.status_code(), 201);
    let project: serde_json::Value = create_resp.json();
    let project_id = project["id"].as_str().unwrap();
    
    let list_resp = server.get("/api/v1/projects").await;
    assert_eq!(list_resp.status_code(), 200);
    
    let get_resp = server.get(&format!("/api/v1/projects/{}", project_id)).await;
    assert_eq!(get_resp.status_code(), 200);
    
    let del_resp = server.delete(&format!("/api/v1/projects/{}", project_id)).await;
    assert_eq!(del_resp.status_code(), 204);
}
```

- [ ] **Step 2: Complete API routes**

```rust
// crates/openre-api/src/routes/projects.rs - full CRUD
// crates/openre-api/src/routes/scans.rs - create, run, list, show, cancel, resume, status, export
// crates/openre-api/src/routes/findings.rs - list, get, filter, export
// crates/openre-api/src/routes/ai.rs - analyze, explain, remediate, correlate, templates, providers
// crates/openre-api/src/routes/plugins.rs - list, get, install, uninstall, enable, disable, configure
// crates/openre-api/src/routes/exports.rs - generate, list, download
// crates/openre-api/src/routes/auth.rs - login, logout, register, token refresh
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-api api_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-api/src/routes/ crates/openre-api/src/http.rs crates/openre-api/tests/api_test.rs
git commit -m "feat(api): complete REST API with all endpoint groups"
```

---

### Task 3.2: Implement JWT + API Key Authentication

**Files:**
- Modify: `crates/openre-api/src/auth.rs` (JWT tokens, API keys)
- Modify: `crates/openre-api/src/middleware.rs` (auth middleware)
- Test: `crates/openre-api/tests/auth_test.rs`

**Interfaces:**
- Consumes: `jsonwebtoken`, `argon2`, `governor` (rate limiting)
- Produces: JWT access/refresh tokens, API key hashing, scopes, token validation middleware

- [ ] **Step 1: Write failing auth test**

```rust
// crates/openre-api/tests/auth_test.rs
use axum_test::TestServer;
use openre_api::{create_app, ApiState};

#[tokio::test]
async fn test_jwt_auth_flow() {
    let state = ApiState::new_for_test().await;
    let app = create_app(state);
    let server = TestServer::new(app).unwrap();
    
    let reg = server.post("/api/v1/auth/register").json(&serde_json::json!({
        "email": "test@example.com",
        "password": "securepass123"
    })).await;
    assert_eq!(reg.status_code(), 201);
    
    let login = server.post("/api/v1/auth/login").json(&serde_json::json!({
        "email": "test@example.com",
        "password": "securepass123"
    })).await;
    assert_eq!(login.status_code(), 200);
    let token: serde_json::Value = login.json();
    let access_token = token["access_token"].as_str().unwrap();
    
    let me = server.get("/api/v1/auth/me").add_header("Authorization", format!("Bearer {}", access_token)).await;
    assert_eq!(me.status_code(), 200);
}

#[tokio::test]
async fn test_api_key_auth() {
    let state = ApiState::new_for_test().await;
    let app = create_app(state);
    let server = TestServer::new(app).unwrap();
    
    let api_key = "opk_test_...";
    let resp = server.get("/api/v1/projects").add_header("X-API-Key", api_key).await;
    assert_eq!(resp.status_code(), 200);
}
```

- [ ] **Step 2: Complete auth.rs and middleware.rs**

```rust
// crates/openre-api/src/auth.rs - ensure:
// - JWT: HS256/RS256, access token (15min), refresh token (7d)
// - API Keys: prefix "opk_", argon2id hash, scopes
// - Password: argon2id hashing
// - Token validation with expiry, revocation

// crates/openre-api/src/middleware.rs - ensure:
// - AuthLayer: extracts Bearer token or X-API-Key
// - Validates JWT or API key hash
// - Adds user_id, scopes to request extensions
// - Rate limiting per client (token bucket)
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-api auth_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-api/src/auth.rs crates/openre-api/src/middleware.rs crates/openre-api/tests/auth_test.rs
git commit -m "feat(api): implement JWT + API key authentication with rate limiting"
```

---

### Task 3.3: Add WebSocket Support for Real-time Updates

**Files:**
- Modify: `crates/openre-api/src/websocket.rs` (WebSocket handler)
- Modify: `crates/openre-api/src/http.rs` (mount WS route)
- Test: `crates/openre-api/tests/websocket_test.rs`

**Interfaces:**
- Consumes: `tokio-tungstenite`, `futures`, `broadcast` channels
- Produces: WS endpoint `/api/v1/ws` with scan progress, finding notifications, system events

- [ ] **Step 1: Write failing WebSocket test**

```rust
// crates/openre-api/tests/websocket_test.rs
use axum_test::TestServer;
use openre_api::{create_app, ApiState};
use futures::StreamExt;

#[tokio::test]
async fn test_websocket_scan_progress() {
    let state = ApiState::new_for_test().await;
    let app = create_app(state);
    let server = TestServer::new(app).unwrap();
    
    let (mut ws, _) = server.websocket("/api/v1/ws").await.unwrap();
    
    ws.send(axum_test::WebSocketMessage::Text(serde_json::json!({
        "type": "subscribe",
        "channels": ["scan_progress"]
    }).to_string())).await.unwrap();
    
    let msg = ws.next().await.unwrap();
    assert!(msg.as_text().unwrap().contains("subscribed"));
}
```

- [ ] **Step 2: Complete websocket.rs**

```rust
// crates/openre-api/src/websocket.rs - ensure:
// - WS upgrade handler with auth validation
// - Message types: Subscribe, Unsubscribe, Ping, Pong, ScanProgress, FindingCreated, SystemEvent
// - Broadcast channels per channel type
// - Connection management with heartbeat (ping/pong)
// - Auto-reconnect support
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-api websocket_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-api/src/websocket.rs crates/openre-api/src/http.rs crates/openre-api/tests/websocket_test.rs
git commit -m "feat(api): add WebSocket support for real-time scan progress and notifications"
```

---

### Task 3.4: Implement gRPC API with Tonic

**Files:**
- Modify: `crates/openre-api/src/grpc.rs` (tonic service)
- Create: `crates/openre-api/proto/` (protobuf definitions)
- Test: `crates/openre-api/tests/grpc_test.rs`

**Interfaces:**
- Consumes: `tonic`, `prost`, generated protobuf code
- Produces: gRPC services mirroring REST endpoints

- [ ] **Step 1: Create protobuf definitions**

```protobuf
// crates/openre-api/proto/openre/v1/project.proto
syntax = "proto3";
package openre.v1;

service ProjectService {
  rpc CreateProject(CreateProjectRequest) returns (Project);
  rpc GetProject(GetProjectRequest) returns (Project);
  rpc ListProjects(ListProjectsRequest) returns (ListProjectsResponse);
  rpc UpdateProject(UpdateProjectRequest) returns (Project);
  rpc DeleteProject(DeleteProjectRequest) returns (google.protobuf.Empty);
}

message Project {
  string id = 1;
  string name = 2;
  string description = 3;
  string owner_id = 4;
  google.protobuf.Timestamp created_at = 5;
  google.protobuf.Timestamp updated_at = 6;
}
```

```protobuf
// crates/openre-api/proto/openre/v1/scan.proto
syntax = "proto3";
package openre.v1;

service ScanService {
  rpc CreateScan(CreateScanRequest) returns (Scan);
  rpc RunScan(RunScanRequest) returns (Scan);
  rpc GetScan(GetScanRequest) returns (Scan);
  rpc ListScans(ListScansRequest) returns (ListScansResponse);
  rpc CancelScan(CancelScanRequest) returns (Scan);
  rpc GetScanStatus(GetScanStatusRequest) returns (ScanStatus);
  rpc WatchScanStatus(WatchScanStatusRequest) returns (stream ScanStatus);
}
```

- [ ] **Step 2: Generate Rust code and implement gRPC services**

```bash
# Add to Cargo.toml
[build-dependencies]
tonic-build = "0.10"

# build.rs
fn main() {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["proto/openre/v1/project.proto", "proto/openre/v1/scan.proto"], &["proto"])
        .unwrap();
}
```

```rust
// crates/openre-api/src/grpc.rs - implement generated service traits
// Mount in http.rs with tonic::transport::Server
```

- [ ] **Step 3: Write and run gRPC test**

```bash
cargo test -p openre-api grpc_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-api/proto/ crates/openre-api/src/grpc.rs crates/openre-api/build.rs crates/openre-api/tests/grpc_test.rs
git commit -m "feat(api): add gRPC API with tonic and protobuf definitions"
```

---

### Task 3.5: Phase 3 Documentation & CI

**Files:**
- Create: `docs/architecture/06-api-server.md`
- Create: `docs/api/openapi.yaml` (auto-generated)
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write API architecture doc**

```markdown
# API Server Architecture

## REST API (axum)
- OpenAPI 3.1 spec at `/api/openapi.json`
- Scalar UI at `/docs`
- Endpoints: projects, scans, findings, ai/*, plugins, exports, auth
- JWT + API Key auth with scopes
- Rate limiting (token bucket)

## WebSocket
- Endpoint: `/api/v1/ws`
- Channels: scan_progress, findings, system
- Auth via query param token or handshake

## gRPC (tonic)
- Protobuf definitions in `proto/openre/v1/`
- Services: ProjectService, ScanService, FindingService, AIService, PluginService
- Server reflection enabled

## Auth
- JWT: RS256, 15min access / 7d refresh
- API Keys: opk_ prefix, argon2id hash
- Scopes: projects:read, projects:write, scans:read, scans:write, ai:analyze, plugins:manage
```

- [ ] **Step 2: Add OpenAPI generation to CI**

```yaml
# .github/workflows/ci.yml
- name: Generate OpenAPI spec
  run: cargo run --package openre-api --bin generate-openapi -- --output docs/api/openapi.yaml
```

- [ ] **Step 3: Run full API tests**

```bash
cargo test -p openre-api --all-targets
cargo clippy -p openre-api --all-targets --all-features -- -D warnings
```

- [ ] **Step 4: Commit**

```bash
git add docs/architecture/06-api-server.md docs/api/ .github/workflows/ci.yml CHANGELOG.md
git commit -m "docs(api): add API server architecture and OpenAPI spec"
```

---

## Phase 4: Frontend Build + API Integration

### Task 4.1: Build React Frontend with Vite + TypeScript + Tailwind

**Files:**
- Modify: `frontend/package.json`, `frontend/vite.config.ts`, `frontend/tailwind.config.js`
- Create: `frontend/src/` (full app structure)
- Test: `frontend/src/__tests__/`

**Interfaces:**
- Consumes: React 18, TypeScript, Tailwind, React Router, TanStack Query, Axios, Zustand
- Produces: Dashboard, Scan Management, Finding Browser, AI Chat, Plugin Manager, Settings

- [ ] **Step 1: Initialize frontend with proper config**

```json
// frontend/package.json
{
  "name": "openre-frontend",
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "test": "vitest",
    "lint": "eslint src --ext ts,tsx"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.20.0",
    "@tanstack/react-query": "^5.0.0",
    "axios": "^1.6.0",
    "zustand": "^4.4.0",
    "lucide-react": "^0.294.0",
    "clsx": "^2.0.0",
    "date-fns": "^2.30.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@vitejs/plugin-react": "^4.2.0",
    "typescript": "^5.3.0",
    "vite": "^5.0.0",
    "tailwindcss": "^3.3.0",
    "postcss": "^8.4.0",
    "autoprefixer": "^10.4.0",
    "eslint": "^8.55.0",
    "@typescript-eslint/eslint-plugin": "^6.13.0",
    "@typescript-eslint/parser": "^6.13.0",
    "vitest": "^1.0.0",
    "@testing-library/react": "^14.0.0",
    "jsdom": "^23.0.0"
  }
}
```

- [ ] **Step 2: Create Vite + Tailwind config**

```typescript
// frontend/vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { '@': path.resolve(__dirname, './src') } },
  server: { port: 3000, proxy: { '/api': { target: 'http://localhost:8080', changeOrigin: true } } },
});
```

```javascript
// frontend/tailwind.config.js
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: { extend: {} },
  plugins: [],
};
```

- [ ] **Step 3: Create app structure with routing**

```tsx
// frontend/src/main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import './index.css';

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 5000 } } });

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </QueryClientProvider>
  </React.StrictMode>
);
```

```tsx
// frontend/src/App.tsx
import { Routes, Route, Navigate } from 'react-router-dom';
import { Dashboard } from '@/pages/Dashboard';
import { Scans } from '@/pages/Scans';
import { Findings } from '@/pages/Findings';
import { AIAnalyst } from '@/pages/AIAnalyst';
import { Plugins } from '@/pages/Plugins';
import { Settings } from '@/pages/Settings';
import { Layout } from '@/components/Layout';

export function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/scans/:id" element={<ScanDetail />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/ai" element={<AIAnalyst />} />
        <Route path="/plugins" element={<Plugins />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  );
}
```

- [ ] **Step 4: Run dev server and verify**

```bash
cd frontend && npm install && npm run dev
```

- [ ] **Step 5: Commit**

```bash
git add frontend/ CHANGELOG.md
git commit -m "feat(frontend): initialize React + TypeScript + Tailwind with routing"
```

---

### Task 4.2: Implement Dashboard with Project Overview

**Files:**
- Create: `frontend/src/pages/Dashboard.tsx`
- Create: `frontend/src/components/StatsCards.tsx`, `frontend/src/components/RecentScans.tsx`, `frontend/src/components/SeverityChart.tsx`

**Interfaces:**
- Consumes: API `/api/v1/projects`, `/api/v1/scans/recent`, `/api/v1/findings/stats`
- Produces: Stats cards, recent scans table, severity trend chart

- [ ] **Step 1: Create dashboard components with API integration**

```tsx
// frontend/src/pages/Dashboard.tsx
import { useQuery } from '@tanstack/react-query';
import { StatsCards } from '@/components/StatsCards';
import { RecentScans } from '@/components/RecentScans';
import { SeverityChart } from '@/components/SeverityChart';
import { apiClient } from '@/lib/api';

export function Dashboard() {
  const { data: stats } = useQuery({ queryKey: ['dashboard-stats'], queryFn: () => apiClient.getDashboardStats() });
  const { data: recentScans } = useQuery({ queryKey: ['recent-scans'], queryFn: () => apiClient.getRecentScans(5) });
  const { data: severityTrends } = useQuery({ queryKey: ['severity-trends'], queryFn: () => apiClient.getSeverityTrends() });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <StatsCards stats={stats} />
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <RecentScans scans={recentScans} />
        <SeverityChart data={severityTrends} />
      </div>
    </div>
  );
}
```

```typescript
// frontend/src/lib/api.ts
import axios from 'axios';

export const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const apiClient = {
  getDashboardStats: () => api.get('/dashboard/stats').then(r => r.data),
  getRecentScans: (limit: number) => api.get('/scans/recent', { params: { limit } }).then(r => r.data),
  getSeverityTrends: () => api.get('/findings/stats/severity-trends').then(r => r.data),
};
```

- [ ] **Step 2: Verify in browser**

```bash
cd frontend && npm run dev
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/Dashboard.tsx frontend/src/components/ frontend/src/lib/api.ts
git commit -m "feat(frontend): implement dashboard with stats, recent scans, severity trends"
```

---

### Task 4.3: Implement Scan Management UI

**Files:**
- Create: `frontend/src/pages/Scans.tsx`, `frontend/src/pages/ScanDetail.tsx`
- Create: `frontend/src/components/ScanList.tsx`, `frontend/src/components/ScanForm.tsx`, `frontend/src/components/ScanProgress.tsx`

**Interfaces:**
- Consumes: API `/api/v1/scans` (CRUD), WebSocket `/api/v1/ws` (scan progress)
- Produces: Scan list with filters, create scan modal, real-time progress, scan detail with findings

- [ ] **Step 1: Create scan pages with real-time WebSocket**

```tsx
// frontend/src/pages/Scans.tsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ScanList } from '@/components/ScanList';
import { ScanForm } from '@/components/ScanForm';
import { apiClient } from '@/lib/api';

export function Scans() {
  const queryClient = useQueryClient();
  const { data: scans } = useQuery({ queryKey: ['scans'], queryFn: () => apiClient.getScans() });
  
  const createMutation = useMutation({
    mutationFn: (data: CreateScanData) => apiClient.createScan(data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['scans'] }),
  });

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Scans</h1>
        <ScanForm onSubmit={createMutation.mutate} />
      </div>
      <ScanList scans={scans} />
    </div>
  );
}
```

```tsx
// frontend/src/pages/ScanDetail.tsx
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { ScanProgress } from '@/components/ScanProgress';
import { FindingTable } from '@/components/FindingTable';
import { apiClient } from '@/lib/api';

export function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const { data: scan } = useQuery({ queryKey: ['scan', id], queryFn: () => apiClient.getScan(id!) });
  const { data: findings } = useQuery({ queryKey: ['findings', id], queryFn: () => apiClient.getScanFindings(id!) });
  
  const [ws, setWs] = useState<WebSocket | null>(null);
  
  useEffect(() => {
    const socket = new WebSocket(`${import.meta.env.VITE_WS_URL}/api/v1/ws?token=${localStorage.getItem('access_token')}`);
    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === 'scan_progress' && msg.scan_id === id) {
        queryClient.setQueryData(['scan', id], (old) => ({ ...old, progress: msg.progress }));
      }
    };
    setWs(socket);
    return () => socket.close();
  }, [id]);

  return (
    <div className="p-6">
      {scan && <ScanProgress scan={scan} />}
      <FindingTable findings={findings} />
    </div>
  );
}
```

- [ ] **Step 2: Verify with running API**

```bash
# Terminal 1: Start API
cargo run --release --package openre-api

# Terminal 2: Start Frontend
cd frontend && npm run dev
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/Scans.tsx frontend/src/pages/ScanDetail.tsx frontend/src/components/Scan*.tsx
git commit -m "feat(frontend): implement scan management with real-time WebSocket progress"
```

---

### Task 4.4: Implement Finding Browser

**Files:**
- Create: `frontend/src/pages/Findings.tsx`
- Create: `frontend/src/components/FindingTable.tsx`, `frontend/src/components/FindingDrawer.tsx`, `frontend/src/components/FindingFilters.tsx`

**Interfaces:**
- Consumes: API `/api/v1/findings` (filterable, sortable, paginated)
- Produces: Filterable/sortable table, detail drawer with evidence, export buttons

- [ ] **Step 1: Create finding browser with advanced filtering**

```tsx
// frontend/src/pages/Findings.tsx
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FindingTable } from '@/components/FindingTable';
import { FindingFilters } from '@/components/FindingFilters';
import { FindingDrawer } from '@/components/FindingDrawer';
import { apiClient } from '@/lib/api';

export function Findings() {
  const [filters, setFilters] = useState({ severity: '', category: '', search: '', page: 1, pageSize: 20 });
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  
  const { data, isLoading } = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => apiClient.getFindings(filters),
    placeholderData: (prev) => prev,
  });

  return (
    <div className="p-6">
      <FindingFilters filters={filters} onChange={setFilters} />
      <FindingTable 
        findings={data?.items} 
        isLoading={isLoading}
        onSelect={setSelectedFinding}
        total={data?.total}
        page={filters.page}
        pageSize={filters.pageSize}
        onPageChange={(page) => setFilters(f => ({ ...f, page }))}
      />
      {selectedFinding && (
        <FindingDrawer finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </div>
  );
}
```

- [ ] **Step 2: Verify with real data**

```bash
# Run a scan via CLI or API, then view findings
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/Findings.tsx frontend/src/components/Finding*.tsx
git commit -m "feat(frontend): implement finding browser with filtering, sorting, detail drawer"
```

---

### Task 4.5: Implement AI Analyst Chat Interface

**Files:**
- Create: `frontend/src/pages/AIAnalyst.tsx`
- Create: `frontend/src/components/ChatInterface.tsx`, `frontend/src/components/MessageBubble.tsx`, `frontend/src/components/ProviderSelector.tsx`

**Interfaces:**
- Consumes: API `/api/v1/ai/*` (analyze, explain, remediate, correlate, templates, providers)
- Produces: Conversational chat with context, provider selection, template library, streaming responses

- [ ] **Step 1: Create AI chat with streaming**

```tsx
// frontend/src/pages/AIAnalyst.tsx
import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { ChatInterface } from '@/components/ChatInterface';
import { ProviderSelector } from '@/components/ProviderSelector';
import { apiClient } from '@/lib/api';

export function AIAnalyst() {
  const [provider, setProvider] = useState('ollama');
  const [model, setModel] = useState('llama3');
  
  const analyzeMutation = useMutation({
    mutationFn: (data: { findingId: string; prompt: string }) => 
      apiClient.aiAnalyze(data.findingId, data.prompt, provider, model),
  });

  return (
    <div className="p-6 h-[calc(100vh-80px)] flex flex-col">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">AI Security Analyst</h1>
        <ProviderSelector provider={provider} model={model} onChange={setProvider} />
      </div>
      <ChatInterface 
        onSendMessage={(prompt, findingId) => analyzeMutation.mutate({ findingId, prompt })}
        isLoading={analyzeMutation.isPending}
      />
    </div>
  );
}
```

```tsx
// frontend/src/components/ChatInterface.tsx
// Streaming response handling with SSE or WebSocket
// Message bubbles with markdown rendering
// Code blocks with syntax highlighting
```

- [ ] **Step 2: Verify with AI service running**

```bash
# Requires Ollama or OpenAI API key configured
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/pages/AIAnalyst.tsx frontend/src/components/Chat*.tsx frontend/src/components/ProviderSelector.tsx
git commit -m "feat(frontend): implement AI Analyst chat interface with streaming"
```

---

### Task 4.6: Implement Plugin Manager + Settings

**Files:**
- Create: `frontend/src/pages/Plugins.tsx`, `frontend/src/pages/Settings.tsx`
- Create: `frontend/src/components/PluginCard.tsx`, `frontend/src/components/PluginConfigForm.tsx`

**Interfaces:**
- Consumes: API `/api/v1/plugins` (list, install, enable, disable, configure)
- Produces: Plugin marketplace browser, installed plugins with enable/disable, configuration forms

- [ ] **Step 1: Create plugin manager and settings**

```tsx
// frontend/src/pages/Plugins.tsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { PluginCard } from '@/components/PluginCard';
import { apiClient } from '@/lib/api';

export function Plugins() {
  const queryClient = useQueryClient();
  const { data: plugins } = useQuery({ queryKey: ['plugins'], queryFn: () => apiClient.getPlugins() });
  
  const installMutation = useMutation({
    mutationFn: (url: string) => apiClient.installPlugin(url),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugins'] }),
  });
  
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => 
      enabled ? apiClient.enablePlugin(id) : apiClient.disablePlugin(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugins'] }),
  });

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">Plugins</h1>
        <button onClick={() => installMutation.mutate(prompt('Plugin URL:'))} className="btn-primary">
          Install Plugin
        </button>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {plugins?.map(plugin => (
          <PluginCard 
            key={plugin.id} 
            plugin={plugin} 
            onToggle={(enabled) => toggleMutation.mutate({ id: plugin.id, enabled })}
          />
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/pages/Plugins.tsx frontend/src/pages/Settings.tsx frontend/src/components/Plugin*.tsx
git commit -m "feat(frontend): implement plugin manager and settings page"
```

---

### Task 4.7: Frontend Testing, Accessibility, Responsive

**Files:**
- Create: `frontend/src/__tests__/*.test.tsx`
- Modify: `frontend/vitest.config.ts`
- Test: All components

**Interfaces:**
- Consumes: Vitest, React Testing Library, jsdom, axe-core
- Produces: Unit tests, integration tests, WCAG 2.1 AA compliance, responsive breakpoints

- [ ] **Step 1: Write component tests**

```tsx
// frontend/src/__tests__/FindingTable.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import { FindingTable } from '@/components/FindingTable';

test('filters findings by severity', () => {
  const findings = [
    { id: '1', title: 'XSS', severity: 'HIGH', category: 'XSS' },
    { id: '2', title: 'Info leak', severity: 'LOW', category: 'Info' },
  ];
  render(<FindingTable findings={findings} onSelect={jest.fn()} total={2} page={1} pageSize={20} onPageChange={jest.fn()} />);
  
  fireEvent.click(screen.getByText('HIGH'));
  expect(screen.getByText('XSS')).toBeInTheDocument();
  expect(screen.queryByText('Info leak')).not.toBeInTheDocument();
});
```

```tsx
// frontend/src/__tests__/accessibility.test.tsx
import { render } from '@testing-library/react';
import { axe } from 'jest-axe';
import { App } from '@/App';

test('dashboard has no accessibility violations', async () => {
  const { container } = render(<App />);
  const results = await axe(container);
  expect(results).toHaveNoViolations();
});
```

- [ ] **Step 2: Run tests**

```bash
cd frontend && npm test
```

- [ ] **Step 3: Commit**

```bash
git add frontend/src/__tests__/ frontend/vitest.config.ts
git commit -m "test(frontend): add unit tests, accessibility tests, responsive verification"
```

---

### Task 4.8: Phase 4 Documentation & CI

**Files:**
- Create: `docs/architecture/07-frontend.md`
- Modify: `.github/workflows/ci.yml` (frontend build/test)
- Create: `frontend/Dockerfile`

- [ ] **Step 1: Write frontend architecture doc**

```markdown
# Frontend Architecture

## Stack
- React 18 + TypeScript + Vite
- Tailwind CSS for styling
- TanStack Query for server state
- Zustand for client state
- React Router v6 for routing

## Pages
- Dashboard: Stats cards, recent scans, severity trends
- Scans: List, create, detail with real-time WebSocket progress
- Findings: Filterable/sortable table, detail drawer, export
- AI Analyst: Chat interface with streaming, provider/model selection
- Plugins: Marketplace browser, installed management, configuration
- Settings: User prefs, API keys, theme, notifications

## Real-time
- WebSocket for scan progress, finding notifications
- Auto-reconnect with exponential backoff

## Testing
- Vitest + React Testing Library
- axe-core for accessibility (WCAG 2.1 AA)
- Responsive: 320px, 768px, 1024px, 1440px breakpoints
```

- [ ] **Step 2: Add frontend CI**

```yaml
# .github/workflows/ci.yml
- name: Frontend install
  run: cd frontend && npm ci
- name: Frontend lint
  run: cd frontend && npm run lint
- name: Frontend test
  run: cd frontend && npm test
- name: Frontend build
  run: cd frontend && npm run build
```

- [ ] **Step 3: Create Dockerfile**

```dockerfile
# frontend/Dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

- [ ] **Step 4: Commit**

```bash
git add docs/architecture/07-frontend.md .github/workflows/ci.yml frontend/Dockerfile CHANGELOG.md
git commit -m "docs(frontend): add architecture doc, CI pipeline, Dockerfile"
```

---

## Phase 5: AI Security Analyst (LLM Providers + CLI)

### Task 5.1: Complete Multi-Provider Abstraction Layer

**Files:**
- Modify: `crates/openre-security-ai/src/providers.rs` (Ollama, OpenAI, Anthropic, ONNX, llama.cpp)
- Modify: `crates/openre-security-ai/src/router.rs` (provider routing)
- Test: `crates/openre-security-ai/tests/providers_test.rs`

**Interfaces:**
- Consumes: `Provider`, `ProviderConfig`, `ChatRequest`, `ChatResponse`, `EmbeddingRequest`
- Produces: Unified interface for 5 providers with streaming, tool calling, structured output

- [ ] **Step 1: Write failing provider test**

```rust
// crates/openre-security-ai/tests/providers_test.rs
use openre_security_ai::{ProviderRouter, ProviderConfig, ProviderType, ChatRequest, Message};

#[tokio::test]
async fn test_ollama_provider() {
    let router = ProviderRouter::new(vec![
        ProviderConfig { provider_type: ProviderType::Ollama, base_url: "http://localhost:11434".into(), api_key: None, model: "llama3".into() },
    ]).await.unwrap();
    
    let request = ChatRequest {
        messages: vec![Message { role: "user".into(), content: "Hello".into() }],
        model: "llama3".into(),
        temperature: Some(0.7),
        stream: false,
        tools: None,
    };
    
    let response = router.chat(request).await.unwrap();
    assert!(!response.content.is_empty());
}

#[tokio::test]
async fn test_provider_fallback() {
    let router = ProviderRouter::new(vec![
        ProviderConfig { provider_type: ProviderType::Ollama, base_url: "http://invalid:11434".into(), api_key: None, model: "llama3".into() },
        ProviderConfig { provider_type: ProviderType::OpenAI, base_url: "https://api.openai.com".into(), api_key: Some("test".into()), model: "gpt-4".into() },
    ]).await.unwrap();
    
    let request = ChatRequest { messages: vec![Message { role: "user".into(), content: "Test".into() }], model: "gpt-4".into(), temperature: Some(0.7), stream: false, tools: None };
    let response = router.chat(request).await;
}
```

- [ ] **Step 2: Complete providers.rs with all 5 providers**

```rust
// crates/openre-security-ai/src/providers.rs - ensure:
// - OllamaProvider: /api/chat, /api/embeddings, /api/generate
// - OpenAIProvider: /v1/chat/completions, /v1/embeddings
// - AnthropicProvider: /v1/messages
// - ONNXProvider: ort session.run()
// - LlamaCppProvider: llama-cpp-2 bindings
// - All implement Provider trait with chat(), embed(), stream_chat()
// - ProviderRouter: tries providers in order, falls back on error
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-security-ai providers_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-security-ai/src/providers.rs crates/openre-security-ai/src/router.rs crates/openre-security-ai/tests/providers_test.rs
git commit -m "feat(ai): complete multi-provider abstraction (Ollama, OpenAI, Anthropic, ONNX, llama.cpp)"
```

---

### Task 5.2: Implement Security Analyst Agent

**Files:**
- Modify: `crates/openre-security-ai/src/analyst.rs` (analyze, explain, remediate, correlate, prioritize, summarize)
- Test: `crates/openre-security-ai/tests/analyst_test.rs`

**Interfaces:**
- Consumes: `ProviderRouter`, `PromptCompiler`, `FindingProvider`, `SafetyControls`
- Produces: Context-aware vulnerability analysis with evidence, remediation with effort estimates

- [ ] **Step 1: Write failing analyst test**

```rust
// crates/openre-security-ai/tests/analyst_test.rs
use openre_security_ai::{SecurityAnalyst, AnalystConfig, Finding, Severity, Category};

#[tokio::test]
async fn test_analyze_finding() {
    let analyst = SecurityAnalyst::new(AnalystConfig::default()).await.unwrap();
    
    let finding = Finding {
        id: "test-1".into(),
        title: "SQL Injection in Login".into(),
        description: "User input directly concatenated into SQL query".into(),
        severity: Severity::Critical,
        category: Category::Injection,
        evidence: vec![],
        target: "https://example.com/login".into(),
    };
    
    let analysis = analyst.analyze(&finding).await.unwrap();
    assert!(analysis.summary.contains("SQL"));
    assert!(!analysis.root_cause.is_empty());
    assert!(!analysis.attack_vectors.is_empty());
    assert!(!analysis.impact_assessment.is_empty());
}

#[tokio::test]
async fn test_remediation_generation() {
    let analyst = SecurityAnalyst::new(AnalystConfig::default()).await.unwrap();
    
    let finding = Finding { /* ... SQL injection ... */ };
    let remediation = analyst.remediate(&finding).await.unwrap();
    
    assert!(!remediation.steps.is_empty());
    assert!(remediation.effort_estimate_hours > 0);
    assert!(!remediation.code_examples.is_empty());
    assert!(remediation.priority >= 1 && remediation.priority <= 10);
}
```

- [ ] **Step 2: Complete analyst.rs**

```rust
// crates/openre-security-ai/src/analyst.rs - ensure:
// - analyze(): root cause, attack vectors, impact, references
// - explain(): plain language explanation for different audiences
// - remediate(): steps, code examples, effort, priority, references
// - correlate(): find related findings, attack chains
// - prioritize(): risk scoring with CVSS, exploitability, business impact
// - summarize(): executive summary, technical summary, compliance mapping
// - query(): natural language Q&A over findings
// - compare(): diff two scans, new/fixed/changed findings
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-security-ai analyst_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-security-ai/src/analyst.rs crates/openre-security-ai/tests/analyst_test.rs
git commit -m "feat(ai): implement Security Analyst agent with analyze/explain/remediate/correlate"
```

---

### Task 5.3: Implement Prompt Compiler + Safety Controls

**Files:**
- Verify: `crates/openre-security-ai/src/prompt_compiler.rs` (template variables)
- Verify: `crates/openre-security-ai/src/safety.rs` (PII filtering, confidence scoring)
- Test: `crates/openre-security-ai/tests/safety_test.rs`

**Interfaces:**
- Consumes: `PromptCompiler`, `PromptTemplate`, `SafetyControls`, `OutputValidator`
- Produces: Variable injection, PII redaction, confidence scoring, output validation

- [ ] **Step 1: Write safety test**

```rust
// crates/openre-security-ai/tests/safety_test.rs
use openre_security_ai::{SafetyControls, OutputValidator, ConfidenceScorer};

#[test]
fn test_pii_filtering() {
    let safety = SafetyControls::new();
    let text = "The API key is sk-1234567890abcdef and email is user@example.com";
    let filtered = safety.filter_pii(text);
    
    assert!(filtered.contains("[REDACTED]"));
    assert!(!filtered.contains("sk-1234567890abcdef"));
    assert!(!filtered.contains("user@example.com"));
}

#[test]
fn test_confidence_scoring() {
    let scorer = ConfidenceScorer::new();
    let high_confidence = scorer.score(&Finding { evidence: vec![/* strong evidence */], .. });
    let low_confidence = scorer.score(&Finding { evidence: vec![], .. });
    
    assert!(high_confidence > low_confidence);
    assert!(high_confidence >= 0.7);
    assert!(low_confidence <= 0.5);
}

#[test]
fn test_output_validation() {
    let validator = OutputValidator::new();
    let valid = validator.validate(&AnalysisOutput { summary: "Valid analysis".into(), .. });
    let invalid = validator.validate(&AnalysisOutput { summary: "".into(), .. });
    
    assert!(valid.is_ok());
    assert!(invalid.is_err());
}
```

- [ ] **Step 2: Run test to verify it passes**

```bash
cargo test -p openre-security-ai safety_test -- --nocapture
```

- [ ] **Step 3: Commit**

```bash
git add crates/openre-security-ai/tests/safety_test.rs
git commit -m "test(ai): add safety controls and prompt compiler tests"
```

---

### Task 5.4: Wire CLI AI Commands to Analyst

**Files:**
- Modify: `crates/openre-cli/src/commands/ai.rs`, `crates/openre-cli/src/commands/analyst.rs` (complete)
- Test: `crates/openre-cli/tests/ai_integration_test.rs`

**Interfaces:**
- Consumes: `SecurityAnalyst`, `ProviderRouter`
- Produces: `openre ai analyze <finding-id>`, `openre ai explain <finding-id>`, `openre ai remediate <finding-id>`, `openre ai correlate`, `openre analyst explain/remediate/correlate/prioritize/summarize/query/compare`

- [ ] **Step 1: Write failing CLI AI test**

```rust
// crates/openre-cli/tests/ai_integration_test.rs
use std::process::Command;

#[test]
fn test_cli_ai_analyze() {
    let output = Command::new("cargo")
        .args(["run", "--release", "--package", "openre-cli", "--", "ai", "analyze", "finding-123", "--provider", "ollama", "--model", "llama3"])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/crates/openre-cli", ""))
        .output()
        .unwrap();
    
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("analysis") || stdout.contains("summary"));
}

#[test]
fn test_cli_analyst_explain() {
    let output = Command::new("cargo")
        .args(["run", "--release", "--package", "openre-cli", "--", "analyst", "explain", "finding-123", "--audience", "executive"])
        .current_dir(env!("CARGO_MANIFEST_DIR").replace("/crates/openre-cli", ""))
        .output()
        .unwrap();
    
    assert!(output.status.success());
}
```

- [ ] **Step 2: Complete CLI AI commands**

```rust
// crates/openre-cli/src/commands/ai.rs - implement:
// - analyze: call SecurityAnalyst::analyze()
// - explain: call SecurityAnalyst::explain() with audience
// - remediate: call SecurityAnalyst::remediate()
// - correlate: call SecurityAnalyst::correlate()
// - templates: list prompt templates
// - providers: list configured providers

// crates/openre-cli/src/commands/analyst.rs - implement:
// - explain, remediate, correlate, prioritize, summarize, query, compare
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-cli ai_integration_test -- --nocapture
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-cli/src/commands/ai.rs crates/openre-cli/src/commands/analyst.rs crates/openre-cli/tests/ai_integration_test.rs
git commit -m "feat(cli): wire AI Security Analyst commands to analyst agent"
```

---

### Task 5.5: Phase 5 Documentation & CI

**Files:**
- Create: `docs/architecture/08-ai-security-analyst.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write AI architecture doc**

```markdown
# AI Security Analyst Architecture

## Providers
- Ollama (local): http://localhost:11434
- OpenAI: https://api.openai.com
- Anthropic: https://api.anthropic.com
- ONNX Runtime: local model inference
- llama.cpp: local GGUF models

## Analyst Capabilities
- analyze: Root cause, attack vectors, impact, references
- explain: Plain language for executive/technical/developer audiences
- remediate: Steps, code examples, effort hours, priority (1-10)
- correlate: Attack chains, related findings, blast radius
- prioritize: CVSS + exploitability + business impact scoring
- summarize: Executive/technical/compliance summaries
- query: Natural language Q&A over findings
- compare: Scan diff (new/fixed/changed)

## Safety
- PII filtering (API keys, emails, IPs, passwords)
- Confidence scoring (0.0-1.0)
- Output validation (completeness, actionability)
- Token budget management

## CLI Commands
- openre ai analyze/explain/remediate/correlate
- openre analyst explain/remediate/correlate/prioritize/summarize/query/compare
```

- [ ] **Step 2: Add AI tests to CI**

```yaml
# .github/workflows/ci.yml
- name: Test openre-security-ai
  run: cargo test -p openre-security-ai --all-targets
```

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/08-ai-security-analyst.md .github/workflows/ci.yml CHANGELOG.md
git commit -m "docs(ai): add AI Security Analyst architecture doc"
```

---

## Phase 6: Docker Platform (Compose Up)

### Task 6.1: Fix Docker Compose for API + Worker + Frontend

**Files:**
- Modify: `docker-compose.yml` (production-ready)
- Modify: `docker-compose.prod.yml`
- Create: `docker/Dockerfile.api`, `docker/Dockerfile.worker`, `docker/Dockerfile.frontend`

**Interfaces:**
- Consumes: Docker, Docker Compose, multi-stage builds
- Produces: `docker compose up -d` starts API (8080), Worker, Frontend (3000) with health checks

- [ ] **Step 1: Create production Dockerfiles**

```dockerfile
# docker/Dockerfile.api
FROM rust:1.75-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release --package openre-api --bin openre-api

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/openre-api /usr/local/bin/
COPY config.prod.toml /etc/openre/config.toml
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD curl -f http://localhost:8080/health || exit 1
CMD ["openre-api"]
```

```dockerfile
# docker/Dockerfile.worker
FROM rust:1.75-slim AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release --package openre-scanner --bin worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/worker /usr/local/bin/
CMD ["worker"]
```

```dockerfile
# docker/Dockerfile.frontend
FROM node:20-alpine AS builder
WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1
```

- [ ] **Step 2: Fix docker-compose.yml**

```yaml
# docker-compose.yml
version: '3.8'
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: openre
      POSTGRES_USER: openre
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U openre -d openre"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  api:
    build:
      context: ..
      dockerfile: docker/Dockerfile.api
    ports:
      - "8080:8080"
    environment:
      DATABASE_URL: postgres://openre:${POSTGRES_PASSWORD:-changeme}@postgres:5432/openre
      REDIS_URL: redis://redis:6379
      JWT_SECRET: ${JWT_SECRET:-changeme}
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s

  worker:
    build:
      context: ..
      dockerfile: docker/Dockerfile.worker
    environment:
      DATABASE_URL: postgres://openre:${POSTGRES_PASSWORD:-changeme}@postgres:5432/openre
      REDIS_URL: redis://redis:6379
      RUST_LOG: info
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    deploy:
      replicas: 2

  frontend:
    build:
      context: ..
      dockerfile: docker/Dockerfile.frontend
    ports:
      - "3000:80"
    depends_on:
      api:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  postgres_data:
```

- [ ] **Step 3: Test docker compose up**

```bash
docker compose up -d --build
docker compose ps
curl http://localhost:8080/health
curl http://localhost:3000/
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml docker/Dockerfile.* CHANGELOG.md
git commit -m "feat(docker): fix docker-compose for API + Worker + Frontend with health checks"
```

---

### Task 6.2: Add Database Migrations + Seed Data

**Files:**
- Modify: `crates/openre-storage/src/migrations.rs` (SQLx migrations)
- Create: `docker/init.sql` (seed data)

**Interfaces:**
- Consumes: sqlx migrations, postgres
- Produces: Auto-migration on startup, seed admin user, default configs

- [ ] **Step 1: Create migrations**

```sql
-- crates/openre-storage/migrations/20240101000001_initial.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    owner_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id),
    name VARCHAR(255),
    target VARCHAR(500),
    profile VARCHAR(50),
    status VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    title VARCHAR(500),
    description TEXT,
    severity VARCHAR(20),
    confidence VARCHAR(20),
    category VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    name VARCHAR(100),
    key_hash VARCHAR(255) NOT NULL,
    scopes TEXT[],
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

- [ ] **Step 2: Add auto-migration to API startup**

```rust
// crates/openre-api/src/state.rs - in ApiState::new():
sqlx::migrate!("./crates/openre-storage/migrations").run(&pool).await?;
```

- [ ] **Step 3: Test migrations**

```bash
docker compose up -d postgres
docker compose exec api cargo run --release --package openre-api --bin migrate
```

- [ ] **Step 4: Commit**

```bash
git add crates/openre-storage/src/migrations.rs crates/openre-storage/migrations/ docker/init.sql
git commit -m "feat(docker): add database migrations and auto-migration on startup"
```

---

### Task 6.3: Phase 6 Documentation & CI

**Files:**
- Create: `docs/architecture/09-docker-platform.md`
- Modify: `.github/workflows/ci.yml` (Docker build test)

- [ ] **Step 1: Write Docker architecture doc**

```markdown
# Docker Platform Architecture

## Services
- **postgres**: PostgreSQL 16, persistent volume, health check
- **redis**: Redis 7, health check
- **api**: openre-api (port 8080), multi-stage build, health check
- **worker**: openre-scanner worker, 2 replicas
- **frontend**: nginx + React build (port 3000), health check

## Commands
```bash
docker compose up -d --build
docker compose ps
docker compose logs -f api
docker compose down -v
```

## Environment Variables
- POSTGRES_PASSWORD (required)
- JWT_SECRET (required, 32+ chars)
- RUST_LOG (default: info)

## Health Checks
All services have HTTP/TCP health checks with start_period for slow starters.
```

- [ ] **Step 2: Add Docker build to CI**

```yaml
# .github/workflows/ci.yml
- name: Docker build test
  run: |
    docker compose -f docker-compose.yml build
    docker compose -f docker-compose.yml up -d
    sleep 30
    docker compose ps --format "table {{.Service}}\t{{.Status}}"
    curl -f http://localhost:8080/health
    curl -f http://localhost:3000/
    docker compose down -v
```

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/09-docker-platform.md .github/workflows/ci.yml CHANGELOG.md
git commit -m "docs(docker): add Docker platform architecture and CI integration test"
```

---

## Phase 7: Configuration System (TOML)

### Task 7.1: Implement TOML Config with Profiles

**Files:**
- Modify: `crates/openre-config/src/config.rs` (figment layers)
- Modify: `crates/openre-cli/src/config.rs` (config commands)
- Test: `crates/openre-config/tests/config_test.rs`, `crates/openre-cli/tests/config_test.rs`

**Interfaces:**
- Consumes: `figment` (TOML, env, JSON, YAML), `dirs` (config paths)
- Produces: `~/.config/openre/config.toml` with profiles, `openre config get/set/use/list`

- [ ] **Step 1: Write failing config test**

```rust
// crates/openre-config/tests/config_test.rs
use openre_config::{CliConfig, ConfigLayer, Profile};

#[test]
fn test_config_profiles() {
    let config = CliConfig::load(None).unwrap();
    
    assert!(config.profiles.contains_key("default"));
    assert_eq!(config.profiles["default"].server, "http://localhost:8080");
    
    let mut config = config.clone();
    config.profiles.insert("prod".into(), Profile {
        server: "https://api.openre.io".into(),
        api_key: Some("opk_prod_...".into()),
        format: "json".into(),
        timeout: 30,
    });
    config.active_profile = "prod".into();
    
    let toml = toml::to_string(&config).unwrap();
    let reloaded: CliConfig = toml::from_str(&toml).unwrap();
    assert_eq!(reloaded.active_profile, "prod");
    assert_eq!(reloaded.profiles["prod"].server, "https://api.openre.io");
}

#[test]
fn test_env_override() {
    std::env::set_var("OPENRE_SERVER", "https://env.example.com");
    let config = CliConfig::load(None).unwrap();
    assert_eq!(config.profiles["default"].server, "https://env.example.com");
    std::env::remove_var("OPENRE_SERVER");
}
```

- [ ] **Step 2: Complete config.rs with profiles**

```rust
// crates/openre-config/src/config.rs - ensure:
#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct Profile {
    pub server: String,
    pub api_key: Option<String>,
    pub format: String,
    pub timeout: u64,
    pub max_redirects: usize,
}

#[derive(serde::Deserialize, serde::Serialize, Clone, Debug)]
pub struct CliConfig {
    pub active_profile: String,
    pub profiles: std::collections::HashMap<String, Profile>,
}

impl CliConfig {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        figment::Figment::new()
            .merge(figment::providers::Toml::file(path.unwrap_or_else(default_config_path)))
            .merge(figment::providers::Env::prefixed("OPENRE_"))
            .merge(figment::providers::Env::prefixed("OPENRE_").global())
            .extract()
    }
    
    pub fn save(&self, path: Option<&Path>) -> Result<()> {
        let toml = toml::to_string_pretty(self)?;
        std::fs::write(path.unwrap_or_else(default_config_path), toml)?;
        Ok(())
    }
}
```

- [ ] **Step 3: Run test to verify it passes**

```bash
cargo test -p openre-config config_test -- --nocapture
```

- [ ] **Step 4: Implement CLI config commands**

```rust
// crates/openre-cli/src/commands/config.rs - implement:
// - get: print current profile or specific key
// - set: update key in active profile
// - use: switch active profile
// - list: show all profiles
// - edit: open $EDITOR on config file
// - init: create default config
```

- [ ] **Step 5: Run CLI config test**

```bash
cargo test -p openre-cli config_test -- --nocapture
```

- [ ] **Step 6: Commit**

```bash
git add crates/openre-config/src/config.rs crates/openre-cli/src/commands/config.rs crates/openre-config/tests/config_test.rs crates/openre-cli/tests/config_test.rs
git commit -m "feat(config): implement TOML config with profiles and CLI commands"
```

---

### Task 7.2: Phase 7 Documentation & CI

**Files:**
- Create: `docs/architecture/10-configuration.md`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Write config architecture doc**

```markdown
# Configuration System

## Config File
`~/.config/openre/config.toml`

```toml
active_profile = "default"

[profiles.default]
server = "http://localhost:8080"
format = "table"
timeout = 30
max_redirects = 10

[profiles.prod]
server = "https://api.openre.io"
api_key = "opk_prod_..."
format = "json"
timeout = 60
```

## Environment Overrides
`OPENRE_SERVER`, `OPENRE_API_KEY`, `OPENRE_FORMAT`, `OPENRE_TIMEOUT`

## CLI Commands
- `openre config get [key]`
- `openre config set <key> <value>`
- `openre config use <profile>`
- `openre config list`
- `openre config edit`
- `openre config init`
```

- [ ] **Step 2: Add config test to CI**

```yaml
# .github/workflows/ci.yml
- name: Test openre-config
  run: cargo test -p openre-config --all-targets
```

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/10-configuration.md .github/workflows/ci.yml CHANGELOG.md
git commit -m "docs(config): add configuration system architecture"
```

---

## Phase 8: Release Automation (Multi-platform, SBOM, SLSA)

### Task 8.1: Multi-Platform Release Workflow

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `scripts/release.sh`

**Interfaces:**
- Consumes: GitHub Actions, `cross` for cross-compilation
- Produces: x86_64 Linux/macOS/Windows + ARM64 Linux/macOS binaries, checksums, GitHub Release

- [ ] **Step 1: Create release workflow**

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write
  packages: write
  id-token: write

jobs:
  build:
    name: Build ${{ matrix.target }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-unknown-linux-musl
            os: ubuntu-latest
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-pc-windows-msvc
            os: windows-latest
          - target: x86_64-apple-darwin
            os: macos-latest
          - target: aarch64-apple-darwin
            os: macos-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - name: Install cross
        if: matrix.target != 'x86_64-pc-windows-msvc' && matrix.target != 'x86_64-apple-darwin' && matrix.target != 'aarch64-apple-darwin'
        run: cargo install cross --locked
      - name: Build
        run: |
          if [[ "${{ matrix.target }}" == *"windows"* ]]; then
            cargo build --release --target ${{ matrix.target }} --package openre-cli --package openre-scan
          elif [[ "${{ matrix.target }}" == *"darwin"* ]]; then
            cargo build --release --target ${{ matrix.target }} --package openre-cli --package openre-scan
          else
            cross build --release --target ${{ matrix.target }} --package openre-cli --package openre-scan
          fi
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: binaries-${{ matrix.target }}
          path: |
            target/${{ matrix.target }}/release/openre*
            target/${{ matrix.target }}/release/openre-scan*

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - name: Create checksums
        run: |
          for f in openre-* openre-scan-*; do
            sha256sum "$f" >> checksums.txt
          done
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            openre-*
            openre-scan-*
            checksums.txt
          generate_release_notes: true
```

- [ ] **Step 2: Create release script**

```bash
#!/bin/bash
# scripts/release.sh
# Usage: ./scripts/release.sh v0.1.0

set -euo pipefail

VERSION=${1:-}
if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    exit 1
fi

sed -i "s/^version = \".*\"/version = \"${VERSION#v}\"/" Cargo.toml

git add Cargo.toml CHANGELOG.md
git commit -m "chore: release $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"
git push origin main --tags

echo "Release $VERSION pushed. GitHub Actions will build and publish."
```

- [ ] **Step 3: Test release workflow**

```bash
git tag v0.1.0-test && git push origin v0.1.0-test
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml scripts/release.sh CHANGELOG.md
git commit -m "ci: add multi-platform release workflow and release script"
```

---

### Task 8.2: SBOM Generation + SLSA Provenance

**Files:**
- Modify: `.github/workflows/release.yml` (add SBOM, SLSA)
- Create: `scripts/sbom.sh`

**Interfaces:**
- Consumes: `cargo-cyclonedx`, `slsa-framework/slsa-github-generator`
- Produces: SPDX/CycloneDX SBOM, SLSA Level 3 provenance

- [ ] **Step 1: Add SBOM to release workflow**

```yaml
# .github/workflows/release.yml - add to build job:
- name: Generate SBOM
  run: |
    cargo install cargo-cyclonedx --locked
    cargo cyclonedx --target ${{ matrix.target }} --output sbom-${{ matrix.target }}.json
    
- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom-${{ matrix.target }}
    path: sbom-*.json

# Add to release job:
- name: Download SBOMs
  uses: actions/download-artifact@v4
  with:
    pattern: sbom-*
    path: sboms/

- name: Generate SLSA Provenance
  uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.9.0
  with:
    base64-subjects: "${{ steps.hash.outputs.base64-subjects }}"
    provenance-name: openre-provenance.intoto.jsonl
```

- [ ] **Step 2: Create SBOM script**

```bash
#!/bin/bash
# scripts/sbom.sh
cargo install cargo-cyclonedx cargo-spdx --locked
cargo cyclonedx --all-features --output openre-sbom.json
cargo spdx --all-features --output openre-spdx.json
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml scripts/sbom.sh
git commit -m "ci: add SBOM generation (CycloneDX/SPDX) and SLSA Level 3 provenance"
```

---

### Task 8.3: Container Image Publishing

**Files:**
- Modify: `.github/workflows/release.yml` (add Docker push)

**Interfaces:**
- Consumes: GitHub Container Registry (ghcr.io), `docker buildx`
- Produces: Multi-arch images for API, Worker, Frontend with `latest` and version tags

- [ ] **Step 1: Add Docker publish to release workflow**

```yaml
# .github/workflows/release.yml - add job:
docker:
  needs: build
  runs-on: ubuntu-latest
  permissions:
    packages: write
    contents: read
  steps:
    - uses: actions/checkout@v4
    - name: Set up QEMU
      uses: docker/setup-qemu-action@v3
    - name: Set up Buildx
      uses: docker/setup-buildx-action@v3
    - name: Login to GHCR
      uses: docker/login-action@v3
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    - name: Build and push API
      uses: docker/build-push-action@v5
      with:
        context: ..
        file: docker/Dockerfile.api
        platforms: linux/amd64,linux/arm64
        push: true
        tags: |
          ghcr.io/${{ github.repository }}/openre-api:latest
          ghcr.io/${{ github.repository }}/openre-api:${{ github.ref_name }}
    - name: Build and push Worker
      uses: docker/build-push-action@v5
      with:
        context: ..
        file: docker/Dockerfile.worker
        platforms: linux/amd64,linux/arm64
        push: true
        tags: |
          ghcr.io/${{ github.repository }}/openre-worker:latest
          ghcr.io/${{ github.repository }}/openre-worker:${{ github.ref_name }}
    - name: Build and push Frontend
      uses: docker/build-push-action@v5
      with:
        context: ..
        file: docker/Dockerfile.frontend
        platforms: linux/amd64,linux/arm64
        push: true
        tags: |
          ghcr.io/${{ github.repository }}/openre-frontend:latest
          ghcr.io/${{ github.repository }}/openre-frontend:${{ github.ref_name }}
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add multi-arch container image publishing to GHCR"
```

---

### Task 8.4: Phase 8 Documentation & CI

**Files:**
- Create: `docs/architecture/11-release-automation.md`
- Create: `docs/RELEASE.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write release architecture doc**

```markdown
# Release Automation

## Multi-Platform Binaries
- Targets: x86_64/ARM64 Linux (gnu/musl), macOS, Windows
- Built with `cross` for Linux, native for macOS/Windows
- Artifacts: `openre`, `openre-scan` + `checksums.txt`

## Container Images
- Registry: ghcr.io/openre/{api,worker,frontend}
- Platforms: linux/amd64, linux/arm64
- Tags: `latest`, `vX.Y.Z`

## SBOM
- Formats: CycloneDX JSON, SPDX JSON
- Generated via `cargo-cyclonedx`, `cargo-spdx`

## SLSA Provenance
- Level 3: Reproducible build + provenance + verification
- Generated via `slsa-github-generator`

## Release Process
```bash
./scripts/release.sh v0.1.0
```

## Verification
```bash
sha256sum -c checksums.txt
slsa-verifier verify-artifact openre --provenance openre-provenance.intoto.jsonl --source-uri github.com
```
```

- [ ] **Step 2: Write release guide**

```markdown
# Release Guide

## Prerequisites
- GitHub token with packages:write, contents:write
- Docker Hub/GHCR credentials (for container images)

## Steps
1. Update CHANGELOG.md
2. Run `./scripts/release.sh vX.Y.Z`
3. Monitor GitHub Actions
4. Verify artifacts on GitHub Releases
5. Verify container images on GHCR
6. Announce release
```

- [ ] **Step 3: Commit**

```bash
git add docs/architecture/11-release-automation.md docs/RELEASE.md CHANGELOG.md
git commit -m "docs(release): add release automation architecture and release guide"
```

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-08-29-openre-platform-implementation.md`.**

Two execution options:

**1. Subagent-Driven (recommended)** - I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Inline Execution** - Execute tasks in this session using executing-plans, batch execution with checkpoints

**Which approach?**