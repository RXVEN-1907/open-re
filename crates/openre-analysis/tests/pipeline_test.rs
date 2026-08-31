// crates/openre-analysis/tests/pipeline_test.rs
use openre_analysis::orchestrator::{default_pipeline_stages, ExecutorConfig};
use openre_core::ids::{AnalysisId, StageId, StageName};
use openre_telemetry::TelemetryHandle;
use std::sync::Arc;

#[tokio::test]
async fn test_default_pipeline_stages() {
    let stages = default_pipeline_stages();
    assert_eq!(stages.len(), 9);

    let expected = vec![
        "identification",
        "loading",
        "disassembly",
        "control_flow",
        "data_flow",
        "type_recovery",
        "decompilation",
        "ai_enrichment",
        "finalization",
    ];

    for (i, stage) in stages.iter().enumerate() {
        assert_eq!(stage.id().as_str(), expected[i]);
    }
}

#[tokio::test]
async fn test_pipeline_creation() {
    let stages = default_pipeline_stages();
    assert_eq!(stages.len(), 9);

    // Verify all expected stages are present
    let stage_names: Vec<String> = stages.iter().map(|s| s.id().as_str().to_string()).collect();
    let expected = vec![
        "identification",
        "loading",
        "disassembly",
        "control_flow",
        "data_flow",
        "type_recovery",
        "decompilation",
        "ai_enrichment",
        "finalization",
    ];

    assert_eq!(stage_names, expected);
}

#[tokio::test]
async fn test_pipeline_stages_have_correct_dependencies() {
    let stages = default_pipeline_stages();

    // Check identification has no dependencies
    let id_stage = stages.iter().find(|s| s.id().as_str() == "identification").unwrap();
    assert_eq!(id_stage.dependencies().len(), 0);

    // Check loading depends on identification
    let load_stage = stages.iter().find(|s| s.id().as_str() == "loading").unwrap();
    assert_eq!(load_stage.dependencies().len(), 1);
    assert!(load_stage.dependencies().contains(&StageId::new("identification")));

    // Check disassembly depends on loading
    let disasm_stage = stages.iter().find(|s| s.id().as_str() == "disassembly").unwrap();
    assert_eq!(disasm_stage.dependencies().len(), 1);
    assert!(disasm_stage.dependencies().contains(&StageId::new("loading")));

    // Check control_flow depends on disassembly
    let cf_stage = stages.iter().find(|s| s.id().as_str() == "control_flow").unwrap();
    assert_eq!(cf_stage.dependencies().len(), 1);
    assert!(cf_stage.dependencies().contains(&StageId::new("disassembly")));

    // Check data_flow depends on control_flow
    let df_stage = stages.iter().find(|s| s.id().as_str() == "data_flow").unwrap();
    assert_eq!(df_stage.dependencies().len(), 1);
    assert!(df_stage.dependencies().contains(&StageId::new("control_flow")));

    // Check type_recovery depends on control_flow and data_flow
    let tr_stage = stages.iter().find(|s| s.id().as_str() == "type_recovery").unwrap();
    assert_eq!(tr_stage.dependencies().len(), 1);
    assert!(tr_stage.dependencies().contains(&StageId::new("data_flow")));

    // Check decompilation depends on type_recovery
    let dec_stage = stages.iter().find(|s| s.id().as_str() == "decompilation").unwrap();
    assert_eq!(dec_stage.dependencies().len(), 1);
    assert!(dec_stage.dependencies().contains(&StageId::new("type_recovery")));

    // Check ai_enrichment depends on decompilation
    let ai_stage = stages.iter().find(|s| s.id().as_str() == "ai_enrichment").unwrap();
    assert_eq!(ai_stage.dependencies().len(), 1);
    assert!(ai_stage.dependencies().contains(&StageId::new("decompilation")));

    // Check finalization depends on ai_enrichment
    let fin_stage = stages.iter().find(|s| s.id().as_str() == "finalization").unwrap();
    assert_eq!(fin_stage.dependencies().len(), 1);
    assert!(fin_stage.dependencies().contains(&StageId::new("ai_enrichment")));
}
