# Analysis Pipeline

## Overview

The analysis pipeline is the core processing engine that transforms a raw binary into a fully analyzed, AI-enriched project. It follows a **stage-based, DAG-driven** architecture where each stage is a replaceable plugin, enabling parallel execution, incremental re-analysis, and graceful degradation.

---

## Pipeline Architecture

```mermaid
graph TB
    subgraph "Pipeline Orchestrator"
        PO[Pipeline Orchestrator<br/>DAG Construction, Scheduling]
        SE[Stage Executor<br/>Timeout, Retry, Cancellation]
        PT[Progress Tracker<br/>Real-time Events]
        AC[Artifact Collector<br/>Results Aggregation]
    end
    
    subgraph "Stage 1: Identification"
        ID1[Format Detection]
        ID2[Architecture Detection]
        ID3[Compiler/Packer Detection]
        ID4[Metadata Extraction]
    end
    
    subgraph "Stage 2: Loading"
        LD1[Binary Parsing]
        LD2[Section/Segment Mapping]
        LD3[Symbol Extraction]
        LD4[Resource Extraction]
    end
    
    subgraph "Stage 3: Disassembly"
        DS1[Linear Sweep]
        DS2[Recursive Traversal]
        DS3[Function Boundary Detection]
        DS4[Instruction Semantics]
    end
    
    subgraph "Stage 4: Control Flow"
        CF1[CFG Construction]
        CF2[Call Graph Building]
        CF3[Indirect Call Resolution]
        CF4[Loop Detection]
    end
    
    subgraph "Stage 5: Data Flow"
        DF1[SSA Construction]
        DF2[Value Set Analysis]
        DF3[Reaching Definitions]
        DF4[Taint Analysis]
    end
    
    subgraph "Stage 6: Type Recovery"
        TR1[Type Inference]
        TR2[Struct/Array Reconstruction]
        TR2b[Function Signature Recovery]
        TR3[C Header Import]
    end
    
    subgraph "Stage 7: Decompilation"
        DC1[IL Lifting (LLIL→MLIL→HLIL)]
        DC2[Control Structure Recovery]
        DC3[Variable Naming]
        DC4[Pseudocode Generation]
    end
    
    subgraph "Stage 8: AI Enrichment"
        AI1[Function Classification]
        AI2[Name/Type Suggestions]
        AI3[Crypto Detection]
        AI4[Obfuscation Detection]
        AI5[Vulnerability Patterns]
    end
    
    subgraph "Stage 9: Finalization"
        FN1[Cross-Reference Resolution]
        FN2[Annotation Persistence]
        FN3[Index Building]
        FN4[Export Preparation]
    end
    
    PO --> ID1
    ID1 --> ID2
    ID2 --> ID3
    ID3 --> ID4
    ID4 --> LD1
    LD1 --> LD2
    LD2 --> LD3
    LD3 --> LD4
    LD4 --> DS1
    DS1 --> DS2
    DS2 --> DS3
    DS3 --> DS4
    DS4 --> CF1
    CF1 --> CF2
    CF2 --> CF3
    CF3 --> CF4
    CF4 --> DF1
    DF1 --> DF2
    DF2 --> DF3
    DF3 --> DF4
    DF4 --> TR1
    TR1 --> TR2
    TR2 --> TR2b
    TR2b --> TR3
    TR3 --> DC1
    DC1 --> DC2
    DC2 --> DC3
    DC3 --> DC4
    DC4 --> AI1
    AI1 --> AI2
    AI2 --> AI3
    AI3 --> AI4
    AI4 --> AI5
    AI5 --> FN1
    FN1 --> FN2
    FN2 --> FN3
    FN3 --> FN4
    
    SE -.->|Manages| ID1
    SE -.->|Manages| LD1
    SE -.->|Manages| DS1
    SE -.->|Manages| CF1
    SE -.->|Manages| DF1
    SE -.->|Manages| TR1
    SE -.->|Manages| DC1
    SE -.->|Manages| AI1
    SE -.->|Manages| FN1
    
    PT -.->|Tracks| SE
    AC -.->|Collects| FN4
```

---

## Pipeline Configuration

```rust
// crates/openre-analysis/src/pipeline_config.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    pub stages: Vec<StageConfig>,
    pub parallelism: ParallelismConfig,
    pub timeouts: TimeoutConfig,
    pub retries: RetryConfig,
    pub ai: AiConfig,
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageConfig {
    pub name: StageName,
    pub enabled: bool,
    pub required: bool,           // If true, failure stops pipeline
    pub plugin_id: Option<PluginId>, // Override default plugin
    pub config: serde_json::Value,   // Stage-specific config
    pub depends_on: Vec<StageName>,  // Explicit dependencies
    pub parallel_group: Option<String>, // Stages in same group run in parallel
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelismConfig {
    pub max_concurrent_stages: usize,
    pub max_concurrent_functions: usize,
    pub work_stealing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    pub stage_default_secs: u64,
    pub stage_overrides: HashMap<StageName, u64>,
    pub pipeline_total_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
    pub exponential_base: f64,
    pub retryable_errors: Vec<String>,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            stages: vec![
                StageConfig { name: StageName::Identification, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::Loading, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::Disassembly, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::ControlFlow, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::DataFlow, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::TypeRecovery, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::Decompilation, enabled: true, required: true, ..Default::default() },
                StageConfig { name: StageName::AiEnrichment, enabled: true, required: false, ..Default::default() },
                StageConfig { name: StageName::Finalization, enabled: true, required: true, ..Default::default() },
            ],
            parallelism: ParallelismConfig {
                max_concurrent_stages: 4,
                max_concurrent_functions: 16,
                work_stealing: true,
            },
            timeouts: TimeoutConfig {
                stage_default_secs: 300,
                stage_overrides: {
                    let mut m = HashMap::new();
                    m.insert(StageName::Decompilation, 600);
                    m.insert(StageName::AiEnrichment, 120);
                    m
                },
                pipeline_total_secs: 3600,
            },
            retries: RetryConfig {
                max_attempts: 3,
                base_delay_secs: 5,
                max_delay_secs: 60,
                exponential_base: 2.0,
                retryable_errors: vec!["timeout".into(), "resource_exhausted".into(), "plugin_crash".into()],
            },
            ai: AiConfig::default(),
            output: OutputConfig::default(),
        }
    }
}
```

---

## Stage Definitions

### Stage 1: Identification

```rust
// crates/openre-analysis/src/stages/identification.rs
pub struct IdentificationStage {
    format_detector: Arc<FormatDetector>,
    architecture_detector: Arc<ArchitectureDetector>,
    packer_detector: Arc<PackerDetector>,
    compiler_fingerprinter: Arc<CompilerFingerprinter>,
}

#[async_trait]
impl AnalysisStage for IdentificationStage {
    fn name(&self) -> StageName { StageName::Identification }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let binary = ctx.file_service.get_binary(ctx.file_id).await?;
        
        // 1. Format detection
        let format = self.format_detector.detect(&binary).await?;
        ctx.set_metadata("format", format.clone());
        
        // 2. Architecture detection
        let arch = self.architecture_detector.detect(&binary, &format).await?;
        ctx.set_metadata("architecture", arch.clone());
        
        // 3. Packer/protector detection
        let packer = self.packer_detector.detect(&binary).await?;
        if let Some(p) = packer {
            ctx.set_metadata("packer", p);
            ctx.add_tag("packed");
        }
        
        // 4. Compiler fingerprinting
        let compiler = self.compiler_fingerprinter.fingerprint(&binary).await?;
        ctx.set_metadata("compiler", compiler);
        
        // 5. Entry point detection
        let entry_points = self.find_entry_points(&binary, &format, &arch).await?;
        ctx.set_metadata("entry_points", entry_points);
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::Metadata("format".into(), format),
                Artifact::Metadata("architecture".into(), arch),
                Artifact::EntryPoints(entry_points),
            ],
            next_stages: vec![StageName::Loading],
        })
    }
}
```

### Stage 2: Loading

```rust
// crates/openre-analysis/src/stages/loading.rs
pub struct LoadingStage {
    loader_registry: Arc<LoaderRegistry>,
    section_mapper: Arc<SectionMapper>,
    symbol_extractor: Arc<SymbolExtractor>,
    resource_extractor: Arc<ResourceExtractor>,
}

#[async_trait]
impl AnalysisStage for LoadingStage {
    fn name(&self) -> StageName { StageName::Loading }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let format = ctx.get_metadata::<BinaryFormat>("format")?;
        let binary = ctx.file_service.get_binary(ctx.file_id).await?;
        
        // 1. Select and invoke loader plugin
        let loader = self.loader_registry.get_loader(&format).await?;
        let loaded = loader.load(&binary, LoadOptions::default()).await?;
        
        // 2. Map sections/segments
        let memory_map = self.section_mapper.map(&loaded).await?;
        ctx.set_metadata("memory_map", memory_map.clone());
        
        // 3. Extract symbols
        let symbols = self.symbol_extractor.extract(&loaded, &memory_map).await?;
        ctx.set_metadata("symbols", symbols.clone());
        
        // 4. Extract resources (embedded files, certs, configs)
        let resources = self.resource_extractor.extract(&loaded).await?;
        if !resources.is_empty() {
            ctx.set_metadata("resources", resources.clone());
        }
        
        // 5. Store loaded binary in project DB
        ctx.project_db.store_loaded_binary(ctx.file_id, &loaded).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::LoadedBinary(loaded),
                Artifact::MemoryMap(memory_map),
                Artifact::Symbols(symbols),
            ],
            next_stages: vec![StageName::Disassembly],
        })
    }
}
```

### Stage 3: Disassembly

```rust
// crates/openre-analysis/src/stages/disassembly.rs
pub struct DisassemblyStage {
    disassembler_registry: Arc<DisassemblerRegistry>,
    function_detector: Arc<FunctionDetector>,
    instruction_semantics: Arc<InstructionSemantics>,
    parallel_executor: Arc<ParallelExecutor>,
}

#[async_trait]
impl AnalysisStage for DisassemblyStage {
    fn name(&self) -> StageName { StageName::Disassembly }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let arch = ctx.get_metadata::<Architecture>("architecture")?;
        let memory_map = ctx.get_metadata::<MemoryMap>("memory_map")?;
        let entry_points = ctx.get_metadata::<Vec<Address>>("entry_points")?;
        
        // 1. Select disassembler plugin
        let disassembler = self.disassembler_registry.get_disassembler(&arch).await?;
        
        // 2. Disassemble in parallel (work-stealing)
        let disassembly = self.parallel_executor.execute(
            |chunk| disassembler.disassemble_chunk(chunk),
            memory_map.executable_sections(),
            DisassemblyOptions {
                strategy: DisassemblyStrategy::Recursive { entry_points },
                include_semantics: true,
                track_overlapping: true,
            },
        ).await?;
        
        // 3. Function boundary detection (ML-enhanced)
        let functions = self.function_detector.detect(&disassembly, &entry_points).await?;
        
        // 4. Build instruction semantics
        let semantics = self.instruction_semantics.build(&disassembly).await?;
        
        // 5. Store in project DB
        ctx.project_db.store_disassembly(ctx.file_id, &disassembly).await?;
        ctx.project_db.store_functions(ctx.file_id, &functions).await?;
        ctx.project_db.store_semantics(ctx.file_id, &semantics).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::Disassembly(disassembly),
                Artifact::Functions(functions),
                Artifact::InstructionSemantics(semantics),
            ],
            next_stages: vec![StageName::ControlFlow],
        })
    }
}
```

### Stage 4: Control Flow

```rust
// crates/openre-analysis/src/stages/control_flow.rs
pub struct ControlFlowStage {
    cfg_builder: Arc<CfgBuilder>,
    call_graph_builder: Arc<CallGraphBuilder>,
    indirect_call_resolver: Arc<IndirectCallResolver>,
    loop_analyzer: Arc<LoopAnalyzer>,
}

#[async_trait]
impl AnalysisStage for ControlFlowStage {
    fn name(&self) -> StageName { StageName::ControlFlow }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let functions = ctx.project_db.get_functions(ctx.file_id).await?;
        let disassembly = ctx.project_db.get_disassembly(ctx.file_id).await?;
        let semantics = ctx.project_db.get_semantics(ctx.file_id).await?;
        
        // 1. Build CFG for each function (parallel)
        let cfgs = self.parallel_executor.execute(
            |func| self.cfg_builder.build(func, &disassembly, &semantics),
            functions,
            CfgOptions { detect_loops: true, detect_exceptions: true },
        ).await?;
        
        // 2. Build call graph
        let call_graph = self.call_graph_builder.build(&functions, &cfgs).await?;
        
        // 3. Resolve indirect calls (vtable, jump tables, function pointers)
        let resolved_calls = self.indirect_call_resolver.resolve(&call_graph, &disassembly).await?;
        
        // 4. Loop analysis
        let loops = self.loop_analyzer.analyze(&cfgs).await?;
        
        // 5. Exception handling flow
        let exception_flow = self.analyze_exceptions(&cfgs, &disassembly).await?;
        
        // 6. Store
        ctx.project_db.store_cfgs(ctx.file_id, &cfgs).await?;
        ctx.project_db.store_call_graph(ctx.file_id, &call_graph).await?;
        ctx.project_db.store_loops(ctx.file_id, &loops).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::ControlFlowGraphs(cfgs),
                Artifact::CallGraph(call_graph),
                Artifact::ResolvedCalls(resolved_calls),
                Artifact::Loops(loops),
            ],
            next_stages: vec![StageName::DataFlow],
        })
    }
}
```

### Stage 5: Data Flow

```rust
// crates/openre-analysis/src/stages/data_flow.rs
pub struct DataFlowStage {
    ssa_builder: Arc<SsaBuilder>,
    vsa_analyzer: Arc<VsaAnalyzer>,
    reaching_defs: Arc<ReachingDefinitions>,
    taint_analyzer: Arc<TaintAnalyzer>,
}

#[async_trait]
impl AnalysisStage for DataFlowStage {
    fn name(&self) -> StageName { StageName::DataFlow }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let cfgs = ctx.project_db.get_cfgs(ctx.file_id).await?;
        let semantics = ctx.project_db.get_semantics(ctx.file_id).await?;
        
        // 1. Build SSA form (parallel per function)
        let ssa_functions = self.parallel_executor.execute(
            |(func, cfg)| self.ssa_builder.build(func, cfg, &semantics),
            cfgs.into_iter().map(|(id, cfg)| (ctx.get_function(id).unwrap(), cfg)),
            SsaOptions { minimal: false, prune_dead: true },
        ).await?;
        
        // 2. Value Set Analysis (abstract interpretation)
        let vsa_results = self.vsa_analyzer.analyze(&ssa_functions).await?;
        
        // 3. Reaching Definitions
        let reaching_defs = self.reaching_defs.compute(&ssa_functions).await?;
        
        // 4. Taint Analysis (if enabled)
        let taint_results = if ctx.config.enable_taint {
            Some(self.taint_analyzer.analyze(&ssa_functions, &vsa_results).await?)
        } else { None };
        
        // 5. Store
        ctx.project_db.store_ssa(ctx.file_id, &ssa_functions).await?;
        ctx.project_db.store_vsa(ctx.file_id, &vsa_results).await?;
        ctx.project_db.store_reaching_defs(ctx.file_id, &reaching_defs).await?;
        if let Some(taint) = taint_results {
            ctx.project_db.store_taint(ctx.file_id, &taint).await?;
        }
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::SsaFunctions(ssa_functions),
                Artifact::VsaResults(vsa_results),
                Artifact::ReachingDefinitions(reaching_defs),
            ],
            next_stages: vec![StageName::TypeRecovery],
        })
    }
}
```

### Stage 6: Type Recovery

```rust
// crates/openre-analysis/src/stages/type_recovery.rs
pub struct TypeRecoveryStage {
    type_inference: Arc<TypeInference>,
    struct_reconstructor: Arc<StructReconstructor>,
    signature_recovery: Arc<SignatureRecovery>,
    header_importer: Arc<HeaderImporter>,
}

#[async_trait]
impl AnalysisStage for TypeRecoveryStage {
    fn name(&self) -> StageName { StageName::TypeRecovery }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let ssa_functions = ctx.project_db.get_ssa_functions(ctx.file_id).await?;
        let vsa_results = ctx.project_db.get_vsa(ctx.file_id).await?;
        let symbols = ctx.get_metadata::<Symbols>("symbols")?;
        
        // 1. Import type libraries (C headers, PDB, DWARF)
        let type_libraries = self.header_importer.import_all(&symbols).await?;
        
        // 2. Constraint-based type inference (interprocedural)
        let inferred_types = self.type_inference.infer(&ssa_functions, &vsa_results, &type_libraries).await?;
        
        // 3. Struct/array reconstruction from access patterns
        let structs = self.struct_reconstructor.reconstruct(&inferred_types, &ssa_functions).await?;
        
        // 4. Function signature recovery
        let signatures = self.signature_recovery.recover(&inferred_types, &ssa_functions).await?;
        
        // 5. Type propagation across call graph
        let propagated = self.propagate_types(&inferred_types, &signatures).await?;
        
        // 6. Store
        ctx.project_db.store_types(ctx.file_id, &propagated).await?;
        ctx.project_db.store_structs(ctx.file_id, &structs).await?;
        ctx.project_db.store_signatures(ctx.file_id, &signatures).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::Types(propagated),
                Artifact::Structs(structs),
                Artifact::Signatures(signatures),
            ],
            next_stages: vec![StageName::Decompilation],
        })
    }
}
```

### Stage 7: Decompilation

```rust
// crates/openre-analysis/src/stages/decompilation.rs
pub struct DecompilationStage {
    il_lifter: Arc<IlLifter>,
    struct_recovery: Arc<StructRecovery>,
    control_structure: Arc<ControlStructureRecovery>,
    pseudocode_generator: Arc<PseudocodeGenerator>,
    variable_namer: Arc<VariableNamer>,
}

#[async_trait]
impl AnalysisStage for DecompilationStage {
    fn name(&self) -> StageName { StageName::Decompilation }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let ssa_functions = ctx.project_db.get_ssa_functions(ctx.file_id).await?;
        let types = ctx.project_db.get_types(ctx.file_id).await?;
        let structs = ctx.project_db.get_structs(ctx.file_id).await?;
        
        // 1. IL Lifting: LLIL → MLIL → HLIL (parallel per function)
        let hlil_functions = self.parallel_executor.execute(
            |(func, ssa)| self.il_lifter.lift(func, ssa, &types),
            ssa_functions,
            LifterOptions { optimize: true, simplify: true },
        ).await?;
        
        // 2. Control structure recovery (if/while/for/switch)
        let structured = self.parallel_executor.execute(
            |func| self.control_structure.recover(func),
            hlil_functions,
            StructRecoveryOptions { aggressive: false },
        ).await?;
        
        // 3. Variable naming (semantic + AI-assisted)
        let named = self.parallel_executor.execute(
            |func| self.variable_namer.name(func, &types),
            structured,
            NamingOptions { use_ai: true },
        ).await?;
        
        // 4. Pseudocode generation
        let pseudocode = self.parallel_executor.execute(
            |func| self.pseudocode_generator.generate(func),
            named,
            GeneratorOptions { style: PseudocodeStyle::CLike },
        ).await?;
        
        // 5. Store
        ctx.project_db.store_decompilation(ctx.file_id, &pseudocode).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::Decompilation(pseudocode),
            ],
            next_stages: vec![StageName::AiEnrichment],
        })
    }
}
```

### Stage 8: AI Enrichment

```rust
// crates/openre-analysis/src/stages/ai_enrichment.rs
pub struct AiEnrichmentStage {
    ai_service: Arc<AiService>,
    annotation_store: Arc<AnnotationStore>,
}

#[async_trait]
impl AnalysisStage for AiEnrichmentStage {
    fn name(&self) -> StageName { StageName::AiEnrichment }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        let functions = ctx.project_db.get_functions(ctx.file_id).await?;
        let pseudocode = ctx.project_db.get_decompilation(ctx.file_id).await?;
        
        let mut all_annotations = Vec::new();
        
        // Process functions in batches for AI efficiency
        for batch in functions.chunks(10) {
            let annotations = self.process_batch(batch, &pseudocode).await?;
            all_annotations.extend(annotations);
        }
        
        // Store AI annotations
        self.annotation_store.store_batch(ctx.file_id, &all_annotations).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::AiAnnotations(all_annotations),
            ],
            next_stages: vec![StageName::Finalization],
        })
    }
    
    async fn process_batch(
        &self,
        functions: &[Function],
        pseudocode: &HashMap<FunctionId, Pseudocode>,
    ) -> Result<Vec<Annotation>, AiError> {
        let mut annotations = Vec::new();
        
        for func in functions {
            let pseudo = pseudocode.get(&func.id);
            
            // 1. Function classification
            if let Ok(classification) = self.ai_service.classify_function(FunctionContext {
                function_id: func.id,
                assembly: func.assembly.clone(),
                pseudocode: pseudo.map(|p| p.code.clone()),
                cfg: func.cfg.clone(),
                calls: func.calls.clone(),
                strings: func.strings.clone(),
                constants: func.constants.clone(),
                metadata: func.metadata.clone(),
            }).await {
                annotations.push(Annotation {
                    target: AnnotationTarget::Function(func.id),
                    type: AnnotationType::Classification,
                    data: serde_json::to_value(classification)?,
                    source: AnnotationSource::Ai,
                    confidence: classification.confidence,
                });
            }
            
            // 2. Name suggestions
            if let Ok(names) = self.ai_service.suggest_names(NamingContext {
                function_id: func.id,
                pseudocode: pseudo.map(|p| p.code.clone()),
                cfg: func.cfg.clone(),
                variables: func.variables.clone(),
            }).await {
                for name in names {
                    annotations.push(Annotation {
                        target: AnnotationTarget::Variable(name.variable_id),
                        type: AnnotationType::Name,
                        data: serde_json::to_value(name)?,
                        source: AnnotationSource::Ai,
                        confidence: name.confidence,
                    });
                }
            }
            
            // 3. Type suggestions
            if let Ok(types) = self.ai_service.suggest_types(TypeContext { ... }).await {
                for ty in types {
                    annotations.push(Annotation { ... });
                }
            }
            
            // 4. Crypto detection
            if let Ok(crypto) = self.ai_service.detect_crypto(CryptoContext { ... }).await {
                for c in crypto {
                    annotations.push(Annotation { ... });
                }
            }
            
            // 5. Obfuscation detection
            if let Ok(obf) = self.ai_service.detect_obfuscation(ObfuscationContext { ... }).await {
                if obf.detected {
                    annotations.push(Annotation { ... });
                }
            }
        }
        
        Ok(annotations)
    }
}
```

### Stage 9: Finalization

```rust
// crates/openre-analysis/src/stages/finalization.rs
pub struct FinalizationStage {
    xref_resolver: Arc<XrefResolver>,
    index_builder: Arc<IndexBuilder>,
    export_preparer: Arc<ExportPreparer>,
}

#[async_trait]
impl AnalysisStage for FinalizationStage {
    fn name(&self) -> StageName { StageName::Finalization }
    
    async fn execute(&self, ctx: &mut StageContext) -> Result<StageOutput, StageError> {
        // 1. Resolve all cross-references
        let xrefs = self.xref_resolver.resolve_all(ctx.file_id).await?;
        ctx.project_db.store_xrefs(ctx.file_id, &xrefs).await?;
        
        // 2. Build search indexes
        let indexes = self.index_builder.build_all(ctx.file_id).await?;
        ctx.project_db.store_indexes(ctx.file_id, &indexes).await?;
        
        // 3. Prepare exports
        let exports = self.export_preparer.prepare(ctx.file_id).await?;
        
        // 4. Mark analysis complete
        ctx.project_db.mark_analysis_complete(ctx.file_id).await?;
        
        // 5. Compute final statistics
        let stats = self.compute_statistics(ctx.file_id).await?;
        
        Ok(StageOutput {
            artifacts: vec![
                Artifact::CrossReferences(xrefs),
                Artifact::Indexes(indexes),
                Artifact::Exports(exports),
                Artifact::Statistics(stats),
            ],
            next_stages: vec![],
        })
    }
}
```

---

## Pipeline Orchestrator

```rust
// crates/openre-analysis/src/pipeline_orchestrator.rs
pub struct PipelineOrchestrator {
    stages: Vec<Box<dyn AnalysisStage>>,
    stage_executor: Arc<StageExecutor>,
    progress_tracker: Arc<ProgressTracker>,
    artifact_collector: Arc<ArtifactCollector>,
    dag: StageDag,
}

impl PipelineOrchestrator {
    pub fn new(config: AnalysisConfig, services: ServiceContainer) -> Result<Self, OrchestratorError> {
        // Build stage DAG from config
        let dag = StageDag::build(&config.stages)?;
        
        // Instantiate stages
        let stages = config.stages.iter()
            .filter(|s| s.enabled)
            .map(|s| Self::instantiate_stage(s, &services))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            stages,
            stage_executor: Arc::new(StageExecutor::new(config.timeouts, config.retries)),
            progress_tracker: Arc::new(ProgressTracker::new()),
            artifact_collector: Arc::new(ArtifactCollector::new()),
            dag,
        })
    }
    
    pub async fn execute(&self, job: AnalysisJob) -> Result<AnalysisResult, PipelineError> {
        let mut context = StageContext::new(job, self.services.clone());
        
        // Emit job started event
        self.progress_tracker.emit(ProgressEvent::JobStarted { job_id: job.id }).await;
        
        // Execute stages in topological order
        let execution_order = self.dag.topological_order()?;
        
        for stage_name in execution_order {
            let stage = self.stages.iter().find(|s| s.name() == stage_name).unwrap();
            
            // Check if stage should run (config, dependencies)
            if !self.should_run_stage(stage_name, &context).await? {
                continue;
            }
            
            // Execute stage with timeout, retry, cancellation
            let result = self.stage_executor.execute(stage, &mut context).await?;
            
            // Collect artifacts
            self.artifact_collector.collect(&result.artifacts).await?;
            
            // Update context with artifacts
            context.apply_artifacts(result.artifacts);
            
            // Emit progress
            self.progress_tracker.emit(ProgressEvent::StageCompleted {
                job_id: job.id,
                stage: stage_name,
                progress: self.dag.progress(&stage_name),
            }).await;
            
            // Check cancellation
            if context.is_cancelled() {
                return Err(PipelineError::Cancelled);
            }
        }
        
        // Collect final results
        let result = self.artifact_collector.finalize().await?;
        
        self.progress_tracker.emit(ProgressEvent::JobCompleted { 
            job_id: job.id, 
            result: result.clone() 
        }).await;
        
        Ok(result)
    }
}
```

---

## Stage Executor (Timeout, Retry, Cancellation)

```rust
// crates/openre-analysis/src/stage_executor.rs
pub struct StageExecutor {
    timeouts: TimeoutConfig,
    retries: RetryConfig,
    cancellation_token: CancellationToken,
}

impl StageExecutor {
    pub async fn execute(
        &self,
        stage: &dyn AnalysisStage,
        context: &mut StageContext,
    ) -> Result<StageOutput, StageError> {
        let stage_name = stage.name();
        let timeout = self.timeouts.for_stage(stage_name);
        let max_attempts = self.retries.max_attempts;
        
        let mut last_error = None;
        
        for attempt in 1..=max_attempts {
            // Check cancellation
            if context.is_cancelled() {
                return Err(StageError::Cancelled);
            }
            
            // Execute with timeout
            let result = tokio::time::timeout(timeout, async {
                stage.execute(context).await
            }).await;
            
            match result {
                Ok(Ok(output)) => return Ok(output),
                Ok(Err(e)) => {
                    last_error = Some(e);
                    
                    // Check if error is retryable
                    if !self.is_retryable(&e) || attempt == max_attempts {
                        return Err(e);
                    }
                    
                    // Wait before retry
                    let delay = self.calculate_delay(attempt);
                    tokio::time::sleep(delay).await;
                    
                    // Reset context for retry (keep artifacts)
                    context.prepare_retry();
                }
                Err(_) => {
                    last_error = Some(StageError::Timeout(stage_name));
                    if attempt == max_attempts {
                        return Err(last_error.unwrap());
                    }
                    let delay = self.calculate_delay(attempt);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        
        Err(last_error.unwrap_or(StageError::MaxRetriesExceeded))
    }
    
    fn is_retryable(&self, error: &StageError) -> bool {
        matches!(error, 
            StageError::Timeout(_) |
            StageError::ResourceExhausted(_) |
            StageError::PluginCrash(_) |
            StageError::Transient(_)
        )
    }
    
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base = Duration::from_secs(self.retries.base_delay_secs);
        let max = Duration::from_secs(self.retries.max_delay_secs);
        let delay = base * (self.retries.exponential_base.powi(attempt as i32 - 1) as u32);
        std::cmp::min(delay, max)
    }
}
```

---

## Progress Tracking

```rust
// crates/openre-analysis/src/progress_tracker.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProgressEvent {
    JobStarted { job_id: JobId },
    StageStarted { job_id: JobId, stage: StageName },
    StageProgress { job_id: JobId, stage: StageName, progress: f32, message: String },
    StageCompleted { job_id: JobId, stage: StageName, duration: Duration },
    StageFailed { job_id: JobId, stage: StageName, error: String },
    JobCompleted { job_id: JobId, result: AnalysisResult },
    JobFailed { job_id: JobId, error: String },
    JobCancelled { job_id: JobId },
}

pub struct ProgressTracker {
    event_tx: broadcast::Sender<ProgressEvent>,
    redis: Arc<RedisClient>,
}

impl ProgressTracker {
    pub async fn emit(&self, event: ProgressEvent) -> Result<(), TrackerError> {
        // 1. Broadcast to WebSocket subscribers
        let _ = self.event_tx.send(event.clone());
        
        // 2. Persist to Redis for polling clients
        let key = format!("progress:{}", event.job_id());
        let data = serde_json::to_vec(&event)?;
        self.redis.lpush(&key, data).await?;
        self.redis.ltrim(&key, 0, 100).await?; // Keep last 100 events
        self.redis.expire(&key, 3600).await?; // TTL 1 hour
        
        Ok(())
    }
    
    pub fn subscribe(&self) -> broadcast::Receiver<ProgressEvent> {
        self.event_tx.subscribe()
    }
}
```

---

## Incremental Re-Analysis

```rust
// crates/openre-analysis/src/incremental.rs
pub struct IncrementalAnalyzer {
    orchestrator: Arc<PipelineOrchestrator>,
    change_detector: Arc<ChangeDetector>,
    dependency_graph: Arc<DependencyGraph>,
}

impl IncrementalAnalyzer {
    pub async fn reanalyze(
        &self,
        project_id: ProjectId,
        changes: Vec<Change>,
    ) -> Result<AnalysisResult, IncrementalError> {
        // 1. Detect affected functions
        let affected = self.change_detector.detect_affected(&changes).await?;
        
        // 2. Compute transitive dependencies
        let affected_functions = self.dependency_graph.compute_transitive(affected).await?;
        
        // 3. Determine minimal stage set
        let stages = self.compute_minimal_stages(&affected_functions).await?;
        
        // 4. Create incremental job
        let job = AnalysisJob {
            id: Uuid::new_v4(),
            project_id,
            file_ids: vec![], // Will be populated from affected functions
            config: AnalysisConfig {
                stages: stages.into_iter().map(|s| StageConfig {
                    name: s,
                    enabled: true,
                    required: true,
                    ..Default::default()
                }).collect(),
                ..Default::default()
            },
            incremental: Some(IncrementalConfig {
                affected_functions,
                preserve_unchanged: true,
            }),
        };
        
        // 5. Execute
        self.orchestrator.execute(job).await
    }
    
    async fn compute_minimal_stages(&self, functions: &[FunctionId]) -> Result<Vec<StageName>, IncrementalError> {
        // If only names/types changed → only Decompilation + AI Enrichment
        // If CFG changed → Control Flow + Data Flow + Decompilation + AI
        // If binary changed → Full pipeline
        
        Ok(vec![
            StageName::Decompilation,
            StageName::AiEnrichment,
            StageName::Finalization,
        ])
    }
}
```

---

## Pipeline Metrics

```rust
// crates/openre-analysis/src/metrics.rs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineMetrics {
    pub job_id: JobId,
    pub total_duration: Duration,
    pub stage_durations: HashMap<StageName, Duration>,
    pub stage_retries: HashMap<StageName, u32>,
    pub peak_memory_mb: u64,
    pub cpu_time_ms: u64,
    pub functions_analyzed: usize,
    pub instructions_processed: usize,
    pub ai_requests: usize,
    pub ai_tokens: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl PipelineOrchestrator {
    async fn collect_metrics(&self, job: &AnalysisJob, context: &StageContext) -> PipelineMetrics {
        PipelineMetrics {
            job_id: job.id,
            total_duration: context.start_time.elapsed(),
            stage_durations: context.stage_durations.clone(),
            stage_retries: context.stage_retries.clone(),
            peak_memory_mb: self.get_peak_memory().await,
            cpu_time_ms: self.get_cpu_time().await,
            functions_analyzed: context.functions_analyzed,
            instructions_processed: context.instructions_processed,
            ai_requests: context.ai_requests,
            ai_tokens: context.ai_tokens,
            cache_hits: context.cache_hits,
            cache_misses: context.cache_misses,
        }
    }
}
```

---

*This pipeline architecture provides a robust, extensible foundation for binary analysis. Each stage is independently replaceable, supports parallel execution, and integrates seamlessly with the plugin and AI systems.*