# Phase 1: Core Binary Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `openre-disasm` and `openre-decomp` crates with Capstone-based disassembly, CFG/DFG recovery, function identification, type inference, and rule-based decompilation — all CLI-accessible and TUI-integrated.

**Architecture:** Two new crates (`openre-disasm`, `openre-decomp`) extending existing `openre-analysis` pipeline. Capstone for multi-arch disassembly → custom lifter to IR → structural analysis (CFG/DFG, loops, SSA) → value-set analysis + pointer analysis for types → rule-based pseudo-C generation with optional LLM enhancement.

**Tech Stack:** `capstone` 0.13, `goblin` 0.8, `object` 0.37, `petgraph` 0.6, `itertools`, `bit-set`, `thiserror`, `anyhow`, `serde`, `clap` (CLI), `ratatui` (TUI)

**Spec:** `docs/superpowers/specs/2026-09-08-openre-platform-transformation-design.md` (Sections 3.1–3.6)

---

## Global Constraints

- **Single binary target**: All code compiles into `openre` CLI and `openre-tui`
- **Cross-platform**: Linux, macOS, Windows, FreeBSD — x86_64, aarch64, armv7
- **No external deps**: Capstone is pure Rust (capstone-sys links statically)
- **Binary size**: <25MB total (strip + LTO)
- **Deterministic**: Fixed seeds, sorted outputs, version-locked deps
- **Architecture**: x86, x86_64, ARM, AArch64, MIPS, RISC-V, PowerPC, SPARC, BPF, EVM
- **Syntax**: Intel (default), ATT
- **Output formats**: table, json, sarif, dot, mermaid

---

## File Structure (New Files)

```
crates/
├── openre-disasm/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── capstone_wrapper.rs
│   │   ├── disassembler.rs
│   │   ├── function.rs
│   │   ├── cfg.rs
│   │   ├── lifter.rs
│   │   ├── architecture.rs
│   │   └── error.rs
│   └── tests/
│       ├── test_binaries/
│       ├── disasm_tests.rs
│       └── function_tests.rs
│
├── openre-decomp/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── structural.rs
│   │   ├── type_inference.rs
│   │   ├── pseudo_c.rs
│   │   ├── llm_client.rs
│   │   ├── variable.rs
│   │   └── control_flow.rs
│   └── tests/
│       ├── decomp_tests.rs
│       └── type_tests.rs
│
├── openre-analysis/
│   ├── src/
│   │   ├── pipeline.rs
│   │   └── binary/
│   │       ├── mod.rs
│   │       └── disasm_integration.rs
│   └── Cargo.toml
│
├── openre-cli/
│   ├── src/commands/
│   │   ├── analyze.rs
│   │   └── decomp.rs
│   └── Cargo.toml
│
└── openre-tui/
    ├── src/panels/
    │   ├── disasm_view.rs
    │   ├── decomp_view.rs
    │   ├── cfg_view.rs
    │   └── dfg_view.rs
    └── src/state.rs
```

---

## Sprint 1: Foundation (Hours 0-8) — 4 Parallel Subagents

### Task 1.1: Create `openre-disasm` Crate Scaffold
**Files:** Create crate structure with Cargo.toml, lib.rs, error.rs, architecture.rs

- [ ] **Step 1: Write Cargo.toml with dependencies** (capstone, goblin, object, petgraph, bit-set, itertools)
- [ ] **Step 2: Write error.rs** with DisasmError enum (CapstoneInit, UnsupportedArch, DisassemblyFailed, FunctionDetection, CfgConstruction, InvalidInstruction, Lifter)
- [ ] **Step 3: Write architecture.rs** — Architecture enum, Endianness, Syntax, CallingConvention, RegisterSet with register names per arch, capstone_arch/capstone_mode mapping
- [ ] **Step 4: Write lib.rs** with public API exports
- [ ] **Step 5: Run `cargo check -p openre-disasm`**
- [ ] **Step 6: Commit**

### Task 1.2: Capstone Wrapper & Disassembler Core
**Files:** Create capstone_wrapper.rs, disassembler.rs

- [ ] **Step 1: Write capstone_wrapper.rs** — CapstoneWrapper struct with new(), disasm(), architecture(), syntax(), inner(). Include tests for x86_64 and ARM64.
- [ ] **Step 2: Write disassembler.rs** — DisassemblyConfig, Disassembler struct with new(), disasm_range(), disasm_function(), disasm_all(), capstone_insn_to_instruction(), analyze_control_flow(), build_basic_blocks(), classify_edge(), extract_branch_target()
- [ ] **Step 3: Run `cargo test -p openre-disasm capstone_wrapper`**
- [ ] **Step 4: Commit**

### Task 1.3: Function Detection & CFG Construction
**Files:** Create function.rs, cfg.rs

- [ ] **Step 1: Write function.rs** — Function, FunctionSignature, Parameter, StackFrame, LocalVariable structs. FunctionDetector with detect_functions(), build_function(), scan_for_prologues(), matches_prologue(), deduplicate_functions(), analyze_stack_frame(), analyze_calling_convention(). Prologue/epilogue patterns for x86_64, AArch64, ARM, RISC-V.
- [ ] **Step 2: Write cfg.rs** — BasicBlock, CfgEdge, ControlFlowGraph with add_node(), add_edge(), compute_dominators() (petgraph), identify_loops() (Kosaraju SCC), DominatorTree, LoopInfo. Tests for dominators.
- [ ] **Step 3: Run `cargo test -p openre-disasm function` and `cargo test -p openre-disasm cfg`**
- [ ] **Step 4: Commit**

### Task 1.4: IR Lifter & Instruction Detail
**Files:** Create lifter.rs

- [ ] **Step 1: Write lifter.rs** — IrInstruction, IrOpcode (Mov, Arithmetic, Logical, ControlFlow, Comparison, Stack, String, Flags, Vec, Nop, Unknown), IrOperand, IrOperandType, MemoryOperand. Lifter with lift(), lift_block(), get_or_cache_opcode(), parse_operands_from_string(), parse_memory_operand(), classify_register(). RegisterClass enum.
- [ ] **Step 2: Add exports to lib.rs**
- [ ] **Step 3: Run `cargo test -p openre-disasm lifter`**
- [ ] **Step 4: Commit**

---

## Sprint 2: Decompilation Engine (Hours 8-24) — 3 Parallel Subagents

### Task 2.1: Create `openre-decomp` Crate + Structural Analysis
**Files:** Create crate, lib.rs, structural.rs, control_flow.rs

- [ ] **Step 1: Write Cargo.toml** with openre-disasm, optional llama-cpp-2/ort/candle-core/tokenizers features
- [ ] **Step 2: Write lib.rs** with module exports
- [ ] **Step 3: Write structural.rs** — DecompilationConfig, DecompilationResult, Decompiler with decompile(), build_ssa() (Cytron algorithm: dominance frontiers → phi placement → renaming), reconstruct_control_flow(), identify_loops(), classify_loop(), extract_loop_condition(), find_induction_variables(), identify_ifs(), identify_switches(), compute_confidence(). PhiFunction struct.
- [ ] **Step 4: Write control_flow.rs** — ControlFlowStructures, LoopStructure, LoopType (While, DoWhile, For, Infinite), IfStructure, SwitchStructure, SwitchCase
- [ ] **Step 5: Run `cargo check -p openre-decomp`**
- [ ] **Step 6: Commit**

### Task 2.2: Type Inference (VSA + Pointer Analysis)
**Files:** Create type_inference.rs, variable.rs

- [ ] **Step 1: Write variable.rs** — Variable, VariableLocation (Register, Stack, Global, Heap, Unknown), VariableScope (Local, Parameter, Return, Global, Static). VariableTracker with register_definition(), get_or_create_register_var(), get_or_create_stack_var(). StackVariable, RegisterVariable.
- [ ] **Step 2: Write type_inference.rs** — Type enum (Void, Bool, Int8-64, Uint8-64, Float32/64, Pointer, Array, Struct, Function, Unknown, Custom). StridedInterval with join(), widen(), add(), sub(), mul(). ValueSet with top(), bottom(), single(), join(), widen(). PointerAnalysis with Andersen's inclusion-based analysis (AddrOf, Assign, Store, Load constraints). ApiSignature, ParameterSig. TypeInferencer with infer_types(), run_vsa() (worklist algorithm), process_block(), process_instruction(), transfer_value(), arithmetic_operation(), logical_operation(), shift_operation(), get_call_target(), handle_api_call(), operand_to_key(), value_set_to_type(), infer_location(), apply_api_signatures(). Load common libc/Win32 signatures.
- [ ] **Step 3: Run `cargo test -p openre-decomp type_inference`**
- [ ] **Step 4: Commit**

### Task 2.3: Rule-Based Pseudo-C Printer + LLM Client (Optional)
**Files:** Create pseudo_c.rs, llm_client.rs

- [ ] **Step 1: Write pseudo_c.rs** — PseudoCPrinter with print_function(), print_block(), print_statement(), print_expression(). Handle: variable declarations, assignments, if/else, while/do-while/for, switch/case, return, function calls, pointer derefs, array access, struct access, casts. PrinterConfig (indent_size, show_addresses, show_types, syntax_style).
- [ ] **Step 2: Write llm_client.rs** — LlmConfig (model_path, context_size, threads, gpu_layers), LlmDecompilerClient with enhance_decompilation(), generate_pseudo_c() using llama-cpp-2 or ONNX. Fallback to rule-based printer.
- [ ] **Step 3: Run `cargo test -p openre-decomp pseudo_c`**
- [ ] **Step 4: Commit**

---

## Sprint 3: Integration & CLI (Hours 24-36) — 3 Parallel Subagents

### Task 3.1: Extend `openre-analysis` Pipeline
**Files:** Modify pipeline.rs, binary/mod.rs, binary/disasm_integration.rs, Cargo.toml

- [ ] **Step 1: Add openre-disasm, openre-decomp to openre-analysis Cargo.toml**
- [ ] **Step 2: Write binary/disasm_integration.rs** — Convert openre-disasm types to openre-analysis types (BinaryMetadata → DisassemblyConfig, BinaryInfo → Function/ControlFlowGraph)
- [ ] **Step 3: Modify pipeline.rs** — Add Disassemble, Cfg, Dataflow, Types, Decompile stages to PipelineStage. Implement run_disassemble(), run_cfg(), run_dfg(), run_types(), run_decompile()
- [ ] **Step 4: Update binary/mod.rs** to re-export openre_disasm, openre_decomp
- [ ] **Step 5: Run `cargo test -p openre-analysis pipeline`**
- [ ] **Step 6: Commit**

### Task 3.2: CLI Commands — Disassembly & Decompilation
**Files:** Modify analyze.rs, Create decomp.rs

- [ ] **Step 1: Extend analyze.rs** — Add DisasmArgs (--function, --range, --count, --bytes, --syntax), DecompileArgs (--function, --llm/--no-llm, --output), CfgArgs (--function, --format dot|json|mermaid), DfgArgs (--function, --taint), TypesArgs (--function). Implement run_disasm(), run_decompile(), run_cfg(), run_dfg(), run_types().
- [ ] **Step 2: Create decomp.rs** — Dedicated decompile subcommands: openre decompile <file> --function <name> [--llm] [--output], openre decompile <file> --all [--output-dir]
- [ ] **Step 3: Register commands in main.rs** — Add AnalyzeCommands variants, DecompileCommands
- [ ] **Step 4: Test CLI** — `cargo run --bin openre analyze ./test-binaries/hello --disasm --function main`
- [ ] **Step 5: Commit**

### Task 3.3: TUI Panels — Disasm, Decomp, CFG, DFG Views
**Files:** Create disasm_view.rs, decomp_view.rs, cfg_view.rs, dfg_view.rs, Modify state.rs, panels.rs

- [ ] **Step 1: Extend state.rs** — Add DisasmState (instructions, selected_addr, syntax, follow_mode), DecompState (pseudo_c, asm_mapping, scroll), CfgState (graph, zoom, layout), DfgState (graph, taint_highlight)
- [ ] **Step 2: Write disasm_view.rs** — Syntax-highlighted assembly with navigation (j/k, g/G, /search, Enter=goto). Color: mnemonics, registers, immediates, memory, comments.
- [ ] **Step 3: Write decomp_view.rs** — Split view: left=assembly, right=pseudo-C. Sync scrolling. Click instruction → highlight corresponding C line.
- [ ] **Step 4: Write cfg_view.rs** — Graphviz DOT → render via mermaid.js or ASCII. Zoom/pan. Click node → show block instructions.
- [ ] **Step 5: Write dfg_view.rs** — Data dependency graph. Taint highlighting (red=source, blue=sink). Filter by variable.
- [ ] **Step 6: Register panels in get_all_panels()**
- [ ] **Step 7: Commit**

---

## Sprint 4: Testing & Polish (Hours 36-48) — 2 Parallel Subagents

### Task 4.1: Comprehensive Test Suite
**Files:** Test binaries, disasm_tests.rs, function_tests.rs, decomp_tests.rs, type_tests.rs

- [ ] **Step 1: Add test binaries** — Compile small C programs for each arch: hello, fibonacci, switch_demo, loop_nested, struct_ptr, virt_call
- [ ] **Step 2: Write disasm_tests.rs** — Round-trip: disasm → bytes match. Multi-arch: x86_64, AArch64, ARM, RISC-V. Instruction detail: regs_read/write, operands, groups.
- [ ] **Step 3: Write function_tests.rs** — Boundary detection accuracy. Prologue/epilogue variants. Complexity calculation. Stack frame analysis. Calling convention detection.
- [ ] **Step 4: Write decomp_tests.rs** — Known patterns → expected pseudo-C: simple_arith, if_else, while_loop, for_loop, switch_case, ptr_arith, struct_access, fn_call
- [ ] **Step 5: Write type_tests.rs** — VSA: constant propagation, interval arithmetic. Pointer analysis: simple alias, function params. API matching: memcpy, strlen, malloc signatures.
- [ ] **Step 6: Run `cargo test --workspace --all-features`**
- [ ] **Step 7: Commit**

### Task 4.2: CI/CD, Docs, Release Build
**Files:** .github/workflows/test.yml, README.md updates, profile optimization

- [ ] **Step 1: Add .github/workflows/test.yml** — cargo test --workspace --all-features, cargo build --release --package openre --package openre-tui, binary size check <25MB
- [ ] **Step 2: Update README.md** — Document new commands: analyze --disasm/--decompile/--cfg/--dfg/--types, decompile, TUI panels (4-7)
- [ ] **Step 3: Optimize release profile** — LTO=fat, codegen-units=1, strip=true, panic=abort
- [ ] **Step 4: Verify cross-compile** — cross build --target x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, x86_64-pc-windows-msvc
- [ ] **Step 5: Final integration test** — `openre analyze /bin/ls --pipeline all --format sarif --output test.sarif`
- [ ] **Step 6: Commit and tag v0.2.0-phase1**

---

## Subagent Dispatch Strategy

### Parallel Groups (Run simultaneously):

**Group A (Hours 0-8):**
- Subagent 1 → Task 1.1 (Crate scaffold)
- Subagent 2 → Task 1.2 (Capstone wrapper)
- Subagent 3 → Task 1.3 (Function/CFG)
- Subagent 4 → Task 1.4 (IR Lifter)

**Group B (Hours 8-24):**
- Subagent 1 → Task 2.1 (Decomp crate + structural)
- Subagent 2 → Task 2.2 (Type inference)
- Subagent 3 → Task 2.3 (Pseudo-C + LLM)

**Group C (Hours 24-36):**
- Subagent 1 → Task 3.1 (Analysis pipeline)
- Subagent 2 → Task 3.2 (CLI commands)
- Subagent 3 → Task 3.3 (TUI panels)

**Group D (Hours 36-48):**
- Subagent 1 → Task 4.1 (Test suite)
- Subagent 2 → Task 4.2 (CI/CD + release)

### Synchronization Points:
- **Hour 8**: All Group A complete → merge → Group B starts
- **Hour 24**: All Group B complete → merge → Group C starts
- **Hour 36**: All Group C complete → merge → Group D starts
- **Hour 48**: All Group D complete → release

---

## Success Criteria (Phase 1 Complete)

- [ ] `openre analyze <bin> --disasm --function main` → syntax-highlighted assembly
- [ ] `openre analyze <bin> --decompile --function main` → readable pseudo-C
- [ ] `openre analyze <bin> --cfg --format dot` → valid Graphviz DOT
- [ ] `openre analyze <bin> --dfg --taint rdi` → data flow with taint
- [ ] `openre analyze <bin> --types --function main` → variable types
- [ ] `openre analyze <bin> --pipeline all --format sarif` → complete SARIF
- [ ] TUI: Panels 4-7 (Disasm, Decomp, CFG, DFG) functional
- [ ] All tests pass: `cargo test --workspace --all-features`
- [ ] Release binary <25MB, runs on Linux/macOS/Windows/FreeBSD

---

**Plan saved to:** `docs/superpowers/plans/2026-09-08-phase1-core-binary-analysis.md`

**Execution choice:** Use **Subagent-Driven** (recommended) — dispatch fresh subagent per task group with two-stage review. Invoke `superpowers:subagent-driven-development` to begin.