# Feature Brainstorm

## Overview

Comprehensive list of potential features for open-re. Each feature includes description, user value, technical difficulty, priority, and phase assignment. This is a brainstorming document - not all features will be implemented.

---

## Feature Categories

1. **Core Analysis** - Disassembly, decompilation, control/data flow
2. **AI-Assisted Analysis** - Local models, semantic understanding
3. **User Experience** - UI, interaction, accessibility, learning
4. **Collaboration & Sharing** - Real-time, web viewer, reproducibility
5. **Extensibility** - Plugin system, scripting, marketplace
6. **Dynamic Analysis** - Debugging, emulation, tracing
7. **Specialized Domains** - Malware, vuln research, firmware, education
8. **Platform & Infrastructure** - Performance, security, distribution

---

## 1. Core Analysis Features

### 1.1 Disassembly & Architecture Support

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-CORE-001 | **Multi-architecture Disassembler** | x86, x64, ARM, ARM64, MIPS, RISC-V, PowerPC, SPARC | Universal tool | High | Critical | 1 |
| F-CORE-002 | **Declarative Architecture Spec** | SLEIGH-like DSL for defining new architectures | Extensibility, obscure archs | High | High | 1 |
| F-CORE-003 | **Instruction Semantics Engine** | Formal semantics for each instruction (regs, mem, flags) | Data flow, symbolic exec | High | Critical | 1 |
| F-CORE-004 | **Variable-Length Instruction Handling** | Thumb, MIPS16, RISC-V C, x86 prefixes | Correctness | Medium | Critical | 1 |
| F-CORE-005 | **Overlapping Instruction Detection** | Handle obfuscation, hand-written assembly | Malware, firmware | Medium | High | 1 |
| F-CORE-006 | **Parallel Disassembly** | Work-stealing scheduler for multi-core | Performance on large binaries | Medium | High | 1 |
| F-CORE-007 | **Incremental Re-disassembly** | Update only changed regions on edit | Interactive patching | High | Medium | 2 |
| F-CORE-008 | **Custom Calling Convention Support** | Define ABIs for embedded, OS kernels | Firmware, kernel analysis | Medium | Medium | 2 |

### 1.2 Control Flow & Data Flow Analysis

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-CFG-001 | **Function Boundary Detection** | ML-enhanced prologue/epilogue + heuristic | Foundation for all analysis | High | Critical | 1 |
| F-CFG-002 | **Indirect Call Resolution** | V-table, jump table, function pointer analysis | Complete call graph | High | Critical | 1 |
| F-CFG-003 | **SSA Form Construction** | Static Single Assignment for data flow | Optimization, decompilation | High | Critical | 1 |
| F-CFG-004 | **Value Set Analysis** | Abstract interpretation for constants/ranges | Constant propagation, bounds | High | High | 1 |
| F-CFG-005 | **Taint Analysis Engine** | Source/sink tracking, sanitizer detection | Vuln discovery, malware | Very High | High | 2 |
| F-CFG-006 | **Loop Analysis** | Natural loops, induction variables, bounds | Decompilation, optimization | Medium | High | 1 |
| F-CFG-007 | **Exception Flow Analysis** | SEH, DWARF, SjLj, setjmp/longjmp | Correct CFG for C++/Go/Rust | High | Medium | 2 |
| F-CFG-008 | **Interprocedural Analysis** | Cross-function data flow, side effects | Whole-program understanding | Very High | Medium | 2 |

### 1.3 Decompilation

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-DEC-001 | **High-Quality C-like Output** | Readable pseudo-code with control structures | Primary analysis view | Very High | Critical | 1 |
| F-DEC-002 | **Type Inference & Propagation** | Constraint-based, interprocedural | Meaningful variable types | Very High | Critical | 1 |
| F-DEC-003 | **Struct/Array Reconstruction** | From access patterns (offsets, sizes) | Real-world data structures | High | Critical | 1 |
| F-DEC-004 | **Control Structure Recovery** | if/else, while, for, switch, goto cleanup | Readable code | High | Critical | 1 |
| F-DEC-005 | **Interactive Decompilation** | Inline/outline, retype, rename, restructure | Analyst control | Medium | Critical | 1 |
| F-DEC-006 | **Multi-Target Export** | C, Rust, Python, LLVM IR, Go | Porting, analysis, recompilation | Medium | High | 2 |
| F-DEC-007 | **Decompilation Diff** | Side-by-side version comparison | Patch analysis, regression | High | High | 2 |
| F-DEC-008 | **Confidence Annotations** | Per-statement reliability indicators | Trust but verify | Medium | Medium | 2 |
| F-DEC-009 | **Decompiler Plugin API** | Custom output languages, transforms | Extensibility | High | Medium | 2 |

### 1.4 Type System

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-TYPE-001 | **Rich Type System** | Primitives, pointers, arrays, structs, unions, enums, functions | Foundation | Medium | Critical | 1 |
| F-TYPE-002 | **C/C++ Header Import** | Clang-based parser for .h files | Standard library types | High | Critical | 1 |
| F-TYPE-003 | **PDB/DWARF Debug Info Import** | Full type fidelity from debug builds | Accurate analysis | High | High | 1 |
| F-TYPE-004 | **Type Library Management** | Versioned, platform-specific, shareable | Reuse across projects | Medium | High | 1 |
| F-TYPE-005 | **Type Inference from Usage** | ML + constraint solving for unknown types | Reverse unknown binaries | High | High | 1 |
| F-TYPE-006 | **Custom Type Definitions** | YAML/JSON format, user + plugin contributed | Domain-specific types | Low | High | 1 |

### 1.5 Binary Parsing & Loading

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-LOAD-001 | **Universal Binary Loader** | ELF, PE, Mach-O, raw, firmware formats | Load anything | Medium | Critical | 1 |
| F-LOAD-002 | **Packer/Protector Detection** | UPX, VMProtect, Themida, custom | Malware triage | Medium | High | 1 |
| F-LOAD-003 | **Compiler/Toolchain Fingerprinting** | GCC, Clang, MSVC, Rust, Go, Nim versions | Attribution, expectations | Low | High | 1 |
| F-LOAD-004 | **Overlay/Resource Extraction** | Embedded files, certificates, configs | Firmware, malware | Low | Medium | 1 |
| F-LOAD-005 | **Streaming/Lazy Loading** | Memory-map large files, parse on demand | 1GB+ binaries | High | Medium | 2 |
| F-LOAD-006 | **Custom Loader Plugins** | Proprietary formats, embedded FS | Extensibility | Medium | High | 1 |

---

## 2. AI-Assisted Analysis Features

### 2.1 Local Models (Privacy-First)

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-AI-001 | **Function Purpose Classification** | "C2 handler", "crypto routine", "parser", "anti-debug" | Rapid understanding | High | Critical | 1 |
| F-AI-002 | **Variable/Parameter Naming** | Context-aware semantic names | Reduce manual work 60% | High | Critical | 1 |
| F-AI-003 | **Type Prediction** | Suggest struct layouts, function signatures | Accelerate typing | High | Critical | 1 |
| F-AI-004 | **Crypto Constant Detection** | S-boxes, magic numbers, curve params | Find crypto instantly | Medium | Critical | 1 |
| F-AI-005 | **Standard Library Recognition** | Beyond FLIRT: ML-based, version-aware | Skip known code | High | Critical | 1 |
| F-AI-006 | **Obfuscation Detection** | Packers, VM-based, control flow flattening | Guide deobfuscation | High | High | 1 |
| F-AI-007 | **Vulnerability Pattern Matching** | CWE patterns: buffer overflow, UAF, RCE | Security focus | Very High | High | 2 |
| F-AI-008 | **Natural Language Query** | "Find all network sends" → highlights | Semantic search | Very High | Medium | 2 |
| F-AI-009 | **Code Summarization** | "This function parses JSON config" | Quick understanding | High | High | 1 |
| F-AI-010 | **Cross-Binary Similarity** | Function-level diffing, library detection | Version tracking, lineage | High | Medium | 2 |

### 2.2 AI Integration UX

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-AI-UX-001 | **Inline Ghost Suggestions** | Gray text at cursor: names, types, comments | Flow-state, non-intrusive | Medium | Critical | 1 |
| F-AI-UX-002 | **"Explain This" Command** | LLM-generated function/block explanation | Learning, verification | Medium | Critical | 1 |
| F-AI-UX-003 | **Confidence Calibration** | Well-calibrated probabilities on suggestions | Trust decisions | High | High | 1 |
| F-AI-UX-004 | **Feedback Loop** | Thumbs up/down → model improvement | Continuous improvement | Medium | High | 1 |
| F-AI-UX-005 | **Offline-First Architecture** | All models local, no network required | Privacy, air-gapped | High | Critical | 1 |
| F-AI-UX-006 | **Model Versioning** | Pin models, rollback, reproducibility | Stable analyses | Medium | Medium | 2 |
| F-AI-UX-007 | **Custom Model Fine-tuning** | User trains on their codebase (opt-in) | Domain adaptation | Very High | Low | 3 |
| F-AI-UX-008 | **AI Action History** | Audit trail of AI suggestions + user actions | Forensics, learning | Low | Medium | 2 |

### 2.3 Model Infrastructure

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-AI-INFRA-001 | **Model Registry** | Versioned, signed, reproducible models | Supply chain security | Medium | High | 1 |
| F-AI-INFRA-002 | **ONNX Runtime Integration** | Cross-platform, hardware-accelerated | Performance, portability | Medium | High | 1 |
| F-AI-INFRA-003 | **Quantized Models** | INT8/INT4 for CPU inference | Speed, memory | Medium | High | 1 |
| F-AI-INFRA-004 | **Training Data Pipeline** | Curated, licensed, diverse corpus | Model quality | High | High | 1 |
| F-AI-INFRA-005 | **Evaluation Framework** | Benchmarks, regression tests | Quality assurance | Medium | High | 1 |

---

## 3. User Experience Features

### 3.1 Core Views

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-UI-001 | **Synchronized Disassembly/Decompiler** | Click in one, highlight in other | Mental model | Medium | Critical | 1 |
| F-UI-002 | **Interactive Graph View** | CFG, call graph, data flow - zoom, pan, layout | Visual analysis | High | Critical | 1 |
| F-UI-003 | **Structured Hex View** | Overlay types, highlight patterns, search | Low-level inspection | Medium | Critical | 1 |
| F-UI-004 | **Smart Strings View** | Encoding detection, xrefs, entropy, stack strings | Data discovery | Low | High | 1 |
| F-UI-005 | **Symbol/Import/Export Tables** | Sortable, filterable, searchable | Navigation | Low | High | 1 |
| F-UI-006 | **Cross-Reference Explorer** | To/from, graph-based, filtered | Navigation | Medium | Critical | 1 |
| F-UI-007 | **Memory Map Visualization** | Sections, segments, permissions, holes | Firmware, packed binaries | Medium | High | 1 |

### 3.2 Interaction & Navigation

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-INT-001 | **Vim/Emacs Keybindings** | Modal editing, muscle memory | Power users | Low | High | 1 |
| F-INT-002 | **Command Palette** | VS Code style: fuzzy search all actions | Discoverability | Medium | Critical | 1 |
| F-INT-003 | **Multi-Cursor Editing** | Rename/retype multiple locations | Refactoring | Medium | High | 1 |
| F-INT-004 | **Unlimited Undo/Redo** | Full history, branching, persistence | Safety, experimentation | Medium | Critical | 1 |
| F-INT-005 | **Spatial Bookmarks** | Named, categorized, shared | Navigation | Low | High | 1 |
| F-INT-006 | **Semantic Search** | "loop with crypto", "function calling send" | Discovery | High | High | 2 |
| F-INT-007 | **Split/Tabbed Layouts** | Save/restore workspaces | Workflow | Medium | High | 1 |
| F-INT-008 | **Minimap/Overview** | Code map with annotations | Orientation | Low | Medium | 1 |

### 3.3 Accessibility & Inclusion

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-A11Y-001 | **Screen Reader Support** | ARIA, semantic structure, live regions | Blind/low vision users | Medium | Critical | 1 |
| F-A11Y-002 | **Keyboard-Only Operation** | No mouse required, focus management | Motor impairments | Low | Critical | 1 |
| F-A11Y-003 | **High Contrast Themes** | WCAG AA/AAA compliant | Low vision | Low | Critical | 1 |
| F-A11Y-004 | **Colorblind-Safe Palettes** | Deuteranopia, protanopia, tritanopia | 8% of males | Low | Critical | 1 |
| F-A11Y-005 | **Scalable UI (100-400%)** | Responsive, no horizontal scroll | Low vision, high DPI | Medium | High | 1 |
| F-A11Y-006 | **Reduced Motion** | Disable animations, transitions | Vestibular disorders | Low | High | 1 |
| F-A11Y-007 | **Localization Framework** | gettext/Fluent, RTL support | Global adoption | Medium | Medium | 2 |

### 3.4 Learning & Onboarding

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-LEARN-001 | **Interactive Tutorials** | Step-by-step guided analysis | Beginners | Medium | High | 1 |
| F-LEARN-002 | **Contextual Help** | "What is a basic block?" on hover | Just-in-time learning | Low | High | 1 |
| F-LEARN-003 | **AI Tutor Mode** | "Explain this like I'm a student" | Self-paced learning | High | High | 2 |
| F-LEARN-004 | **Challenge Library** | Curated binaries with solutions | Practice, education | Medium | Medium | 2 |
| F-LEARN-005 | **Progress Tracking** | Skills learned, concepts mastered | Motivation | Low | Medium | 2 |
| F-LEARN-006 | **Instructor Tools** | Lab creation, auto-grading, dashboards | Education | High | High | 2 |

---

## 4. Collaboration & Sharing Features

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-COL-001 | **Project File Format** | SQLite + JSON, mergeable, portable | Foundation | Medium | Critical | 1 |
| F-COL-002 | **Annotation Layers** | Comments, names, types separate from core | Non-destructive collab | Medium | Critical | 1 |
| F-COL-003 | **Real-Time Collaboration** | CRDT-based, conflict-free, presence | Team analysis | Very High | High | 3 |
| F-COL-004 | **Web-Based Read-Only Viewer** | Share link, zero-install, interactive | Stakeholders, management | High | High | 2 |
| F-COL-005 | **Analysis Replay** | Step-by-step reconstruction | Teaching, forensics, audit | High | Medium | 2 |
| F-COL-006 | **Git Integration** | Diff annotations, blame, history | Version control | Medium | High | 2 |
| F-COL-007 | **Shared Symbol Server** | Central type/function library | Org-wide consistency | Medium | Medium | 2 |
| F-COL-008 | **Export Packages** | Self-contained analysis + viewer | Distribution | Low | Medium | 2 |

---

## 5. Extensibility Features

### 5.1 Plugin System

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-PLG-001 | **WASM Plugin Runtime** | Sandboxed, polyglot (Rust, Go, TS, Python) | Security, language freedom | High | Critical | 1 |
| F-PLG-002 | **Plugin Manifest & Permissions** | Capabilities: fs, net, api, ui | Security model | Medium | Critical | 1 |
| F-PLG-003 | **Hot Reload** | Update plugins without restart | Developer experience | Medium | High | 1 |
| F-PLG-004 | **Extension Points** | Loader, analyzer, view, exporter, AI model | Composability | High | Critical | 1 |
| F-PLG-005 | **Plugin Registry/Marketplace** | Discover, install, update, rate | Ecosystem | High | High | 2 |
| F-PLG-006 | **Plugin SDK & Templates** | Scaffolding, testing, CI, docs | Lower barrier | Medium | High | 1 |
| F-PLG-007 | **Core as Plugins** | Disassembler, decompiler are plugins | Dogfooding, replaceability | High | Critical | 1 |

### 5.2 Scripting & Automation

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-SCRIPT-001 | **Python API (Type-Stubbed)** | Full access, async, IDE support | Automation | Medium | Critical | 1 |
| F-SCRIPT-002 | **Jupyter Notebook Integration** | REPL + visualization + markdown | Research, reporting | Medium | High | 1 |
| F-SCRIPT-003 | **Headless/CLI Mode** | Identical API, no GUI deps | CI/CD, batch | Low | Critical | 1 |
| F-SCRIPT-004 | **Script Marketplace** | Share, discover, rate scripts | Community | Medium | Medium | 2 |
| F-SCRIPT-005 | **Workflow Automation** | Visual pipeline builder (no-code) | Non-programmers | High | Low | 3 |

---

## 6. Dynamic Analysis Features (Phase 2+)

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-DYN-001 | **DAP Debugger Support** | GDB, LLDB, WinDbg, WinDbg via DAP | Standard debugging | High | High | 2 |
| F-DYN-002 | **Emulator Integration** | Unicorn, QEMU user-mode | Firmware, shellcode | High | High | 2 |
| F-DYN-003 | **Trace Import & Analysis** | Intel PT, rr, Frida, DynamoRIO | Time-travel debugging | Very High | Medium | 3 |
| F-DYN-004 | **Dynamic Taint Analysis** | Runtime data flow | Exploit dev, malware | Very High | Medium | 3 |
| F-DYN-005 | **Hybrid Static/Dynamic** | Static guides dynamic, dynamic refines static | Best of both | Very High | Medium | 3 |
| F-DYN-006 | **Peripheral/Device Modeling** | MMIO, interrupts, timers | Firmware, embedded | High | Medium | 3 |

---

## 7. Specialized Domain Features

### 7.1 Malware Analysis

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-MAL-001 | **Capa Integration** | Built-in capability detection | Triage | Low | Critical | 1 |
| F-MAL-002 | **YARA Rule Engine** | Scan, write, test rules | Detection | Medium | High | 1 |
| F-MAL-003 | **String Decryption Emulation** | Auto-decrypt stack strings | Hidden IOCs | High | High | 2 |
| F-MAL-004 | **C2 Extraction Heuristics** | Pattern-based config extraction | Actionable intel | High | High | 2 |
| F-MAL-005 | **Family Classification** | ML-based, explainable | Attribution | High | Medium | 2 |
| F-MAL-006 | **MITRE ATT&CK Mapping** | Technique tags on functions | Reporting | Medium | High | 2 |

### 7.2 Vulnerability Research

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-VULN-001 | **Sink/Source Database** | Curated dangerous APIs | Audit focus | Medium | High | 2 |
| F-VULN-002 | **Path Constraint Solver** | SMT-backed reachability | Exploitability | Very High | High | 3 |
| F-VULN-003 | **Patch Diffing Engine** | Binary diffing, semantic equivalence | Variant hunting | High | High | 2 |
| F-VULN-004 | **Exploit Mitigation Analysis** | CFG, CET, PAC, stack cookies | Bypass assessment | Medium | Medium | 2 |
| F-VULN-005 | **Fuzzing Harness Generation** | Auto-generate harnesses from entry points | Scale fuzzing | High | Medium | 3 |

### 7.3 Firmware & Embedded

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-FW-001 | **Flash Memory Mapper** | Visualize regions, partitions, FS | Firmware layout | Medium | High | 2 |
| F-FW-002 | **RTOS Awareness** | FreeRTOS, Zephyr, ThreadX objects | Kernel analysis | High | Medium | 3 |
| F-FW-003 | **Hardware Peripheral Models** | UART, SPI, I2C, GPIO, timers | Emulation | Very High | Low | 3 |
| F-FW-004 | **Bootloader Analysis** | Chain of trust, verification | Secure boot | High | Medium | 3 |

### 7.4 Education

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-EDU-001 | **Lab Authoring Tool** | Create guided exercises with hints | Instructors | Medium | High | 2 |
| F-EDU-002 | **Auto-Grading API** | Check student annotations programmatically | Scale teaching | Medium | High | 2 |
| F-EDU-003 | **LTI/Canvas Integration** | LMS integration | Adoption | Medium | Medium | 3 |
| F-EDU-004 | **Curriculum Packs** | Semester-ready materials | Adoption | Low | High | 2 |

---

## 8. Platform & Infrastructure Features

### 8.1 Performance & Scalability

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-PERF-001 | **Incremental Analysis** | Only re-analyze changed portions | Speed | High | Critical | 1 |
| F-PERF-002 | **Lazy Loading** | Load views on demand | Startup time | Medium | Critical | 1 |
| F-PERF-003 | **Streaming Decompilation** | Function-by-function, cancelable | Responsiveness | High | High | 1 |
| F-PERF-004 | **Distributed Analysis** | Worker pool for large binaries | Scale | Very High | Low | 3 |
| F-PERF-005 | **Memory Profiling Built-in** | Leak detection, optimization | Self-hosting | Medium | Medium | 2 |

### 8.2 Security & Trust

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-SEC-001 | **Reproducible Builds** | Bit-for-bit identical artifacts | Supply chain | High | Critical | 1 |
| F-SEC-002 | **Signed Releases** | Cosign/SBOM, keyless signing | Integrity | Medium | Critical | 1 |
| F-SEC-003 | **Plugin Sandbox** | WASM capability-based security | Safe extensions | High | Critical | 1 |
| F-SEC-004 | **No Telemetry by Default** | Opt-in only, transparent | Privacy | Low | Critical | 1 |
| F-SEC-005 | **Dependency Scanning** | Automated SBOM, vulnerability alerts | Maintenance | Medium | High | 1 |

### 8.3 Distribution & Operations

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-DIST-001 | **Native Installers** | .deb, .rpm, .dmg, .msi, AppImage | Easy install | Medium | Critical | 1 |
| F-DIST-002 | **Auto-Update** | Delta updates, rollback, channels | Maintenance | Medium | High | 1 |
| F-DIST-003 | **Portable/Standalone** | Single binary, no install | Air-gapped, USB | Low | High | 1 |
| F-DIST-004 | **Container Images** | Docker, Podman, distroless | CI/CD, cloud | Low | Medium | 2 |
| F-DIST-005 | **WebAssembly Build** | Browser-based viewer | Zero-install sharing | High | Medium | 2 |

---

## 9. Creative/Experimental Features

| ID | Feature | Description | User Value | Difficulty | Priority | Phase |
|----|---------|-------------|------------|------------|----------|-------|
| F-EXP-001 | **Time-Travel Analysis** | Full history as first-class object | Debug analysis itself | Very High | Low | 3+ |
| F-EXP-002 | **Natural Language Programming** | "Rename all crypto functions" → executes | Accessibility | Very High | Low | 3+ |
| F-EXP-003 | **Collaborative AI** | Shared model fine-tuning (federated) | Org intelligence | Very High | Low | 3+ |
| F-EXP-004 | **AR/VR Visualization** | 3D call graphs, spatial memory | Novel exploration | Very High | Low | Future |
| F-EXP-005 | **Binary Synthesis** | Generate binaries from specs | Testing, education | Very High | Low | Future |
| F-EXP-006 | **Cross-Architecture Translation** | x86 → ARM lifting | Porting | Very High | Low | Future |

---

## 10. Feature Prioritization Summary

### MVP (Phase 1) - Must Have
| Category | Features |
|----------|----------|
| **Core** | F-CORE-001, 003, 004, 006; F-CFG-001, 002, 003, 004, 006; F-DEC-001-005; F-TYPE-001-005; F-LOAD-001-003 |
| **AI** | F-AI-001-006, 009; F-AI-UX-001-005; F-AI-INFRA-001-003 |
| **UX** | F-UI-001-007; F-INT-001-005, 007; F-A11Y-001-006; F-LEARN-001-002 |
| **Collab** | F-COL-001, 002 |
| **Extensibility** | F-PLG-001-004, 007; F-SCRIPT-001-003 |
| **Platform** | F-PERF-001-003; F-SEC-001-004; F-DIST-001-003 |

### Phase 2 - Should Have
| Category | Features |
|----------|----------|
| **Core** | F-CORE-002, 007, 008; F-CFG-005, 007, 008; F-DEC-006-009; F-TYPE-006; F-LOAD-004-006 |
| **AI** | F-AI-007, 008, 010; F-AI-UX-006, 008; F-AI-INFRA-004, 005 |
| **UX** | F-INT-006, 008; F-A11Y-007; F-LEARN-003-006 |
| **Collab** | F-COL-003-008 |
| **Extensibility** | F-PLG-005, 006; F-SCRIPT-004, 005 |
| **Dynamic** | F-DYN-001, 002 |
| **Domains** | F-MAL-001-006; F-VULN-001, 003, 004; F-FW-001; F-EDU-001, 002, 004 |
| **Platform** | F-PERF-005; F-SEC-005; F-DIST-004, 005 |

### Phase 3 - Could Have
| Category | Features |
|----------|----------|
| **Dynamic** | F-DYN-003-006 |
| **Domains** | F-VULN-002, 005; F-FW-002-004; F-EDU-003 |
| **Experimental** | F-EXP-001-003 |

---

## 11. Feature Dependencies Graph

```
F-CORE-001 (Disassembler)
    ├── F-CFG-001 (Function Detection)
    │   ├── F-DEC-001 (Decompiler)
    │   │   ├── F-AI-002 (Naming)
    │   │   └── F-DEC-005 (Interactive)
    │   ├── F-CFG-003 (SSA)
    │   │   ├── F-CFG-004 (VSA)
    │   │   └── F-CFG-005 (Taint)
    │   └── F-AI-001 (Classification)
    ├── F-TYPE-001 (Type System)
    │   ├── F-TYPE-002 (Header Import)
    │   └── F-DEC-002 (Type Inference)
    └── F-PLG-007 (Core as Plugins)
        ├── F-PLG-001 (WASM Runtime)
        └── F-PLG-004 (Extension Points)
```

---

## 12. Decision Framework for New Features

When evaluating new feature proposals, score on:

| Criterion | Weight | Questions |
|-----------|--------|-----------|
| **User Value** | 30% | Which personas? How much time saved? |
| **Differentiation** | 25% | Unique vs. competitors? Moat? |
| **Strategic Alignment** | 20% | Advances vision? Enables other features? |
| **Technical Feasibility** | 15% | Do we have expertise? Proven approach? |
| **Maintenance Burden** | 10% | Long-term cost? Dependencies? |

**Threshold**: Score > 7/10 → Consider for roadmap

---

*This brainstorm is exhaustive but not binding. Features move between phases based on learning. Review quarterly.*