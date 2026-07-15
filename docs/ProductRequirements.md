# Product Requirements Document

## Overview

This document defines the functional and non-functional requirements for open-re, organized by subsystem and priority. Requirements are traced to user needs and competitive gaps identified in research.

---

## 1. Core Analysis Engine

### 1.1 Binary Loading & Parsing

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-CORE-001 | Load ELF, PE, Mach-O, raw binaries | Must | 1 | Support 32/64-bit, all common variants |
| REQ-CORE-002 | Parse headers, sections, segments, symbols | Must | 1 | Full metadata extraction |
| REQ-CORE-003 | Detect compiler, packer, protector | Should | 1 | Integrate with capa/PEiD signatures |
| REQ-CORE-004 | Support custom loaders via plugin | Must | 1 | For firmware, embedded, obscure formats |
| REQ-CORE-005 | Stream large binaries (>1GB) without full load | Could | 2 | Memory-mapped, lazy parsing |
| REQ-CORE-006 | Validate binary integrity (checksums, signatures) | Should | 1 | Detect corruption/tampering |

### 1.2 Disassembly

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-DASM-001 | Support x86, x86-64, ARM, ARM64, MIPS, RISC-V | Must | 1 | Minimum viable architectures |
| REQ-DASM-002 | Support Thumb, MIPS16, RISC-V compressed | Must | 1 | Variable-length instruction sets |
| REQ-DASM-003 | Linear sweep + recursive traversal | Must | 1 | Configurable strategy |
| REQ-DASM-004 | Handle obfuscation (overlapping, opaque predicates) | Should | 1 | Heuristic + ML-assisted |
| REQ-DASM-005 | Instruction semantics (effects on regs/mem/flags) | Must | 1 | For data flow analysis |
| REQ-DASM-006 | Extensible instruction definitions (JSON/DSL) | Must | 1 | For custom architectures |
| REQ-DASM-007 | Parallel disassembly with work-stealing | Should | 1 | Multi-core utilization |
| REQ-DASM-008 | Incremental re-disassembly on edit | Could | 2 | For interactive patching |

### 1.3 Control Flow & Data Flow

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-CFG-001 | Build function CFGs (basic blocks, edges) | Must | 1 | Standard algorithm |
| REQ-CFG-002 | Identify function boundaries (prologue/epilogue) | Must | 1 | ML-enhanced |
| REQ-CFG-003 | Build call graph (direct + indirect) | Must | 1 | With resolution hints |
| REQ-CFG-004 | Data flow analysis (def-use, reaching defs) | Must | 1 | SSA form preferred |
| REQ-CFG-005 | Value set analysis / abstract interpretation | Should | 1 | For constant propagation |
| REQ-CFG-006 | Taint analysis (source/sink tracking) | Should | 2 | Security-focused |
| REQ-CFG-007 | Loop detection and analysis | Should | 1 | Natural loops, reducibility |
| REQ-CFG-008 | Exception handling flow (SEH, DWARF, SjLj) | Could | 2 | Platform-specific |

### 1.4 Decompilation

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-DEC-001 | Generate readable pseudo-code (C-like) | Must | 1 | Primary output |
| REQ-DEC-002 | Type inference (local vars, args, return) | Must | 1 | Constraint-based |
| REQ-DEC-003 | Struct/array reconstruction | Must | 1 | From access patterns |
| REQ-DEC-004 | Control structure recovery (if/while/for/switch) | Must | 1 | Structured analysis |
| REQ-DEC-005 | Variable naming (semantic + ML) | Should | 1 | Context-aware |
| REQ-DEC-006 | Inline/outline functions interactively | Must | 1 | User control |
| REQ-DEC-007 | Export to C, Rust, Python, LLVM IR | Should | 2 | Multiple targets |
| REQ-DEC-008 | Decompilation diff (version comparison) | Could | 2 | Side-by-side view |

### 1.5 Type System

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-TYPE-001 | Primitive types (int, float, ptr, bool, void) | Must | 1 | Architecture-sized |
| REQ-TYPE-002 | Composite types (struct, union, enum, array) | Must | 1 | Nested, recursive |
| REQ-TYPE-003 | Function types (calling convention, variadic) | Must | 1 | Platform ABIs |
| REQ-TYPE-004 | Type library import (C headers, PDB, DWARF) | Must | 1 | Clang-based parser |
| REQ-TYPE-005 | Type propagation across call graph | Must | 1 | Interprocedural |
| REQ-TYPE-006 | Custom type definitions (user + plugins) | Must | 1 | JSON/YAML format |
| REQ-TYPE-007 | Type equivalence and canonicalization | Should | 1 | Structural equality |

---

## 2. User Interface

### 2.1 Core Views

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-UI-001 | Disassembly view (linear + graph) | Must | 1 | Synchronized |
| REQ-UI-002 | Decompiler view (pseudo-code) | Must | 1 | Side-by-side with asm |
| REQ-UI-003 | Graph view (CFG, call graph, data flow) | Must | 1 | Interactive, zoomable |
| REQ-UI-004 | Hex view (with structure overlay) | Must | 1 | Pattern highlighting |
| REQ-UI-005 | Strings view (with encoding detection) | Must | 1 | Search, filter, xrefs |
| REQ-UI-006 | Symbols/imports/exports tables | Must | 1 | Sortable, filterable |
| REQ-UI-007 | Sections/segments view | Must | 1 | Permissions, mapping |
| REQ-UI-008 | Cross-references panel (to/from) | Must | 1 | Context menu navigation |

### 2.2 Interaction

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-INT-001 | Keyboard-first navigation (Vim/Emacs modes) | Must | 1 | Configurable bindings |
| REQ-INT-002 | Multi-cursor editing (rename, retype) | Must | 1 | Refactoring support |
| REQ-INT-003 | Undo/redo for all analysis actions | Must | 1 | Full history |
| REQ-INT-004 | Bookmarks and spatial navigation | Must | 1 | Named, categorized |
| REQ-INT-005 | Search (text, regex, pattern, semantic) | Must | 1 | Across all views |
| REQ-INT-006 | Command palette (VS Code style) | Must | 1 | Discoverability |
| REQ-INT-007 | Split/tabbed layout management | Must | 1 | Persistent workspaces |
| REQ-INT-008 | Touch/trackpad gestures (zoom, pan) | Could | 2 | Graph view |

### 2.3 Accessibility & Internationalization

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-A11Y-001 | Screen reader compatible (ARIA) | Must | 1 | Semantic HTML/Widgets |
| REQ-A11Y-002 | High contrast / colorblind themes | Must | 1 | WCAG AA minimum |
| REQ-A11Y-003 | Full keyboard navigation | Must | 1 | No mouse required |
| REQ-A11Y-004 | Scalable UI (125%-400%) | Must | 1 | Responsive layout |
| REQ-I18N-001 | Translation framework (gettext/fluent) | Should | 2 | Community translations |
| REQ-I18N-002 | RTL language support | Could | 3 | Arabic, Hebrew |

---

## 3. Scripting & Automation

### 3.1 Python API

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-PY-001 | Full access to analysis database | Must | 1 | Read/write |
| REQ-PY-002 | Type-stubbed API (pyi files) | Must | 1 | IDE support |
| REQ-PY-003 | Async/await support for long operations | Must | 1 | Non-blocking |
| REQ-PY-004 | Jupyter notebook integration | Should | 1 | REPL + visualization |
| REQ-PY-005 | Headless mode (CI/CD, batch analysis) | Must | 1 | No GUI deps |
| REQ-PY-006 | Script marketplace / sharing | Could | 2 | Community repo |

### 3.2 Plugin System

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-PLG-001 | Dynamic plugin loading (no restart) | Must | 1 | Hot reload |
| REQ-PLG-002 | Stable plugin API (semver, deprecation policy) | Must | 1 | C ABI + Python |
| REQ-PLG-003 | Plugin manifest (metadata, deps, permissions) | Must | 1 | TOML/JSON |
| REQ-PLG-004 | Plugin types: loader, analyzer, view, exporter | Must | 1 | Extensibility points |
| REQ-PLG-005 | Plugin sandboxing (WASM/deno) | Should | 2 | Security |
| REQ-PLG-006 | Local plugin index + remote registry | Could | 2 | Discovery |
| REQ-PLG-007 | Plugin development SDK (templates, CI) | Should | 1 | Developer experience |

---

## 4. AI-Assisted Analysis

### 4.1 Local Models (Privacy-First)

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-AI-001 | Function purpose classification | Must | 1 | On-device, <100MB model |
| REQ-AI-002 | Variable/parameter naming suggestions | Must | 1 | Context-aware |
| REQ-AI-003 | Cryptographic constant detection | Must | 1 | S-boxes, magic numbers |
| REQ-AI-004 | Standard library function recognition | Must | 1 | Beyond FLIRT |
| REQ-AI-005 | Obfuscation detection (packers, VM, control flow) | Should | 1 | Heuristic + ML |
| REQ-AI-006 | Vulnerability pattern matching | Should | 2 | CWE mapping |
| REQ-AI-007 | Natural language query ("find crypto") | Could | 2 | Semantic search |
| REQ-AI-008 | Model fine-tuning pipeline (user data) | Could | 3 | Opt-in, local |

### 4.2 AI Integration UX

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-AI-UX-001 | Inline suggestions (ghost text) | Must | 1 | Accept/reject |
| REQ-AI-UX-002 | "Explain this function" command | Must | 1 | LLM-generated summary |
| REQ-AI-UX-003 | Confidence indicators on AI output | Must | 1 | Calibrated probabilities |
| REQ-AI-UX-004 | User feedback loop (thumbs up/down) | Must | 1 | Improve models |
| REQ-AI-UX-005 | Offline mode (no network) | Must | 1 | Fully local |
| REQ-AI-UX-006 | Model versioning and rollback | Should | 2 | Reproducibility |

---

## 5. Collaboration & Sharing

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-COL-001 | Project file format (SQLite + JSON) | Must | 1 | Portable, mergeable |
| REQ-COL-002 | Annotation layer (comments, names, types) | Must | 1 | Separate from core DB |
| REQ-COL-003 | Real-time collaborative editing | Could | 3 | CRDT/OT based |
| REQ-COL-004 | Read-only shareable analysis (web viewer) | Should | 2 | Zero-install |
| REQ-COL-005 | Analysis replay (step-by-step) | Could | 2 | Teaching/forensics |
| REQ-COL-006 | Git integration (diff annotations) | Should | 2 | Version control |

---

## 6. Dynamic Analysis (Future)

| ID | Requirement | Priority | Phase | Notes |
|----|-------------|----------|-------|-------|
| REQ-DYN-001 | Debugger adapter protocol (DAP) support | Should | 2 | VS Code compatible |
| REQ-DYN-002 | GDB/LLDB/WinDbg backends | Should | 2 | Multi-platform |
| REQ-DYN-003 | Emulator integration (Unicorn, QEMU) | Could | 2 | For firmware |
| REQ-DYN-004 | Trace import (Intel PT, rr, Frida) | Could | 3 | Time-travel |
| REQ-DYN-005 | Dynamic taint analysis | Could | 3 | Runtime |

---

## 7. Non-Functional Requirements

### 7.1 Performance

| ID | Requirement | Target | Phase |
|----|-------------|--------|-------|
| NFR-PERF-001 | Cold start (app launch) | <3s | 1 |
| NFR-PERF-002 | Load 50MB binary | <10s | 1 |
| NFR-PERF-003 | Full auto-analysis (50MB) | <60s | 1 |
| NFR-PERF-004 | Decompile single function | <500ms | 1 |
| NFR-PERF-005 | Graph layout (10k nodes) | <2s | 1 |
| NFR-PERF-006 | Memory usage (100MB binary) | <2GB | 1 |
| NFR-PERF-007 | UI responsiveness (60fps) | Always | 1 |

### 7.2 Reliability

| ID | Requirement | Target | Phase |
|----|-------------|--------|-------|
| NFR-REL-001 | Crash recovery (auto-save) | <30s data loss | 1 |
| NFR-REL-002 | Graceful degradation (OOM) | Warn, not crash | 1 |
| NFR-REL-003 | Deterministic analysis | Same input = same output | 1 |
| NFR-REL-004 | Binary compatibility (plugins) | 1 year minimum | 1 |

### 7.3 Security

| ID | Requirement | Target | Phase |
|----|-------------|--------|-------|
| NFR-SEC-001 | No code execution from parsed binary | Guaranteed | 1 |
| NFR-SEC-002 | Sandboxed plugin execution | WASM/deno | 2 |
| NFR-SEC-003 | Signed releases + reproducible builds | Required | 1 |
| NFR-SEC-004 | Dependency scanning (SBOM) | Automated | 1 |
| NFR-SEC-005 | No telemetry without consent | Opt-in only | 1 |

### 7.4 Portability

| ID | Requirement | Target | Phase |
|----|-------------|--------|-------|
| NFR-PORT-001 | Linux (x64, ARM64) | Native | 1 |
| NFR-PORT-002 | macOS (x64, ARM64) | Native | 1 |
| NFR-PORT-003 | Windows (x64, ARM64) | Native | 1 |
| NFR-PORT-004 | WebAssembly (viewer only) | Should | 2 |
| NFR-PORT-005 | FreeBSD/OpenBSD | Could | 2 |

---

## 8. Data & File Formats

### 8.1 Project Format

- **Container**: SQLite database (ACID, incremental, queryable)
- **Schema**: Versioned, migratable, documented
- **Annotations**: Separate tables (user-modifiable without schema change)
- **Blobs**: Large data (graphs, ML embeddings) in separate files

### 8.2 Import/Export

| Format | Import | Export | Phase |
|--------|--------|--------|-------|
| Ghidra project | Should | Could | 2 |
| IDA database (.idb/.i64) | Should | Could | 2 |
| Binary Ninja (.bndb) | Could | Could | 2 |
| radare2 project | Could | Could | 2 |
| C pseudo-code | - | Must | 1 |
| GraphViz DOT | - | Must | 1 |
| JSON/GraphQL API | - | Must | 1 |
| SARIF (static analysis) | - | Should | 2 |

---

## 9. Testing Requirements

| ID | Requirement | Details |
|----|-------------|---------|
| REQ-TEST-001 | Unit test coverage | >80% for core analysis |
| REQ-TEST-002 | Integration tests | Real binaries corpus |
| REQ-TEST-003 | Regression test suite | 1000+ binaries, CI |
| REQ-TEST-004 | Fuzzing harness | Binary parsers, 24/7 |
| REQ-TEST-005 | Performance benchmarks | Tracked per release |
| REQ-TEST-006 | Accessibility testing | Automated + manual |
| REQ-TEST-007 | Plugin API compatibility | Test matrix |

---

## 10. Documentation Requirements

| ID | Requirement | Format | Audience |
|----|-------------|--------|----------|
| REQ-DOC-001 | User guide | Markdown + Web | Analysts |
| REQ-DOC-002 | API reference | Auto-generated (Sphinx) | Developers |
| REQ-DOC-003 | Plugin development guide | Tutorial + Reference | Plugin authors |
| REQ-DOC-004 | Architecture decision records | Markdown (ADR) | Contributors |
| REQ-DOC-005 | Video tutorials | YouTube/PeerTube | Beginners |
| REQ-DOC-006 | FAQ / Troubleshooting | Searchable | All |

---

## 11. Release Criteria (MVP)

### Must Pass
- [ ] All Must-priority requirements implemented and tested
- [ ] Zero critical/high security findings
- [ ] Performance targets met on reference hardware
- [ ] 3+ example plugins demonstrating extensibility
- [ ] Documentation covers all core workflows
- [ ] Installers for Linux/macOS/Windows
- [ ] Automated CI/CD with release artifacts

### Should Pass
- [ ] 10+ community-contributed plugins
- [ ] Localization for 3+ languages
- [ ] Jupyter notebook examples
- [ ] Comparison benchmarks vs Ghidra/IDA

---

## 12. Traceability Matrix

Each requirement traces to:
- **User Persona** (from UserPersonas.md)
- **Competitive Gap** (from CompetitiveAnalysis.md)
- **Feature Idea** (from FeatureBrainstorm.md)
- **Risk** (from Risks.md)

*Full traceability maintained in GitHub Projects with custom fields.*

---

*This document is version-controlled. Changes require RFC process for Must-priority items.*