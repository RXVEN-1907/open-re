# openre Platform Transformation Design Specification

> **Status**: Draft — awaiting user review
> **Date**: 2026-09-08
> **Scope**: Architectural transformation adding 35+ major features across 7 phased implementations

---

## 1. Executive Summary

Transform `openre` from a capable binary analysis + web scanning platform into the **definitive cross-platform reverse engineering and offensive security toolkit** — a single ~20MB binary combining:

- **Static Analysis**: Disassembly, decompilation, CFG/DFG, data-flow, type inference, function identification
- **Dynamic Analysis**: Tracing, emulation, runtime instrumentation, coverage-guided fuzzing
- **Multi-Format**: ELF, PE, Mach-O, WASM, firmware images, shared libraries, raw binaries
- **Web/API Security**: Crawling, GraphQL, WebSockets, OpenAPI-aware, auth/session analysis
- **AI Intelligence**: Vulnerability hypothesis generation, PoC generation, patch diff, CVE correlation, NL queries
- **Specialized Domains**: Firmware extraction, malware behavioral analysis, secrets discovery, SBOM, supply-chain
- **Collaboration**: Portable project files (ZIP), cross-binary diff, binary similarity, reproducible runs
- **Deployment**: Zero-deps, air-gapped, CI/CD ready (SARIF), terminal-first (CLI + TUI)

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              openre Platform (Single Binary)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│  │   CLI        │  │   TUI        │  │  Library API │  │  Plugins     │            │
│  │  (openre)    │  │  (openre-tui)│  │  (openre-*)  │  │  (WASM)      │            │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│         │                 │                 │                 │                    │
│         └─────────────────┼─────────────────┼─────────────────┘                    │
│                           ▼                 ▼                                       │
│              ┌─────────────────────────────────────────┐                           │
│              │           openre-core                   │                           │
│              │  Types, Errors, Traits, Results, IDs   │                           │
│              └──────────────────┬──────────────────────┘                           │
│                                 │                                                  │
│        ┌────────────────────────┼────────────────────────┐                        │
│        ▼                        ▼                        ▼                        │
│ ┌─────────────┐         ┌─────────────┐         ┌─────────────┐                 │
│ │openre-scan  │         │openre-analysis│        │openre-ai    │                 │
│ │ Web/API     │         │ Binary      │         │ AI Engine   │                 │
│ │ Scanner     │         │ Analyzer    │         │ Local/Cloud │                 │
│ └──────┬──────┘         └──────┬──────┘         └──────┬──────┘                 │
│        │                       │                       │                         │
│        └───────────────────────┼───────────────────────┘                         │
│                                ▼                                                │
│                 ┌────────────────────────┐                                      │
│                 │  openre-intelligence   │                                      │
│                 │  Coordinator Agent     │                                      │
│                 │  Vuln Research → PoC   │                                      │
│                 │  Exploit Gen → Remediate│                                     │
│                 │  Fuzz → Triage → Patch │                                      │
│                 └────────────────────────┘                                      │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

### New Crates to Add

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| `openre-disasm` | Capstone-based disassembly + lifter | capstone, goblin, object |
| `openre-decomp` | ML/LLM-assisted decompilation | openre-disasm, openre-ai, candle/ort |
| `openre-fuzz` | libafl-based coverage-guided fuzzing | libafl, openre-disasm, openre-analysis |
| `openre-firmware` | Firmware extraction + analysis | scroll, goblin, openre-analysis |
| `openre-malware` | Behavioral analysis, unpacking, IOCs | openre-analysis, openre-fuzz, openre-disasm |
| `openre-supply-chain` | SBOM, dependency analysis, license | openre-analysis, cargo-metadata, spdx, cyclonedx |
| `openre-similarity` | Binary similarity, clustering, diffing | openre-analysis, openre-disasm, simhash, minhash |
| `openre-project` | Portable project files (ZIP), collaboration | zip, serde, openre-core |
| `openre-threat-intel` | CVE/CWE/CAPEC/ATT&CK knowledge base | reqwest, sqlite, openre-core |
| `openre-secrets` | Secret/credential discovery | regex, entropy, openre-core |

---

## 3. Phase 1: Core Binary Analysis (Weeks 1-12)

### 3.1 Disassembly Engine (`openre-disasm`)

**Technology**: Capstone (via `capstone` crate) + custom instruction lifter to intermediate representation (IR)

```rust
// Core types
pub struct Disassembler {
    cs: capstone::Capstone,
    architecture: Architecture,
    mode: Mode,
    syntax: Syntax, // Intel/ATT
}

pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub groups: Vec<InsnGroup>,
    pub detail: Option<InstructionDetail>, // registers, memory operands, etc.
}

pub struct Function {
    pub address: u64,
    pub name: Option<String>,
    pub size: u64,
    pub blocks: Vec<BasicBlock>,
    pub calls: Vec<u64>,
    pub called_by: Vec<u64>,
    pub complexity: u32,
    pub stack_frame: Option<StackFrame>,
    pub signature: Option<FunctionSignature>,
}
```

**Capabilities**:
- Multi-arch: x86, x86_64, ARM, AArch64, MIPS, RISC-V, PowerPC, SPARC, SystemZ, BPF, EVM
- Syntax: Intel (default), ATT
- Control flow analysis: direct/indirect calls, jumps, conditional branches
- Register/memory operand tracking
- Function prologue/epilogue detection
- Thunk identification

### 3.2 Decompilation Engine (`openre-decomp`)

**Technology**: Hybrid approach
- **Stage 1**: Structural analysis (CFG recovery, loop detection, SSA form) — pure Rust
- **Stage 2**: Type inference (value-set analysis, pointer analysis) — pure Rust
- **Stage 3**: Pseudo-C generation via local LLM (llama.cpp/ONNX) — optional, falls back to rule-based

```rust
pub struct Decompiler {
    disassembler: Disassembler,
    type_inferencer: TypeInferencer,
    llm_client: Option<LlmDecompilerClient>, // Local only
}

pub struct DecompilationResult {
    pub function: Function,
    pub pseudo_c: String,
    pub confidence: f32,
    pub variable_map: HashMap<u64, Variable>,
    pub type_map: HashMap<u64, Type>,
    pub control_flow: ControlFlowStructures, // loops, ifs, switches
}
```

**LLM Integration**: Fine-tuned CodeLlama-7B/DeepSeek-Coder-6B model (~1.5-2GB quantized Q4_K_M) loaded via `llama-cpp-2` (CPU/Apple Silicon/CUDA) or ONNX Runtime. Runs entirely offline. Model downloaded on first use (not bundled) to keep binary <25MB.

**Rule-based Fallback**: When LLM unavailable, uses structured pretty-printer:
- SSA → C-like syntax with `goto` for irreducible control flow
- Type annotations from value-set analysis
- Loop reconstruction: `while`/`for` from loop headers
- Switch detection from jump tables
- Variable naming: `var_<addr>`, `arg_<n>`, `local_<n>`

### 3.3 CFG/DFG Recovery

```rust
pub struct ControlFlowGraph {
    pub nodes: Vec<CfgNode>,        // Basic blocks
    pub edges: Vec<CfgEdge>,        // Control flow edges
    pub entry: u64,
    pub exits: Vec<u64>,
    pub loops: Vec<Loop>,
    pub dominator_tree: DominatorTree,
    pub post_dominator_tree: DominatorTree,
}

pub struct DataFlowGraph {
    pub nodes: Vec<DfgNode>,        // Variables/definitions
    pub edges: Vec<DfgEdge>,        // Def-use chains
    pub reaching_defs: HashMap<u64, BitSet>,
    pub live_variables: HashMap<u64, BitSet>,
    pub taint_sources: Vec<TaintSource>,
    pub taint_sinks: Vec<TaintSink>,
}
```

### 3.4 Function Identification & Type Inference

- **FLIRT-style signatures**: Parse `.pat`/`.sig` files (IDA-compatible) for libc/msvcrt/glibc/stdlib detection. Built-in signatures for common libraries.
- **Function boundary detection**: 
  - Heuristic: Prologue patterns (push rbp; mov rbp, rsp; sub rsp, N), epilogue patterns (pop rbp; ret)
  - ML-assisted: Lightweight CNN on instruction sequences (ONNX model, ~5MB) for edge cases
  - Tail call / sibling call detection
- **Type propagation**: 
  - Value-set analysis (VSA) on registers/memory (Strided Interval abstract domain)
  - Pointer analysis: Andersen's inclusion-based (sparse, flow-insensitive)
  - API signature matching: Windows API, POSIX, libc, kernel syscalls
- **Calling convention detection**: System V AMD64, Microsoft x64, ARM64 AAPCS, ARM AAPCS, RISC-V, MIPS O32/N32/N64

### 3.5 CLI Commands (Phase 1)

```bash
openre analyze <file> --disasm [--function <name>|--range <start> <end>] [--syntax intel|att]
openre analyze <file> --decompile [--function <name>] [--llm|--no-llm] [--output <file>]
openre analyze <file> --cfg [--function <name>] [--format dot|json|mermaid]
openre analyze <file> --dfg [--function <name>] [--taint <source>]
openre analyze <file> --functions [--filter <pattern>] [--details]
openre analyze <file> --types [--function <name>]
openre analyze <file> --pipeline [--stages identify,load,disassemble,cfg,dfg,types,decompile,ai]
```

### 3.6 TUI Panels (Phase 1)

- **Disassembly View**: Syntax-highlighted assembly with navigation
- **Decompilation View**: Side-by-side asm + pseudo-C
- **CFG View**: Graphviz/mermaid rendering with zoom/pan
- **DFG View**: Data dependency graph with taint highlighting
- **Function Browser**: Searchable, filterable function list

---

## 4. Phase 2: Advanced Binary Formats (Weeks 13-18)

### 4.1 Firmware Analysis (`openre-firmware`)

```rust
pub struct FirmwareAnalyzer {
    extractors: Vec<Box<dyn FirmwareExtractor>>,
    analyzer: BinaryAnalyzer,
}

pub trait FirmwareExtractor {
    fn can_handle(&self, data: &[u8]) -> bool;
    fn extract(&self, data: &[u8], output_dir: &Path) -> Result<Vec<ExtractedFile>>;
    fn identify(&self, data: &[u8]) -> FirmwareInfo;
}

pub struct ExtractedFile {
    pub path: PathBuf,
    pub file_type: FileType,
    pub entropy: f64,
    pub is_binary: bool,
    pub architecture: Option<Architecture>,
}
```

**Supported Formats**:
- Filesystems: squashfs, jffs2, yaFFS2, cramfs, ext2/3/4, UBIFS, romfs
- Bootloaders: U-Boot, GRUB, EDK2
- Containers: Docker/OCI layers, CPIO, TAR
- Encryption: LZMA, LZ4, gzip, xz, custom XOR/RC4
- Partition tables: MBR, GPT, MTD

**CLI**:
```bash
openre firmware extract <file> --output <dir> [--recursive]
openre firmware analyze <file> --attack-surface [--format json]
openre firmware identify <file>
```

### 4.2 Raw Binary & Shared Library Support

- Raw binary: Auto-detect architecture via entropy/string analysis + entry point heuristics
- Shared libraries: `.so`, `.dylib`, `.dll` — export/import analysis, version scripts
- Kernel modules: `.ko` — symbol versioning, vermagic

### 4.3 Architecture Support

| Architecture | Disasm | Decompile | CFG | Notes |
|--------------|--------|-----------|-----|-------|
| x86 | ✅ | ✅ | ✅ | 16/32/64-bit |
| x86_64 | ✅ | ✅ | ✅ | Primary target |
| ARM (32-bit) | ✅ | ✅ | ✅ | Thumb/Thumb-2 |
| AArch64 | ✅ | ✅ | ✅ | ARMv8-A |
| MIPS | ✅ | 🟡 | ✅ | 32/64, endianness |
| RISC-V | ✅ | 🟡 | ✅ | RV32/64, compressed |
| PowerPC | ✅ | ❌ | ✅ | 32/64 |
| SPARC | ✅ | ❌ | ✅ | |
| BPF/eBPF | ✅ | ❌ | ✅ | Kernel bytecode |
| EVM | ✅ | ❌ | ✅ | Ethereum bytecode |

🟡 = Rule-based decompilation only (no LLM fine-tune yet)

---

## 5. Phase 3: Dynamic Analysis & Fuzzing (Weeks 19-32)

### 5.1 Tracing & Emulation

```rust
pub struct Tracer {
    backend: TracerBackend, // Ptrace, Frida, DynamoRIO, QEMU-user
    config: TraceConfig,
}

pub enum TracerBackend {
    Ptrace(PtraceTracer),
    Frida(FridaTracer),
    QemuUser(QemuUserTracer),
    #[cfg(windows)]
    WinDbg(WinDbgTracer),
}

pub struct TraceEvent {
    pub timestamp: u64,
    pub tid: u32,
    pub event_type: TraceEventType,
    pub ip: u64,
    pub memory: Option<MemoryAccess>,
    pub registers: RegisterState,
    pub syscall: Option<SyscallEvent>,
}

pub enum TraceEventType {
    Instruction,
    Branch,
    Call,
    Return,
    SyscallEnter,
    SyscallExit,
    MemoryRead,
    MemoryWrite,
    Signal,
}
```

### 5.2 Runtime Instrumentation

- **Dynamic Binary Instrumentation (DBI)**: Frida (via `frida` crate, optional feature) for cross-platform hooking — requires Frida server on target
- **Lightweight**: `ptrace`-based for Linux, `VmRead/Write` for Windows, `procfs` for Linux
- **Coverage Collection**: Edge coverage via instrumentation callbacks
- **QEMU-user mode**: `qemu-user` + `libafl-qemu` plugin for binary-only coverage (no source)

### 5.3 Fuzzing Engine (`openre-fuzz`)

**Technology**: `libafl` — pure Rust, in-process, coverage-guided

```rust
pub struct Fuzzer {
    executor: InProcessExecutor<Harness>,
    mutator: ScheduledMutator<BytesInput>,
    feedback: MaxMapFeedback,
    objective: CrashObjective,
    corpus: Corpus<BytesInput>,
    state: StdState<BytesInput>,
}

pub struct FuzzConfig {
    pub target_binary: PathBuf,
    pub harness: HarnessType, // Persistent, forkserver, QEMU
    pub input_dir: PathBuf,
    pub output_dir: PathBuf,
    pub timeout: Duration,
    pub max_len: usize,
    pub dict: Option<PathBuf>,
    pub dictionary: Vec<Vec<u8>>,
    pub sanctions: SanitizerConfig, // ASAN, MSAN, TSAN
    pub parallel: usize,
}

pub enum HarnessType {
    Persistent { function: String, args: Vec<String> },
    ForkServer { binary: PathBuf },
    QemuUser { binary: PathBuf, arch: Architecture },
    Frida { script: String },
    Custom { library: PathBuf, entry: String },
}
```

**Features**:
- **Structure-aware mutation**: 
  - Built-in: JSON (via `serde_json`), XML (via `quick-xml`), Protocol Buffers (via `prost`)
  - Custom grammars: RFC 5234 ABNF format or libafl's `GrammarMutator` with BNF-like DSL
  - Dictionary-based: Auto-extract strings/constants from target binary
- **Coverage-guided**: Edge coverage via:
  - Compiler instrumentation: `-fsanitize-coverage=trace-pc-guard` (LLVM) / `/fsanitize-coverage=trace-pc-guard` (MSVC)
  - QEMU-user mode: `qemu-x86_64 -plugin libafl-qemu.so` for binary-only targets
  - Frida: `Stalker` API for dynamic instrumentation
- **Crash triage**: Deduplication via stack trace hashing (top 5 frames + fault address), exploitability classification
- **Corpus minimization**: libafl's `CorpusMinimizer` with coverage-preserving reduction
- **Parallel fuzzing**: Multi-process via `libafl::multiprocess` (TCP/Unix socket coordination)
- **Sanitizer integration**: ASAN/MSAN/TSAN via compiler flags (`-fsanitize=address,memory,thread`)
- **Network fuzzing**: Custom mutators for HTTP, DNS, TLS, custom protocols via state machines
- **Web/API fuzzing**: OpenAPI-driven — generates valid/invalid requests per schema, auth fuzzing

**CLI**:
```bash
openre fuzz <binary> --harness persistent --function vulnerable_func --input corpus/ --output findings/
openre fuzz <binary> --harness qemu --arch x86_64 --input corpus/
openre fuzz --api <openapi.json> --target https://api.example.com --output findings/
openre fuzz --triage findings/ --deduplicate --minimize
```

### 5.4 Exploitability Analysis

```rust
pub struct ExploitabilityAnalyzer {
    crash: CrashInfo,
    binary: BinaryInfo,
    trace: Option<Trace>,
}

pub struct CrashInfo {
    pub crash_type: CrashType,
    pub ip: u64,
    pub fault_address: u64,
    pub register_state: RegisterState,
    pub stack: Vec<u64>,
    pub backtrace: Vec<Frame>,
    pub signal: Option<i32>,
    pub sanitizer_report: Option<String>,
}

pub struct ExploitabilityResult {
    pub classification: ExploitClass,
    pub root_cause: RootCause,
    pub primitives: Vec<Primitive>,
    pub score: ExploitabilityScore, // 0.0-10.0 (CVSS-like)
    pub constraints: Vec<Constraint>,
    pub mitigation_bypass: Vec<MitigationBypass>,
}

pub enum ExploitClass {
    NotExploitable,
    DenialOfService,
    ControlledCrash,
    PartialControl,
    FullControl,
    RemoteCodeExecution,
}
```

---

## 6. Phase 4: Web/API Security (Weeks 33-40)

### 6.1 Enhanced Scanner (`openre-scan`)

**New Checks**:
- GraphQL: Introspection, field suggestions, batching, alias overloading, depth DoS
- WebSocket: Handshake validation, message fuzzing, origin checks
- OpenAPI/Swagger: Spec validation, operation fuzzing, auth flow testing
- Auth/Session: JWT analysis, OAuth/OIDC flows, session fixation, cookie flags
- Crawling: JS rendering (headless), SPA support, form authentication

```rust
pub struct WebScanner {
    http_client: HttpClient,
    crawler: Crawler,
    graphql_tester: GraphQLTester,
    websocket_tester: WebSocketTester,
    api_tester: ApiTester,
    auth_analyzer: AuthAnalyzer,
}

pub enum ScanCheck {
    // Existing 18 checks...
    GraphQLIntrospection,
    GraphQLFieldSuggestions,
    GraphQLBatchingAbuse,
    GraphQLDepthDoS,
    WebSocketHandshake,
    WebSocketMessageFuzzing,
    OpenAPISpecValidation,
    OpenAPIOperationFuzzing,
    AuthJWTAnalysis,
    AuthOAuthFlow,
    SessionFixation,
    CookieSecurity,
    JavaScriptRendering,
    SPARouting,
    FormAuthentication,
    // ...
}
```

### 6.2 API Security Testing

```bash
openre scan https://api.example.com --profile full --openapi spec.json
openre scan wss://ws.example.com --websocket
openre scan https://app.example.com --graphql --introspect
openre scan https://app.example.com --auth oauth2 --client-id xxx --client-secret yyy
```

### 6.3 Authentication/Session Analysis

- JWT: Algorithm confusion, key confusion, `none` alg, weak secrets, claims validation
- OAuth/OIDC: PKCE, redirect URI validation, state parameter, token leakage
- SAML: Signature wrapping, XML parsing, assertion replay
- Session: Fixation, hijacking, concurrent sessions, rotation

---

## 7. Phase 5: AI/Intelligence (Weeks 41-52)

### 7.1 Vulnerability Hypothesis Generation

```rust
pub struct HypothesisGenerator {
    ai_client: AiClient,
    knowledge_base: VulnerabilityKnowledgeBase,
    code_context: CodeContextBuilder,
}

pub struct VulnerabilityHypothesis {
    pub id: String,
    pub title: String,
    pub description: String,
    pub cwe: Vec<String>,
    pub attack_vector: AttackVector,
    pub affected_functions: Vec<FunctionRef>,
    pub evidence: Vec<Evidence>,
    pub confidence: f32,
    pub exploitability: ExploitabilityAssessment,
    pub suggested_poc: Option<PoCPlan>,
}
```

### 7.2 Automated PoC Generation

```rust
pub struct PoCGenerator {
    ai_client: AiClient,
    sandbox: WasmtimeSandbox,
    templates: PoCTemplateRegistry,
}

pub struct PoCPlan {
    pub language: PoCLanguage,
    pub strategy: PoCStrategy,
    pub steps: Vec<PoCStep>,
    pub prerequisites: Vec<String>,
    pub validation: ValidationCriteria,
}

pub enum PoCLanguage {
    Python,     // Compiled to WASM via `wasm-pack` + `python-wasm` (pyodide) or native via `wasmtime-wasi` with Python embedded
    Rust,       // `cargo build --target wasm32-wasi` → native WASM
    C,          // `clang --target=wasm32-wasi` via WASI SDK
    Go,         // `GOOS=wasip1 GOARCH=wasm go build` (Go 1.21+)
    JavaScript, // Direct WASM via `wasmtime` JS API or `quickjs`
    WASM,       // Pre-compiled WASM module
}

**Compilation to WASM for Sandboxed Validation**:
- Rust/C/Go: Native WASI targets — direct compilation, fast startup
- Python: Pyodide (WebAssembly port of CPython) or `wasmtime` with `wasi-preview1` + embedded Python — slower but compatible
- JavaScript: `quickjs` compiled to WASM or Wasmtime's JS host bindings
- All WASM modules run in `Wasmtime` with `ResourceLimits` (CPU, memory, wall time, syscalls via WASI)
```

### 7.3 Patch Diff Analysis

```rust
pub struct PatchAnalyzer {
    disassembler: Disassembler,
    similarity: BinarySimilarity,
}

pub struct PatchDiffResult {
    pub changed_functions: Vec<FunctionDiff>,
    pub security_relevant: Vec<SecurityRelevantChange>,
    pub introduced_vulnerabilities: Vec<VulnerabilityHypothesis>,
    pub fixed_vulnerabilities: Vec<FixedVulnerability>,
}
```

### 7.4 CVE/CWE/CAPEC Correlation

**Data Sources (Online, Cached Locally)**:
| Source | Format | Update Frequency | Size |
|--------|--------|------------------|------|
| Exploit-DB (GitHub) | CSV + exploit files | Daily | ~500MB |
| NVD JSON Feeds | JSON (CVE-year.json.gz) | Daily | ~2GB/year |
| MITRE CWE | XML/CSV/STIX | Monthly | ~50MB |
| MITRE CAPEC | STIX 2.0/2.1 JSON | Monthly | ~20MB |
| MITRE ATT&CK | STIX 2.0/2.1 JSON | Monthly | ~30MB |
| GitHub Advisory Database | JSON/OSV | Daily | ~100MB |

**Local Cache Strategy**:
```rust
pub struct VulnerabilityKnowledgeBase {
    cve_index: CveIndex,           // CVE ID → CveEntry
    cwe_index: CweIndex,           // CWE ID → CweEntry
    capec_index: CapecIndex,       // CAPEC ID → CapecEntry
    exploit_db: ExploitDbIndex,    // CVE/EDB-ID → ExploitEntry
    cve_cwe_map: HashMap<String, Vec<String>>,
    cwe_capec_map: HashMap<String, Vec<String>>,
    cache_dir: PathBuf,
    last_updated: DateTime<Utc>,
    auto_update: bool,
}
```

**CLI**:
```bash
openre intel update-kb                    # Download/update all sources
openre intel search-cve CVE-2024-XXXX     # Lookup CVE
openre intel search-cwe CWE-787           # Lookup CWE
openre intel search-capec CAPEC-123       # Lookup CAPEC
openre intel correlate --binary ./app     # Map binary findings to CVE/CWE/CAPEC
openre intel hypothesis --binary ./app --function vulnerable_func
openre intel poc <finding-id> --language python --sandbox
openre intel patch-diff ./v1 ./v2 --output patch-report.json
```

### 7.5 Natural Language Interface

```bash
openre ai "Where does user input reach this memory operation at 0x401230?" --binary ./app
openre ai "Find all paths from network recv to memcpy" --binary ./app
openre ai "Explain this buffer overflow in function parse_packet" --binary ./app --decompile
```

---

## 8. Phase 6: Supply-chain, Firmware, Malware (Weeks 53-62)

### 8.1 Supply-Chain Analysis (`openre-supply-chain`)

```rust
pub struct SupplyChainAnalyzer {
    sbom_generator: SbomGenerator,
    dependency_analyzer: DependencyAnalyzer,
    license_analyzer: LicenseAnalyzer,
    vulnerability_matcher: VulnerabilityMatcher,
}

pub struct SbomResult {
    pub packages: Vec<Package>,
    pub relationships: Vec<Relationship>,
    pub format: SbomFormat, // SPDX, CycloneDX
}

pub struct Package {
    pub name: String,
    pub version: String,
    pub ecosystem: String,  // crates.io, pypi, npm, maven, go, nuget, etc.
    pub license: Option<String>,
    pub hash: String,       // SHA256 of package contents
    pub path: Option<PathBuf>, // Local path if available
}

pub struct Relationship {
    pub from: String,      // Package ID
    pub to: String,        // Package ID
    pub rel_type: RelationshipType, // DependsOn, Contains, BuildDependsOn, etc.
}

pub enum SbomFormat {
    Spdx,
    CycloneDx,
}

pub struct DependencyFinding {
    pub package: Package,
    pub vulnerability: CveEntry,
    pub exploit_available: bool,
    pub exploit_maturity: ExploitMaturity,  // PoC, Functional, High, Weaponized
    pub fix_version: Option<String>,
    pub reachability: ReachabilityAnalysis,  // Is vulnerable code actually called?
}

pub enum ExploitMaturity {
    ProofOfConcept,
    Functional,
    High,
    Weaponized,
}

pub struct ReachabilityAnalysis {
    pub reachable: bool,
    pub call_chain: Vec<String>,  // Function call chain from entry to vulnerable function
    pub confidence: f32,
}
```

**CLI**:
```bash
openre supply-chain sbom --project ./my-project --format spdx --output sbom.spdx.json
openre supply-chain audit --sbom sbom.spdx.json --kb
openre supply-chain licenses --project ./my-project --policy policy.yaml
openre supply-chain reachability --binary ./app --sbom sbom.spdx.json
```

### 8.2 Malware Analysis (`openre-malware`)

```rust
pub struct MalwareAnalyzer {
    static_analyzer: StaticAnalyzer,
    dynamic_analyzer: DynamicAnalyzer,
    unpacker: UnpackerRegistry,
    ioc_extractor: IoCExtractor,
    capability_mapper: CapabilityMapper,
}

pub struct MalwareReport {
    pub family: Option<String>,
    pub classification: MalwareClassification,
    pub iocs: Vec<IoC>,
    pub capabilities: Vec<Capability>,
    pub unpacked_layers: Vec<UnpackedLayer>,
    pub behavior: BehavioralSummary,
    pub mitre_attack: Vec<AttackTechnique>,
}

pub enum MalwareClassification {
    Trojan,
    Ransomware,
    Worm,
    Virus,
    Rootkit,
    Backdoor,
    Downloader,
    Dropper,
    Botnet,
    Spyware,
    Adware,
    Miner,
    Unknown,
}

pub struct IoC {
    pub ioc_type: IoCType,
    pub value: String,
    pub context: Option<String>,  // Where found (memory, network, filesystem, registry)
    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub tags: Vec<String>,
}

pub enum IoCType {
    IP,
    Domain,
    URL,
    FileHash,
    RegistryKey,
    Mutex,
    Pipe,
    CryptoWallet,
    Email,
}

pub struct Capability {
    pub name: String,
    pub description: String,
    pub mitre_technique: Option<String>,  // ATT&CK technique ID
    pub confidence: f32,
    pub evidence: Vec<String>,
}

pub struct UnpackedLayer {
    pub layer: u32,
    pub format: String,       // e.g., "UPX", "custom", "encrypted"
    pub entropy: f64,
    pub size: u64,
    pub extracted_path: PathBuf,
    pub detection_method: String,
}

pub struct BehavioralSummary {
    pub processes_created: Vec<ProcessEvent>,
    pub files_accessed: Vec<FileEvent>,
    pub network_connections: Vec<NetworkEvent>,
    pub registry_modifications: Vec<RegistryEvent>,
    pub mutexes_created: Vec<String>,
    pub services_installed: Vec<String>,
    pub persistence_mechanisms: Vec<PersistenceMechanism>,
    pub anti_analysis: Vec<AntiAnalysisTechnique>,
}

pub struct AttackTechnique {
    pub technique_id: String,     // e.g., "T1059.001"
    pub technique_name: String,   // e.g., "PowerShell"
    pub tactic: String,           // e.g., "Execution"
    pub confidence: f32,
    pub evidence: Vec<String>,
}

pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub command_line: String,
    pub timestamp: DateTime<Utc>,
    pub action: ProcessAction,  // Create, Exit, Inject
}

pub struct FileEvent {
    pub path: PathBuf,
    pub action: FileAction,  // Read, Write, Delete, Create, Modify
    pub timestamp: DateTime<Utc>,
    pub entropy_before: Option<f64>,
    pub entropy_after: Option<f64>,
}

pub struct NetworkEvent {
    pub protocol: String,   // TCP, UDP, HTTP, DNS, etc.
    pub local_addr: String,
    pub remote_addr: String,
    pub direction: NetworkDirection,  // Inbound, Outbound
    pub timestamp: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

pub struct RegistryEvent {
    pub key: String,
    pub value_name: String,
    pub action: RegistryAction,  // Create, Modify, Delete
    pub timestamp: DateTime<Utc>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

pub enum ProcessAction { Create, Exit, Inject }
pub enum FileAction { Read, Write, Delete, Create, Modify }
pub enum NetworkDirection { Inbound, Outbound }
pub enum RegistryAction { Create, Modify, Delete }

pub struct PersistenceMechanism {
    pub technique: String,      // e.g., "Run Key", "Service", "Scheduled Task", "WMI"
    pub location: String,       // Registry path, file path, etc.
    pub description: String,
    pub mitre_technique: Option<String>,
}

pub struct AntiAnalysisTechnique {
    pub name: String,           // e.g., "VM Detection", "Debugger Check", "Timing Check"
    pub description: String,
    pub detected: bool,
    pub details: String,
}
```

**CLI**:
```bash
openre malware analyze <file> --static --dynamic --unpack --output report.json
openre malware iocs <file> --format stix
openre malware unpack <file> --output ./unpacked/
openre malware behavior <file> --trace --duration 60s
```

### 8.3 Secrets Discovery

```rust
pub struct SecretsScanner {
    rules: Vec<SecretRule>,
    entropy_analyzer: EntropyAnalyzer,
    validator: SecretValidator,
}

pub struct SecretFinding {
    pub rule: String,
    pub location: Location,
    pub value: String, // Masked in output
    pub entropy: f64,
    pub validated: bool,
    pub validator_result: Option<ValidationResult>,
}
```

**Detects**: API keys, tokens, passwords, private keys, certificates, database URLs, cloud credentials, JWTs, PGP keys, SSH keys, AWS/GCP/Azure keys, Slack/Discord/Telegram tokens, etc.

---

## 9. Phase 7: Collaboration, Reporting, Reproducibility (Weeks 63-68)

### 9.1 Portable Project Files (`openre-project`)

**Format**: ZIP container with structured layout

```
project.oproj/
├── manifest.json          # Project metadata, version, schema
├── metadata/
│   ├── project.json       # Name, description, created, tags
│   ├── binaries.json      # Binary hashes, paths, analysis status
│   ├── findings.json      # All findings with evidence
│   ├── annotations.json   # Analyst notes, tags, classifications
│   └── sessions.json      # Analysis sessions, tool runs, parameters
├── binaries/
│   ├── <sha256>.bin       # Original binary (optional, can be external ref)
│   └── <sha256>.meta.json # Per-binary metadata
├── analysis/
│   ├── cfg/<func>.dot     # Control flow graphs
│   ├── dfg/<func>.json    # Data flow graphs
│   ├── decomp/<func>.c    # Decompilation output
│   └── traces/            # Execution traces
├── evidence/
│   ├── <finding-id>/      # Per-finding evidence
│   │   ├── screenshots/
│   │   ├── memory_dumps/
│   │   └── pcaps/
└── exports/
    ├── report.html
    ├── report.sarif
    └── findings.csv
```

```rust
pub struct ProjectFile {
    pub manifest: ProjectManifest,
    pub binaries: HashMap<FileId, BinaryEntry>,
    pub findings: Vec<Finding>,
    pub annotations: Vec<Annotation>,
    pub sessions: Vec<AnalysisSession>,
}

pub struct ProjectManifest {
    pub version: u32,
    pub schema_version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub openre_version: String,
}

pub struct BinaryEntry {
    pub file_id: FileId,
    pub path: PathBuf,
    pub sha256: String,
    pub format: BinaryFormat,
    pub architecture: Architecture,
    pub analysis_status: AnalysisStatus,
    pub metadata_path: PathBuf,  // Relative to project root
}

pub struct AnalysisSession {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub tool: String,           // e.g., "disasm", "decomp", "fuzz", "scan"
    pub version: String,
    pub parameters: HashMap<String, String>,
    pub input_hashes: Vec<String>,
    pub output_hashes: Vec<String>,
    pub duration_ms: u64,
    pub status: SessionStatus,
}

pub enum AnalysisStatus { Pending, InProgress, Completed, Failed }
pub enum SessionStatus { Success, Failed, Partial }

pub enum ReportFormat { Html, Sarif, Json, Csv, Markdown, Pdf }

pub struct ProjectDiff {
    pub added_binaries: Vec<BinaryEntry>,
    pub removed_binaries: Vec<BinaryEntry>,
    pub modified_binaries: Vec<BinaryDiff>,
    pub added_findings: Vec<Finding>,
    pub removed_findings: Vec<Finding>,
    pub modified_findings: Vec<FindingDiff>,
}

pub struct BinaryDiff {
    pub file_id: FileId,
    pub changes: Vec<String>,
}

pub struct FindingDiff {
    pub finding_id: String,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
}

pub fn create_project(path: &Path, binaries: &[PathBuf]) -> Result<ProjectFile>
pub fn open_project(path: &Path) -> Result<ProjectFile>
pub fn add_finding(&mut self, finding: Finding) -> Result<()>
pub fn add_annotation(&mut self, finding_id: &str, annotation: Annotation) -> Result<()>
pub fn export_report(&self, format: ReportFormat, output: &Path) -> Result<()>
pub fn diff_projects(&self, other: &ProjectFile) -> ProjectDiff
```

### 9.2 Cross-Binary Comparison

```rust
pub struct BinaryDiffer {
    similarity: BinarySimilarity,
    disassembler: Disassembler,
}

pub struct BinarySimilarity {
    feature_extractor: FunctionFeatureExtractor,
    index: LshIndex,
}

pub struct BinaryDiffResult {
    pub function_matches: Vec<FunctionMatch>,
    pub unmatched_a: Vec<FunctionInfo>,
    pub unmatched_b: Vec<FunctionInfo>,
    pub cfg_diffs: Vec<CfgDiff>,
    pub string_diffs: Vec<StringDiff>,
    pub import_diffs: Vec<ImportDiff>,
    pub export_diffs: Vec<ExportDiff>,
}

pub struct CfgDiff {
    pub func_addr_a: u64,
    pub func_addr_b: u64,
    pub added_blocks: Vec<u64>,
    pub removed_blocks: Vec<u64>,
    pub added_edges: Vec<(u64, u64)>,
    pub removed_edges: Vec<(u64, u64)>,
    pub modified_blocks: Vec<BlockDiff>,
}

pub struct BlockDiff {
    pub address: u64,
    pub added_instructions: Vec<Instruction>,
    pub removed_instructions: Vec<Instruction>,
    pub modified_instructions: Vec<InstructionDiff>,
}

pub struct StringDiff {
    pub string: String,
    pub in_a: bool,
    pub in_b: bool,
    pub references_a: Vec<u64>,
    pub references_b: Vec<u64>,
}

pub struct ImportDiff {
    pub library: String,
    pub function: String,
    pub in_a: bool,
    pub in_b: bool,
}

pub struct ExportDiff {
    pub name: String,
    pub address_a: Option<u64>,
    pub address_b: Option<u64>,
    pub in_a: bool,
    pub in_b: bool,
}

pub struct FunctionDiff {
    pub size_diff: i64,
    pub complexity_diff: i32,
    pub block_count_diff: i32,
    pub instruction_count_diff: i32,
    pub cfg_diff: Option<CfgDiff>,
    pub signature_match: bool,
}

pub struct FunctionMatch {
    pub func_a: FunctionInfo,
    pub func_b: FunctionInfo,
    pub similarity: f32, // 0.0-1.0
    pub match_type: MatchType,
    pub diff: FunctionDiff,
}
```

### 9.3 Binary Similarity & Clustering (`openre-similarity`)

```rust
pub struct SimilarityEngine {
    feature_extractor: FunctionFeatureExtractor,
    index: LshIndex,        // Locality-Sensitive Hashing (MinHash LSH)
    clusterer: DbscanClusterer,
}

pub struct FunctionFeatureExtractor {
    disassembler: Disassembler,
    cfg_hasher: SimHasher,
    minhasher: MinHasher,
}

pub struct LshIndex {
    tables: Vec<LshTable>,
    num_tables: usize,
    num_hashes: usize,
}

pub struct DbscanClusterer {
    eps: f32,
    min_samples: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchType {
    Exact,          // 1.0 similarity
    Strong,         // 0.8-0.99
    Moderate,       // 0.5-0.79
    Weak,           // 0.3-0.49
    Different,      // < 0.3
}

pub struct FunctionFeatures {
    pub cfg_hash: u64,                    // SimHash of CFG structure (64-bit)
    pub instruction_histogram: Vec<u32>,  // Normalized mnemonic frequencies (top 50 mnemonics)
    pub constant_features: Vec<u64>,      // Extracted constants (immediates, addresses)
    pub string_features: Vec<String>,     // Referenced strings (filtered, min len 4)
    pub call_graph_signature: u64,        // MinHash of call graph neighborhood (k=3 hops)
    pub semantic_hash: u64,               // Semantic features from decompilation (if available)
}

impl FunctionFeatures {
    pub fn similarity(&self, other: &Self) -> f32 {
        // Weighted combination: CFG (40%) + Instructions (20%) + Constants (15%) + Strings (10%) + CallGraph (15%)
        let cfg_sim = simhash_similarity(self.cfg_hash, other.cfg_hash);
        let inst_sim = cosine_similarity(&self.instruction_histogram, &other.instruction_histogram);
        let const_sim = jaccard_similarity(&self.constant_features, &other.constant_features);
        let str_sim = jaccard_similarity_strings(&self.string_features, &other.string_features);
        let cg_sim = minhash_similarity(self.call_graph_signature, other.call_graph_signature);
        
        0.40 * cfg_sim + 0.20 * inst_sim + 0.15 * const_sim + 0.10 * str_sim + 0.15 * cg_sim
    }
}
```

**CLI**:
```bash
openre project create my-project.oproj --binaries ./bin1 ./bin2
openre project open my-project.oproj
openre project diff v1.oproj v2.oproj --output diff.json
openre similarity index ./samples/ --output similarity.idx
openre similarity search ./target.bin --index similarity.idx --threshold 0.8
openre similarity cluster ./samples/ --eps 0.3 --min-samples 5 --output clusters.json
```

### 9.4 CI/CD Integration & Reproducible Analysis

```yaml
# .github/workflows/security.yml
- name: Binary Analysis
  run: |
    ./openre analyze ./app --pipeline all --format sarif --output results.sarif
    ./openre fuzz ./app --harness persistent --function parse_input --input corpus/ --timeout 300 --output fuzz/
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Reproducibility Features**:
- Deterministic analysis: Fixed seeds, sorted outputs, version-locked deps
- Project snapshots: `openre project snapshot` captures tool versions, config, inputs
- Hash verification: All outputs include SHA256 of inputs
- Analysis provenance: Every finding traces back to tool, version, parameters, input hash

---

## 10. Resource Controls & Sandboxing

### 10.1 Cross-Platform Resource Limits

```rust
pub struct ResourceLimits {
    pub cpu_time: Option<Duration>,
    pub wall_time: Option<Duration>,
    pub memory: Option<u64>,        // bytes
    pub memory_swap: Option<u64>,
    pub processes: Option<u32>,
    pub file_size: Option<u64>,
    pub open_files: Option<u32>,
    pub cpu_cores: Option<f32>,     // CPU quota
}

pub fn apply_limits(limits: &ResourceLimits) -> Result<()> {
    #[cfg(target_os = "linux")]
    linux::apply_cgroups_limits(limits);
    #[cfg(target_os = "macos")]
    macos::apply_appsandbox_limits(limits);
    #[cfg(target_os = "windows")]
    windows::apply_job_object_limits(limits);
    #[cfg(target_os = "freebsd")]
    freebsd::apply_rctl_limits(limits);
}
```

### 10.2 Sandboxing

| Platform | Mechanism | Capabilities |
|----------|-----------|--------------|
| Linux | seccomp-bpf + namespaces + cgroups v2 | Syscall filtering, FS/network isolation, resource limits |
| macOS | App Sandbox + XPC | File access, network, syscalls |
| Windows | Job Objects + AppContainer | Process tree, memory, CPU, filesystem, network |
| FreeBSD | Capsicum + rctl | Capability mode, resource limits |

### 10.3 PoC Validation Sandbox (Wasmtime)

```rust
pub struct PocValidationSandbox {
    engine: wasmtime::Engine,
    linker: wasmtime::Linker<()>,
    limits: ResourceLimits,
}

impl PocValidationSandbox {
    pub fn validate_poc(&self, poc_wasm: &[u8], test_cases: &[TestCase]) -> ValidationResult {
        // Compile PoC to WASM (if not already)
        // Instantiate with resource limits
        // Run test cases
        // Return pass/fail with evidence
    }
}
```

**Flow**:
1. PoC generated as source (Python/Rust/C/Go)
2. Compiled to WASM via `wasm-pack` / `cargo build --target wasm32-wasi` / `emcc`
3. Executed in Wasmtime with resource limits
4. Network/filesystem access controlled via WASI capabilities
5. Results captured and reported

---

## 11. Threat Intelligence Integration

### 11.1 Data Sources & Sync

```rust
pub struct ThreatIntelUpdater {
    sources: Vec<Box<dyn IntelSource>>,
    cache: VulnerabilityKnowledgeBase,
    schedule: UpdateSchedule,
}

pub trait IntelSource {
    fn name(&self) -> &str;
    fn fetch(&self) -> Result<IntelUpdate>;
    fn parse(&self, data: &[u8]) -> Result<Vec<IntelEntry>>;
    fn last_modified(&self) -> Option<DateTime<Utc>>;
}

pub struct ExploitDbSource {
    repo_url: String,  // "https://github.com/malwareengineering/exploit-database.git"
    local_path: PathBuf,
    files_csv: PathBuf,  // files_exploits.csv from repo
}

pub struct NvdSource {
    base_url: String,  // "https://nvd.nist.gov/feeds/json/cve/1.1/"
    years: Vec<u32>,   // e.g., 2020-2025
    api_key: Option<String>,  // Optional NVD API key for higher rate limits
}

pub struct MitreSource {
    cwe_url: String,   // "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    capec_url: String, // "https://github.com/mitre/cti/raw/master/capec/capec-stix2.json"
    attack_url: String, // "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack-stix2.json"
}
```

### 11.2 Offline-First Design

- All intelligence cached locally in `~/.openre/intel/`
- `openre intel update-kb` downloads incrementally (If-Modified-Since, ETags)
- Works fully offline after initial sync
- Cache format: SQLite for queries, compressed JSON for bulk
- TTL-based staleness warnings

---

## 12. CLI Command Structure (Complete)

```bash
openre --help

SCANNING:
  openre scan <target> --profile quick|standard|full [--openapi] [--graphql] [--websocket] [--auth]
  openre scan <target> --custom --checks "headers,cors,graphql" --exclude "tls"

BINARY ANALYSIS:
  openre analyze <file> --info|--symbols|--imports|--exports|--strings|--sections|--segments
  openre analyze <file> --functions [--filter] [--details]
  openre analyze <file> --disasm [--function] [--range] [--syntax intel|att] [--bytes]
  openre analyze <file> --decompile [--function] [--llm|--no-llm] [--output]
  openre analyze <file> --cfg [--function] [--format dot|json|mermaid]
  openre analyze <file> --dfg [--function] [--taint <source>]
  openre analyze <file> --types [--function]
  openre analyze <file> --pipeline [--stages identify,load,disasm,cfg,dfg,types,decompile,ai]
  openre analyze <file> --arch x86_64|arm64|mips|riscv [--endian little|big]

FUZZING:
  openre fuzz <binary> --harness persistent|forkserver|qemu|frida [--function] [--input] [--output] [--timeout] [--dict] [--sanitizer asan|msan|tsan] [--parallel N]
  openre fuzz --api <openapi.json> --target <url> [--auth] [--output]
  openre fuzz --triage <dir> --deduplicate --minimize

FIRMWARE:
  openre firmware extract <file> --output <dir> [--recursive]
  openre firmware analyze <file> --attack-surface [--format]
  openre firmware identify <file>

MALWARE:
  openre malware analyze <file> --static --dynamic --unpack [--output]
  openre malware iocs <file> --format stix|json
  openre malware unpack <file> --output <dir>
  openre malware behavior <file> --trace --duration 60s

SUPPLY CHAIN:
  openre supply-chain sbom --project <dir> --format spdx|cyclonedx [--output]
  openre supply-chain audit --sbom <file> [--kb]
  openre supply-chain licenses --project <dir> --policy <file>
  openre supply-chain reachability --binary <file> --sbom <file>

SECRETS:
  openre secrets scan <path> [--rules <file>] [--entropy-threshold 4.5] [--validate]

INTELLIGENCE:
  openre intel update-kb [--source exploit-db|nvd|mitre|github]
  openre intel search-cve <cve-id>
  openre intel search-cwe <cwe-id>
  openre intel search-capec <capec-id>
  openre intel correlate --binary <file> [--kb]
  openre intel hypothesis --binary <file> [--function] [--output]
  openre intel poc <finding-id> --language python|rust|c|wasm [--sandbox]
  openre intel patch-diff <v1> <v2> [--output]

SIMILARITY:
  openre similarity index <dir> --output <file>
  openre similarity search <binary> --index <file> --threshold 0.8
  openre similarity cluster <dir> --eps 0.3 --min-samples 5 [--output]

PROJECTS:
  openre project create <name.oproj> --binaries <files...>
  openre project open <file.oproj>
  openre project diff <v1.oproj> <v2.oproj> [--output]
  openre project export <file.oproj> --format html|sarif|json|csv [--output]

AI:
  openre ai "question" --binary <file> [--decompile] [--function]
  openre ai chat --binary <file> [--model <name>]
  openre exploit <finding-id> [--language] [--sandbox]
  openre remediate <finding-id> [--format]

TUI:
  openre tui [--project <file.oproj>]

CONFIG:
  openre config show|set|get|reset
  openre config path
```

---

## 13. TUI Panels (Complete Set)

| Panel | Key | Description |
|-------|-----|-------------|
| Projects | 1 | Project management, creation, selection |
| Jobs | 2 | Background job queue, status, control |
| Scans | 3 | Web/API scan management, live progress |
| **Reverse Engineering** | 4 | **Disasm, Decomp, CFG, DFG, Functions, Strings, Imports, Exports** |
| **Fuzzing** | 5 | **Campaigns, Corpus, Crashes, Coverage, Triage** |
| **Firmware** | 6 | **Extraction, Filesystem, Attack Surface** |
| **Malware** | 7 | **Behavior, IOCs, Unpacking, Capabilities, MITRE ATT&CK** |
| **Supply Chain** | 8 | **SBOM, Dependencies, Vulnerabilities, Licenses, Reachability** |
| Findings | 9 | Unified findings across all domains |
| Workflows | 0 | Automation pipelines |
| AI | a | Analyses, Chat, Models, Settings |
| Plugins | p | Plugin management, marketplace |
| Logs | l | Unified logging |
| Reports | r | Report generation, preview, settings |
| **Similarity** | s | **Binary similarity search, clustering, diffing** |
| **Intelligence** | i | **CVE/CWE/CAPEC lookup, Hypothesis, PoC, Patch Diff** |

**Navigation**: `1-9, 0, a, p, l, r, s, i` or `Tab`/`Shift+Tab` to cycle
**Vim keys**: `j/k` navigate, `g/G` top/bottom, `/` search, `?` help

---

## 14. Configuration (Layered)

```toml
# ~/.config/openre/config.toml
[core]
offline = false
cache_dir = "~/.openre/cache"
intel_dir = "~/.openre/intel"
project_dir = "~/.openre/projects"
max_parallel_jobs = 4

[scan]
default_profile = "standard"
timeout = 30
rate_limit = 10.0
user_agent = "openre/{version}"
follow_redirects = true
max_redirects = 10

[analysis]
default_pipeline = ["identify", "load", "disassemble", "cfg", "dfg", "types"]
disasm_syntax = "intel"
decompile_llm = true
decompile_model = "codellama-7b"
max_function_size = 10000

[fuzz]
default_harness = "persistent"
default_timeout = 300
corpus_dir = "~/.openre/fuzz/corpus"
findings_dir = "~/.openre/fuzz/findings"
sanitizer = "asan"
parallel = 0  # 0 = auto (CPU count)

[firmware]
extract_recursive = true
max_file_size = "100MB"

[malware]
dynamic_timeout = 60
unpack_max_layers = 10

[supply_chain]
sbom_format = "spdx"
license_policy = "~/.openre/license-policy.yaml"

[secrets]
entropy_threshold = 4.5
validate_secrets = true

[intel]
auto_update = true
update_interval_hours = 24
sources = ["exploit-db", "nvd", "mitre-cwe", "mitre-capec", "mitre-attack", "github-advisory"]

[ai]
provider = "auto"  # auto|local|ollama|llamacpp|onnx|openai|anthropic|vllm
model = ""
local_models_dir = "~/.openre/models"
offline_only = false

[tui]
theme = "dark"
vim_mode = true
panel_layout = "default"
refresh_interval = 1000

[resources]
cpu_limit = 0      # 0 = unlimited
memory_limit = 0   # 0 = unlimited
timeout = 0        # 0 = unlimited
sandbox = true
```

---

## 15. Output Formats

| Format | Use Case |
|--------|----------|
| `table` | Human-readable CLI (default) |
| `json` | Automation, scripting |
| `jsonl` | Streaming large outputs |
| `sarif` | CI/CD (GitHub Code Scanning, Azure DevOps, GitLab) |
| `yaml` | Configuration, readable |
| `csv` | Spreadsheet import |
| `html` | Reports, sharing |
| `markdown` | Documentation, GitHub issues |
| `dot`/`mermaid` | Graph visualization |
| `stix` | Threat intel sharing |

---

## 16. Dependencies Summary

### New Workspace Dependencies

```toml
# Workspace Cargo.toml additions
[workspace.dependencies]
# Disassembly
capstone = "0.13"
# Fuzzing
libafl = { version = "0.10", features = ["std", "serde"] }
libafl_bolts = { version = "0.10", features = ["std", "serde"] }
# Firmware (scroll for parsing, goblin for binary formats)
scroll = { version = "0.12", features = ["std"] }
# Web/API
headless_chrome = { version = "0.12", optional = true }  # For JS rendering
graphql-client = { version = "0.12", optional = true }
async-tungstenite = { version = "0.24", optional = true }  # WebSocket
# Dynamic instrumentation
frida = { version = "0.1", optional = true }  # Frida DBI (requires Frida server)
# ML/LLM
candle-core = { version = "0.8", features = ["cuda", "metal"], optional = true }
candle-nn = { version = "0.8", optional = true }
candle-transformers = { version = "0.8", optional = true }
tokenizers = { version = "0.19", optional = true }
# Project files
zip = "0.6"
# Similarity
simhash = "0.1"
minhash = "0.3"
# Threat intel
reqwest = { workspace = true, features = ["json", "gzip", "brotli"] }
sqlite = { version = "0.37", features = ["bundled"], optional = true }
# Sandbox
wasmtime = { workspace = true, features = ["component-model", "async"] }
# Cross-platform sandboxing
seccomp = { version = "0.9", optional = true }  # For Linux seccomp
# Supply chain
spdx = { version = "0.3", optional = true }
cyclonedx = { version = "0.7", optional = true }
# Secrets
entropy = "0.1"
regex = { workspace = true }
```

### Feature Flags

```toml
[features]
default = ["full"]
full = [
    "scan", "analysis", "ai", "fuzz", "firmware", "malware",
    "supply-chain", "secrets", "intel", "similarity", "project",
    "tui", "sarif", "js-rendering", "graphql", "websocket"
]
minimal = []
scan = ["dep:openre-scan"]
analysis = ["dep:openre-analysis", "dep:openre-disasm", "dep:openre-decomp"]
ai = ["dep:openre-ai", "dep:openre-intelligence"]
fuzz = ["dep:openre-fuzz"]
firmware = ["dep:openre-firmware"]
malware = ["dep:openre-malware"]
supply-chain = ["dep:openre-supply-chain"]
secrets = ["dep:openre-secrets"]
intel = ["dep:openre-threat-intel"]
similarity = ["dep:openre-similarity"]
project = ["dep:openre-project"]
tui = ["dep:openre-tui"]
sarif = ["dep:sarif_rust"]
js-rendering = ["dep:headless_chrome"]
graphql = ["dep:graphql-client"]
websocket = ["dep:async-tungstenite"]
frida = ["dep:frida"]
```

---

## 17. Testing Strategy

### 17.1 Unit Tests (per crate)
- Disassembly: Round-trip asm ↔ bytes, multi-arch
- Decompilation: Known patterns → expected pseudo-C
- CFG/DFG: Synthetic binaries with known structure
- Fuzzing: Harness execution, crash detection
- Similarity: Known-similar function pairs

### 17.2 Integration Tests
- Full pipeline: Binary → analysis → findings → report
- Fuzzing campaign: Target → corpus → crashes → triage
- Project file: Create → modify → export → diff
- Intel KB: Download → parse → query → correlate

### 17.3 Corpus Tests
- **Binaries**: `/bin/ls`, `libc.so`, `kernel32.dll`, test ELF/PE/Mach-O/WASM
- **Firmware**: Router firmware images, IoT device dumps
- **Malware**: TheZoo samples (with permission), custom test cases
- **Web**: httpbin.org, OWASP Juice Shop, custom test apps

### 17.4 CI/CD
```yaml
# .github/workflows/test.yml
- cargo test --workspace --all-features
- cargo test --package openre-cli --features full
- ./openre analyze ./test-binaries/hello --pipeline all --format sarif
- ./openre scan https://httpbin.org --profile quick --format json
- ./openre fuzz ./test-binaries/vuln --harness persistent --function vuln --input corpus/ --timeout 60
- cargo build --release --package openre --package openre-scan --package openre-tui
```

---

## 18. Release Artifacts

| Platform | Architectures | Artifact |
|----------|---------------|----------|
| Linux | x86_64, aarch64, armv7 | `openre-linux-{arch}` |
| macOS | x86_64, arm64 | `openre-macos-{arch}` |
| Windows | x86_64 | `openre-windows-x86_64.exe` |
| FreeBSD | x86_64, aarch64 | `openre-freebsd-{arch}` |

**Size Target**: < 25MB per binary (strip, LTO, UPX optional)

---

## 19. Security Considerations

- **No telemetry**: Zero data collection, no phoning home
- **Offline-first**: All features work without internet
- **Sandboxed PoC validation**: WASM isolation with resource limits
- **Supply-chain**: `cargo deny` for dependency auditing, pinned versions
- **Reproducible builds**: `SOURCE_DATE_EPOCH`, deterministic compilation
- **Signed releases**: cosign/GPG signatures on GitHub releases

---

## 20. Open Questions for User Review

1. **LLM Model Distribution**: Bundle quantized model (~1.5GB) in release or download on first use?
2. **JavaScript Rendering**: Include `headless_chrome` (adds ~50MB) or make optional feature?
3. **Windows ARM64**: Support `aarch64-pc-windows-msvc` target?
4. **FreeBSD Tier**: Tier 1 (full support) or Tier 2 (community-maintained)?
5. **GPU Acceleration**: CUDA/Metal for ML inference — require or optional?
6. **Plugin SDK Stability**: Guarantee ABI stability for WASM plugins across versions?
7. **Telemetry Opt-in**: Anonymous usage stats for prioritization? (Default: OFF)

---

## 21. Next Steps

1. **User reviews this spec** — request changes or approve
2. **Invoke `writing-plans` skill** — detailed implementation plan for **Phase 1 only** (Core Binary Analysis: disasm, decomp, CFG/DFG, types, function ID)
3. **Begin Phase 1 implementation** — `openre-disasm` crate first
4. **Subsequent phases** will each get their own implementation plan after Phase 1 completion

> **Note**: This specification covers 7 phases (~68 weeks). Each phase will have a separate implementation plan created via `writing-plans` skill. Phase 1 plan will be created first upon approval.

---

*End of Design Specification*