# System Architecture Overview

## Executive Summary

This document describes the high-level architecture of open-re, an AI-native reverse engineering platform. The architecture follows a **plugin-first, local-first, privacy-by-design** philosophy where every core capability is implemented as a replaceable plugin, AI runs locally by default, and user data never leaves the machine without explicit consent.

---

## High-Level Component Diagram

```mermaid
graph TB
    subgraph "Client Layer"
        UI[Web Frontend<br/>React + TypeScript]
        CLI[CLI / Headless<br/>Python/Rust]
        API[REST/gRPC API<br/>External Integrations]
    end

    subgraph "API Gateway"
        GW[API Gateway<br/>Auth, Rate Limit, Routing]
    end

    subgraph "Core Services"
        AS[Analysis Service<br/>Orchestration]
        PS[Plugin Service<br/>Lifecycle, Sandbox]
        AI[AI Service<br/>Local/Remote Models]
        FS[File Service<br/>Storage, Streaming]
        WS[Workspace Service<br/>Projects, Sessions]
    end

    subgraph "Plugin Runtime"
        PR[Plugin Runtime<br/>WASM + Native]
        PL[Plugin Loader<br/>Discovery, Versioning]
        PM[Plugin Manager<br/>Install, Update, Config]
    end

    subgraph "Analysis Pipeline"
        PI[Pipeline Orchestrator<br/>DAG Execution]
        ST[Stage Workers<br/>Parallel Execution]
        QU[Queue Manager<br/>Redis/RabbitMQ]
    end

    subgraph "Data Layer"
        PG[(PostgreSQL<br/>Metadata, Projects)]
        SQ[(SQLite<br/>Analysis DB per Project)]
        OB[(Object Storage<br/>Binaries, Artifacts)]
        RD[(Redis<br/>Cache, Queue, Pub/Sub)]
    end

    subgraph "AI Layer"
        LM[Local Model Runtime<br/>ONNX Runtime / llama.cpp]
        RM[Remote Model Gateway<br/>OpenAI, vLLM, Custom]
        MC[Model Cache<br/>Quantized Models]
        PC[Prompt Compiler<br/>Templates, Context]
    end

    UI --> GW
    CLI --> GW
    API --> GW
    GW --> AS
    GW --> PS
    GW --> AI
    GW --> FS
    GW --> WS
    AS --> PI
    AS --> PS
    AS --> AI
    AS --> FS
    AS --> WS
    PI --> QU
    PI --> ST
    ST --> PR
    PR --> PL
    PL --> PM
    PS --> PR
    AI --> LM
    AI --> RM
    AI --> MC
    AI --> PC
    FS --> OB
    WS --> PG
    WS --> SQ
    AS --> PG
    AS --> RD
    QU --> RD
```

---

## Data Flow

### 1. Binary Upload Flow

```mermaid
sequenceDiagram
    participant User
    participant GW as API Gateway
    participant FS as File Service
    participant OB as Object Storage
    participant PG as PostgreSQL
    participant QU as Queue
    participant AS as Analysis Service

    User->>GW: POST /api/v1/files (multipart)
    GW->>FS: Validate & Stream
    FS->>OB: Store binary (chunked)
    FS->>PG: Create FileRecord
    FS->>QU: Enqueue IdentificationJob
    QU->>AS: Process IdentificationJob
    AS->>FS: Read binary stream
    AS->>PG: Update FileRecord with metadata
    AS->>QU: Enqueue AnalysisPipeline
    AS-->>User: 202 Accepted + Job ID
```

### 2. Analysis Pipeline Flow

```mermaid
sequenceDiagram
    participant QU as Queue Manager
    participant PI as Pipeline Orchestrator
    participant ST as Stage Workers
    participant PR as Plugin Runtime
    participant PS as Plugin Service
    participant AI as AI Service
    participant SQ as SQLite (Project DB)
    participant RD as Redis (Progress)

    QU->>PI: Dequeue AnalysisJob
    PI->>RD: Update status: RUNNING
    PI->>PI: Build DAG from pipeline config
    par Parallel Stages
        PI->>ST: Execute DisassemblyStage
        ST->>PR: Load Disassembler Plugin
        PR->>PS: Get plugin manifest
        ST->>SQ: Write CFG, Functions
        PI->>ST: Execute TypeRecoveryStage
        ST->>PR: Load Type Inference Plugin
        ST->>SQ: Write Types
        PI->>ST: Execute DecompilationStage
        ST->>PR: Load Decompiler Plugin
        ST->>SQ: Write Pseudocode
        PI->>ST: Execute AIEnrichmentStage
        ST->>AI: Request naming/typing
        AI->>LM: Run local model
        AI->>SQ: Write AI annotations
    end
    PI->>RD: Update status: COMPLETED
    PI->>QU: Acknowledge job
```

### 3. AI Interaction Flow

```mermaid
sequenceDiagram
    participant User
    participant GW as API Gateway
    participant AI as AI Service
    participant PC as Prompt Compiler
    participant LM as Local Model Runtime
    participant RM as Remote Model Gateway
    participant MC as Model Cache
    participant SQ as SQLite

    User->>GW: POST /api/v1/ai/explain (function_id)
    GW->>AI: ExplainFunctionRequest
    AI->>SQ: Load function context (asm, cfg, types)
    AI->>PC: Compile prompt (template + context)
    PC-->>AI: Rendered prompt + tools
    alt Local Model Available
        AI->>MC: Check cache
        AI->>LM: Inference (streaming)
        LM-->>AI: Token stream
    else Fallback to Remote
        AI->>RM: Request (with auth)
        RM-->>AI: Token stream
    end
    AI->>SQ: Store conversation
    AI-->>User: Streaming response
```

---

## Request Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Received: HTTP Request
    Received --> Authenticated: Validate JWT/API Key
    Authenticated --> Authorized: Check Permissions
    Authorized --> RateLimited: Check Quota
    RateLimited --> Routed: Match Route
    Routed --> Validated: Validate Input
    Validated --> Processing: Execute Handler
    Processing --> Streaming: If SSE/WebSocket
    Processing --> Completed: Sync Response
    Streaming --> Completed: Stream End
    Completed --> Logged: Audit Log
    Logged --> [*]
    
    Authenticated --> Failed: Invalid Credentials
    Authorized --> Failed: Insufficient Permissions
    RateLimited --> Failed: Quota Exceeded
    Validated --> Failed: Invalid Input
    Processing --> Failed: Internal Error
    Failed --> Logged: Error Log
    Logged --> [*]
```

---

## Analysis Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Uploaded: File Stored
    Uploaded --> Identified: Format Detection
    Identified --> Queued: Pipeline Enqueued
    Queued --> Running: Worker Picked Up
    Running --> Disassembling: Disassembly Stage
    Disassembling --> Analyzing: CFG/Types/Decomp
    Analyzing --> AIEnrichment: AI Annotations
    AIEnrichment --> Finalizing: Persist Results
    Finalizing --> Completed: Ready for UI
    Completed --> Archived: After Retention
    Archived --> [*]
    
    Identified --> Failed: Unknown Format
    Running --> Failed: Worker Crash
    Disassembling --> Failed: Plugin Error
    Analyzing --> Failed: Analysis Error
    AIEnrichment --> Failed: Model Error
    Failed --> Retryable: Transient Error
    Retryable --> Queued: Re-queue (max 3)
    Failed --> DeadLetter: Permanent Error
    DeadLetter --> [*]
```

---

## AI Interaction Lifecycle

```mermaid
stateDiagram-v2
    [*] --> Idle: Model Loaded
    Idle --> Compiling: Request Received
    Compiling --> ContextAssembly: Gather Binary Context
    ContextAssembly --> PromptRendering: Apply Template
    PromptRendering --> Inference: Model Execution
    Inference --> Streaming: Token Generation
    Streaming --> ToolCalling: If Function Call
    ToolCalling --> Inference: Tool Result
    Streaming --> Complete: Stop Token
    Complete --> Caching: Store in Cache
    Caching --> Idle: Ready
    
    Inference --> Failed: OOM / Timeout
    Failed --> Fallback: Try Remote
    Fallback --> Inference: Retry
    Failed --> Error: All Providers Failed
    Error --> Idle: Log & Continue
```

---

## Storage Lifecycle

```mermaid
graph LR
    subgraph "Hot Storage (Active Analysis)"
        SQ[(SQLite per Project<br/>~100MB-10GB)]
        RD[(Redis<br/>Progress, Cache, Pub/Sub)]
    end
    
    subgraph "Warm Storage (Recent Projects)"
        PG[(PostgreSQL<br/>Metadata, Indexes)]
        OB[(Object Storage<br/>Binaries, Exports)]
    end
    
    subgraph "Cold Storage (Archived)"
        AR[(Archive Storage<br/>Compressed, Encrypted)]
    end
    
    SQ -->|Sync on Save| PG
    RD -->|TTL 24h| PG
    PG -->|After 90 days| AR
    OB -->|After 90 days| AR
    
    style SQ fill:#e1f5fe
    style RD fill:#e1f5fe
    style PG fill:#fff3e0
    style OB fill:#fff3e0
    style AR fill:#f3e5f5
```

---

## Key Architectural Principles

| Principle | Implementation |
|-----------|----------------|
| **Plugin-First** | Core analysis (disassembly, decompilation, CFG) are plugins loaded at runtime |
| **Local-First AI** | Models run locally via ONNX/llama.cpp; remote only as opt-in fallback |
| **Privacy by Design** | No telemetry, no auto-upload, air-gapped operation supported |
| **Deterministic Analysis** | Same binary + same config = identical results (reproducible builds) |
| **Incremental Everything** | Lazy loading, streaming, incremental re-analysis on changes |
| **Observability First** | Structured logging, distributed tracing, metrics at every layer |
| **Graceful Degradation** | Remote AI fails → local only; plugin crashes → isolated, analysis continues |
| **Unix Philosophy** | Small, sharp tools that compose via well-defined interfaces |

---

## Technology Stack Summary

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **Core Language** | Rust | Memory safety, performance, WASM target, no GC pauses |
| **API Layer** | Axum (Rust) / FastAPI (Python) | High performance, async, type-safe |
| **Frontend** | React 18 + TypeScript + Vite | Modern, accessible, great DX |
| **State Management** | Zustand + TanStack Query | Simple, performant, server-state aware |
| **Database (Metadata)** | PostgreSQL 16 | ACID, JSONB, full-text search, mature |
| **Database (Analysis)** | SQLite (per project) | Portable, embeddable, no server needed |
| **Object Storage** | MinIO (S3-compatible) | Local-first, scalable, standard API |
| **Queue** | Redis + BullMQ | Reliable, priority queues, delayed jobs |
| **Cache** | Redis Cluster | Sub-ms latency, pub/sub for real-time |
| **AI Runtime** | ONNX Runtime + llama.cpp | Cross-platform, quantized, hardware accel |
| **Plugin Runtime** | Wasmtime (WASM) + dlopen (Native) | Sandboxed, polyglot, near-native speed |
| **Message Bus** | Redis Streams | Ordered, consumer groups, replay |
| **Observability** | OpenTelemetry + Prometheus + Grafana | Vendor-neutral, comprehensive |
| **Auth** | OIDC + JWT (RS256) | Standards-based, delegable |
| **Config** | Figment (Rust) / Pydantic Settings | Layered, validated, hot-reload |

---

## Deployment Topology

```mermaid
graph TB
    subgraph "User Machine (Air-Gapped Capable)"
        D[Docker Compose / Podman]
        D --> API[API Container]
        D --> UI[UI Container]
        D --> WORKER[Worker Container xN]
        D --> REDIS[(Redis)]
        D --> PG[(PostgreSQL)]
        D --> MINIO[(MinIO)]
        D --> MODELS[(Model Cache)]
    end
    
    subgraph "Optional Cloud"
        GW[API Gateway]
        AUTH[Auth Provider]
        REMOTE_AI[Remote AI Gateway]
        REGISTRY[Plugin Registry]
    end
    
    API -.->|Opt-in| GW
    API -.->|Opt-in| REMOTE_AI
    WORKER -.->|Opt-in| REGISTRY
    UI --> API
```

---

## Scalability Targets

| Metric | Target | Strategy |
|--------|--------|----------|
| **Concurrent Analyses** | 100+ | Horizontal worker scaling, priority queues |
| **Binary Size** | 10GB+ | Streaming, memory-mapped, chunked processing |
| **Project Size** | 100GB+ | SQLite per project, lazy loading, pagination |
| **Plugin Count** | 1000+ | Lazy plugin loading, capability-based sandboxing |
| **AI Requests/sec** | 100+ | Model caching, batching, quantization |
| **API Latency (p99)** | <200ms | Connection pooling, read replicas, caching |
| **Startup Time** | <3s | Pre-warmed workers, lazy initialization |

---

## Failure Modes & Mitigations

| Failure Mode | Detection | Mitigation |
|--------------|-----------|------------|
| **Worker OOM** | Memory metrics, health checks | Restart worker, re-queue job, reduce parallelism |
| **Plugin Crash** | Panic hook, watchdog | Isolate in WASM, mark plugin unhealthy, continue |
| **Model Load Fail** | Startup probe | Fallback to smaller model, disable AI features |
| **DB Connection Pool Exhausted** | Pool metrics | Queue requests, alert, auto-scale read replicas |
| **Object Storage Unavailable** | Health checks | Local cache, retry with backoff, degrade to read-only |
| **Remote AI Timeout** | Circuit breaker | Fail fast, use local model, cache previous results |
| **Queue Backlog** | Queue depth alerts | Auto-scale workers, priority inversion protection |

---

*This document is the architectural north star. All ADRs and detailed designs must align with these principles.*