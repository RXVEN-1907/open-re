# Roadmap

## Overview

This roadmap outlines the phased development of open-re from research through maturity. Each phase has clear objectives, deliverables, exit criteria, and success metrics. Dates are targets, not commitments.

---

## Phase Summary

| Phase | Name | Duration | Focus | Key Deliverable |
|-------|------|----------|-------|-----------------|
| **0** | Research & Definition | 3 months | Documentation, architecture, community | Complete docs, ADRs, contributor base |
| **1** | Core Platform & MVP | 12 months | Disassembly, decompilation, AI, plugin system | Usable RE platform |
| **2** | Intelligence & Ecosystem | 12 months | Advanced AI, collaboration, plugins, domains | Production-ready + ecosystem |
| **3** | Scale & Sustainability | 12+ months | Enterprise, cloud, education, governance | Self-sustaining project |

---

## Phase 0: Research & Definition (Months 0-3)

### Objective
Establish technical direction, build contributor community, and produce comprehensive documentation before writing production code.

### Status: **IN PROGRESS** (Current)

### Workstreams

#### 0.1 Documentation (Complete)
- [x] Vision.md - Mission, philosophy, MVP scope
- [x] ProductRequirements.md - Detailed requirements
- [x] CompetitiveAnalysis.md - 15+ tools analyzed
- [x] MarketResearch.md - TAM, personas, GTM
- [x] UserPersonas.md - 4 primary, 4 secondary personas
- [x] FeatureBrainstorm.md - 200+ features categorized
- [x] Risks.md - 25 risks with mitigations
- [x] SuccessMetrics.md - 100+ metrics with targets
- [x] Roadmap.md - This document

#### 0.2 Architecture Decisions (In Progress)
- [ ] ADR-001: Core Language Selection (Rust + Python)
- [ ] ADR-002: Plugin Architecture (WASM + Native)
- [ ] ADR-003: Database Format (SQLite + JSON)
- [ ] ADR-004: Disassembly Architecture (Capstone vs Custom)
- [ ] ADR-005: Decompiler Approach (IL-based like Binary Ninja)
- [ ] ADR-006: AI Model Strategy (Local-first, ONNX)
- [ ] ADR-007: UI Framework (Web-based vs Native)
- [ ] ADR-008: Collaboration Protocol (CRDT vs OT)
- [ ] ADR-009: License Confirmation (MIT)
- [ ] ADR-010: Governance Model (Foundation)

#### 0.3 Community Building
- [ ] GitHub repository initialized with templates
- [ ] CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md
- [ ] Issue templates (bug, feature, research)
- [ ] PR template
- [ ] GitHub Discussions categories
- [ ] Discord/Matrix community chat
- [ ] "Good First Issue" labels on 20+ documentation tasks
- [ ] First 10 contributors onboarded

#### 0.4 Technical Spikes (Time-boxed)
- [ ] Spike: Rust + Python binding performance (1 week)
- [ ] Spike: WASM plugin sandbox feasibility (1 week)
- [ ] Spike: SQLite project format performance (1 week)
- [ ] Spike: ONNX Runtime integration (1 week)
- [ ] Spike: Capstone vs custom disassembler (1 week)
- [ ] Spike: Web UI vs Native UI prototype (2 weeks)

#### 0.5 Legal & Governance
- [ ] MIT license confirmed
- [ ] CLA/Contributor agreement (if needed)
- [ ] Foundation exploration (OpenSSF, Linux Foundation)
- [ ] Trademark policy
- [ ] Security policy published

### Exit Criteria
- [ ] All 9 core docs complete and reviewed
- [ ] 15+ ADRs recorded
- [ ] 20+ contributors (any contribution type)
- [ ] 500+ GitHub stars
- [ ] Technical spikes completed with decisions
- [ ] Architecture baseline documented
- [ ] Phase 1 project plan approved by contributors

### Success Metrics
| Metric | Target |
|--------|--------|
| Documentation completeness | 100% |
| ADRs recorded | 20 |
| Contributors | 20 |
| GitHub stars | 500 |
| Spike decisions made | 6/6 |

---

## Phase 1: Core Platform & MVP (Months 3-15)

### Objective
Build a usable reverse engineering platform with disassembly, decompilation, AI assistance, and plugin system.

### Theme: **"Solid Foundation"**

### Milestones

#### M1: Skeleton (Month 3-5)
**Goal**: Running application with basic binary loading and disassembly

| Epic | Stories | Done When |
|------|---------|-----------|
| **Project Setup** | Monorepo, CI/CD, release pipeline, pre-commit | Green CI on all platforms |
| **Core Infrastructure** | Plugin system (WASM), SQLite project, config, logging | Plugin loads, project saves/loads |
| **Binary Loading** | ELF, PE, Mach-O parsers, section/segment mapping | Load test corpus (100 binaries) |
| **Disassembly Engine** | Capstone integration, instruction semantics, basic CFG | Disassemble /bin/ls correctly |
| **Basic UI** | Window, disassembly view, hex view, navigation | Navigate functions, view hex |

#### M2: Analysis Core (Month 5-8)
**Goal**: Function detection, call graph, data flow, type system

| Epic | Stories | Done When |
|------|---------|-----------|
| **Function Analysis** | Boundary detection, prologue/epilogue, calling convention | 90% functions identified in test corpus |
| **Control Flow** | CFG construction, loop detection, dominators | CFG matches reference for test binaries |
| **Data Flow** | SSA construction, value set analysis, reaching definitions | Constant propagation works |
| **Type System** | Primitives, pointers, structs, arrays, function types | Type inference on simple functions |
| **Cross-References** | Code/data xrefs, call graph, global xrefs | All xrefs findable and navigable |

#### M3: Decompilation (Month 8-11)
**Goal**: Readable pseudo-code output with interactive editing

| Epic | Stories | Done When |
|------|---------|-----------|
| **IL Infrastructure** | LLIL → MLIL → HLIL lifting, optimization passes | IL passes unit tested |
| **Structural Analysis** | Control structure recovery (if/while/for/switch) | Structured output for test functions |
| **Type Inference** | Constraint-based, interprocedural, struct reconstruction | Types propagate across calls |
| **Pseudo-Code Generation** | C-like output, formatting, variable naming | 90% functions compilable |
| **Interactive Decompilation** | Rename, retype, restructure, inline/outline | All edits persist, undo works |

#### M4: AI Integration (Month 9-12)
**Goal**: Local AI models providing naming, typing, classification

| Epic | Stories | Done When |
|------|---------|-----------|
| **Model Infrastructure** | ONNX Runtime, model registry, quantization, benchmarking | Models load, infer <100ms |
| **Function Classification** | Train/eval on labeled dataset, 20+ categories | F1 > 0.8 on test set |
| **Naming Suggestions** | Context-aware variable/function naming | 40% acceptance rate in user testing |
| **Type Prediction** | Struct layout, function signature suggestion | 50% reduction in manual typing |
| **Crypto Detection** | Magic constants, S-boxes, algorithm identification | 95% recall on known crypto |
| **AI UX** | Ghost suggestions, "Explain This", feedback loop | Integrated in all views |

#### M5: Plugin System & Scripting (Month 10-13)
**Goal**: Extensible platform with Python API and plugin marketplace

| Epic | Stories | Done When |
|------|---------|-----------|
| **Plugin Runtime** | WASM sandbox, capability permissions, hot reload | 3 example plugins work |
| **Extension Points** | Loader, analyzer, view, exporter, AI model | Core features as plugins |
| **Python API** | Type-stubbed, async, full database access | Script automates full analysis |
| **Jupyter Integration** | Kernel, visualization helpers, tutorials | Notebook analyzes binary |
| **Headless Mode** | CLI, batch processing, CI/CD examples | GitHub Action analyzes on push |
| **Plugin SDK** | Templates, testing, CI, documentation | New plugin in <30 min |

#### M6: Polish & MVP Release (Month 12-15)
**Goal**: Production-quality release with installers, docs, benchmarks

| Epic | Stories | Done When |
|------|---------|-----------|
| **Performance Optimization** | Meet all NFR-PERF targets | Benchmarks pass |
| **Accessibility** | WCAG AA, keyboard nav, screen reader | Audit passes |
| **Installers** | .deb, .rpm, .dmg, .msi, AppImage, portable | All platforms install |
| **Documentation** | User guide, API reference, plugin guide | Complete for MVP features |
| **Test Corpus** | 1000+ binaries, regression suite | CI runs full suite |
| **Release** | v1.0.0 tagged, announced, downloadable | Public release |

### Phase 1 Exit Criteria
- [ ] All Must-have requirements from PRD implemented
- [ ] Decompilation correctness ≥90% on test corpus
- [ ] Performance targets met (NFR-PERF-*)
- [ ] 3+ example plugins demonstrating extensibility
- [ ] Documentation covers all core workflows
- [ ] Installers for Linux/macOS/Windows
- [ ] Automated CI/CD with signed releases
- [ ] 50+ contributors, 5000+ stars

### Phase 1 Success Metrics
| Metric | Target |
|--------|--------|
| MAU | 5,000 |
| Decompilation correctness | 90% |
| Cold start | <3s |
| GitHub stars | 5,000 |
| Contributors | 50 |
| Plugins | 20 |
| Academic adoptions | 10 |

---

## Phase 2: Intelligence & Ecosystem (Months 15-27)

### Objective
Deepen AI capabilities, enable collaboration, grow plugin ecosystem, add domain-specific features.

### Theme: **"Smart & Social"**

### Milestones

#### M7: Advanced AI (Month 15-19)
| Feature | Description |
|---------|-------------|
| **Semantic Code Search** | Natural language queries ("find crypto") |
| **Vulnerability Pattern Matching** | CWE detection with explainability |
| **Cross-Binary Analysis** | Library detection, version diffing, lineage |
| **Model Fine-tuning Pipeline** | User data (opt-in), domain adaptation |
| **AI-Assisted Deobfuscation** | Control flow flattening, VM detection, string decryption |

#### M8: Collaboration (Month 17-21)
| Feature | Description |
|---------|-------------|
| **Real-Time Collaboration** | CRDT-based, presence, conflict-free |
| **Web-Based Viewer** | Shareable read-only analysis, zero-install |
| **Analysis Replay** | Step-by-step reconstruction for teaching |
| **Git Integration** | Diff annotations, blame, history view |
| **Shared Symbol Server** | Org-wide type/function library |

#### M9: Plugin Ecosystem (Month 16-22)
| Feature | Description |
|---------|-------------|
| **Plugin Marketplace** | Discover, install, update, rate, review |
| **Plugin Categories** | Loader, analyzer, view, exporter, AI model |
| **Verified Publisher Program** | Security review, trusted badges |
| **Plugin Analytics** | Usage, performance, crash reporting |
| **Monetization Options** | Donations, paid plugins (platform takes %) |

#### M10: Domain Features (Month 18-24)
| Domain | Features |
|--------|----------|
| **Malware Analysis** | Capa built-in, YARA engine, string decryption, C2 extraction, ATT&CK mapping |
| **Vulnerability Research** | Sink/source DB, patch diffing, mitigation analysis, fuzzing harness gen |
| **Firmware/Embedded** | Flash mapper, RTOS awareness, peripheral models, bootloader analysis |
| **Education** | Lab authoring, auto-grading, curriculum packs, LTI integration |

#### M11: Dynamic Analysis Foundation (Month 20-25)
| Feature | Description |
|---------|-------------|
| **DAP Debugger Support** | GDB, LLDB, WinDbg via Debug Adapter Protocol |
| **Emulator Integration** | Unicorn, QEMU user-mode for firmware/shellcode |
| **Trace Import** | Intel PT, rr, Frida trace analysis |
| **Hybrid Analysis** | Static guides dynamic, dynamic refines static |

#### M12: Phase 2 Release (Month 24-27)
| Goal | Criteria |
|------|----------|
| **v2.0.0 Release** | All Phase 2 features stable |
| **Ecosystem Metrics** | 100 plugins, 1000 installs/month |
| **Enterprise Pilots** | 10 design partners |
| **Cloud Beta** | Hosted collaboration service |

### Phase 2 Exit Criteria
- [ ] Advanced AI features in production use
- [ ] Real-time collaboration working
- [ ] 100+ plugins in marketplace
- [ ] Domain features used by target personas
- [ ] Dynamic analysis foundation stable
- [ ] Enterprise pilots converting to paid

### Phase 2 Success Metrics
| Metric | Target |
|--------|--------|
| MAU | 25,000 |
| Decompilation correctness | 95% |
| Plugins | 100 |
| Enterprise pilots | 10 |
| Cloud revenue | $10K/mo |

---

## Phase 3: Scale & Sustainability (Months 27-39+)

### Objective
Achieve self-sustaining project with enterprise adoption, cloud revenue, educational dominance, and mature governance.

### Theme: **"Sustainable Impact"**

### Milestones

#### M13: Enterprise Readiness (Month 27-33)
| Feature | Description |
|---------|-------------|
| **Air-Gapped Deployment** | Offline install, update, license |
| **SSO/SAML/OIDC** | Enterprise identity integration |
| **RBAC & Audit Logs** | Role-based access, compliance reporting |
| **FIPS 140-2 Mode** | Certified crypto modules |
| **Professional Support** | SLA, dedicated channels, training |

#### M14: Cloud Platform (Month 28-34)
| Feature | Description |
|---------|-------------|
| **Hosted Analysis** | Scalable workers, queue management |
| **Team Workspaces** | Shared projects, permissions, billing |
| **API & Integrations** | REST/GraphQL, webhooks, SIEM connectors |
| **Marketplace Revenue Share** | Platform takes % of paid plugins |
| **Global CDN** | Low-latency worldwide |

#### M15: Education Leadership (Month 27-33)
| Feature | Description |
|---------|-------------|
| **Certified Analyst Program** | Proctored exam, certificate, directory |
| **Curriculum Partnerships** | University adoption, textbook integration |
| **CTF Platform Integration** | Native challenge format, scoring |
| **MOOC Course** | Free comprehensive RE course |

#### M16: Research & Innovation (Month 30-36)
| Area | Investments |
|------|-------------|
| **Binary Synthesis** | Generate binaries from specs for testing |
| **Cross-Arch Translation** | x86 ↔ ARM lifting for porting |
| **Formal Verification** | Prove decompiler correctness properties |
| **AI Research** | Novel architectures for code understanding |
| **Standards Leadership** | SBOM, VEX, RE-specific formats |

#### M17: Governance Maturity (Month 27-39)
| Milestone | Criteria |
|-----------|----------|
| **Foundation Graduated** | Linux Foundation / OpenSSF top tier |
| **Diverse Leadership** | No single org >30% control |
| **Sustainable Funding** | 3+ year runway, diverse sources |
| **Standards Body Participation** | Active in 3+ relevant groups |

### Phase 3 Success Metrics
| Metric | Target |
|--------|--------|
| MAU | 100,000 |
| Enterprise customers | 50 |
| Cloud revenue | $100K/mo |
| University courses | 50 |
| Certified analysts | 500 |
| Foundation status | Graduated |

---

## Cross-Phase Initiatives

### Continuous: Security
- [ ] Quarterly security audits
- [ ] Bug bounty program (Phase 1+)
- [ ] Supply chain hardening (SLSA Level 3 by Phase 2)
- [ ] Incident response drills

### Continuous: Performance
- [ ] Benchmark regression detection in CI
- [ ] Annual performance review
- [ ] Profiling infrastructure

### Continuous: Accessibility
- [ ] Annual WCAG audit
- [ ] User testing with disabled users
- [ ] Accessibility regression tests

### Continuous: Documentation
- [ ] Docs-as-code: same PR, same repo
- [ ] Video tutorials per major feature
- [ ] Translation pipeline (Phase 2+)

---

## Resource Requirements

### Phase 1 Team (Target)
| Role | Count | Notes |
|------|-------|-------|
| **Core Engineers** | 4-6 | Rust, Python, RE expertise |
| **AI/ML Engineer** | 1-2 | Model training, ONNX, quantization |
| **UI/UX Engineer** | 1-2 | Web or native, accessibility |
| **Technical Writer** | 1 | Docs, tutorials, API reference |
| **Community Manager** | 1 | Part-time → full-time |
| **Release/DevOps Engineer** | 1 | CI/CD, packaging, reproducible builds |
| **Total** | **9-13** | Mix of full-time + contractors |

### Funding Estimate (Phase 1)
| Category | Annual Cost |
|----------|-------------|
| **Personnel** | $1.2M - $1.8M |
| **Infrastructure** | $50K - $100K |
| **Compute (AI training)** | $100K - $200K |
| **Legal/Compliance** | $50K |
| **Travel/Events** | $50K |
| **Total** | **$1.5M - $2.2M** |

---

## Risk-Adjusted Timeline

```
Phase 0: ████████░░ (Months 0-3)     ← CURRENT
Phase 1: ░░████████████████░░ (Months 3-15)
Phase 2: ░░░░░░████████████████ (Months 15-27)
Phase 3: ░░░░░░░░░░████████████ (Months 27-39+)

Buffers: +20% each phase for unknowns
```

### Key Dependencies
- **Phase 1 → Phase 2**: Plugin API stability, AI model quality
- **Phase 2 → Phase 3**: Enterprise pilot feedback, cloud architecture validated
- **All Phases**: Contributor growth, funding continuity

---

## Decision Gates

### Gate 1: Phase 0 → Phase 1 (Month 3)
**Criteria**:
- [ ] All docs complete, reviewed
- [ ] 15+ ADRs with team consensus
- [ ] Technical spikes validate architecture
- [ ] 20+ contributors, 500+ stars
- [ ] Funding secured for 18 months
- [ ] Core team committed

### Gate 2: Phase 1 → Phase 2 (Month 15)
**Criteria**:
- [ ] MVP release shipped (v1.0.0)
- [ ] All exit criteria met
- [ ] 5000+ MAU or clear growth trajectory
- [ ] Plugin ecosystem self-sustaining (10+ external)
- [ ] AI features providing measurable value
- [ ] Team capacity for Phase 2 scope

### Gate 3: Phase 2 → Phase 3 (Month 27)
**Criteria**:
- [ ] v2.0.0 released with collaboration
- [ ] 100+ plugins, active marketplace
- [ ] 3+ enterprise pilots converting
- [ ] Cloud beta validated architecture
- [ ] Financial path to sustainability clear
- [ ] Governance structure operational

---

## Communication Plan

| Audience | Channel | Frequency | Content |
|----------|---------|-----------|---------|
| **Contributors** | GitHub Discussions, Discord | Daily | Technical decisions, PR reviews |
| **Users** | Blog, Twitter/X, Release Notes | Monthly | Features, tutorials, releases |
| **Enterprise** | Email, Direct, Conferences | Quarterly | Roadmap, pilots, support |
| **Academia** | Education mailing list, Conferences | Per semester | Curriculum, grants, adoption |
| **Governance** | Board meetings, Public minutes | Quarterly | Strategy, budget, risks |

---

## Appendix: Feature-to-Phase Mapping

See [FeatureBrainstorm.md](FeatureBrainstorm.md) for complete mapping. Summary:

| Phase | Core | AI | UX | Collab | Plugins | Dynamic | Domains |
|-------|------|-----|-----|--------|---------|---------|---------|
| **1** | ★★★★★ | ★★★★☆ | ★★★★★ | ★★☆☆☆ | ★★★★★ | ☆☆☆☆☆ | ★★☆☆☆ |
| **2** | ★★★★☆ | ★★★★★ | ★★★★☆ | ★★★★★ | ★★★★★ | ★★★☆☆ | ★★★★★ |
| **3** | ★★★☆☆ | ★★★★☆ | ★★★☆☆ | ★★★★★ | ★★★★★ | ★★★★★ | ★★★★★ |

★ = Investment level (1-5)

---

*This roadmap is a living document. Updated at each phase gate based on learning, feedback, and resources.*