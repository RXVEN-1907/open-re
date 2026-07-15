# Risks

## Overview

Comprehensive risk assessment for open-re, categorized by type, with probability, impact, mitigation strategies, and ownership. This is a living document reviewed each phase.

---

## Risk Matrix

| Probability \ Impact | Low (1) | Medium (2) | High (3) | Critical (4) |
|---------------------|---------|------------|----------|--------------|
| **Very High (4)** | 4 | 8 | 12 | 16 |
| **High (3)** | 3 | 6 | 9 | 12 |
| **Medium (2)** | 2 | 4 | 6 | 8 |
| **Low (1)** | 1 | 2 | 3 | 4 |

**Risk Score = Probability × Impact**
- **1-3**: Low (Monitor)
- **4-6**: Medium (Mitigate)
- **8-12**: High (Active Management)
- **16**: Critical (Immediate Action)

---

## 1. Technical Risks

### RISK-TECH-001: Decompiler Quality Gap
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | Critical (4) |
| **Score** | **8 (High)** |
| **Description** | Building a production-quality decompiler is extremely hard. Ghidra/IDA took decades. We may not reach parity in MVP. |
| **Root Causes** | Complex control flow, type inference, struct recovery, compiler optimizations |
| **Mitigation** | 1. Start with proven architecture (LLIL/MLIL/HLIL like Binary Ninja)<br>2. Hire/contract decompiler experts early<br>3. Define "good enough" MVP criteria (90% functions compilable)<br>4. Leverage existing research (Phoenix, DREAM, academic)<br>5. Plugin architecture allows swapping decompiler |
| **Contingency** | Integrate Ghidra decompiler via plugin if needed (Apache 2.0 compatible) |
| **Owner** | Technical Lead |
| **Review** | Monthly during Phase 1 |
| **Early Warning** | Decompilation correctness <70% on test corpus at 6 months |

---

### RISK-TECH-002: Architecture Coverage Insufficient
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | Supporting 10+ architectures with quality disassembly/analysis requires massive effort. SLEIGH took NSA years. |
| **Root Causes** | Instruction semantics complexity, varying ABIs, obscure architectures |
| **Mitigation** | 1. Prioritize top 6 (x86, x64, ARM, ARM64, MIPS, RISC-V) for MVP<br>2. Build declarative spec language (like SLEIGH but simpler)<br>3. Community-contributed architecture definitions<br>4. Capstone/LLVM as fallback for less common archs |
| **Contingency** | Partner with architecture vendors for specs |
| **Owner** | Architecture Lead |
| **Review** | Quarterly |
| **Early Warning** | <4 architectures working at 9 months |

---

### RISK-TECH-003: AI Model Quality Insufficient
| Attribute | Value |
|-----------|-------|
| **Probability** | High (3) |
| **Impact** | High (3) |
| **Score** | **9 (High)** |
| **Description** | Local models may not match cloud API quality. Training data scarcity for RE tasks. |
| **Root Causes** | Limited labeled RE data, model size constraints (local), domain specificity |
| **Mitigation** | 1. Start with focused, high-value tasks (naming, crypto detection)<br>2. Curate high-quality training corpus (open source + synthetic)<br>3. Use retrieval-augmented generation (RAG) with local knowledge base<br>4. Design for graceful degradation (suggestions, not automation)<br>5. Benchmark against cloud APIs regularly |
| **Contingency** | Optional cloud API integration (opt-in, privacy warning) |
| **Owner** | AI Lead |
| **Review** | Monthly |
| **Early Warning** | Human eval score <3.5/5 on naming task at 6 months |

---

### RISK-TECH-004: Performance at Scale
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | Large binaries (100MB+), firmware images, or complex C++ may cause memory/CPU issues. |
| **Root Causes** | Quadratic algorithms, memory leaks, insufficient incremental architecture |
| **Mitigation** | 1. Performance budgets from day one (NFR-PERF-*)<br>2. Incremental, lazy, streaming architecture<br>3. Continuous benchmarking in CI<br>4. Memory profiling built into dev workflow<br>5. Rust for performance-critical paths |
| **Contingency** | 64-bit only, warn on >500MB, chunked processing |
| **Owner** | Performance Engineer |
| **Review** | Per release |
| **Early Warning** | 50MB binary >60s analysis or >4GB RAM at 9 months |

---

### RISK-TECH-005: Plugin API Instability
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | Changing plugin API breaks ecosystem, destroys trust. |
| **Root Causes** | Evolving core, insufficient abstraction, no versioning policy |
| **Mitigation** | 1. Semantic versioning from v0.1<br>2. Deprecation policy: 2 major versions minimum<br>3. Plugin compatibility test suite in CI<br>4. Stable "core" API vs "experimental" API separation<br>5. Dogfood: core features as plugins |
| **Contingency** | Compatibility shim layer for v1 plugins |
| **Owner** | Platform Lead |
| **Review** | Per release |
| **Early Warning** | >2 breaking changes per minor release |

---

### RISK-TECH-006: WASM Plugin Sandbox Limitations
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | Medium (2) |
| **Score** | **4 (Medium)** |
| **Description** | WASM may not provide enough performance or API access for complex plugins. |
| **Root Causes** | WASM sandbox overhead, limited syscalls, no native threads (yet) |
| **Mitigation** | 1. Native plugin path for trusted/performance-critical plugins<br>2. WASI preview 2 (threads, networking)<br>3. Benchmark plugin types early<br>4. Allow opt-out for verified publishers |
| **Contingency** | Native plugin API as primary, WASM for untrusted |
| **Owner** | Platform Lead |
| **Review** | Phase 1 end |
| **Early Warning** | Plugin benchmarks >10x slower than native |

---

## 2. Project & Resource Risks

### RISK-PROJ-001: Insufficient Contributor Base
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | Complex project needs sustained contributors. May not attract enough. |
| **Root Causes** | High barrier to entry, niche domain, competing projects |
| **Mitigation** | 1. Excellent onboarding (docs, good first issues, mentorship)<br>2. Modular architecture = parallel workstreams<br>3. Paid internships (Google Summer of Code, etc.)<br>4. Company sponsorships for specific features<br>5. Recognize all contributions (not just code) |
| **Contingency** | Core team maintains velocity; scope adjusts to capacity |
| **Owner** | Community Manager |
| **Review** | Quarterly |
| **Early Warning** | <5 regular contributors at 12 months |

---

### RISK-PROJ-002: Key Person Dependency
| Attribute | Value |
|-----------|-------|
| **Probability** | High (3) |
| **Impact** | High (3) |
| **Score** | **9 (High)** |
| **Description** | Founding engineer/architect holds critical knowledge. Bus factor = 1. |
| **Root Causes** | Complex architecture, early stage, limited documentation |
| **Mitigation** | 1. Architecture Decision Records (ADRs) for all major decisions<br>2. Pair programming / mob sessions recorded<br>3. Comprehensive onboarding docs<br>4. Delegate ownership of subsystems early<br>5. Succession plan documented |
| **Contingency** | Consulting budget for knowledge transfer |
| **Owner** | Project Lead |
| **Review** | Monthly |
| **Early Warning** | Any subsystem with only 1 contributor |

---

### RISK-PROJ-003: Funding / Sustainability Gap
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | Critical (4) |
| **Score** | **8 (High)** |
| **Description** | No revenue model in Phase 0-1. Grants/sponsorships uncertain. |
| **Root Causes** | Open source sustainability problem, no VC, niche market |
| **Mitigation** | 1. Establish non-profit foundation early (OpenSSF, Linux Foundation)<br>2. Diversify: GitHub Sponsors, corporate sponsors, grants (NLnet, Sovereign Tech Fund)<br>3. Cloud service revenue (Phase 2+)<br>4. Training/certification revenue (Phase 3+)<br>5. Keep burn rate low (remote, contractors) |
| **Contingency** | Reduce scope, extend timeline, seek acquisition/partnership |
| **Owner** | Project Lead |
| **Review** | Quarterly |
| **Early Warning** | <12 months runway |

---

### RISK-PROJ-004: Scope Creep / Perfectionism
| Attribute | Value |
|-----------|-------|
| **Probability** | Very High (4) |
| **Impact** | High (3) |
| **Score** | **12 (High)** |
| **Description** | RE tools have infinite depth. Team may over-engineer MVP. |
| **Root Causes** | Passion for craft, competitive pressure, unclear MVP boundary |
| **Mitigation** | 1. Strict MVP definition with exit criteria<br>2. "Good enough" thresholds documented<br>3. Parking lot for deferred features<br>4. Regular scope reviews with stakeholders<br>5. Time-boxed spikes for exploration |
| **Contingency** | Hard deadline for MVP release |
| **Owner** | Product Lead |
| **Review** | Sprint planning |
| **Early Warning** | MVP scope grows >20% from baseline |

---

### RISK-PROJ-005: Burnout
| Attribute | Value |
|-----------|-------|
| **Probability** | High (3) |
| **Impact** | High (3) |
| **Score** | **9 (High)** |
| **Description** | Ambitious project, volunteer contributors, high expectations. |
| **Root Causes** | Unpaid labor, scope pressure, community demands, isolation |
| **Mitigation** | 1. Sustainable pace: no crunch, mandatory breaks<br>2. Clear boundaries: "not now" is valid answer<br>3. Rotate leadership roles<br>4. Celebrate small wins<br>5. Mental health resources visible |
| **Contingency** | Reduce scope, extend timeline |
| **Owner** | Community Manager |
| **Review** | Monthly |
| **Early Warning** | Contributor churn >20%/quarter |

---

## 3. Market & Competitive Risks

### RISK-MKT-001: Incumbent Response (Ghidra Adds Native AI)
| Attribute | Value |
|-----------|-------|
| **Probability** | High (3) |
| **Impact** | Medium (2) |
| **Score** | **6 (Medium)** |
| **Description** | NSA/Ghidra team adds local AI, modern UI, collaboration. |
| **Root Causes** | Resources, motivation, existing user base |
| **Mitigation** | 1. Move faster on UX (Ghidra's weakness)<br>2. Local-first privacy as differentiator<br>3. Better plugin architecture (WASM vs Java)<br>4. Community governance vs corporate<br>5. Build moat: ecosystem, not just features |
| **Contingency** | Pivot to niche (education, firmware, collaboration) |
| **Owner** | Product Lead |
| **Review** | Quarterly |
| **Early Warning** | Ghidra announces AI roadmap |

---

### RISK-MKT-002: Binary Ninja Opens Core
| Attribute | Value |
|-----------|-------|
| **Probability** | Low (1) |
| **Impact** | High (3) |
| **Score** | **3 (Low)** |
| **Description** | Vector 35 open-sources Binary Ninja core. |
| **Root Causes** | Competitive pressure, community demand |
| **Mitigation** | 1. Differentiate on AI-native, collaboration, license (MIT vs custom)<br>2. Focus on markets they don't serve (education, firmware)<br>3. Build community moat first |
| **Contingency** | Collaborate? Merge? |
| **Owner** | Project Lead |
| **Review** | Annually |
| **Early Warning** | Binary Ninja announces open source plans |

---

### RISK-MKT-003: Commercial AI RE Tool Dominates
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | Well-funded startup builds superior AI RE tool, captures mindshare. |
| **Root Causes** | VC funding, focused team, cloud compute |
| **Mitigation** | 1. Open source = trust moat (security tools)<br>2. Local-first = privacy moat<br>3. Extensibility = ecosystem moat<br>4. Speed to community adoption |
| **Contingency** | Integrate their models via plugin API |
| **Owner** | Product Lead |
| **Review** | Quarterly |
| **Early Warning** | Major funding announcement in space |

---

### RISK-MKT-004: User Adoption Too Slow
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | RE community conservative. Switching costs high. Network effects favor incumbents. |
| **Root Causes** | Muscle memory, existing scripts/workflows, team standardization |
| **Mitigation** | 1. Import from Ghidra/IDA/Binary Ninja (high priority)<br>2. Familiar keybindings, workflows<br>3. Killer feature: AI that actually saves time<br>4. Education pipeline (students = future users)<br>5. Plugin compatibility layer |
| **Contingency** | Niche dominance first (education, firmware) then expand |
| **Owner** | Product Lead |
| **Review** | Quarterly post-MVP |
| **Early Warning** | <1000 MAU at 6 months post-MVP |

---

## 4. Security & Legal Risks

### RISK-SEC-001: Supply Chain Attack
| Attribute | Value |
|-----------|-------|
| **Probability** | Low (1) |
| **Impact** | Critical (4) |
| **Score** | **4 (Medium)** |
| **Description** | Compromised dependency or build infrastructure. |
| **Root Causes** | Typosquatting, compromised maintainer, CI/CD breach |
| **Mitigation** | 1. Reproducible builds (bit-for-bit)<br>2. Signed releases (cosign, keyless)<br>3. Dependency pinning + automated scanning<br>4. Minimal dependencies<br>5. SBOM generation |
| **Contingency** | Incident response plan, rapid revocation |
| **Owner** | Security Lead |
| **Review** | Per release |
| **Early Warning** | Any dependency vulnerability in critical path |

---

### RISK-SEC-002: Malicious Plugin
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | High (3) |
| **Score** | **6 (Medium)** |
| **Description** | Plugin exfiltrates data, executes code, corrupts analysis. |
| **Root Causes** | Insufficient sandboxing, excessive permissions, social engineering |
| **Mitigation** | 1. WASM capability-based sandbox (deny by default)<br>2. Plugin review process for registry<br>3. Permission manifests (user-approved)<br>4. Reputation system<br>5. Auto-disable on suspicious behavior |
| **Contingency** | Remote kill switch for malicious plugins |
| **Owner** | Platform Lead |
| **Review** | Phase 1 end |
| **Early Warning** | Any plugin requesting excessive permissions |

---

### RISK-SEC-003: AI Model Poisoning / Bias
| Attribute | Value |
|-----------|-------|
| **Probability** | Low (1) |
| **Impact** | High (3) |
| **Score** | **3 (Low)** |
| **Description** | Training data poisoned, model gives wrong/dangerous suggestions. |
| **Root Causes** | Malicious contributions, biased corpus, adversarial examples |
| **Mitigation** | 1. Curated, verified training data<br>2. Model signing + verification<br>3. Confidence calibration (low confidence = no suggestion)<br>4. User feedback loop catches errors<br>5. Diverse evaluation benchmarks |
| **Contingency** | Rollback to previous model version |
| **Owner** | AI Lead |
| **Review** | Per model release |
| **Early Warning** | Evaluation metrics regress |

---

### RISK-LEGAL-001: Patent Infringement
| Attribute | Value |
|-----------|-------|
| **Probability** | Low (1) |
| **Impact** | Critical (4) |
| **Score** | **4 (Medium)** |
| **Description** | RE techniques may be patented (Hex-Rays, etc.). |
| **Root Causes** | Software patents in US, broad claims |
| **Mitigation** | 1. Prior art research for key algorithms<br>2. Clean room implementation where risky<br>3. Legal review of decompiler approach<br>4. Defensive patent pool (Open Invention Network)<br>5. MIT license = patent grant from contributors |
| **Contingency** | Workaround, remove feature, legal defense fund |
| **Owner** | Project Lead |
| **Review** | Phase 1 start |
| **Early Warning** | Cease & desist or patent claim |

---

### RISK-LEGAL-002: Export Control / Sanctions
| Attribute | Value |
|-----------|-------|
| **Probability** | Low (1) |
| **Impact** | High (3) |
| **Score** | **3 (Low)** |
| **Description** | RE tools classified as "cybersecurity items" under Wassenaar. |
| **Root Causes** | Government regulation, dual-use classification |
| **Mitigation** | 1. Open source = generally exempt (public domain)<br>2. No encryption functionality (analysis only)<br>3. Legal review of distribution<br>4. Foundation in favorable jurisdiction |
| **Contingency** | Restrict distribution if required |
| **Owner** | Project Lead |
| **Review** | Annually |
| **Early Warning** | Regulatory guidance changes |

---

## 5. Operational Risks

### RISK-OPS-001: Release Engineering Complexity
| Attribute | Value |
|-----------|-------|
| **Probability** | Medium (2) |
| **Impact** | Medium (2) |
| **Score** | **4 (Medium)** |
| **Description** | Multi-platform (Win/Mac/Linux), multi-arch, signed, reproducible builds. |
| **Root Causes** | Matrix complexity, code signing certificates, CI/CD cost |
| **Mitigation** | 1. Invest in CI/CD early (GitHub Actions + self-hosted)<br>2. Automated release pipeline<br>3. Single binary distribution where possible<br>4. Container images for consistency |
| **Contingency** | Reduce platform matrix initially |
| **Owner** | Release Engineer |
| **Review** | Phase 1 start |
| **Early Warning** | Release takes >1 day |

---

### RISK-OPS-002: Documentation Drift
| Attribute | Value |
|-----------|-------|
| **Probability** | High (3) |
| **Impact** | Medium (2) |
| **Score** | **6 (Medium)** |
| **Description** | Code evolves, docs don't. Users frustrated, contributors blocked. |
| **Root Causes** | No docs-as-code process, no ownership, velocity |
| **Mitigation** | 1. Docs in same repo, same PR required<br>2. Automated link checking, example testing<br>3. Documentation owner per subsystem<br>4. "Docs debt" tracked like tech debt |
| **Contingency** | Documentation sprints |
| **Owner** | Technical Writer |
| **Review** | Per release |
| **Early Warning** | >50 open doc issues |

---

## 6. Risk Register Summary

| Risk ID | Category | Score | Status | Owner | Next Review |
|---------|----------|-------|--------|-------|-------------|
| RISK-TECH-001 | Technical | 8 | Active | Tech Lead | Monthly |
| RISK-TECH-002 | Technical | 6 | Monitoring | Arch Lead | Quarterly |
| RISK-TECH-003 | Technical | 9 | Active | AI Lead | Monthly |
| RISK-TECH-004 | Technical | 6 | Monitoring | Perf Eng | Per Release |
| RISK-TECH-005 | Technical | 6 | Active | Platform Lead | Per Release |
| RISK-TECH-006 | Technical | 4 | Monitoring | Platform Lead | Phase 1 End |
| RISK-PROJ-001 | Project | 6 | Active | Community Mgr | Quarterly |
| RISK-PROJ-002 | Project | 9 | Active | Project Lead | Monthly |
| RISK-PROJ-003 | Project | 8 | Active | Project Lead | Quarterly |
| RISK-PROJ-004 | Project | 12 | Active | Product Lead | Sprint |
| RISK-PROJ-005 | Project | 9 | Active | Community Mgr | Monthly |
| RISK-MKT-001 | Market | 6 | Monitoring | Product Lead | Quarterly |
| RISK-MKT-002 | Market | 3 | Monitoring | Project Lead | Annually |
| RISK-MKT-003 | Market | 6 | Monitoring | Product Lead | Quarterly |
| RISK-MKT-004 | Market | 6 | Monitoring | Product Lead | Quarterly |
| RISK-SEC-001 | Security | 4 | Active | Security Lead | Per Release |
| RISK-SEC-002 | Security | 6 | Active | Platform Lead | Phase 1 End |
| RISK-SEC-003 | Security | 3 | Monitoring | AI Lead | Per Model |
| RISK-LEGAL-001 | Legal | 4 | Monitoring | Project Lead | Phase 1 Start |
| RISK-LEGAL-002 | Legal | 3 | Monitoring | Project Lead | Annually |
| RISK-OPS-001 | Operational | 4 | Active | Release Eng | Phase 1 Start |
| RISK-OPS-002 | Operational | 6 | Active | Tech Writer | Per Release |

---

## 7. Risk Management Process

### 7.1 Review Cadence
- **Monthly**: High/Critical risks (score ≥8)
- **Quarterly**: Medium risks (score 4-6)
- **Annually**: Low risks (score 1-3)
- **Ad-hoc**: When early warning triggers

### 7.2 Risk Response Types
| Response | When |
|----------|------|
| **Avoid** | Change plan to eliminate risk |
| **Mitigate** | Reduce probability/impact |
| **Transfer** | Insurance, contracts, partnerships |
| **Accept** | Monitor, contingency only |

### 7.3 Escalation
- **Score 12+**: Immediate escalation to Project Lead + stakeholders
- **Score 8-11**: Active management, weekly check-ins
- **Score 4-7**: Regular monitoring, monthly check-ins
- **Score 1-3**: Passive monitoring, quarterly check-ins

---

*This risk register is reviewed and updated at each phase gate. New risks added as discovered.*