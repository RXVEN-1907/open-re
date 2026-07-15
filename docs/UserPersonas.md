# User Personas

## Overview

This document defines the primary and secondary user personas for open-re. Each persona represents a distinct user segment with unique needs, workflows, and pain points. Features are prioritized based on persona impact.

---

## 1. Primary Personas

### 1.1 Maya — Senior Malware Analyst

#### Demographics
- **Role**: Senior Malware Analyst at cybersecurity consultancy
- **Experience**: 8 years RE, 5 years malware analysis
- **Tools**: IDA Pro (work), Ghidra (personal), Binary Ninja (eval)
- **Environment**: Linux (primary), Windows VM, air-gapped lab

#### Goals
- Rapidly triage 20+ samples/day
- Extract IOCs, C2 infrastructure, attribution clues
- Produce client-ready reports with evidence
- Collaborate with junior analysts on complex samples
- Automate repetitive analysis tasks

#### Workflows
1. **Triage**: Load sample → quick capability assessment (capa) → family classification
2. **Deep Dive**: Decompile key functions → rename/retype → trace data flow → find crypto/C2
3. **Collaboration**: Share annotated database with team → review findings → merge insights
4. **Reporting**: Export decompilation + graphs + narrative → client report

#### Pain Points
- IDA license management (floating, VPN, dongles)
- Ghidra's slow startup and memory issues on large samples
- No real-time collaboration (Git merges are painful)
- AI tools send samples to cloud (policy violation)
- Manual renaming/retyping takes 60% of analysis time
- Junior analysts need constant guidance

#### Needs from open-re
| Need | Priority | Feature Mapping |
|------|----------|-----------------|
| Fast, reliable decompiler | Critical | REQ-DEC-001, REQ-DEC-002 |
| Local AI for naming/typing | Critical | REQ-AI-001, REQ-AI-002 |
| Real-time collaboration | High | REQ-COL-003 |
| Headless/automation | High | REQ-PY-005, REQ-CORE-005 |
| Capability detection (capa) | High | REQ-CORE-003 |
| Air-gapped operation | Critical | NFR-SEC-005, NFR-PORT-001 |
| Scripting for automation | High | REQ-PY-001, REQ-PY-003 |

#### Success Metrics
- Triage time: 15 min → 5 min/sample
- Deep dive time: 4 hrs → 2 hrs/sample
- Junior analyst autonomy: +50%

---

### 1.2 Alex — CTF Player / Security Student

#### Demographics
- **Role**: University student, CTF team captain
- **Experience**: 2 years RE, self-taught + coursework
- **Tools**: Ghidra (free), Cutter, online decompilers, pwntools
- **Environment**: Linux (WSL2), macOS, limited budget

#### Goals
- Solve RE challenges fast during competitions
- Learn RE concepts deeply (not just tool usage)
- Build portfolio for job applications
- Contribute to open source
- Compete with better-funded teams

#### Workflows
1. **Challenge Start**: Download binary → quick recon (strings, imports, entry)
2. **Analysis**: Find main → trace logic → identify constraints → solve
3. **Learning**: Document approach → compare with writeups → improve
4. **Tool Building**: Write scripts for common patterns → share with team

#### Pain Points
- Ghidra UI overwhelming for beginners
- No guided learning in tools
- Commercial tools unaffordable
- Decompiler output confusing without context
- Hard to script repetitive CTF patterns
- No collaboration during team events

#### Needs from open-re
| Need | Priority | Feature Mapping |
|------|----------|-----------------|
| Guided learning mode | Critical | REQ-AI-UX-002, Feature: Interactive Tutorials |
| Free, no restrictions | Critical | MIT License |
| Keyboard-first, fast | High | REQ-INT-001, REQ-INT-006 |
| AI explanations ("why this?") | High | REQ-AI-UX-002 |
| Scripting for CTF patterns | High | REQ-PY-001, REQ-PLG-007 |
| Team collaboration | Medium | REQ-COL-003 |
| Cross-platform (macOS) | High | NFR-PORT-002 |

#### Success Metrics
- Time to first useful analysis: <10 min
- Challenge solve rate: +30%
- Learning retention: Measurable improvement

---

### 1.3 Jordan — Vulnerability Researcher

#### Demographics
- **Role**: Vulnerability Researcher at tech company / bug bounty hunter
- **Experience**: 6 years RE, focus on 0-day discovery
- **Tools**: IDA Pro (Hex-Rays), Binary Ninja, custom scripts, fuzzers
- **Environment**: Linux, multiple VMs, high-end hardware

#### Goals
- Find exploitable vulnerabilities in target software
- Audit proprietary codebases (no source)
- Develop exploits for verification
- Track patches and regressions
- Publish advisories responsibly

#### Workflows
1. **Target Selection**: Identify attack surface → prioritize components
2. **Static Analysis**: Load binary → map attack surface → find sinks/sources
3. **Deep Analysis**: Taint tracking → path constraints → exploitability
4. **Dynamic Verification**: Debugger → trace execution → confirm crash
5. **Patch Diffing**: Compare versions → find silent fixes → variant hunting

#### Pain Points
- Taint analysis manual/limited in current tools
- Patch diffing clunky (BinDiff, manual)
- No semantic search ("find all strcpy-like calls")
- Decompiler misses complex control flow
- Symbolic execution integration poor
- Collaboration on sensitive research difficult

#### Needs from open-re
| Need | Priority | Feature Mapping |
|------|----------|-----------------|
| Advanced taint analysis | Critical | REQ-CFG-006 |
| Semantic code search | High | REQ-AI-007, REQ-INT-005 |
| Patch/binary diffing | High | REQ-DEC-008, Feature: Binary Diffing |
| Symbolic execution integration | High | REQ-DYN-003, angr integration |
| Exploit development helpers | Medium | REQ-DYN-001, REQ-DYN-004 |
| Secure collaboration | High | REQ-COL-001, REQ-COL-003 |
| Headless for CI/fuzzing | High | REQ-PY-005 |

#### Success Metrics
- Vuln discovery rate: +25%
- False positive reduction: 50%
- Patch analysis time: 2 hrs → 30 min

---

### 1.4 Sam — Reverse Engineering Educator

#### Demographics
- **Role**: Professor / Instructor teaching RE, malware analysis, compilers
- **Experience**: 15 years teaching, 10 years industry
- **Tools**: Ghidra (teaching), IDA (research), custom courseware
- **Environment**: University lab (Linux/Windows), student laptops (varied)

#### Goals
- Teach RE concepts, not tool mechanics
- Provide hands-on labs that work on any laptop
- Grade assignments efficiently
- Create reusable curriculum materials
- Lower barrier to entry for diverse students

#### Workflows
1. **Course Prep**: Design labs → create binaries → write instructions → test
2. **Lecture**: Live demo → students follow → troubleshoot
3. **Lab Sessions**: Students analyze → instructor helps → collect submissions
4. **Grading**: Review analyses → check key findings → provide feedback
5. **Iteration**: Update materials → share with community

#### Pain Points
- Ghidra UI teaches tool, not concepts
- Lab environment setup takes 1st week
- Grading manual, inconsistent
- No cloud option for Chromebooks/weak laptops
- Materials not shareable across institutions
- Students can't afford commercial tools

#### Needs from open-re
| Need | Priority | Feature Mapping |
|------|----------|-----------------|
| Web-based viewer (zero install) | Critical | REQ-COL-004 |
| Guided labs with hints | Critical | Feature: Learning Mode |
| Automated grading hooks | High | REQ-PY-005, Feature: Assignment API |
| Curriculum-ready content | High | Feature: Teaching Packs |
| Accessibility (WCAG) | Critical | REQ-A11Y-001 to 004 |
| Free for students | Critical | MIT License |
| LMS integration | Medium | Feature: LTI/Canvas |

#### Success Metrics
- Lab setup time: 1 week → 0 min
- Student completion rate: +40%
- Instructor prep time: -50%
- Accessibility compliance: 100%

---

## 2. Secondary Personas

### 2.5 Casey — Embedded/IoT Security Engineer

#### Profile
- Analyzes firmware, bootloaders, RTOS
- Architectures: ARM Cortex-M, RISC-V, MIPS, Xtensa, custom
- Tools: IDA (processor modules), Ghidra (SLEIGH), custom scripts
- Needs: Custom architecture support, flash memory mapping, hardware interfaces

#### Key Needs
- Architecture definition language (like SLEIGH but better) → REQ-DASM-006
- Memory map visualization → REQ-UI-007
- Hardware peripheral modeling → Feature: Peripheral Simulation
- Binary patching/emulation → REQ-DYN-003

---

### 2.6 Riley — Compiler/Toolchain Engineer

#### Profile
- Verifies compiler output, optimizations, ABI compliance
- Works with LLVM, GCC, custom backends
- Needs: IR comparison, optimization verification, regression testing

#### Key Needs
- LLVM IR import/export → REQ-DEC-007
- Binary diffing (compiler versions) → REQ-DEC-008
- Structured analysis for optimization patterns → REQ-CFG-007
- Headless CI integration → REQ-PY-005

---

### 2.7 Morgan — Digital Forensics Investigator

#### Profile
- Incident response, artifact analysis, timeline reconstruction
- Analyzes memory dumps, disk images, malicious binaries
- Tools: Volatility, Ghidra, custom parsers
- Needs: Fast triage, timeline integration, evidence export

#### Key Needs
- Fast capability detection → REQ-CORE-003
- Memory analysis integration → Feature: Volatility Plugin
- Evidence-grade export (hash, chain of custody) → Feature: Forensic Export
- Collaboration with legal/management → REQ-COL-004

---

### 2.8 Taylor — Hobbyist / Retro Computing Enthusiast

#### Profile
- Analyzes vintage games, firmware, demoscene
- Architectures: 6502, Z80, 68k, SH4, custom
- Tools: Ghidra (custom SLEIGH), radare2, emulators
- Needs: Obscure architecture support, community sharing, fun

#### Key Needs
- Easy custom architecture definition → REQ-DASM-006
- Community plugin sharing → REQ-PLG-006
- Emulator integration → REQ-DYN-003
- Low barrier to entry → REQ-INT-006, REQ-AI-UX-002

---

## 3. Persona Prioritization Matrix

| Feature Area | Maya (Malware) | Alex (Student) | Jordan (Vuln) | Sam (Edu) | Weighted Score |
|--------------|----------------|----------------|---------------|-----------|----------------|
| Decompiler Quality | 10 | 8 | 10 | 7 | **9.2** |
| AI Assistance (Local) | 10 | 9 | 8 | 9 | **9.0** |
| Modern UX/Accessibility | 7 | 10 | 6 | 10 | **8.2** |
| Collaboration | 9 | 7 | 8 | 9 | **8.3** |
| Scripting/Automation | 9 | 8 | 9 | 8 | **8.5** |
| Plugin Extensibility | 8 | 7 | 9 | 6 | **7.8** |
| Architecture Support | 8 | 5 | 7 | 4 | **6.5** |
| Dynamic Analysis | 6 | 4 | 9 | 3 | **5.8** |
| Learning/Education | 5 | 10 | 4 | 10 | **7.0** |
| Cost/Freedom | 8 | 10 | 7 | 10 | **8.5** |

**Weighting**: Maya 30%, Alex 25%, Jordan 25%, Sam 20%

---

## 4. Anti-Personas (Who We're NOT Building For)

| Anti-Persona | Reason | Avoid |
|--------------|--------|-------|
| **Enterprise Procurement** | Needs RFP checkboxes, not user value | Don't optimize for feature lists |
| **Script Kiddie** | Wants push-button exploits | No "exploit generation" features |
| **Cloud-Only User** | Won't run local tools | Web viewer is read-only supplement |
| **Legacy IDA Die-hard** | Won't switch regardless | Don't mimic IDA workflows exactly |

---

## 5. Persona Validation Plan

### 5.1 Research Methods (Phase 0)
- [ ] Survey 50+ RE practitioners (Reddit, Discord, conferences)
- [ ] Interview 5 per primary persona
- [ ] Observe 3 analysis sessions per persona
- [ ] Analyze 100+ GitHub issues from competitor repos

### 5.2 Validation Metrics (Phase 1+)
| Persona | Metric | Target |
|---------|--------|--------|
| Maya | Triage time reduction | 50% |
| Alex | Time to first analysis | <10 min |
| Jordan | Vuln discovery rate | +25% |
| Sam | Lab setup time | 0 min |

---

## 6. Journey Maps (Key Workflows)

### 6.1 Maya: Malware Triage → Deep Dive

```
Load Sample
    ↓
Quick Recon (strings, imports, capa) ← AI: "This is Emotet loader"
    ↓
Find Entry → Main → Key Functions ← AI: "C2 comms at 0x401230"
    ↓
Decompile + Annotate ← AI: Suggest names, types, comments
    ↓
Share with Team ← Real-time collab, conflict-free merge
    ↓
Export Report ← One-click: decompilation + graph + narrative
```

### 6.2 Alex: CTF Challenge

```
Download Binary
    ↓
"Analyze" Button ← AI: Overview + suggested entry points
    ↓
Interactive Tutorial Mode ← "Press 'g' to go to main"
    ↓
Decompile + AI Explain ← "This function checks flag format"
    ↓
Script Pattern ← "Save as 'xor_decrypt' snippet"
    ↓
Solve → Submit → Learn from Writeup
```

### 6.3 Sam: Teaching Lab

```
Instructor: Create Lab
    ↓
Upload Binary + Hints + Checks
    ↓
Student: Open Link (Web Viewer)
    ↓
Guided Mode: "Find the password check"
    ↓
AI Hint: "Look for strcmp at 0x401000"
    ↓
Student Annotates → Auto-graded
    ↓
Instructor: Dashboard → Feedback
```

---

## 7. Accessibility Considerations per Persona

| Persona | Accessibility Needs |
|---------|---------------------|
| **Maya** | High contrast (long hours), keyboard shortcuts, reduced motion |
| **Alex** | Screen reader (some students), keyboard-only, clear focus indicators |
| **Jordan** | Customizable layout, multi-monitor, high DPI |
| **Sam** | **All WCAG AA** - legal requirement for education |

---

*Personas are living documents. Validate with real users each phase. Update based on feedback.*