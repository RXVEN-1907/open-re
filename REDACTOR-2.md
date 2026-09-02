Build OpenRE into a real, working reverse-engineering + software-development + cybersecurity platform, not a demo and not a collection of fake UI screens.

Core features to implement
Crash → root cause → patch → regression test
Source ↔ binary ↔ runtime correlation
Autonomous tool-chain execution
Security-aware code refactoring
Version-to-version security behavior diff
Persistent project-wide investigation state
Build → test → analyze → modify → rebuild loops
Cross-component vulnerability propagation analysis
AI-generated adversarial tests for modified code
Automatic rollback when an AI change breaks behavior
Whole-system dependency reasoning
Runtime behavior reconstruction
Semantic binary diffing
Patch correctness verification
Automatic exploitability validation
Bug-introducing commit detection
Security regression hunting
Multi-agent parallel investigation
Evidence-based agent decisions
Self-generated workflows for unfamiliar tasks
Local LLM support
Cloud LLM support
Multiple concurrent investigations/tasks
Important: actually implement them

Do NOT just create:

Fake scan results
Hardcoded graphs
Fake progress bars
Pretend agent activity
Static workflow diagrams
Mock vulnerabilities
Printed statements pretending something happened

Every displayed result must come from an actual operation, subprocess, analyzer, compiler, debugger, test, LLM call, filesystem operation, or other real backend functionality.

If something cannot currently be implemented, don't fake it. Mark it clearly as unavailable/TODO.

Agent architecture

Use multiple specialized agents/subagents where useful:

Reverse-engineering agent
Code-analysis agent
Security-analysis agent
Exploitability-validation agent
Patch/refactoring agent
Testing/fuzzing agent
Build agent
Verification agent
Research/context agent

Give agents real tool access and let them create workflows dynamically.

Agents should be able to work in parallel on independent tasks rather than forcing everything into one sequential pipeline.

Implement proper:

Task queue
Dependency graph
Parallel workers
Agent coordination
Shared project state
Task cancellation
Retry handling
Timeouts
Failure recovery
Artifact tracking
Evidence tracking
Audit logs
CLI/TUI

Create a real full-screen terminal UI, not a program that prints a fake dashboard and exits.

The TUI should have real interactive views for:

Projects
Targets
Active tasks
Agents
Workflows
Findings
Source/code
Binary analysis
Runtime activity
Builds
Tests
Fuzzing
Patches
Diffs
Artifacts
Logs
Evidence
History

Show genuinely live information:

Real task progress
Real subprocess status
Real agent state
Real CPU/memory/resource usage where available
Real findings
Real workflow dependencies
Real build/test results
Real logs
Real artifacts

Graphs must represent actual collected data. Do not hardcode attractive-looking graphs.

Concurrency

The user must be able to start multiple operations simultaneously, for example:

[1] Reverse engineer binary
[2] Run security analysis
[3] Fuzz API
[4] Analyze dependencies
[5] Build/test current patch


These should appear as independent live tasks and execute concurrently when resources allow.

The user should be able to:

Start tasks
Pause tasks
Cancel tasks
Retry failed tasks
Inspect task output
Open artifacts
Compare results
Spawn another investigation without stopping existing work
Workflows

Implement a workflow engine where a task can produce artifacts consumed by another task.

Example:

Binary
  ↓
RE Agent
  ↓
Function Map
  ↓
Security Agent ───────┐
  ↓                   │
Potential Bug         │
  ↓                   │
Exploitability Agent  │
  ↓                   │
Confirmed Issue       │
  ↓                   │
Patch Agent            │
  ↓                   │
Build → Tests → Fuzz ─┘
  ↓
Verification


This must be generated from actual task relationships, not a hardcoded illustration.

Development approach

Before implementing anything:

Inspect the existing OpenRE workspace.
Identify what already genuinely works.
Identify incomplete, mocked, duplicated, or dead functionality.
Reuse existing architecture instead of rebuilding working components.
Write tests for every new subsystem.
Implement features incrementally.
Run the real tests/builds after each major change.
Do not claim a feature works until you actually execute it.

Use subagents aggressively for independent repository exploration, implementation, testing, and review.

At the end, provide a concise report containing:

What was actually implemented
What was already present
What was fixed
What tests were executed
What remains incomplete
Exact commands to run the real TUI and demonstrate each capability
___________________________________________________________________________________________________________________________________________________________________________
You are working on the open-re repository.

GOAL:
Turn the existing project into a genuinely integrated CSE platform combining:
1. Software creation/development
2. Cybersecurity / offensive + defensive analysis
3. Reverse engineering / program analysis

IMPORTANT:
Do NOT blindly implement features that already exist.
First inspect the entire repository and determine what is:
- actually implemented
- partially implemented
- implemented in source but not exposed
- broken
- documentation-only
- roadmap-only

Then implement the missing/unfinished pieces below and integrate them properly.

FEATURES TO COMPLETE / ADD:

- Unified `openre` CLI that exposes the project's real capabilities instead of having disconnected crates/tools.
- Full-screen interactive TUI for scanning, reverse engineering, findings, projects, workflows, jobs and results.
  - Do NOT make it a stream of printed statements.
  - It should behave like a real terminal application with panels, navigation, tables, graphs, progress, logs and interactive actions.
- Proper scan profiles: quick / standard / full.
- Connect binary analysis to the usable CLI.
- Multi-format reverse engineering workflow for ELF, PE, Mach-O and WASM.
- Real disassembly / control-flow / data-flow / symbol / string / type-analysis workflows where supported by the existing architecture.
- AI-assisted reverse engineering using local LLMs and optional cloud LLMs.
- AI should ACT, not just explain:
  - inspect artifacts
  - select tools
  - run analysis
  - correlate results
  - generate patches/code where appropriate
  - execute workflows
  - verify results
- Make AI model providers interchangeable.
- Plugin system should be actually usable end-to-end from the CLI/TUI.
- Connect security scanning, binary analysis, plugins and AI into shared workflows.
- Concurrent jobs/workflows so multiple analyses can run at once without blocking the UI.
- Background job manager with cancellation, retry, status and logs.
- Real workflow/pipeline system where one operation can feed another operation.
  Example:
  binary → identify → disassemble → detect suspicious behavior → AI analysis → security finding → remediation → verification.
- Cross-domain correlation between software-development artifacts, binaries, dependencies and security findings.
- Make reports/results usable by both humans and other tools.
- JSON/SARIF/etc. output should represent the actual underlying results rather than being a superficial wrapper.
- Proper configuration support where currently missing.
- Finish useful API/worker/frontend integration where source already exists but components are disconnected.
- Ensure Docker/development setup actually works if advertised.
- Add missing development/setup scripts only where they are genuinely needed.
- Make all advertised CLI commands either work or remove them from the README.
- Do not claim a feature is supported unless it actually works.

CRITICAL DESIGN REQUIREMENT:

This is NOT supposed to become "another web vulnerability scanner".

The core product should combine:

software creation
        ↕
program understanding / reverse engineering
        ↕
cybersecurity

It should be possible to move between these domains in one workflow.

For example:
- create/build software
- inspect the resulting binary
- reverse engineer it
- identify security weaknesses
- modify/fix the software
- rebuild
- rescan
- compare before/after results
- let AI orchestrate the workflow

CONCURRENCY:

Implement a real job/workflow architecture so users can do multiple things simultaneously.

Example:
- binary analysis running
- web scan running
- dependency analysis running
- AI analysis running
- another project being built

All should have independent jobs/status/logs and remain visible/manageable from the TUI.

TUI REQUIREMENTS:

Build a genuine full-screen terminal UI.

It should have useful sections such as:
- Projects
- Jobs
- Scans
- Reverse Engineering
- Findings
- Workflows
- AI
- Plugins
- Logs
- Reports

Use the existing Rust architecture/dependencies where possible rather than rewriting the project unnecessarily.

TUI interactions should perform real actions.

Do NOT fake graphs, fake progress, fake scan results or fake workflow execution.

If a graph is displayed, derive it from real collected data.
If a progress indicator is displayed, derive it from actual job state.
If a workflow says "running", something should actually be running.

ENGINEERING RULES:

1. Inspect before modifying.
2. Reuse existing crates and implementations.
3. Avoid duplicate implementations.
4. Wire existing functionality together before replacing it.
5. Add tests for every major integration.
6. Test CLI commands from the compiled binaries.
7. Test TUI startup.
8. Test concurrent jobs.
9. Test at least one end-to-end reverse-engineering workflow.
10. Test at least one end-to-end security workflow.
11. Test local LLM integration if the repository supports it.
12. Keep cloud LLM support optional.
13. Never hard-code fake/demo results into production paths.
14. Preserve existing working functionality.
15. Fix compilation errors and integration errors rather than hiding them.

README:

After implementation, completely audit and update README.md.

The README must describe ONLY functionality that actually works in the current checkout.

For every feature:
- remove outdated claims
- remove commands that don't work
- update CLI examples
- document the actual TUI
- document scan profiles
- document binary/reverse-engineering capabilities
- document AI providers and configuration
- document plugins
- document concurrent jobs/workflows
- document installation/build instructions
- document Docker setup if actually working
- clearly separate CURRENT functionality from ROADMAP
- include real examples of workflows

Do not inflate the README with marketing language.

VALIDATION:

At the end, run:

cargo check --workspace
cargo test --workspace
cargo build --release --workspace

Then test the important binaries directly.

Also inspect the final CLI:

./target/release/openre --help
./target/release/openre-scan --help

If the architecture supports it, test the TUI binary as well.

Finally produce a concise implementation report containing:

1. What already existed
2. What was missing
3. What you implemented
4. What was only partially possible
5. Tests performed
6. Commands that now work
7. README sections updated
8. Any remaining limitations

Do not stop at creating structs, traits or placeholder commands.

A feature is considered implemented only when a user can actually invoke it and it performs the intended operation end-to-end.
