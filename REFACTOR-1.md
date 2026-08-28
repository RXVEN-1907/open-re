And based on what I've seen, there is a significant mismatch between what this repository's README promises and what the checkout actually exposes.

I checked the public repository listing as well; the project is indeed presented as an open-source reverse-engineering/offensive-security platform with binary, web, API, and application analysis. 
G
GitHub

However, I want to distinguish “not implemented” from “implemented in source but not exposed/working”. From your local results alone, we can already prove some gaps, while others need a source-level audit.

What we've already proven is missing/broken
README promise	What you actually have	Status
openre-scan tui	tui is an unrecognized subcommand	❌ Not exposed
scripts/setup-dev.sh	scripts/ only contains hourly_automation.py	❌ Missing
Scan profiles quick, standard, full	Your CLI help doesn't show --profile	⚠️ Likely missing/outdated
openre-scan binary analysis	openre-scan exposes only scan and version	❌ Not through this CLI
Unified openre CLI	Not yet verified in your checkout	⚠️ Unknown
Full platform	API/worker/frontend exist in repository listing, but runtime status unknown	⚠️ Unknown

And there are more claims in that README that need checking.

1. TUI — ❌ clearly not delivered through the advertised command

README claims:

Interactive TUI (experimental)

openre-scan tui


Your actual executable says:

Commands:
  scan
  version
  help


Therefore:

openre-scan tui is not part of the CLI you built.

This isn't a usage mistake on your side.

2. Development setup script — ❌ missing

README says:

./scripts/setup-dev.sh


Your actual directory is:

scripts/
└── hourly_automation.py


Therefore the documented development setup command cannot work in your checkout.

That's a concrete documentation/repository mismatch.

3. Scan profiles — ⚠️ README and binary disagree

README promises:

openre-scan scan https://example.com --profile quick
openre-scan scan https://example.com --profile standard
openre-scan scan https://example.com --profile full


But your top-level help has no --profile.

We should check:

./target/release/openre-scan scan --help


If --profile isn't there either, then the documented profile functionality is not exposed by the current scanner CLI.

The README claims:

Quick       6 checks
Standard   15 checks
Full       18 checks


That is a substantial advertised feature, so I'd classify it as a major mismatch if absent.

4. Binary analysis — ⚠️ very important distinction

The README claims:

Multi-format Binary Support — ELF, PE, MachO, WASM parsing and analysis

and describes:

Identification
Loading
Disassembly
Control Flow
Data Flow
Type Recovery
Decompilation
AI Enrichment
Finalization


There is a crate called:

crates/openre-analysis


so the repository does contain a binary-analysis component.

But your executable:

openre-scan


doesn't expose binary analysis.

That's not necessarily a false claim about the entire repository. It means the functionality may exist at the library/crate level without being connected to a usable CLI.

That's a distinction we should verify before calling it "implemented."

5. Unified CLI — ⚠️ needs testing

The README promises:

openre project create
openre project list

openre scan create
openre scan run
openre scan list

openre finding list

openre ai analyze
openre ai explain
openre ai remediate

openre plugin list
openre plugin install

openre report generate


But we haven't established whether your compiled:

openre


actually contains these.

Run:

cargo build --release --package openre-cli


then:

./target/release/openre --help


This is one of the biggest things I'd audit next.

6. AI Security Analyst — ⚠️ likely needs dependency/configuration verification

README promises:

Ollama
OpenAI
Anthropic
ONNX Runtime
llama.cpp
automated vulnerability analysis
remediation generation
finding correlation
context management
PII filtering
confidence scoring

The presence of a crate:

openre-security-ai


is evidence that code exists.

But that's not evidence that the feature is actually usable end-to-end.

For example, there's a huge difference between:

struct SecurityAnalyst { ... }


existing in Rust and:

openre ai analyze <finding-id>


successfully analyzing a real finding using Ollama/OpenAI.

So this belongs in:

Implemented in some form, end-to-end functionality unverified.

7. Plugin system — ⚠️ needs end-to-end verification

README promises:

WASM runtime
sandboxing
capability system
plugin registry
plugin install
plugin enable/disable
configuration
security plugins
Fuel metering
memory limits
syscall filtering

Again, there is apparently an openre-plugins crate and a plugins/security directory.

That means this isn't something I'd immediately call fake.

But the important test is:

openre plugin list


then actually installing/enabling a plugin.

If the CLI doesn't expose those commands or the runtime cannot execute a plugin, it's another partially implemented feature.

8. API — ⚠️ advertised, but needs runtime testing

README promises:

REST API
gRPC
WebSockets
JWT
API keys
rate limiting
API versioning


and endpoints such as:

/api/v1/projects
/api/v1/scans
/api/v1/findings
/api/v1/ai/*
/api/v1/plugins
/api/v1/exports
/api/v1/auth


The repository contains:

openre-api


but again, that doesn't prove the server actually starts.

The real test will be something like:

docker compose up


and then determining which services actually become healthy.

9. Frontend — ⚠️ advertised, needs runtime verification

README promises a React/Tailwind frontend with:

Dashboard
scan management
finding browser
AI chat
plugin manager
settings
WebSockets
responsive UI
WCAG 2.1 AA

There is a:

frontend/


directory.

That's good evidence that there is frontend code.

But until we run it, we shouldn't call all of those features fulfilled.

10. Docker full platform — ⚠️ needs verification

README claims:

docker compose -f docker-compose.yml up -d


will run:

API + Worker + Frontend


We should inspect:

docker compose config --services


and then:

docker compose up -d
docker compose ps


A compose file existing isn't enough; the services need to actually build/start.

11. Release binaries — ⚠️

README claims:

Multi-platform binaries — x86_64 Linux/macOS/Windows + ARM64

and:

GitHub Releases

Your pasted repository page says:

Releases
1 tag
Create a new release


and:

Packages
No packages published


So the release/distribution story deserves scrutiny.

The existence of CI release automation doesn't necessarily mean published artifacts exist.

12. Plugin marketplace — ⚠️ roadmap says future

Interestingly, the README simultaneously talks about plugin registry functionality and says:

v0.2.0
Plugin marketplace integration


That suggests some plugin infrastructure may exist while the marketplace itself isn't finished.

I'd classify:

Plugin runtime          → potentially implemented
Plugin registry         → potentially implemented
Plugin marketplace      → roadmap / not complete

13. Configuration — explicitly incomplete

The README says:

Scanner Config
Works without configuration.
Optional via:
Command-line flags
TOML config file (planned)


And roadmap:

v0.2.0
Configuration file support (TOML)


So this one is actually explicitly unfinished.

The platform configuration example:

~/.config/openre/config.toml


shouldn't be assumed to work just because it's documented.

14. Recursive crawling — ❌ roadmap

README explicitly puts this under:

v0.2.0
Recursive crawling/spidering
JavaScript rendering/analysis (headless)


Therefore these aren't promises of the current release; they're planned features.

Same for:

OAuth/JWT/API-key authentication handling
multi-tenant API
distributed scanning
custom check SDK
compliance reporting
IDE integrations
enterprise RBAC/SSO
cloud offering

Those should be marked planned, not "broken."

15. The really interesting problem

The repository is describing itself as something much larger than the executable you just ran.

The README essentially describes:

                    open-re
                       │
       ┌───────────────┼────────────────┐
       │               │                │
    Web/API         Binary             AI
    Scanner         Analysis           Analyst
       │               │                │
       └───────────────┼────────────────┘
                       │
                   Plugins
                       │
                    API/UI


But what you've actually demonstrated is:

openre-scan
    │
    ├── scan
    ├── version
    └── help


That's a much smaller surface.

That doesn't prove the rest is fake—it suggests the repository is in a partially integrated development state, which is consistent with the README's Alpha/Beta labels.

What I would audit next

Rather than manually guessing from the README, we can make this definitive.

Run this from the repository root:

echo "=== WORKSPACE ==="
cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("\n".join(p["name"] for p in d["packages"]))'

echo
echo "=== BINARIES ==="
find target/release -maxdepth 1 -type f -executable -printf '%f\n' 2>/dev/null

echo
echo "=== CRATES ==="
find crates -maxdepth 2 -name Cargo.toml -print

echo
echo "=== TUI REFERENCES ==="
grep -RniE 'ratatui|tui|Terminal' crates 2>/dev/null | head -100

echo
echo "=== BINARY ANALYSIS ==="
grep -RniE 'ELF|MachO|PE|WASM|disassembl|decompil|control.flow|data.flow' \
  crates/openre-analysis 2>/dev/null | head -100

echo
echo "=== CLI COMMANDS ==="
cargo run --release --package openre-cli -- --help 2>&1

echo
echo "=== DOCKER SERVICES ==="
docker compose config --services 2>&1


Paste that output here.

Then I can give you a proper audit in this format:

Feature	README promise	Source exists	CLI/API exposed	Actually runnable	Verdict
TUI	Yes	?	❌	❌	❌
Web scanner	Yes	✅	✅	?	?
Binary analysis	Yes	?	?	?	?
ELF	Yes	?	?	?	?
PE	Yes	?	?	?	?
Mach-O	Yes	?	?	?	?
WASM	Yes	?	?	?	?
AI analyst	Yes	?	?	?	?
Plugins	Yes	?	?	?	?
REST API	Yes	?	?	?	?
gRPC	Yes	?	?	?	?
Frontend	Yes	?	?	?	?
Docker platform	Yes	?	?	?	?
Reports	Yes	?	?	?	?
Security checks	18+	?	?	?	?

That will let us separate real functionality, partially wired functionality, documentation-only claims, and roadmap items instead of relying on the README.

G
Sources
