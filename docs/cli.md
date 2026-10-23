# CLI reference

`openre` is the unified CLI (crate `openre-cli`, clap derive). Global flag:

| Flag | Effect |
| --- | --- |
| `-d`, `--debug` | Force a trace-level tracing subscriber in addition to `RUST_LOG`-driven filtering (default filter: `openre=info`) |

Command modules live in `crates/openre-cli/src/commands/` and are all wired in `main.rs` under the ten top-level groups; the engine crates behind them are direct (non-optional) dependencies of `openre-cli`. One gap: the `queue` module imports an `openre_queue` crate that is neither a workspace member nor a declared dependency of `openre-cli` yet.

Command surface documented here comes from the `Args`/`Subcommand` structs in each command module. The argument definitions, defaults, and value enums below are copied from source.

## hunt: one-shot assessment

Pipeline command: scan target, analyze exploitability, generate PoCs for Medium+ findings, write an HTML report.

```
openre hunt [FLAGS] --target <TARGET>
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-t`, `--target <TARGET>` | required | URL, IP, hostname, or file path |
| `-d`, `--depth <DEPTH>` | `standard` | Scan depth: `quick`, `standard`, `deep` |
| `-f`, `--format <FORMAT>` | `terminal` | Output: `json`, `yaml`, `html`, `terminal` |
| `-o`, `--open` | off | Open results in browser after completion |
| `-T`, `--technical` | off | Show technical details |
| `-v`, `--viral` | off | Badge/social-ready output |
| `-a`, `--achievements` | off | Achievement tracking and badges |
| `-O`, `--output <DIR>` | cwd | Custom output directory (report lands at `<DIR>/openre-hunt-report.html`) |
| `-y`, `--yes` | off | Skip confirmation prompts |

## scan: web vulnerability scanning

Profile subcommands share `ScanArgs`; `custom` picks its own profile.

| Subcommand | Checks run |
| --- | --- |
| `scan quick` | Quick profile (6 checks) |
| `scan standard` | Standard profile (16 checks) |
| `scan full` | Full profile (all 18) |
| `scan custom` | Profile + explicit `--checks`/`--exclude` |
| `scan pause <SCAN_ID>` / `scan resume <SCAN_ID>` | Flip a running scan's status in history storage |
| `scan export findings\|scans\|projects` | Dump history as JSON/CSV |
| `scan import findings\|scans\|projects` | Load history from JSON/CSV |

`ScanArgs` (quick/standard/full):

| Flag | Default | Meaning |
| --- | --- | --- |
| `<TARGET>` | required | Target URL or domain |
| `-o`, `--output <PATH>` | none | Output file. `.sarif` extension selects SARIF, `.json` selects JSON |
| `--header <HEADER>` | empty | Repeatable `Key: Value` header |
| `--timeout <SECS>` | `30` | Request timeout |
| `--follow-redirects <BOOL>` | `true` | Follow redirects |
| `--max-redirects <N>` | `10` | Redirect depth cap |
| `--user-agent <UA>` | none | User agent string |
| `--proxy <URL>` | none | e.g. `http://127.0.0.1:8080` |
| `--rate-limit <RPS>` | none | Requests per second cap |
| `--exclude <LIST>` | empty | Comma-separated check names to skip |
| `--checks <LIST>` | empty | Comma-separated check names to include |

`CustomScanArgs` adds `--profile <quick|standard|full>` (default `standard`) and shares `--checks`, `--exclude`, `--output`, `--header`, `--timeout`.

Behavior notes from `commands/scan.rs`:

- If neither `--checks` nor `--exclude` is given, the run filters out `sensitive-files` to keep default scans quiet.
- Each scan writes a `ScanSummary` to SQLite (`<storage.local_path>/history.db`), updates per-check progress, and persists severity/risk stats at completion.
- A running scan polls its summary status before each check and honors `paused`/`cancelled`/`failed` transitions set by `scan pause` or external tooling.
- Export filters for `scans`: `--project-id`, `--status`, `--date-from`/`--date-to` (RFC 3339), `--tags`, `--min-severity <critical|high|medium|low|info>`; `--format <json|csv>`.
- `import findings` requires `--scan-id` pointing at an existing scan.

## analyze: binary analysis

All subcommands take a binary path and can force a format with `--binary-format <elf|pe|macho|wasm|auto>` and write to `--output`.

| Subcommand | Extra flags |
| --- | --- |
| `analyze info <FILE>` | none |
| `analyze symbols <FILE>` / `imports <FILE>` / `exports <FILE>` / `sections <FILE>` / `segments <FILE>` | none |
| `analyze strings <FILE>` | `--min-length <N>` (default `4`) |
| `analyze functions <FILE>` | `--filter <PATTERN>`, `--details` |
| `analyze disasm <FILE>` | `--function <NAME\|ADDR>`, `--start <HEX>`, `--end <HEX>`, `--count <N>` (default `50`), `--bytes` |
| `analyze decompile <FILE>` | `--function <NAME\|ADDR>` (required) |
| `analyze pipeline <FILE>` | `--stages <LIST>` comma-separated from `all,identify,load,disassemble,cfg,dataflow,types,decompile,ai-enrich` (default `all`) |

## ai: AI-assisted analysis

| Subcommand | Flags |
| --- | --- |
| `ai chat [MESSAGE]` | `--system <PROMPT>`, `--temperature <F32>` (default `0.7`), `--max-tokens <U32>`; omit MESSAGE for interactive mode |
| `ai analyze <FINDING>` | `--context <TEXT>`, `--ultrathink` (max thinking budget) |
| `ai explain <FINDING>` | `--detail <brief|standard|deep>` (default `standard`), `--audience <developer|security-team|management|executive>` (default `developer`) |
| `ai remediate <FINDING>` | `--fix-type <code|config|architecture|process>` (default `code`), `--language <LANG>` |
| `ai correlate <PATH>` | `--format <table|json|sarif|yaml|csv>`, `--min-confidence <F32>` (default `0.5`) |
| `ai providers` | Lists registered providers with health status; hints at API keys when none are registered |
| `ai test` | `--provider <TYPE>` (e.g. `openai`, `anthropic`, `vllm`), `--model <NAME>`; health-checks registered providers matching the filters |

`FINDING` is a finding ID or a path to a finding JSON file (JSON file is the supported form). See [ai-providers.md](ai-providers.md) for provider configuration.

## exploit: PoC generation

| Subcommand | Flags |
| --- | --- |
| `exploit generate <FINDING>` | `--language <python|bash|javascript|go|rust|ruby|php|java|csharp|powershell>` (default `python`), `--template <NAME>`, `--target <URL>`, `-o/--output <PATH>`, `--safe <BOOL>` (default `true`: no destructive payloads) |
| `exploit templates` | `--category <sqli|xss|rce|ssrf|xxe|path-traversal|command-injection|ldap-injection|template-injection|deserialization|auth-bypass|idor|csrf|open-redirect>`, `--language <LANG>` |
| `exploit validate <FILE>` | `--target <URL>` (required), `--dry-run` |
| `exploit show <TEMPLATE>` | none |

## remediate: fix guidance

| Subcommand | Flags |
| --- | --- |
| `remediate plan <FINDING>` | `--environment <development|staging|production|ci-cd>` (default `production`), `--compliance <owasp|pci-dss|hipaa|gdpr|soc2|iso27001|nist>`, `-o/--output <PATH>` |
| `remediate quick-fix <FINDING>` | `--language <LANG>` |
| `remediate report <PATH>` | `-o/--output <PATH>`, `--group-by <severity|category|component|compliance>` (default `severity`) |
| `remediate verify <FINDING>` | `--target <URL>` |

## report: report templates

| Subcommand | Flags |
| --- | --- |
| `report list` | `--limit <N>` (default `100`), `--offset <N>` |
| `report create` | `-n/--name <NAME>`, `-f/--format <markdown|html|json|sarif>`, `-c/--content <TEXT\|PATH>`, `--from-file` |
| `report delete` | `-n/--name <NAME>` |
| `report use` | `-n/--name <NAME>`, `--scan-id <ID>`, `-o/--output <PATH>` |

## config: configuration

Keys use dot notation (`ai.provider`, `scan.timeout`).

| Subcommand | Flags |
| --- | --- |
| `config show` | `--section <NAME>`, `--json` |
| `config set <KEY> <VALUE>` | none |
| `config get <KEY>` | none |
| `config reset` | `--section <NAME>`, `--yes` |
| `config path` | Prints the config file location |
| `config edit` | Opens `$EDITOR` |
| `config init` | `--force` overwrites an existing config |

## queue: job queue

Depends on the `openre_queue` crate (not currently a workspace member). Job types: `analysis`, `identification`, `disassembly`, `control-flow`, `data-flow`, `type-recovery`, `decompilation`, `ai-enrichment`.

| Subcommand | Flags |
| --- | --- |
| `queue submit` | `--job-type <TYPE>` (default `analysis`), `-P/--priority <low|default|high>`, `-p/--payload <JSON\|@FILE>` (required), `--max-attempts <N>` (default `3`), `--schedule-at <RFC3339>`, `--project-id`, `--file-id`, `--user-id`, `--timeout <SECS>`, `--tag <KEY=VALUE>` (repeatable), `-f/--format <table|json|yaml>` |
| `queue status <JOB_ID>` | `-f/--format` |
| `queue cancel <JOB_ID>` | `--reason <TEXT>` (default `User requested cancellation`) |
| `queue retry <JOB_ID>` | none |
| `queue logs <JOB_ID>` | `-l/--limit <N>` (default `100`), `-F/--follow`, `-f/--format` |
| `queue stats` | `-f/--format` |
| `queue list` | `--status <pending|queued|running|completed|failed|cancelled|scheduled>`, `--job-type`, `--priority`, `--project-id`, `-l/--limit` (default `50`), `-f/--format` |

## schedule: recurring scans

| Subcommand | Flags |
| --- | --- |
| `schedule add <TARGET>` | `-n/--name <NAME>` (required), `--profile <quick|standard|full>` (default `standard`), `-i/--interval <MINUTES>` (default `60`), plus the scan tuning flags: `--checks`, `--exclude`, `--header`, `--timeout`, `--follow-redirects`, `--max-redirects`, `--user-agent`, `--proxy`, `--rate-limit`, `--no-tls-verify` |
| `schedule list` | `--enabled-only`, `--disabled-only` |
| `schedule remove <ID>` / `pause <ID>` / `resume <ID>` / `show <ID>` | none |
| `schedule daemon` | `--once` runs one scheduling pass and exits (internal entry point) |
