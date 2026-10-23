# openre next to nmap, nuclei, and radare2

These four get mentioned together, so here is the honest positioning.
Every openre cell traces to the code listed under **Sources**; the other
three columns come from each project's public docs and licenses, not from
running them here.

| dimension | openre | nmap | nuclei | radare2 |
|---|---|---|---|---|
| primary job | web/API vuln scanning + binary analysis | network discovery and port/service scanning | template-based vuln scanning | reverse engineering of binaries |
| what it scans | HTTP targets (18 checks, 3 profiles) and local ELF/PE/Mach-O/WASM files | hosts, ports, services, OS fingerprints | web apps and network services via YAML templates | files on your disk |
| output formats | table, JSON, YAML, SARIF; CSV export of findings/scans/projects | interactive text, grepable, XML | text, JSON, JSONL, markdown, SARIF | interactive text/commands, JSON |
| AI layer | optional; local (llama.cpp/ONNX) or remote (OpenAI/Anthropic/vLLM); off by default | none | none | none built in (r2ai is a separate plugin) |
| binary analysis | symbols/imports/sections/strings, capstone disassembly, CFG + dataflow + types + decompile pipeline | none | none | its whole point: many ISAs, debugger, decompilers via plugins |
| exploit/fix help | PoC templates, remediation plans, knowledge-base verification | NSE scripts can be exploits | templates are detection + some exploit paths | none |
| runtime dependencies | one binary, no server/DB; SQLite bundled; glibc build links system OpenSSL (ldd-verified) | single binary, NSE engine built in | single Go binary + a clone of `nuclei-templates` | self-contained C binary |
| license | MIT | GPL-2.0 | MIT | LGPL-3.0 |

## Where the others plainly win

- **nmap** is the network tool; openre has no host discovery, port scan,
  or OS fingerprinting at all. If the job is "map a network", use nmap.
- **nuclei** beats openre on vulnerability breadth: thousands of
  community-maintained templates against openre's 18 built-in checks.
  Its SARIF and JSON pipelines are also older and battle-tested.
- **radare2** is far deeper for RE: dozens of architectures, an
  interactive debugger, and decompiler plugins. openre's analysis is
  read-only capstone output plus its pipeline. A report, not a workspace.
- openre's claim is narrower: one binary with no server, database, or
  Docker that covers a scan-and-triage pass **and** first-line binary
  analysis, with an AI layer that stays out of the way when
  unconfigured. It will not replace any of the three at their specialty.

## Sources

- openre column: `crates/openre-scan/src/checks.rs` (`get_all_checks`,
  18 checks, profile membership), `crates/openre-cli/src/output.rs`
  (table/json/sarif/yaml), `crates/openre-cli/src/commands/scan.rs`
  (CSV/JSON export-import), `crates/openre-analysis/src/binary/`
  (elf/pe/macho/wasm), `crates/openre-disasm` (capstone),
  `crates/openre-ai/src/providers/` (remote OpenAI/Anthropic/vLLM,
  llama.cpp, ONNX), `crates/openre-storage/Cargo.toml` (bundled SQLite),
  root `Cargo.toml` (`license = "MIT"`); the OpenSSL note is `ldd
  target/release/openre` plus `cargo tree -i openssl-sys` (reqwest's
  default TLS through native-tls).
- nmap, nuclei, radare2 cells: each project's published documentation and
  license files as of writing; re-check before quoting specific flags or
  format lists, both move between releases.
