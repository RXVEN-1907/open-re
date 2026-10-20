# SARIF output

`openre-scan` emits SARIF 2.1.0 so scan results can be ingested by CI systems, including GitHub code scanning. The writer is `print_sarif_results` in `crates/openre-scan/src/output.rs`.

## Selecting SARIF

- Library: `display_results(..., &OutputFormat::Sarif, ...)` or `print_sarif_results` directly (`openre_scan::output`).
- CLI scan: pass `--output report.sarif` — the extension selects SARIF (`report.json` selects JSON).

## Document shape

```json
{
  "version": "2.1.0",
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "openre-scan",
          "version": "<crate version>",
          "informationUri": "https://github.com/RXVEN-1907/open-re",
          "rules": []
        }
      },
      "results": [ ... ],
      "invocations": [
        { "toolExecutionSuccessful": true, "startTimeUtc": "...", "endTimeUtc": "..." }
      ]
    }
  ]
}
```

`version` is the `openre-scan` crate version at compile time. There is one run per document; `rules` is currently empty (rule metadata is not published — rule identity travels on each result, below).

## Result mapping

Each `Finding` becomes one SARIF result:

| SARIF field | Source | Notes |
| --- | --- | --- |
| `ruleId` | `finding.plugin_source` | The check name, e.g. `security-headers`, `csp` — the same names accepted by `scan --checks`/`--exclude` (see [checks.md](checks.md)) |
| `level` | `finding.severity` | `Critical`, `High` → `error`; `Medium` → `warning`; `Low`, `Info` → `note` |
| `message.text` | `finding.title` | Human-readable title; full description rides in properties |
| `locations[0].physicalLocation.artifactLocation.uri` | scan target URL | The scanned target, not a source file — these are runtime findings |
| `locations[0].physicalLocation.region.startLine` | `1` | Fixed placeholder; web findings have no line semantics |
| `properties.severity` | `finding.severity` | Original five-level severity, preserved because SARIF's `level` collapses it |
| `properties.confidence` | `finding.confidence` | `VeryHigh`/`High`/`Medium`/`Low`/`VeryLow` |
| `properties.category` | `finding.category` | e.g. `SecurityMisconfiguration`, `InformationDisclosure` |
| `properties.description` | `finding.description` | Full finding text |
| `properties.cwe` | first `finding.cwe_ids` entry | Omitted when the finding has no CWE ids |

The original five-level severity is deliberately duplicated into `properties.severity`: SARIF has no `critical` level, and code scanning dashboards read `level`, while triage tooling can still recover Critical/High/Low/Info from properties.

## GitHub code scanning

```yaml
name: scan
on:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * 1"

jobs:
  openre-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install openre
        run: cargo install --path crates/openre-cli --locked # see INSTALLATION.md; binary name follows the openre rename
      - name: Scan
        run: openre scan full https://staging.example.org --output openre.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: openre.sarif
```

## Caveats

- `artifactLocation.uri` is the scan target URL, not a path inside the scanned repository — for a web target the location is the URL itself. Consumers that expect repo-relative paths will need to map these.
- `startTimeUtc`/`endTimeUtc` are stamped at write time, not measured around the scan run.
- The generic CLI output path (`--format sarif` on non-scan commands) currently writes JSON with a SARIF name; only the `openre-scan` writer produces valid SARIF.
