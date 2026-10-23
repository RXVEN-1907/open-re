# Performance

Release build tuning notes and measured results. Baseline was taken before any change, on the same machine and toolchain as the tuned build.

Environment: Linux x86_64, rustc 1.97.1, 224 cores. Measurements were taken while other workspace builds were running, so build times are upper bounds. No crate sources changed between the baseline and tuned builds (verified by file mtime), so size deltas are attributable to the profile and dependency changes below.

## Release profile

`[profile.release]` in the root `Cargo.toml`:

| setting        | before         | after                                  |
| -------------- | -------------- | -------------------------------------- |
| `lto`          | `"thin"`       | `"fat"` (cross-crate inlining workspace-wide) |
| `codegen-units`| `1`            | `1` (unchanged)                        |
| `panic`        | `"abort"`      | `"abort"` (unchanged)                  |
| `strip`        | `"debuginfo"`  | `true` (also removes the symbol table) |
| `opt-level`    | `3`            | `3` (unchanged)                        |

Notes:

-   `panic = "abort"` was already enabled and is kept: no `catch_unwind` anywhere in the workspace, and `cargo test` runs under the `test` profile (unwind), so tests are unaffected.
-   `strip = true` removes the symbol table in addition to debuginfo. Release binaries no longer carry symbols; keep `strip = "debuginfo"` locally if symbolized release backtraces are needed.
-   A full workspace `cargo build --release` with fat LTO took 4m54s under concurrent load on this machine, so fat is kept rather than falling back to thin.

## tokio features

Workspace dependency line, before:

```toml
tokio = { version = "1.53", features = ["full", "tracing", "macros", "rt-multi-thread"] }
```

after:

```toml
# rt-multi-thread implies rt; process is required by openre-scan integration tests
tokio = { version = "1.53", features = ["rt", "rt-multi-thread", "macros", "fs", "io-util", "sync", "time", "process"] }
```

Each remaining feature maps to actual usage in the workspace:

-   `fs`: openre-storage, openre-scan, openre-core, openre-plugins, openre-scanner
-   `io-util`: `AsyncReadExt` / `AsyncWriteExt` / `AsyncSeekExt` / `Empty` in openre-storage, openre-core, openre-analysis
-   `sync`, `time`: openre-intelligence, openre-analysis, openre-telemetry, openre-scan tests
-   `process`: openre-scan integration tests only
-   `macros`, `rt-multi-thread`: `#[tokio::main]` / `#[tokio::test]` and the multi-threaded runtime

Dropped: `full` (umbrella), `tracing`, `parking_lot`. No workspace code uses tokio's `net` or `signal` modules directly. Transitive dependencies re-enable parts of the set regardless: hyper/reqwest/axum/metrics-exporter-prometheus pull `net`, wasmtime-wasi and tower pull `io-std`, and tokio's `process` pulls `signal-hook-registry`. Resolved tokio feature set (via `cargo tree -f '{f}' -p tokio`):

-   before: `bytes,default,fs,full,io-std,io-util,libc,macros,mio,net,parking_lot,process,rt,rt-multi-thread,signal,signal-hook-registry,socket2,sync,test-util,time,tokio-macros,tracing`
-   after: `bytes,default,fs,io-std,io-util,libc,macros,mio,net,process,rt,rt-multi-thread,signal-hook-registry,socket2,sync,test-util,time,tokio-macros`

The trim narrows what the workspace itself requests; the remaining transitive features are required by the network stack and stay.

## Measured results

### Binary size

| binary        | before (bytes) | after (bytes) | change  |
| ------------- | -------------- | ------------- | ------- |
| `openre-cli`  | 2,435,968      | 1,954,000     | -19.8%  |
| `openre-scan` | 14,525,944     | 11,224,984    | -22.7%  |
| `openre-tui`  | 7,070,176      | 5,930,008     | -16.1%  |
| `sentinel`    | 806,760        | 603,728       | -25.2%  |
| total         | 24,838,848     | 19,712,720    | -20.6%  |

`openre-cli` is being renamed to `openre` in a parallel change; the sizes above are for the same source before and after the profile change.

### Runtime smoke

`openre-cli hunt --target https://example.com --depth quick`, `/usr/bin/time -v`, 3 runs each:

| metric   | before       | after        |
| -------- | ------------ | ------------ |
| elapsed  | 0.04-0.06 s  | 0.04-0.06 s  |
| max RSS  | 1,792 KB     | 1,792 KB     |

No measurable runtime change on this path: it is short-lived and the RSS delta from the tokio feature trim is below page granularity. The wins are on-disk size and install footprint; startup-path work (lazy loading of analysis backends) is the next lever for RAM.

Each `hunt` run writes `openre-hunt-report.html` into the working directory.

## Verification

-   `cargo build --release`: passes for the full workspace, including the CLI binary.
-   `cargo test --workspace --exclude openre-cli`: all unit tests pass. The openre-scan integration suite fails 6 of 12 tests because it spawns `python3 test_server.py` from the repo root and that fixture is not in the repository (`error sending request for url (http://localhost:8080/)`); the failures are environmental and predate these changes.
-   A full `cargo test --workspace` additionally compiles the openre-cli test target, which was mid-refactor in a parallel change when this was measured; rerun it once that change lands.

## Reproducing

```sh
cargo build --release
ls -la target/release/{openre-cli,openre-tui,sentinel,openre-scan}
/usr/bin/time -v ./target/release/openre-cli hunt --target https://example.com --depth quick
cargo tree -f '{f}' -p tokio
```
