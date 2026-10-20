openre - the open-source reverse engineering and offensive security
platform. Recon, scanning, analysis, and reporting from one toolchain,
against binaries, websites, APIs, and applications.

## Highlights

- **One release, three tools.** Every archive carries the `openre` CLI,
  the `openre-tui` full-screen terminal interface, and `sentinel`, the
  lightweight scanner - all built from the same tag.
- **Self-contained archives.** Unpack anywhere and run; each archive ships
  shell completions for bash/zsh/fish/PowerShell and the platform docs
  alongside the binaries.
- **19 platform archives.** Linux (glibc and musl) across x86-64, aarch64,
  armv7/armv6, i686, riscv64, loongarch64, powerpc64le, and s390x; Windows
  (MSVC, GNU x86-64/i686, arm64); macOS (Apple silicon, Intel, and a
  universal2 fat binary); FreeBSD x86-64.
- **Deterministic packaging.** Archives are staged with epoch mtimes,
  root ownership, sorted entries, and timestamp-free gzip, so the same
  inputs always produce the same bytes; every archive has a `.sha256`
  sidecar and the release carries a combined checksums file.

## Install

Grab the archive for your platform, unpack, and run `openre` (or
`openre.exe`). Every archive ships all three binaries, shell completions,
and docs.

| platform | archive |
|---|---|
| Linux x86-64 (glibc) | `openre-@VERSION@-x86_64-unknown-linux-gnu.tar.gz` |
| Linux x86-64 (musl, static) | `openre-@VERSION@-x86_64-unknown-linux-musl.tar.gz` |
| Linux x86-64 (32-bit) | `openre-@VERSION@-i686-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (glibc / musl) | `openre-@VERSION@-aarch64-unknown-linux-{gnu,musl}.tar.gz` |
| Linux armv7 / armv6 (32-bit) | `openre-@VERSION@-armv7-unknown-linux-gnueabihf.tar.gz` / `openre-@VERSION@-arm-unknown-linux-gnueabihf.tar.gz` |
| Linux riscv64 / loongarch64 / powerpc64le / s390x | `openre-@VERSION@-<triple>.tar.gz` |
| Windows x86-64 (MSVC) | `openre-@VERSION@-x86_64-pc-windows-msvc.zip` |
| Windows x86-64 / arm64 (GNU) | `openre-@VERSION@-x86_64-pc-windows-gnu.zip` / `openre-@VERSION@-aarch64-pc-windows-gnullvm.zip` |
| Windows x86-64 (32-bit) | `openre-@VERSION@-i686-pc-windows-gnu.zip` |
| macOS aarch64 (Apple silicon) | `openre-@VERSION@-aarch64-apple-darwin.tar.gz` |
| macOS x86-64 (Intel) | `openre-@VERSION@-x86_64-apple-darwin.tar.gz` |
| macOS universal2 | `openre-@VERSION@-universal2-apple-darwin.tar.gz` |
| FreeBSD x86-64 | `openre-@VERSION@-x86_64-unknown-freebsd.tar.gz` |

Verify with the combined checksums file:

```console
$ sha256sum -c sha256sums-v@VERSION@.txt
```

Or build from source: `cargo install --path crates/openre-cli` (Rust 1.75+).

```console
$ openre hunt --target https://example.com --depth deep
$ openre-tui                       # full-screen terminal interface
$ sentinel scan <target> --profile full
```

Full documentation in the [README](https://github.com/RXVEN-1907/open-re#readme).
