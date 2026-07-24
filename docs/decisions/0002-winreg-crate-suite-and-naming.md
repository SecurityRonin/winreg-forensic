# 2. `winreg-*` multi-crate suite, layer split, and `reg4n6` front-end

Date: 2026-07-24
Status: Accepted

## Context

The registry is not one artifact but many — the REGF binary container, dozens of
application-level artifacts (Amcache, ShellBags, ShimCache, services, COM hijacking,
LSA secrets, WSL/LXSS, UserAssist, TypedURLs, SAM, Run keys), plus cross-cutting
operations (discovery, diff, carving, timeline). A single monolithic crate would
force every consumer that wants only a REGF *reader* to also pull the whole analyzer
and CLI stack, and would give the fleet no low-MSRV library floor to reuse.

The fleet constitution defines two repo shapes: Pattern A (single-format, exactly
`<x>-core` + `<x>-forensic`) and Pattern B (a multi-crate PARSER/domain suite
decomposed *by concern* with role suffixes). The registry is squarely Pattern B —
like `memf-*` and `winevt-*` — because it hosts many independent readers and
analyzers, not one reader + one auditor.

## Decision

1. **Decompose by concern into a `winreg-*` suite** (`Cargo.toml` `members`), not one
   crate:
   - `winreg-format` — KNOWLEDGE leaf: pure REGF type definitions, zero I/O
     (`crates/winreg-format/src/lib.rs`).
   - `winreg-core` — the REGF hive reader (`Hive`).
   - `winreg-artifacts` / `winreg-carve` / `winreg-diff` / `winreg-discover` /
     `winreg-recover` / `winreg-timeline` — analyzers and operations.
   - `winreg-cli` — the end-user front-end binary `reg4n6`.
   - `winreg-testutil` — a shared in-memory hive builder for tests.
2. **Use the distinctive `winreg-` prefix, not `winreg-forensic-*`.** Per the naming
   grammar, a *distinctive* short prefix stands alone on crates.io and is preferred
   for import brevity (like `memf-`/`winevt-`); only a *generic-word* prefix takes the
   full `<repo>-*` form. `winreg` is distinctive, so the crates are `winreg-format`,
   `winreg-core`, etc. — the repo `winreg-forensic` is the umbrella and is **not**
   itself a crate.
3. **Name the reader `winreg-core`, not `winreg-forensic`.** Pattern B never renames a
   suite's reader to `<repo>-forensic`; that Pattern-A name is reserved for the
   one-reader/one-analyzer shape. (`winreg-core` publishes with its own package name;
   the popular third-party `winreg` crate — the Win32 API wrapper — is why the import
   path stays `winreg_core`, not a hijacked `winreg`.)
4. **The CLI binary is `reg4n6`, the crate is `winreg-cli`** — the `<x>4n6`
   convention. The legacy `rt-reg` name was renamed to this in commit `403a159`
   ("rename legacy rt-reg -> winreg-cli / reg4n6").

## Consequences

- Third parties can link only `winreg-format` (types) or `winreg-core` (reader) at a
  low MSRV without dragging in analyzers, `clap`, `serde_json`, or FUSE:
  `winreg-format` depends only on `binrw` + `bitflags`, and `winreg-core` adds only
  the reader stack (`memmap2`/`miette`/`thiserror`/`jiff`/`serde`) — none of them
  `clap`, `serde_json`, or FUSE (`crates/winreg-format/Cargo.toml`,
  `crates/winreg-core/Cargo.toml`).
- The dependency arrows point strictly down: analyzers depend on `winreg-core` +
  `winreg-format`; the CLI depends on the analyzers; `winreg-format` depends on
  nobody in-workspace.
- `winreg-fuse`, `winreg-py`, `winreg-recover`, and `winreg-timeline` are currently
  placeholders (their `lib.rs` say "placeholder, implementation in Plan N"); the
  suite structure reserves their slots without shipping empty capability. `winreg-cli`
  today wires `info` / `dump` / `search` / `discover` / `diff` (`crates/winreg-cli/src/main.rs`).
- `winreg-fuse` and `winreg-py` are `publish = false` (FUSE needs libfuse at build
  time; the PyO3 bindings ship as wheels), so release-plz never tries to publish them.
