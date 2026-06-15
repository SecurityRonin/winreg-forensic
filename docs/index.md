# winreg-forensic

**A pure-Rust Windows Registry forensic suite — parse REGF hives, decode forensic artifacts, carve deleted keys and values, diff hive states, and build registry timelines.**

`winreg-forensic` is the SecurityRonin fleet's registry layer: a from-scratch REGF reader plus a set of analyzer crates that turn raw hive bytes into forensic meaning. Hives are untrusted, attacker-controllable input, so the parser is panic-free by design (Paranoid Gatekeeper).

## What it does

The workspace is split into focused crates:

| Crate | Role |
|---|---|
| `winreg-format` | Windows Registry (REGF) binary format definitions — pure type definitions with zero I/O; structs derive `BinRead` for declarative parsing. |
| `winreg-core` | Core REGF hive parser — `Hive` reads hive files via memory-mapped I/O or in-memory buffers. |
| `winreg-artifacts` | Forensic artifact decoders for Windows Registry (Amcache, COM hijacking, LSA dump, WSL/LXSS, ShellBags via a PIDL/ITEMIDLIST shell-item decoder, and more). |
| `winreg-discover` | Registry hive source discovery — scans evidence directories to find every copy of a hive (live, `RegBack`, VSC, transaction logs) with provenance metadata. |
| `winreg-diff` | Hive diff engine — compares two `Hive` states into a structured `DiffResult` with key- and value-level changes. |
| `winreg-carve` | Registry hive carving — recovers deleted keys and values from unallocated cells and cell slack. |
| `winreg-recover` | Deleted registry key/value recovery. |
| `winreg-timeline` | Timeline generation from registry artifacts. |
| `winreg-fuse` | FUSE virtual filesystem mount for registry hives. |
| `winreg-py` | Python bindings for `winreg-forensic`. |

The end-user CLI is `rt-reg` (the Windows Registry forensic CLI).

## Design

- **Panic-free** — hives are untrusted, attacker-controllable input; lengths, offsets, and counts are range-checked before use, and reads go through bounds-checked helpers (Paranoid Gatekeeper standard).
- **Knowledge leaf** — the registry-artifact catalog (which keys, what they mean) is data-driven, not hardcoded special cases.
- **Provenance-aware discovery** — every located hive carries where it came from (live, `RegBack`, Volume Shadow Copy, transaction logs).
