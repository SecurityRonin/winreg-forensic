# winreg-forensic

[![Crates.io (winreg-core)](https://img.shields.io/crates/v/winreg-core.svg?label=winreg-core)](https://crates.io/crates/winreg-core)
[![Crates.io (winreg-artifacts)](https://img.shields.io/crates/v/winreg-artifacts.svg?label=winreg-artifacts)](https://crates.io/crates/winreg-artifacts)
[![docs.rs](https://img.shields.io/docsrs/winreg-core)](https://docs.rs/winreg-core)
[![Rust 1.75+](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**`reg4n6` reads a Windows Registry hive the way a forensic examiner needs it — REGF metadata, the full key tree, deleted-cell carving, hive-to-hive diffs, and provenance-aware hive discovery across a mounted image — from one panic-free static binary.** Point it at a `SYSTEM`, `SOFTWARE`, `NTUSER.DAT`, or `Amcache.hve`, or at a whole extracted filesystem, and it finds every copy of every hive (live, `RegBack`, Volume Shadow Copy, transaction logs) and tells you what changed.

## See it work in 30 seconds

```console
$ cargo install winreg-cli   # crate: winreg-cli, binary: reg4n6
```

Read a hive's header — type, format version, last-write time, and checksum integrity:

```console
$ reg4n6 info /evidence/Windows/System32/config/SYSTEM
```

Find every hive in a mounted image, with where each copy came from:

```console
$ reg4n6 discover /mnt/evidence --format table
```

Diff two snapshots of the same hive to see exactly which keys and values changed:

```console
$ reg4n6 diff before/NTUSER.DAT after/NTUSER.DAT --changes-only
```

## What it does

`winreg-forensic` is the SecurityRonin fleet's registry layer: a from-scratch REGF reader plus analyzer crates that turn raw hive bytes into forensic meaning. The end-user CLI is **`reg4n6`** (crate `winreg-cli`); the library crates publish independently.

| Crate | Role |
|---|---|
| `winreg-format` | REGF binary-format definitions — pure types, zero I/O. |
| `winreg-core` | Core REGF hive parser — `Hive` reads via memory-mapped or in-memory I/O. |
| `winreg-artifacts` | Forensic artifact decoders (Amcache, COM hijacking, LSA dump, WSL/LXSS, ShellBags, services, and more). |
| `winreg-discover` | Provenance-aware hive discovery (live, `RegBack`, VSC, transaction logs). |
| `winreg-diff` | Hive diff engine — two `Hive` states → a structured `DiffResult`. |
| `winreg-carve` | Carves deleted keys and values from unallocated cells and slack. |
| `winreg-recover` | Deleted key/value recovery. |
| `winreg-timeline` | Timeline generation from registry artifacts. |
| `winreg-fuse` | FUSE virtual-filesystem mount for hives. |

## Trust but verify

- **Panic-free** — hives are untrusted, attacker-controllable input; lengths, offsets, and counts are range-checked before use, and reads go through bounds-checked helpers (Paranoid Gatekeeper standard).
- **`#![forbid(unsafe_code)]`** across the workspace.
- **Provenance-aware** — every located hive carries where it came from (live, `RegBack`, Volume Shadow Copy, transaction logs), so you never silently diff the wrong copy.
- **Knowledge-driven** — the registry-artifact catalog (which keys, what they mean) is data-driven via `forensicnomicon`, not hardcoded special cases.

---

[Privacy Policy](https://securityronin.github.io/winreg-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/winreg-forensic/terms/) · © 2026 Security Ronin Ltd
