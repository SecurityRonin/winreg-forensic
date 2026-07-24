# 4. `forbid(unsafe_code)` workspace-wide via an I/O-generic reader

Date: 2026-07-24
Status: Accepted

## Context

Registry hives are untrusted, attacker-controllable input. `unsafe` in a parser of
such input is exactly where a crafted hive could reintroduce the memory-corruption
class safe Rust deletes by construction. The fleet's default posture is
`unsafe_code = "forbid"`, downgraded to `"deny"` + a bounded per-site `#[allow]`
*only* when a real benefit (e.g. `memmap2::Mmap::map`, whose API is `unsafe`)
justifies it — as `ewf` and `memory-forensic` do for their mmap scanners.

The question for `winreg-core` was whether reading hives needs that mmap exception at
all, or whether it can hold the stronger `forbid`.

## Decision

1. **Hold `unsafe_code = "forbid"` across the entire workspace**
   (`Cargo.toml` `[workspace.lints.rust] unsafe_code = "forbid"`), the provable
   "zero places a crafted input can corrupt memory" posture — not the `deny` +
   bounded-allow downgrade the mmap crates use.
2. **Make the reader generic over `R: ReadSeek`** instead of committing to a memory
   map (`crates/winreg-core/src/hive.rs`: "Generic over `R: ReadSeek` to support mmap,
   in-memory buffers, and overlays"). The reader never calls the `unsafe`
   `Mmap::map`; a memory-mapped source, if used, is constructed by the caller and
   handed in as a `ReadSeek`, keeping the `unsafe` (if any) out of this workspace.
3. **Earn the `unsafe forbidden` badge honestly** — the README carries it (unlike the
   mmap crates, which per fleet standard *skip* it because they are `deny` +
   bounded-allow).

## Consequences

- `winreg-core` gives up in-crate mmap zero-copy in exchange for a categorically
  stronger, badge-able safety guarantee — a good trade for an untrusted-input parser,
  and the whole workspace inherits it via `[lints] workspace = true`.
- `memmap2` is declared as a `winreg-core` dependency (`crates/winreg-core/Cargo.toml`)
  but is **not** invoked in the crate's source (no `Mmap` usage found in
  `crates/*/src`). Whether this dep is a vestige or a planned caller-side mmap backend
  is **not recoverable from the visible history**; it does not weaken the `forbid`
  posture because no `unsafe` mmap call exists in-tree. Flagged for a follow-up
  cleanup (drop the unused dep, or wire the mmap backend behind the `ReadSeek` seam).
- Any future need for an `unsafe` primitive forces a deliberate downgrade to `deny`
  + an annotated per-site allow — it cannot slip in silently under `forbid`.
