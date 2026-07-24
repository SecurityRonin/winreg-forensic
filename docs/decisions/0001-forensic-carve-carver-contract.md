# 1. Deleted-cell carving via the fleet `forensic-carve` Carver contract

Date: 2026-07-24
Status: Accepted

## Context

When a registry key or value is deleted, the live tree is unlinked but the
underlying *cell* is only marked free — its 4-byte size field flips from negative
(allocated) to positive (free). The `nk`/`vk` record bytes survive in the now
unallocated cell, and in the slack of cells later reallocated to a smaller record,
until the space is overwritten (`crates/winreg-carve/src/lib.rs` module docs). A
forensic reader that only walks the *live* tree cannot see any of this, so recovery
of deleted keys/values is a first-class capability, not an afterthought.

Two shapes were possible: bake a bespoke carving API into `winreg-carve` alone, or
implement the fleet's shared carving contract so a registry carver plugs into the
same orchestration (`disk4n6` / issen) as every other format's carver.

## Decision

1. **Implement the published `forensic-carve` `Carver` contract** rather than a
   private carving API (`crates/winreg-carve/Cargo.toml`: `forensic-carve = "0.1"`
   + `inventory = "0.3"`). `HiveCarver` satisfies the contract (commits
   `b120fdf` RED "HiveCarver satisfies forensic-carve Carver contract",
   `6de7615` GREEN "HiveCarver carves whole regf hives from a sweep"), and registers
   itself through `inventory` so the fleet carve-registry discovers it without a
   central match arm.
2. **The carver is medium-agnostic** — it sees only a `&[u8]` window
   (`crates/winreg-carve/src/carver.rs` header comment), never a `Path` or a
   container, so it works identically over a live hive, a file carved from
   unallocated disk, or a page recovered from a memory image.
3. **Bounded by construction** against carve bombs: `MAX_RECOVERIES = 100_000` and
   `MAX_SCAN_BYTES = 512 MiB` (`crates/winreg-carve/src/lib.rs`).
4. **Recoveries carry a `RecoverySource` + `Confidence`** (`lib.rs`) so a carved
   record is never presented as a live, authoritative one — the epistemic stance the
   crate documents in its module header.
5. **Depend on the *published* `forensic-carve 0.1`, not a path dep** (commit
   `e36860c` "use published forensic-carve 0.1 (was path dep)"), per the fleet
   "prefer the published registry crate once it is on crates.io" rule.

## Consequences

- A registry carver is exercised by the same fleet carve sweep as every other
  format; adding registry carving benefited every downstream consumer at once
  (issen, `disk4n6`) with no per-consumer wiring.
- `winreg-carve` depends *down* on `winreg-core` + `winreg-format` and *sideways* on
  the `forensic-carve` KNOWLEDGE-adjacent contract — it never inverts the layer graph.
- A `cargo-fuzz` target (`fuzz/fuzz_targets/hive_carve.rs`, commit `6d22c9e`) fuzzes
  the carve path against crafted input, matching the Paranoid-Gatekeeper requirement
  that untrusted-input structures be fuzzed.
- `winreg-recover` remains a placeholder (`crates/winreg-recover/src/lib.rs`); the
  survived-record carving lives in `winreg-carve`, and the eventual
  higher-level reassembly/recovery layer is a separate, still-unbuilt crate.
