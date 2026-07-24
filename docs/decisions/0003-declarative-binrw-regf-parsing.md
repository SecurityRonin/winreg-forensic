# 3. Declarative `binrw` REGF parsing in a zero-I/O format leaf

Date: 2026-07-24
Status: Accepted

## Context

REGF (the Windows Registry hive on-disk format) is a little-endian, cell-based binary
format: a `regf` base block, a chain of `hbin` bins, and typed cells (`nk` key nodes,
`vk` value keys, `sk` security descriptors, `lf`/`lh`/`ri`/`li` subkey lists, `db`
big-data). Every multi-byte field is little-endian. The parser must map raw bytes to
typed structures without hand-rolling offset arithmetic for each field, which is where
inverted splits and wrong offsets ship green.

## Decision

1. **Keep the format definitions in a pure-types leaf, `winreg-format`, with zero
   I/O** (`crates/winreg-format/src/lib.rs`: "Pure type definitions with zero I/O").
   Modules: `header` (regf base block), `hbin`, `cells`, `flags`, `version`, `bytes`.
2. **Parse declaratively with `binrw`** (`binrw = "0.4"`, `crates/winreg-format/Cargo.toml`)
   — structs derive `BinRead` so the byte layout is described once, declaratively,
   rather than as imperative `read_uNN`/offset math. Little-endian is the format
   default and is applied uniformly.
3. **Use `bitflags` for the flag fields** (`crates/winreg-format/src/flags.rs`) —
   `ValueType`, key-node flags, etc. are named bit sets, not magic integer comparisons.
4. **The reader (`winreg-core`) layers navigation on top of these types** — `Hive`,
   `CellReader`, key/value iteration — but the *format truth* (offsets, signatures,
   field widths) lives only in `winreg-format`, consumed by every analyzer.

## Consequences

- The REGF layout is stated once and reused by the reader, the carver
  (`winreg-carve` imports `CellHeader`, `CellSignature`, `RawKeyNode`, `RawKeyValue`
  from `winreg-format`), and the test hive builder (`winreg-testutil` uses
  `winreg_format::cells::lh_hash`) — one source of format truth, no drift.
- `winreg-format` has only two dependencies (`binrw`, `bitflags`) and no I/O, so it is
  the cheapest possible thing for a third party to link when they need REGF constants.
- A hand-rolled REGF parser was not built; the declarative `binrw` derive is the
  decode mechanism. Note that raw fixed-width integer reads that the reader/analyzers
  do outside a `binrw` struct still go through the bounds-checked, panic-free helpers
  in `crates/winreg-format/src/bytes.rs` (`le_u32`/`read4`, which return a zero value
  instead of an out-of-bounds slice panic), not raw slice indexing.
