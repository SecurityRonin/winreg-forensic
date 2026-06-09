//! Windows Registry (REGF) binary format definitions.
//!
//! Pure type definitions with zero I/O. All structs derive `BinRead` for
//! declarative parsing from byte streams.

pub mod bytes;
pub mod cells;
pub mod flags;
pub mod hbin;
pub mod header;
pub mod version;
