//! Registry hive diff engine.
//!
//! Compare two `Hive` instances and produce a structured `DiffResult`
//! with key-level and value-level changes.

pub mod types;

pub use types::{
    DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind, ValueSnapshot,
};
