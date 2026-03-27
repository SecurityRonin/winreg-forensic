//! Registry hive diff engine.
//!
//! Compare two `Hive` instances and produce a structured `DiffResult`
//! with key-level and value-level changes.

pub mod engine;
pub mod snapshot;
pub mod types;

pub use engine::diff_hives;
pub use types::{
    DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind, ValueSnapshot,
};
