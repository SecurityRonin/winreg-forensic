//! Registry hive source discovery.
//!
//! Scan evidence directories to find all copies of registry hives
//! with provenance metadata (live, `RegBack`, VSC, transaction logs).

pub mod types;

pub use types::{HiveSource, SourceOrigin};
