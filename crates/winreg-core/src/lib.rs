//! Core Windows Registry hive parser.
//!
//! Provides `Hive` for reading REGF hive files via memory-mapped I/O
//! or in-memory buffers.

pub mod bytes;
pub mod cell_reader;
pub mod detect;
pub mod error;
pub mod hive;
pub mod iter;
pub mod key;
pub mod path;
pub mod security;
pub mod txlog;
pub mod value;
