//! Generic registry key/value walker — foundation module for forensic artifact extraction.
//!
//! Produces `RegistryKeyInfo` and `RegistryValueInfo` structs for every key and value
//! in a hive, suitable for downstream artifact decoders.

use std::io::Cursor;

use winreg_core::hive::{Hive, ReadSeek};

/// Metadata for a single registry key.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryKeyInfo {
    /// Full path from root, e.g. `"SOFTWARE\\Microsoft\\Windows"`.
    pub path: String,
    /// Just the key name (last component).
    pub name: String,
    /// ISO 8601 timestamp, or `None` if not set.
    pub last_written: Option<String>,
    /// Number of direct subkeys.
    pub subkey_count: usize,
    /// Number of values attached to this key.
    pub value_count: usize,
}

/// Metadata for a single registry value.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryValueInfo {
    /// Full path of the parent key.
    pub key_path: String,
    /// Value name; empty string for the default (unnamed) value.
    pub name: String,
    /// Human-readable type string, e.g. `"REG_SZ"`, `"REG_DWORD"`.
    pub data_type: String,
    /// Human-readable preview of the data, truncated at 256 chars.
    pub data_preview: String,
    /// Raw data size in bytes.
    pub raw_size: usize,
}

/// Walk all keys in the hive (BFS order), returning metadata for each.
pub fn walk_keys(_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RegistryKeyInfo> {
    todo!("walk_keys not yet implemented")
}

/// Walk all values under a specific key path.
///
/// Returns an empty `Vec` if the path is not found.
pub fn walk_values(_hive: &Hive<Cursor<Vec<u8>>>, _key_path: &str) -> Vec<RegistryValueInfo> {
    todo!("walk_values not yet implemented")
}

/// Walk all keys AND their values recursively (BFS), returning a `RegistryValueInfo`
/// for every value in the hive.
pub fn walk_all_values(_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RegistryValueInfo> {
    todo!("walk_all_values not yet implemented")
}
