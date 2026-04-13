//! ShimCache (AppCompatCache) registry artifact extractor.
//!
//! ShimCache is stored in the SYSTEM hive and records application execution
//! metadata for compatibility checking. It is evidence of program execution.
//!
//! Key path: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
//! Value name: `AppCompatCache` (REG_BINARY)

use std::io::Cursor;

use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// A single entry decoded from the AppCompatCache (ShimCache) binary blob.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimcacheEntry {
    /// Executable path extracted from the cache entry. Empty if unparseable.
    pub path: String,
    /// Last modified time as ISO 8601, or `None` if unavailable.
    pub last_modified: Option<String>,
    /// Size of the raw `AppCompatCache` REG_BINARY blob.
    pub raw_size: usize,
    /// Position in the cache (0 = most recently executed).
    pub entry_index: usize,
}

// ---------------------------------------------------------------------------
// Key / value paths
// ---------------------------------------------------------------------------

const APPCOMPAT_KEY: &str =
    "CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
const APPCOMPAT_VALUE: &str = "AppCompatCache";

// ---------------------------------------------------------------------------
// Public parse function — STUB (RED phase)
// ---------------------------------------------------------------------------

/// Extract ShimCache entries from a SYSTEM hive.
///
/// Navigates to `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`,
/// reads the `AppCompatCache` REG_BINARY value, and attempts to parse entries.
///
/// Returns an empty `Vec` if the key or value is absent.
/// Returns a single entry with an empty path if the blob exists but the format
/// is unrecognised.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ShimcacheEntry> {
    vec![]
}
