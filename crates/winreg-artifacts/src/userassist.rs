//! UserAssist registry artifact extractor (stub — not yet implemented).

use std::io::Cursor;

use winreg_core::hive::Hive;

/// A UserAssist entry from the registry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserAssistEntry {
    /// ROT13-decoded program path / name.
    pub program: String,
    /// Raw run count from bytes 4-7 of the binary value data.
    pub run_count: u32,
    /// Focus count from bytes 8-11.
    pub focus_count: u32,
    /// Focus duration in milliseconds from bytes 12-15.
    pub focus_duration_ms: u32,
    /// ISO 8601 last-run timestamp from FILETIME at bytes 60-67, or `None` if zero.
    pub last_run: Option<String>,
    /// The GUID subkey this entry came from.
    pub guid: String,
}

/// Extract all UserAssist entries from an NTUSER.DAT hive.
pub fn parse(_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<UserAssistEntry> {
    todo!("userassist::parse not yet implemented")
}
