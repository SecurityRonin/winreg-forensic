//! COM object hijacking detection from offline registry hives.
//!
//! Detects when a CLSID has a user-side `Software\Classes\CLSID\{guid}\InprocServer32`
//! registration (from NTUSER.DAT) that overrides the system-wide HKCR entry
//! (from SOFTWARE or USRCLASS.DAT), a technique used by malware to load
//! arbitrary DLLs into COM clients without admin privileges.

use std::io::Cursor;

use winreg_core::hive::Hive;

// ── Output type ───────────────────────────────────────────────────────────────

/// A COM class registration where HKCU may override HKCR (potential hijack).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ComHijackInfo {
    /// The CLSID string, e.g. `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
    pub clsid: String,
    /// DLL path registered under HKCU (the user-side override).
    pub hkcu_server: String,
    /// DLL path registered under HKCR (empty if no HKCR hive or not found).
    pub hkcr_server: String,
    /// `true` when the HKCU server path is in an unusual/writable location.
    pub is_suspicious: bool,
    /// Human-readable explanation when `is_suspicious` is `true`.
    pub suspicious_reason: Option<String>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a HKCU COM server path.
///
/// Returns `(is_suspicious, reason)`.
pub fn classify_com_hijack(_hkcr_server: &str, _hkcu_server: &str) -> (bool, Option<String>) {
    (false, None)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse COM hijacking candidates from a pair of hives.
pub fn parse_pair(
    _hku_hive: &Hive<Cursor<Vec<u8>>>,
    _hkcr_hive: &Hive<Cursor<Vec<u8>>>,
) -> Vec<ComHijackInfo> {
    vec![]
}

/// Parse user-side COM registrations from a single NTUSER.DAT hive.
pub fn parse_hkcu_only(_hku_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ComHijackInfo> {
    vec![]
}
