//! Windows autostart (Run/RunOnce) registry key artifact extractor.
//!
//! Enumerates all standard persistence-related Run keys from a REGF hive and
//! classifies each entry against known LOLBin / living-off-the-land abuse
//! patterns (MITRE ATT&CK T1547.001).

use std::io::Cursor;

use winreg_core::detect::HiveType;
use winreg_core::hive::Hive;

// ── Key paths to enumerate ────────────────────────────────────────────────────

/// Run key paths stored in a SOFTWARE hive (HKLM) — relative to hive root.
const SOFTWARE_RUN_PATHS: &[&str] = &[
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
];

/// Run key paths stored in an NTUSER.DAT hive (HKCU) — relative to hive root.
const NTUSER_RUN_PATHS: &[&str] = &[
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
];

/// Winlogon key — same path in both SOFTWARE and NTUSER.DAT.
const WINLOGON_PATH_SOFTWARE: &str =
    "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
const WINLOGON_PATH_NTUSER: &str =
    "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

/// Winlogon values that can hold persistence commands.
const WINLOGON_VALUES: &[&str] = &["Userinit", "Shell"];

// ── Output type ───────────────────────────────────────────────────────────────

/// A single autorun entry extracted from a registry hive.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunKeyEntry {
    /// Hive origin: `"HKLM"` for SOFTWARE, `"HKCU"` for NTUSER.DAT,
    /// or `"UNKNOWN"` for unrecognised hive types.
    pub hive: String,
    /// Full registry key path (relative to hive root).
    pub key_path: String,
    /// Value name (the persistence entry identifier).
    pub value_name: String,
    /// Value data: the command or path that runs at startup.
    pub command: String,
    /// `true` if the command matches a known LOLBin abuse pattern.
    pub is_suspicious: bool,
    /// Human-readable explanation when `is_suspicious` is `true`.
    pub suspicious_reason: Option<String>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a run-key command string for suspicious LOLBin abuse patterns.
///
/// Returns `Some(reason)` when suspicious, `None` when benign.
pub fn classify_run_entry(command: &str) -> Option<String> {
    // stub: always returns None
    let _ = command;
    None
}

// ── Public parse function ─────────────────────────────────────────────────────

/// Extract all Run-key entries from a hive.
///
/// Auto-detects whether the hive is a SOFTWARE (HKLM) or NTUSER.DAT (HKCU)
/// hive and selects the appropriate key paths accordingly.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RunKeyEntry> {
    // stub: always returns empty
    let _ = hive;
    vec![]
}
