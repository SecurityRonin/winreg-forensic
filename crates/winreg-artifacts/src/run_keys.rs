//! Windows autostart (Run/RunOnce) registry key artifact extractor.
//!
//! Enumerates all standard persistence-related Run keys from a REGF hive and
//! classifies each entry against known `LOLBin` / living-off-the-land abuse
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

/// Winlogon key path for a SOFTWARE hive.
const WINLOGON_PATH_SOFTWARE: &str = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

/// Winlogon key path for an NTUSER.DAT hive.
const WINLOGON_PATH_NTUSER: &str = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

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
    /// `true` if the command matches a known `LOLBin` abuse pattern.
    pub is_suspicious: bool,
    /// Human-readable explanation when `is_suspicious` is `true`.
    pub suspicious_reason: Option<String>,
    /// The Run key's `LastWriteTime` — approximately when this autorun entry
    /// was last written. `None` when the key carries no timestamp.
    pub last_written: Option<jiff::Timestamp>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a run-key command string for suspicious `LOLBin` abuse patterns.
///
/// Returns `Some(reason)` when suspicious, `None` when benign.
///
/// Patterns detected:
/// - `powershell` with `-enc` or `-encodedcommand`
/// - `cmd` with `/c` and (`http`, `ftp`, or `\\`)
/// - `mshta` anywhere in the command
/// - `regsvr32` with `/s /n` or `/u /s`
/// - `certutil` with `-decode` or `-urlcache`
/// - `bitsadmin` with `/transfer`
/// - `wscript` or `cscript` launched from `\temp\` or `\appdata\`
/// - `rundll32` with a path containing `\temp\` or `\appdata\`
/// - path contains `\temp\` or `\appdata\local\temp\`
/// - `msiexec` with `/q` and `http`
pub fn classify_run_entry(command: &str) -> Option<String> {
    if command.is_empty() {
        return None;
    }

    let lower = command.to_ascii_lowercase();

    // PowerShell encoded command
    if lower.contains("powershell") && (lower.contains("-enc") || lower.contains("-encodedcommand"))
    {
        return Some("powershell encoded command (-enc / -encodedcommand)".to_string());
    }

    // cmd /c with network or UNC path
    if lower.contains("cmd")
        && lower.contains("/c")
        && (lower.contains("http") || lower.contains("ftp") || lower.contains("\\\\"))
    {
        return Some("cmd /c with remote resource (http/ftp/UNC)".to_string());
    }

    // mshta
    if lower.contains("mshta") {
        return Some("mshta execution (HTML Application host abuse)".to_string());
    }

    // regsvr32 squiblydoo / bypass
    if lower.contains("regsvr32") && (lower.contains("/s") && lower.contains("/n"))
        || (lower.contains("regsvr32") && lower.contains("/u") && lower.contains("/s"))
    {
        return Some("regsvr32 /s /n or /u /s (AppLocker bypass / squiblydoo)".to_string());
    }

    // certutil download cradle or decode
    if lower.contains("certutil") && (lower.contains("-decode") || lower.contains("-urlcache")) {
        return Some("certutil -decode or -urlcache (download cradle / obfuscation)".to_string());
    }

    // bitsadmin
    if lower.contains("bitsadmin") && lower.contains("/transfer") {
        return Some("bitsadmin /transfer (BITS download abuse)".to_string());
    }

    // wscript/cscript from temp or appdata
    if (lower.contains("wscript") || lower.contains("cscript"))
        && (lower.contains("\\temp\\") || lower.contains("\\appdata\\"))
    {
        return Some("wscript/cscript launched from \\temp\\ or \\appdata\\ path".to_string());
    }

    // rundll32 from temp or appdata
    if lower.contains("rundll32") && (lower.contains("\\temp\\") || lower.contains("\\appdata\\")) {
        return Some("rundll32 with DLL in \\temp\\ or \\appdata\\ path".to_string());
    }

    // path itself is in temp or appdata\local\temp
    if lower.contains("\\appdata\\local\\temp\\") || lower.starts_with("\\temp\\") {
        return Some("executable path is in \\temp\\ or \\appdata\\local\\temp\\".to_string());
    }

    // msiexec silent with HTTP URL
    if lower.contains("msiexec") && lower.contains("/q") && lower.contains("http") {
        return Some("msiexec /q with HTTP URL (silent remote install)".to_string());
    }

    None
}

// ── Public parse function ─────────────────────────────────────────────────────

/// Extract all Run-key entries from a hive.
///
/// Auto-detects whether the hive is a SOFTWARE (HKLM) or NTUSER.DAT (HKCU)
/// hive and selects the appropriate key paths accordingly.  Winlogon
/// `Userinit` and `Shell` values are also collected.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RunKeyEntry> {
    let hive_type = hive.detect_hive_type();

    let (hive_label, run_paths, winlogon_path) = match hive_type {
        HiveType::Software => ("HKLM", SOFTWARE_RUN_PATHS, WINLOGON_PATH_SOFTWARE),
        HiveType::NtUser => ("HKCU", NTUSER_RUN_PATHS, WINLOGON_PATH_NTUSER),
        // For unknown hive types, try SOFTWARE paths as a best-effort.
        _ => ("UNKNOWN", SOFTWARE_RUN_PATHS, WINLOGON_PATH_SOFTWARE),
    };

    let mut entries: Vec<RunKeyEntry> = Vec::new();

    // Enumerate standard Run/RunOnce/… key paths.
    for &key_path in run_paths {
        let Ok(Some(key)) = hive.open_key(key_path) else {
            continue;
        };

        let Ok(values) = key.values() else {
            continue;
        };

        let last_written = key.last_written();

        for val in values {
            let command = val.as_string().unwrap_or_default();
            let suspicious_reason = classify_run_entry(&command);
            let is_suspicious = suspicious_reason.is_some();
            entries.push(RunKeyEntry {
                hive: hive_label.to_string(),
                key_path: key_path.to_string(),
                value_name: val.name(),
                command,
                is_suspicious,
                suspicious_reason,
                last_written,
            });
        }
    }

    // Enumerate Winlogon persistence values.
    if let Ok(Some(winlogon)) = hive.open_key(winlogon_path) {
        let last_written = winlogon.last_written();
        for &vname in WINLOGON_VALUES {
            let Ok(Some(val)) = winlogon.value(vname) else {
                continue;
            };
            let command = val.as_string().unwrap_or_default();
            let suspicious_reason = classify_run_entry(&command);
            let is_suspicious = suspicious_reason.is_some();
            entries.push(RunKeyEntry {
                hive: hive_label.to_string(),
                key_path: winlogon_path.to_string(),
                value_name: vname.to_string(),
                command,
                is_suspicious,
                suspicious_reason,
                last_written,
            });
        }
    }

    entries
}
