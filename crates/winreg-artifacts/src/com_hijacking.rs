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
    /// The CLSID GUID key's `LastWriteTime` — approximately when this COM
    /// registration was written. `None` when the key carries no timestamp.
    pub last_written: Option<jiff::Timestamp>,
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify a HKCU COM server path.
///
/// Returns `(is_suspicious, reason)`.
/// Suspicious when the path is in a user-writable directory (`\temp\`,
/// `\appdata\`, `\downloads\`, `\public\`, `\programdata\`), or when it
/// overrides a non-empty HKCR registration with a different path.
// `hkcr_server`/`hkcu_server` differ only by the hive root (HKCR vs HKCU);
// that distinction is the whole point of the comparison, so keep both names.
#[allow(clippy::similar_names)]
pub fn classify_com_hijack(hkcr_server: &str, hkcu_server: &str) -> (bool, Option<String>) {
    if hkcu_server.is_empty() {
        return (false, None);
    }
    let lower = hkcu_server.to_ascii_lowercase();

    if lower.contains("\\temp\\") {
        return (true, Some("DLL in \\temp\\".to_string()));
    }
    if lower.contains("\\appdata\\") {
        return (true, Some("DLL in \\appdata\\".to_string()));
    }
    if lower.contains("\\downloads\\") {
        return (true, Some("DLL in \\downloads\\".to_string()));
    }
    if lower.contains("\\public\\") {
        return (true, Some("DLL in \\public\\".to_string()));
    }
    if lower.contains("\\programdata\\") {
        return (true, Some("DLL in \\programdata\\".to_string()));
    }
    if !hkcr_server.is_empty() && !hkcu_server.eq_ignore_ascii_case(hkcr_server) {
        return (true, Some(format!("HKCU overrides HKCR ({hkcr_server})")));
    }
    (false, None)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse COM hijacking candidates from a pair of hives.
///
/// `hku_hive`: NTUSER.DAT — contains `Software\Classes\CLSID` user overrides.
/// `hkcr_hive`: SOFTWARE or USRCLASS.DAT — contains the system-wide CLSID registrations.
// `hkcu_server`/`hkcr_server` differ only by the hive root, which is the point.
#[allow(clippy::similar_names)]
pub fn parse_pair(
    hku_hive: &Hive<Cursor<Vec<u8>>>,
    hkcr_hive: &Hive<Cursor<Vec<u8>>>,
) -> Vec<ComHijackInfo> {
    let mut results = Vec::new();

    let Some(clsid_key) = open_user_clsid_key(hku_hive) else {
        return results;
    };

    let Ok(guids) = clsid_key.subkeys() else {
        return results;
    };

    for guid_key in guids {
        let clsid = guid_key.name();

        // Find InprocServer32 under this GUID key in HKCU
        let Ok(Some(inproc)) = guid_key.subkey("InprocServer32") else {
            continue;
        };

        let hkcu_server = read_default_value(&inproc);
        if hkcu_server.is_empty() {
            continue;
        }

        // Look up the same CLSID in HKCR
        let hkcr_server = read_hkcr_server(hkcr_hive, &clsid);

        let (is_suspicious, suspicious_reason) = classify_com_hijack(&hkcr_server, &hkcu_server);

        results.push(ComHijackInfo {
            clsid,
            hkcu_server,
            hkcr_server,
            is_suspicious,
            suspicious_reason,
            last_written: guid_key.last_written(),
        });
    }

    results
}

/// Parse user-side COM registrations from a single NTUSER.DAT hive.
///
/// Returns entries without HKCR comparison (`hkcr_server` will be empty).
pub fn parse_hkcu_only(hku_hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ComHijackInfo> {
    let mut results = Vec::new();

    let Some(clsid_key) = open_user_clsid_key(hku_hive) else {
        return results;
    };

    let Ok(guids) = clsid_key.subkeys() else {
        return results;
    };

    for guid_key in guids {
        let clsid = guid_key.name();

        let Ok(Some(inproc)) = guid_key.subkey("InprocServer32") else {
            continue;
        };

        let hkcu_server = read_default_value(&inproc);
        if hkcu_server.is_empty() {
            continue;
        }

        let (is_suspicious, suspicious_reason) = classify_com_hijack("", &hkcu_server);

        results.push(ComHijackInfo {
            clsid,
            hkcu_server,
            hkcr_server: String::new(),
            is_suspicious,
            suspicious_reason,
            last_written: guid_key.last_written(),
        });
    }

    results
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Open the per-user CLSID enumeration key, trying each hive layout in turn:
/// NTUSER.DAT `Software\Classes\CLSID` (rare), SOFTWARE/HKCR `Classes\CLSID`,
/// and UsrClass.dat root `CLSID` — the real Win10 per-user COM home.
fn open_user_clsid_key(hive: &Hive<Cursor<Vec<u8>>>) -> Option<winreg_core::key::Key<'_>> {
    ["Software\\Classes\\CLSID", "Classes\\CLSID", "CLSID"]
        .iter()
        .find_map(|path| hive.open_key(path).ok().flatten())
}

/// Read the default (empty-name) value from a key as a string.
fn read_default_value(key: &winreg_core::key::Key<'_>) -> String {
    let Ok(vals) = key.values() else {
        return String::new();
    };
    for val in vals {
        if val.name().is_empty() {
            return val.as_string().unwrap_or_default();
        }
    }
    String::new()
}

/// Try to look up the CLSID `InprocServer32` default value in the HKCR hive.
///
/// Tries multiple path prefixes to handle both SOFTWARE hives and USRCLASS.DAT.
fn read_hkcr_server(hkcr_hive: &Hive<Cursor<Vec<u8>>>, clsid: &str) -> String {
    let paths = [
        format!("SOFTWARE\\Classes\\CLSID\\{clsid}\\InprocServer32"),
        format!("Classes\\CLSID\\{clsid}\\InprocServer32"),
        format!("CLSID\\{clsid}\\InprocServer32"),
    ];
    for path in &paths {
        if let Ok(Some(k)) = hkcr_hive.open_key(path) {
            let s = read_default_value(&k);
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}
