//! UserAssist registry artifact extractor.
//!
//! Windows stores program launch counts and last-run timestamps in
//! `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`
//! in NTUSER.DAT hives. Value names are ROT13-encoded paths; value data is a
//! 72-byte binary struct with run count, focus info, and a FILETIME.

use std::io::Cursor;

use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;

// ── Well-known UserAssist GUIDs ───────────────────────────────────────────────

/// Win7+ executable stats GUID.
const GUID_EXE: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";

/// Win7+ shortcut (.lnk) stats GUID.
const GUID_LNK: &str = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

/// All GUIDs to enumerate.
const KNOWN_GUIDS: &[&str] = &[GUID_EXE, GUID_LNK];

// ── Binary value layout ───────────────────────────────────────────────────────

/// Minimum data size for a valid UserAssist binary value.
const UA_DATA_SIZE: usize = 68; // bytes 60-67 (FILETIME) must be accessible

// ── Output type ───────────────────────────────────────────────────────────────

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

// ── ROT13 decode ──────────────────────────────────────────────────────────────

/// ROT13-decode a string: rotate A-Z and a-z by 13, leave other chars unchanged.
pub fn rot13_decode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' => (b'A' + (c as u8 - b'A' + 13) % 26) as char,
            'a'..='z' => (b'a' + (c as u8 - b'a' + 13) % 26) as char,
            other => other,
        })
        .collect()
}

// ── Public parse function ─────────────────────────────────────────────────────

/// Extract all UserAssist entries from an NTUSER.DAT hive.
///
/// Enumerates both the executable and shortcut GUID subkeys under
/// `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`,
/// ROT13-decodes each value name, and parses the binary payload.
///
/// Returns an empty Vec if no UserAssist keys are present.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<UserAssistEntry> {
    let mut entries = Vec::new();

    for &guid in KNOWN_GUIDS {
        let count_path = format!(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid}\\Count"
        );

        let count_key = match hive.open_key(&count_path) {
            Ok(Some(k)) => k,
            _ => continue,
        };

        let values = match count_key.values() {
            Ok(v) => v,
            Err(_) => continue,
        };

        for val in values {
            let raw = match val.raw_data() {
                Ok(d) => d,
                Err(_) => continue,
            };

            if raw.len() < UA_DATA_SIZE {
                continue;
            }

            let run_count = winreg_core::bytes::le_u32(&raw[..], 4);
            let focus_count = winreg_core::bytes::le_u32(&raw[..], 8);
            let focus_duration_ms = winreg_core::bytes::le_u32(&raw[..], 12);
            let filetime = winreg_core::bytes::le_u64(&raw[..], 60);

            let last_run = filetime_to_datetime(filetime)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

            let program = rot13_decode(&val.name());

            entries.push(UserAssistEntry {
                program,
                run_count,
                focus_count,
                focus_duration_ms,
                last_run,
                guid: guid.to_string(),
            });
        }
    }

    entries
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_roundtrip_hello() {
        let s = "Hello, World!";
        assert_eq!(rot13_decode(&rot13_decode(s)), s);
    }

    #[test]
    fn rot13_numbers_unchanged() {
        assert_eq!(rot13_decode("12345"), "12345");
    }

    #[test]
    fn rot13_special_chars_unchanged() {
        assert_eq!(rot13_decode("\\:{}[]()"), "\\:{}[]()");
    }

    #[test]
    fn rot13_uppercase() {
        assert_eq!(rot13_decode("HELLO"), "URYYB");
    }

    #[test]
    fn rot13_lowercase() {
        assert_eq!(rot13_decode("hello"), "uryyb");
    }
}
