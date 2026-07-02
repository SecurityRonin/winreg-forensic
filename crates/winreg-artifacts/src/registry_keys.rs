//! Generic registry key/value walker — foundation module for forensic artifact extraction.
//!
//! Produces `RegistryKeyInfo` and `RegistryValueInfo` structs for every key and value
//! in a hive, suitable for downstream artifact decoders.

use std::io::Cursor;

use winreg_core::hive::Hive;

/// Metadata for a single registry key.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegistryKeyInfo {
    /// Full path from root, e.g. `"SOFTWARE\\Microsoft\\Windows"`.
    pub path: String,
    /// Just the key name (last component).
    pub name: String,
    /// ISO 8601 timestamp, or `None` if not set / zero FILETIME.
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
pub fn walk_keys(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RegistryKeyInfo> {
    let Ok(iter) = hive.iter_bfs() else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for item in iter {
        let Ok(key) = item else {
            continue;
        };

        let path = if key.is_root() {
            // Root key: path is empty string (no path from root to root)
            String::new()
        } else {
            key.path().unwrap_or_default()
        };

        let last_written = key
            .last_written()
            .and_then(|dt| jiff::fmt::strtime::format("%Y-%m-%dT%H:%M:%S", dt).ok());

        result.push(RegistryKeyInfo {
            name: key.name(),
            path,
            last_written,
            subkey_count: key.subkey_count() as usize,
            value_count: key.value_count() as usize,
        });
    }
    result
}

/// Walk all values under a specific key path.
///
/// Returns an empty `Vec` if the path is not found or the key has no values.
pub fn walk_values(hive: &Hive<Cursor<Vec<u8>>>, key_path: &str) -> Vec<RegistryValueInfo> {
    let Ok(Some(key)) = hive.open_key(key_path) else {
        return Vec::new();
    };

    let Ok(values) = key.values() else {
        return Vec::new();
    };

    values
        .into_iter()
        .map(|v| value_to_info(&v, key_path))
        .collect()
}

/// Walk all keys AND their values recursively (BFS), returning a `RegistryValueInfo`
/// for every value in the hive.
pub fn walk_all_values(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RegistryValueInfo> {
    let Ok(iter) = hive.iter_bfs() else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for item in iter {
        let Ok(key) = item else {
            continue;
        };

        let key_path = if key.is_root() {
            String::new()
        } else {
            key.path().unwrap_or_default()
        };

        let Ok(values) = key.values() else {
            continue;
        };

        for v in values {
            result.push(value_to_info(&v, &key_path));
        }
    }
    result
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Convert a `winreg_core::value::Value` into a `RegistryValueInfo`.
fn value_to_info(v: &winreg_core::value::Value<'_>, key_path: &str) -> RegistryValueInfo {
    let data_type = v.data_type().to_string();
    let raw_size = v.data_size() as usize;
    let data_preview = build_preview(v);

    RegistryValueInfo {
        key_path: key_path.to_string(),
        name: v.name(),
        data_type,
        data_preview,
        raw_size,
    }
}

/// Build a human-readable preview of the value data, truncated at 256 chars.
fn build_preview(v: &winreg_core::value::Value<'_>) -> String {
    use winreg_format::flags::ValueType;

    match v.data_type() {
        ValueType::Sz | ValueType::ExpandSz | ValueType::Link => {
            let s = v.as_string().unwrap_or_default();
            truncate_string(s, 256)
        }
        ValueType::Dword => {
            let n = v.as_u32().unwrap_or(0);
            format!("0x{n:08X} ({n})")
        }
        ValueType::DwordBigEndian => {
            let n = v.as_u32_be().unwrap_or(0);
            format!("0x{n:08X} ({n})")
        }
        ValueType::Qword => {
            let n = v.as_u64().unwrap_or(0);
            format!("0x{n:016X} ({n})")
        }
        ValueType::MultiSz => {
            let parts = v.as_multi_string().unwrap_or_default();
            let joined = parts.join(" | ");
            truncate_string(joined, 256)
        }
        _ => {
            // Binary / Unknown: hex preview up to 32 bytes
            let data = v.raw_data().unwrap_or_default();
            let preview_len = data.len().min(32);
            let hex: Vec<String> = data[..preview_len]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect();
            let s = hex.join(" ");
            if data.len() > 32 {
                format!("{s}...")
            } else {
                s
            }
        }
    }
}

/// Truncate a `String` to at most `max_chars` characters.
fn truncate_string(mut s: String, max_chars: usize) -> String {
    if s.chars().count() > max_chars {
        s = s.chars().take(max_chars).collect();
    }
    s
}
