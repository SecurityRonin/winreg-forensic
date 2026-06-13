//! ShellBags registry artifact extractor.
//!
//! ShellBags record folder navigation history in Windows. `BagMRU` keys hold
//! slot values (numeric names "0", "1", ...) containing binary `ShellItem` data,
//! and a `MRUListEx` value encoding the access order.
//!
//! This implementation walks `BagMRU` keys recursively and emits one
//! `ShellbagEntry` per key. Full `ShellItem` binary parsing is out of scope;
//! slot data is represented as a human-readable size preview.

use std::io::Cursor;

use winreg_core::hive::Hive;
use winreg_core::key::{filetime_to_datetime, Key};

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// A single `BagMRU` entry from the ShellBags registry area.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShellbagEntry {
    /// Reconstructed / descriptive folder path.
    /// For this implementation, slot data is represented as
    /// `"BagMRU[slot=N, size=M bytes]"` for each numeric slot value present,
    /// or an empty string if no slot values exist.
    pub path: String,
    /// Registry path to this `BagMRU` key (relative to hive root).
    pub key_path: String,
    /// Key `LastWriteTime` as ISO 8601, or `None` if unavailable.
    pub last_written: Option<String>,
    /// Decoded MRU order from `MRUListEx` (slot index strings),
    /// terminator (0xFFFFFFFF) is excluded. Empty if value is absent.
    pub mru_order: Vec<String>,
}

// ---------------------------------------------------------------------------
// BagMRU candidate paths to probe (NTUSER.DAT and USRCLASS.DAT variants)
// ---------------------------------------------------------------------------

const BAGMRU_PATHS: &[&str] = &[
    "Software\\Microsoft\\Windows\\Shell\\BagMRU",
    "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU",
    "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
];

// ---------------------------------------------------------------------------
// Public parse function
// ---------------------------------------------------------------------------

/// Extract all `ShellBag` entries from a hive.
///
/// Probes several well-known `BagMRU` key paths. For each that exists, walks
/// the key tree recursively and emits one [`ShellbagEntry`] per key.
///
/// Returns an empty `Vec` if no `BagMRU` key is present.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ShellbagEntry> {
    let mut entries = Vec::new();

    for &path in BAGMRU_PATHS {
        if let Ok(Some(root)) = hive.open_key(path) {
            walk_key(&root, path, &mut entries);
        }
    }

    entries
}

// ---------------------------------------------------------------------------
// Recursive key walker
// ---------------------------------------------------------------------------

fn walk_key(key: &Key<'_>, key_path: &str, entries: &mut Vec<ShellbagEntry>) {
    let last_written = filetime_to_datetime(key.last_written_raw())
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

    // Decode MRUListEx value
    let mru_order = decode_mrulistex(key);

    // Build a path description from numeric slot values.
    let path = build_slot_path(key);

    entries.push(ShellbagEntry {
        path,
        key_path: key_path.to_string(),
        last_written,
        mru_order,
    });

    // Recurse into subkeys
    if let Ok(subkeys) = key.subkeys() {
        for subkey in subkeys {
            let child_path = format!("{}\\{}", key_path, subkey.name());
            walk_key(&subkey, &child_path, entries);
        }
    }
}

// ---------------------------------------------------------------------------
// MRUListEx decoder
// ---------------------------------------------------------------------------

/// Decode `MRUListEx`: a `REG_BINARY` value holding an array of `u32` LE
/// slot indices, terminated by `0xFFFF_FFFF`.
fn decode_mrulistex(key: &Key<'_>) -> Vec<String> {
    let Ok(Some(val)) = key.value("MRUListEx") else {
        return Vec::new();
    };
    let Ok(raw) = val.raw_data() else {
        return Vec::new();
    };

    let mut order = Vec::new();
    let mut i = 0;
    while i + 4 <= raw.len() {
        let slot = u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        if slot == 0xFFFF_FFFF {
            break;
        }
        order.push(slot.to_string());
        i += 4;
    }
    order
}

// ---------------------------------------------------------------------------
// Slot path builder
// ---------------------------------------------------------------------------

/// Build a descriptive path string from numeric slot values in this key.
///
/// Numeric value names ("0", "1", ...) each hold a binary `ShellItem` blob. Each
/// slot is decoded with the [`shellitem`] primitive to its real folder name
/// (volume, folder, file entry). When a slot does not decode to a named item
/// (truncated or unrecognised class), it degrades to the `BagMRU[slot=N,
/// size=M bytes]` preview so the slot is never silently dropped.
fn build_slot_path(key: &Key<'_>) -> String {
    let Ok(values) = key.values() else {
        return String::new();
    };

    let mut parts: Vec<String> = Vec::new();
    for val in values {
        let name = val.name();
        // Numeric names are slot entries (skip "MRUListEx" and others).
        if name.chars().all(|c| c.is_ascii_digit()) {
            parts.push(decode_slot(&name, &val));
        }
    }

    parts.join("; ")
}

/// Decode one numeric slot value: its real shell-namespace folder name when the
/// `ShellItem` blob decodes, otherwise a size preview (never silently dropped).
fn decode_slot(slot: &str, val: &winreg_core::value::Value<'_>) -> String {
    if let Ok(raw) = val.raw_data() {
        let items = shellitem::parse_idlist(&raw);
        let path = shellitem::reconstruct_path(&items);
        if !path.is_empty() {
            return path;
        }
    }
    let size = val.data_size() as usize;
    format!("BagMRU[slot={slot}, size={size} bytes]")
}
