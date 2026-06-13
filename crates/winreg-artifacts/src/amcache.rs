//! Amcache registry artifact extractor.
//!
//! Amcache.hve records application execution evidence. This module decodes
//! entries from `Root\InventoryApplicationFile`, each subkey representing a
//! file that was executed or installed on the system.

use std::io::Cursor;

use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// A single file entry from `Root\InventoryApplicationFile`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AmcacheEntry {
    /// Full lowercase file path (`LowerCaseLongPath`).
    pub file_path: String,
    /// SHA-1 hash: the `FileId` value with the leading `0000` prefix stripped.
    /// Empty string if the value is absent.
    pub sha1: String,
    /// File size in bytes (`Size` as `REG_DWORD`).
    pub size: u64,
    /// PE link timestamp string, e.g. `"01/15/2023 10:30:00"` (`LinkDate`).
    pub link_date: Option<String>,
    /// Publisher name (`Publisher`).
    pub publisher: String,
    /// Product name (`ProductName`).
    pub product_name: String,
    /// Product version string (`ProductVersion`).
    pub product_version: String,
    /// Binary file version string (`BinFileVersion`).
    pub bin_file_version: String,
    /// The subkey name (hash identifier for this entry).
    pub key_name: String,
    /// Key `LastWriteTime` as ISO 8601, or `None` if unavailable.
    pub last_written: Option<String>,
}

// ---------------------------------------------------------------------------
// Key paths
// ---------------------------------------------------------------------------

/// Path to the `InventoryApplicationFile` container key (relative to hive root).
const INVENTORY_APP_FILE: &str = "Root\\InventoryApplicationFile";

// ---------------------------------------------------------------------------
// Public parse function
// ---------------------------------------------------------------------------

/// Extract all `InventoryApplicationFile` entries from an Amcache hive.
///
/// Navigates `Root\InventoryApplicationFile`, iterates each subkey, and
/// extracts the forensically relevant values. Missing values produce empty
/// strings or zero rather than errors.
///
/// Returns an empty `Vec` if the key is not present.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<AmcacheEntry> {
    let Ok(Some(container)) = hive.open_key(INVENTORY_APP_FILE) else {
        return Vec::new();
    };

    let Ok(subkeys) = container.subkeys() else {
        return Vec::new();
    };

    let mut entries = Vec::with_capacity(subkeys.len());

    for subkey in subkeys {
        let key_name = subkey.name();

        let last_written = filetime_to_datetime(subkey.last_written_raw())
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());

        // Helper: read a REG_SZ value, returning empty string on any error.
        let read_sz = |name: &str| -> String {
            subkey
                .value(name)
                .ok()
                .flatten()
                .and_then(|v| v.as_string().ok())
                .unwrap_or_default()
        };

        let file_path = read_sz("LowerCaseLongPath");

        // FileId: strip the leading "0000" prefix if present.
        let file_id_raw = read_sz("FileId");
        let sha1 = file_id_raw
            .strip_prefix("0000")
            .map_or_else(|| file_id_raw.clone(), ToString::to_string);

        let size = u64::from(
            subkey
                .value("Size")
                .ok()
                .flatten()
                .and_then(|v| v.as_u32().ok())
                .unwrap_or(0),
        );

        let link_date_raw = read_sz("LinkDate");
        let link_date = if link_date_raw.is_empty() {
            None
        } else {
            Some(link_date_raw)
        };

        let publisher = read_sz("Publisher");
        let product_name = read_sz("ProductName");
        let product_version = read_sz("ProductVersion");
        let bin_file_version = read_sz("BinFileVersion");

        entries.push(AmcacheEntry {
            file_path,
            sha1,
            size,
            link_date,
            publisher,
            product_name,
            product_version,
            bin_file_version,
            key_name,
            last_written,
        });
    }

    entries
}
