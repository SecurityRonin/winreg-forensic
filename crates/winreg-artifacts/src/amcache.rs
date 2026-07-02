//! Amcache registry artifact extractor.
//!
//! Amcache.hve records application execution evidence. Two on-disk schemas
//! exist and a hive carries exactly one of them depending on OS version:
//!
//! - **Modern (Win10 1607+):** `Root\InventoryApplicationFile` — one subkey per
//!   file, rich values (`LowerCaseLongPath`, `FileId`, `Size`, `Publisher`, …).
//! - **Legacy (Win8 / Server 2012 R2):** `Root\File\{VolumeGUID}\{seq}` — one
//!   subkey per file under a per-volume GUID, sparse numeric values
//!   (`15` = full path, `101` = SHA-1 with the same `0000` prefix).
//!
//! [`parse`] decodes both, so it surfaces execution evidence regardless of the
//! host's Windows version.

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

/// Path to the legacy `File` container key (per-volume subkeys beneath it).
const ROOT_FILE: &str = "Root\\File";

// ---------------------------------------------------------------------------
// Public parse function
// ---------------------------------------------------------------------------

/// Extract all execution entries from an Amcache hive, across BOTH the modern
/// (`Root\InventoryApplicationFile`) and legacy (`Root\File\{VolumeGUID}`)
/// schemas. A real hive carries one or the other; decoding both means the
/// caller surfaces execution evidence regardless of the host's Windows version.
///
/// Missing values produce empty strings or zero rather than errors. Returns an
/// empty `Vec` when neither container key is present.
#[must_use]
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<AmcacheEntry> {
    let mut entries = parse_inventory_app_file(hive);
    entries.extend(parse_root_file(hive));
    entries
}

/// Decode the modern `Root\InventoryApplicationFile` schema (Win10 1607+).
fn parse_inventory_app_file(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<AmcacheEntry> {
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
            .and_then(|dt| jiff::fmt::strtime::format("%Y-%m-%dT%H:%M:%SZ", dt).ok());

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

/// Decode the legacy `Root\File\{VolumeGUID}\{seq}` schema (Win8 / Server
/// 2012 R2). Each per-volume GUID subkey holds one subkey per file; the
/// forensically relevant values are numeric: `15` = full path, `101` = SHA-1
/// (carrying the same `0000` prefix the modern `FileId` does). The richer
/// modern fields (size, publisher, …) do not exist here and stay empty/zero.
fn parse_root_file(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<AmcacheEntry> {
    let Ok(Some(container)) = hive.open_key(ROOT_FILE) else {
        return Vec::new();
    };
    let Ok(volumes) = container.subkeys() else {
        return Vec::new();
    };

    let mut entries = Vec::new();
    for volume in volumes {
        let Ok(files) = volume.subkeys() else {
            continue; // cov:unreachable: a volume key returned by subkeys() is enumerable
        };
        for file in files {
            let read_sz = |name: &str| -> String {
                file.value(name)
                    .ok()
                    .flatten()
                    .and_then(|v| v.as_string().ok())
                    .unwrap_or_default()
            };

            let file_path = read_sz("15");
            let sha1_raw = read_sz("101");
            let sha1 = sha1_raw
                .strip_prefix("0000")
                .map_or_else(|| sha1_raw.clone(), ToString::to_string);
            let last_written = filetime_to_datetime(file.last_written_raw())
                .and_then(|dt| jiff::fmt::strtime::format("%Y-%m-%dT%H:%M:%SZ", dt).ok());

            entries.push(AmcacheEntry {
                file_path,
                sha1,
                size: 0,
                link_date: None,
                publisher: String::new(),
                product_name: String::new(),
                product_version: String::new(),
                bin_file_version: String::new(),
                key_name: file.name(),
                last_written,
            });
        }
    }

    entries
}
