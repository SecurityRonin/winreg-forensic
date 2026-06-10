//! ShimCache (AppCompatCache) registry artifact extractor.
//!
//! ShimCache is stored in the SYSTEM hive and records application execution
//! metadata for compatibility checking. It is evidence of program execution.
//!
//! Key path: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`
//! Value name: `AppCompatCache` (REG_BINARY)

use std::io::Cursor;

use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// A single entry decoded from the AppCompatCache (ShimCache) binary blob.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ShimcacheEntry {
    /// Executable path extracted from the cache entry. Empty if unparseable.
    pub path: String,
    /// Last modified time as ISO 8601, or `None` if unavailable.
    pub last_modified: Option<String>,
    /// Size of the raw `AppCompatCache` REG_BINARY blob.
    pub raw_size: usize,
    /// Position in the cache (0 = most recently executed).
    pub entry_index: usize,
}

// ---------------------------------------------------------------------------
// Key / value paths
// ---------------------------------------------------------------------------

const APPCOMPAT_KEY: &str = "CurrentControlSet\\Control\\Session Manager\\AppCompatCache";
const APPCOMPAT_VALUE: &str = "AppCompatCache";

// ---------------------------------------------------------------------------
// Format signatures
// ---------------------------------------------------------------------------

/// Windows 10 entry signature: "10ts" as u32 LE = 0x73743031.
const WIN10_ENTRY_SIG: u32 = 0x7374_3031;

/// Windows 8 / Server 2012 header signature: 0x80 at byte 0.
const WIN8_HEADER_SIG: u8 = 0x80;

// ---------------------------------------------------------------------------
// Public parse function
// ---------------------------------------------------------------------------

/// Extract ShimCache entries from a SYSTEM hive.
///
/// Navigates to `CurrentControlSet\Control\Session Manager\AppCompatCache`,
/// reads the `AppCompatCache` REG_BINARY value, and attempts to parse entries.
///
/// Returns an empty `Vec` if the key or value is absent.
/// Returns a single sentinel entry (empty path) if the blob exists but the
/// format is unrecognised.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ShimcacheEntry> {
    // Navigate to the correct key.
    let key = match hive.open_key(APPCOMPAT_KEY) {
        Ok(Some(k)) => k,
        _ => return Vec::new(),
    };

    // Read the REG_BINARY value.
    let blob: Vec<u8> = match key.value(APPCOMPAT_VALUE) {
        Ok(Some(v)) => match v.raw_data() {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        },
        _ => return Vec::new(),
    };

    let raw_size = blob.len();

    // Blobs shorter than 4 bytes cannot contain a valid signature.
    if raw_size < 4 {
        return Vec::new();
    }

    let sig = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);

    if sig == WIN10_ENTRY_SIG || blob[0] == WIN8_HEADER_SIG {
        // Win10 "10ts" format or Win8 0x80 format.
        parse_win10(&blob, raw_size)
    } else {
        // Unrecognised format — return single sentinel entry.
        vec![ShimcacheEntry {
            path: String::new(),
            last_modified: None,
            raw_size,
            entry_index: 0,
        }]
    }
}

// ---------------------------------------------------------------------------
// Win10 parser
// ---------------------------------------------------------------------------

/// Parse the Windows 10 AppCompatCache format.
///
/// Header (128 bytes):
///   Bytes 0-3:   signature `0x73743031` ("10ts" LE)
///   Bytes 4-7:   number of entries (u32 LE)
///   Bytes 8-127: padding
///
/// Each entry starts with:
///   Bytes 0-3:   entry signature `0x73743031`
///   Bytes 4-7:   entry data length (u32 LE) — length of the body *after* these 8 bytes
///   Then entry body (variable):
///     Bytes 0-1:  path length in bytes (u16 LE)
///     Bytes 2-7:  padding / reserved
///     Bytes 8-15: LastModifiedTime (FILETIME, u64 LE)
///     Bytes 16-17: path data offset within the entry body (u16 LE, often 0x20)
///     ... path data (UTF-16LE) at body offset indicated by path_offset_in_body
///
/// In practice the layout is approximately:
///   entry_data_len (from header) bytes of body, containing:
///     [0..2]   path_len  (u16 LE) — byte count of UTF-16LE path
///     [8..16]  last_modified (u64 LE FILETIME)
///     [16..18] path_offset   (u16 LE) — offset within body to the path data
///     [path_offset .. path_offset + path_len] path bytes (UTF-16LE)
fn parse_win10(blob: &[u8], raw_size: usize) -> Vec<ShimcacheEntry> {
    // The cache header is 128 bytes for Win10.
    const HEADER_SIZE: usize = 128;

    if blob.len() < HEADER_SIZE {
        return Vec::new();
    }

    let entry_count = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    if entry_count == 0 {
        return Vec::new();
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut offset = HEADER_SIZE;
    let mut entry_index = 0;

    while offset + 8 <= blob.len() && entry_index < entry_count {
        // Each entry starts with a 4-byte signature.
        let entry_sig = u32::from_le_bytes([
            blob[offset],
            blob[offset + 1],
            blob[offset + 2],
            blob[offset + 3],
        ]);

        if entry_sig != WIN10_ENTRY_SIG {
            break;
        }

        let entry_data_len = u32::from_le_bytes([
            blob[offset + 4],
            blob[offset + 5],
            blob[offset + 6],
            blob[offset + 7],
        ]) as usize;

        let body_start = offset + 8;
        let body_end = body_start + entry_data_len;

        if body_end > blob.len() {
            break;
        }

        let body = &blob[body_start..body_end];

        let (path, last_modified) = decode_entry_body(body);

        entries.push(ShimcacheEntry {
            path,
            last_modified,
            raw_size,
            entry_index,
        });

        offset = body_end;
        entry_index += 1;
    }

    entries
}

/// Decode a single Win10 entry body.
///
/// Layout (best-effort; fields may be absent for short bodies):
///   [0..2]   path_len  (u16 LE) — byte count of the UTF-16LE path
///   [8..16]  last_modified (u64 LE FILETIME)
///   [16..18] path_data_offset (u16 LE) — offset within body to path bytes
fn decode_entry_body(body: &[u8]) -> (String, Option<String>) {
    if body.len() < 2 {
        return (String::new(), None);
    }

    let path_len = u16::from_le_bytes([body[0], body[1]]) as usize;

    let last_modified: Option<String> = if body.len() >= 16 {
        let ft = winreg_core::bytes::le_u64(&body[..], 8);
        filetime_to_datetime(ft).map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    } else {
        None
    };

    let path: String = if path_len == 0 || body.len() < 18 {
        String::new()
    } else {
        let path_offset = u16::from_le_bytes([body[16], body[17]]) as usize;
        let path_end = path_offset + path_len;
        if path_offset < body.len() && path_end <= body.len() {
            decode_utf16le(&body[path_offset..path_end])
        } else {
            String::new()
        }
    };

    (path, last_modified)
}

/// Decode UTF-16LE bytes to a `String`, stopping at the first null.
fn decode_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let trimmed: &[u16] = match u16s.iter().position(|&c| c == 0) {
        Some(pos) => &u16s[..pos],
        None => &u16s,
    };
    String::from_utf16_lossy(trimmed).to_owned()
}
