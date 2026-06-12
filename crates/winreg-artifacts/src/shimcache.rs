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

/// Key path suffix below the ControlSet (`CurrentControlSet` on live hives,
/// `ControlSet00N` on offline ones).
const APPCOMPAT_SUFFIX: &str = "Control\\Session Manager\\AppCompatCache";
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
/// Resolves the active ControlSet, then reads
/// `<ControlSet>\Control\Session Manager\AppCompatCache`. Live hives expose a
/// `CurrentControlSet` symlink; **offline** hives do not — they carry
/// `ControlSet00N` selected by `Select\Current`, so we resolve that.
///
/// Returns an empty `Vec` if the key or value is absent.
/// Returns a single sentinel entry (empty path) if the blob exists but the
/// format is unrecognised.
pub fn parse(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<ShimcacheEntry> {
    // `Select\Current` (REG_DWORD) names the active set on an offline hive;
    // default to set 1 when the Select key is absent.
    let current = hive
        .open_key("Select")
        .ok()
        .flatten()
        .and_then(|sel| sel.value("Current").ok().flatten())
        .and_then(|v| v.raw_data().ok())
        .filter(|d| d.len() >= 4)
        .map_or(1u32, |d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]));

    // Try the live symlink, the Select-resolved set, then ControlSet001.
    let candidates = [
        format!("CurrentControlSet\\{APPCOMPAT_SUFFIX}"),
        format!("ControlSet{current:03}\\{APPCOMPAT_SUFFIX}"),
        format!("ControlSet001\\{APPCOMPAT_SUFFIX}"),
    ];
    let key = match candidates
        .iter()
        .find_map(|p| hive.open_key(p).ok().flatten())
    {
        Some(k) => k,
        None => return Vec::new(),
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

    // Win10 (1507 = 0x30, 1607+ = 0x34): the blob opens with a small header whose
    // first u32 is the header size; the `"10ts"` entries follow it.
    if sig == 0x30 || sig == 0x34 {
        return parse_win10_entries(&blob, sig as usize, raw_size);
    }
    // Header-less `"10ts"` stream (some synthetic/edge captures put entries at 0).
    if sig == WIN10_ENTRY_SIG {
        return parse_win10_entries(&blob, 0, raw_size);
    }
    // Win8 0x80 header (legacy fixed 128-byte-header parser).
    if blob[0] == WIN8_HEADER_SIG {
        return parse_win10(&blob, raw_size);
    }
    // Unrecognised format — return single sentinel entry.
    vec![ShimcacheEntry {
        path: String::new(),
        last_modified: None,
        raw_size,
        entry_index: 0,
    }]
}

/// Parse a stream of Win10 `"10ts"` AppCompatCache entries beginning at `start`.
///
/// Each entry: `"10ts" | unknown(4) | ce_data_size(4) | body[ce_data_size]`,
/// where the body is `path_size(2) | path(UTF-16LE) | FILETIME(8) | data_size(4)
/// | data`.
fn parse_win10_entries(blob: &[u8], start: usize, raw_size: usize) -> Vec<ShimcacheEntry> {
    let mut entries = Vec::new();
    let mut offset = start;
    let mut entry_index = 0;

    while offset + 12 <= blob.len() {
        if &blob[offset..offset + 4] != b"10ts" {
            break;
        }
        // offset+4: unknown (4 bytes), then the cache-entry data size.
        let ce_data_size =
            u32::from_le_bytes([blob[offset + 8], blob[offset + 9], blob[offset + 10], blob[offset + 11]])
                as usize;
        let body_start = offset + 12;
        let body_end = match body_start.checked_add(ce_data_size) {
            Some(e) if e <= blob.len() => e,
            _ => break,
        };

        let (path, last_modified) = decode_win10_entry_body(&blob[body_start..body_end]);
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

/// Decode a Win10 entry body: `path_size(2) | path(UTF-16LE) | FILETIME(8) | …`.
fn decode_win10_entry_body(body: &[u8]) -> (String, Option<String>) {
    if body.len() < 2 {
        return (String::new(), None);
    }
    let path_size = u16::from_le_bytes([body[0], body[1]]) as usize;
    let path_end = 2 + path_size;
    let path = if path_size > 0 && path_end <= body.len() {
        decode_utf16le(&body[2..path_end])
    } else {
        String::new()
    };
    let last_modified = if path_end + 8 <= body.len() {
        let ft = winreg_core::bytes::le_u64(body, path_end);
        filetime_to_datetime(ft).map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    } else {
        None
    };
    (path, last_modified)
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
