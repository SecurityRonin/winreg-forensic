//! Registry hive carving — recover deleted keys and values from unallocated
//! cells and cell slack.
//!
//! # What this recovers
//!
//! When a registry key or value is deleted, the live tree is unlinked but the
//! underlying *cell* is merely marked free (its 4-byte size field flips from
//! negative to positive). The `nk`/`vk` record bytes survive in the now
//! unallocated cell — and in the slack of cells that were reallocated to a
//! smaller record — until the space is overwritten. This crate walks every
//! hive bin, scans unallocated cells and slack for `nk`/`vk` signatures, and
//! recovers structurally valid records.
//!
//! # Epistemic stance
//!
//! A recovered record is **consistent with deletion-but-not-yet-overwritten**,
//! never a certainty. Each [`RecoveredCell`] carries provenance (file offset,
//! whether the enclosing cell was allocated, the scan source) and a graded
//! [`Confidence`]. The analyst — not this crate — concludes.
//!
//! # Robustness
//!
//! Hives are untrusted, attacker-controllable input. The scan is panic-free
//! (bounds-checked reads, no slice indexing on attacker lengths) and
//! breadth-capped ([`MAX_RECOVERIES`], [`MAX_SCAN_BYTES`]) so a crafted hive
//! cannot drive unbounded work.
//!
//! Transaction-log / dirty-page recovery (`.LOG1`/`.LOG2`) is a *separate*
//! concern handled by `winreg-recover`; this crate only carves the primary
//! hive image.

use std::io::Cursor;

use winreg_core::hive::Hive;
use winreg_format::cells::{CellHeader, CellSignature, RawKeyNode, RawKeyValue};
use winreg_format::flags::ValueType;

/// Hard cap on the number of recovered records, so a hive packed with
/// signature-like bytes cannot exhaust memory.
pub const MAX_RECOVERIES: usize = 100_000;

/// Hard cap on the total number of bytes scanned across all hbins.
pub const MAX_SCAN_BYTES: usize = 512 * 1024 * 1024;

/// Smallest plausible cell (size field + 8-byte alignment).
const MIN_CELL_SIZE: usize = 8;

/// Where a recovered record was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoverySource {
    /// The whole enclosing cell was free (positive size). Strongest signal.
    UnallocatedCell,
    /// An orphaned signature found inside an allocated cell's trailing slack or
    /// a cross-cell gap — a record whose cell was partially reused.
    Slack,
}

/// Graded confidence that a carved record is a genuine deleted artifact.
///
/// Never `Certain`: carving recovers *bytes consistent with* a deleted record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Structurally intact record in a cleanly-freed cell.
    High,
    /// Structurally valid but found in slack / partially-overwritten context.
    Medium,
    /// Signature + minimal structure only; surrounding context is ambiguous.
    Low,
}

/// A recovered deleted key (`nk` record).
#[derive(Debug, Clone)]
pub struct RecoveredKey {
    /// Decoded key name.
    pub name: String,
    /// FILETIME last-written timestamp from the record.
    pub last_written: u64,
    /// Parent cell offset claimed by the record (relative to hive bins data).
    pub parent_offset: u32,
    /// Absolute file offset of the enclosing cell's size field.
    pub file_offset: u32,
    /// Whether the enclosing cell was allocated when found.
    pub allocated: bool,
    /// Where the record was carved from.
    pub source: RecoverySource,
    /// Graded recovery confidence.
    pub confidence: Confidence,
}

/// A recovered deleted value (`vk` record).
#[derive(Debug, Clone)]
pub struct RecoveredValue {
    /// Decoded value name (empty for the default value).
    pub name: String,
    /// Raw `REG_*` data type number.
    pub data_type: u32,
    /// Recovered data bytes when resident (inline, ≤ 4 bytes); empty when the
    /// data lived in a separate (possibly reused) cell that carving cannot
    /// trust to still hold this value's data.
    pub data: Vec<u8>,
    /// Absolute file offset of the enclosing cell's size field.
    pub file_offset: u32,
    /// Whether the enclosing cell was allocated when found.
    pub allocated: bool,
    /// Where the record was carved from.
    pub source: RecoverySource,
    /// Graded recovery confidence.
    pub confidence: Confidence,
}

/// A single carved record.
#[derive(Debug, Clone)]
pub enum RecoveredCell {
    Key(RecoveredKey),
    Value(RecoveredValue),
}

/// Carve a hive for deleted keys and values.
///
/// Walks every hive bin, enumerates unallocated cells (positive size), and
/// scans allocated-cell slack, recovering structurally valid `nk`/`vk` records.
/// Results are capped at [`MAX_RECOVERIES`].
#[must_use]
pub fn recover_deleted(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<RecoveredCell> {
    let data = hive.raw_bytes();
    let mut out = Vec::new();
    let mut scanned: usize = 0;

    for bin in hive.bins() {
        if out.len() >= MAX_RECOVERIES || scanned >= MAX_SCAN_BYTES {
            break;
        }
        let bin_start = usize::try_from(bin.file_offset).unwrap_or(usize::MAX);
        // Cell data begins 32 bytes past the hbin header.
        let cells_start = bin_start.saturating_add(32);
        let bin_end = bin_start.saturating_add(usize::try_from(bin.size).unwrap_or(0));
        let bin_end = bin_end.min(data.len());
        if cells_start >= bin_end {
            continue; // cov:unreachable: cataloged hbins always have a cell region
        }
        scanned = scanned.saturating_add(bin_end - cells_start);
        scan_bin(data, cells_start, bin_end, &mut out);
    }

    out
}

/// Walk one hbin's cell chain, emitting recoveries into `out`.
fn scan_bin(data: &[u8], start: usize, end: usize, out: &mut Vec<RecoveredCell>) {
    let mut pos = start;
    while pos + 4 <= end && out.len() < MAX_RECOVERIES {
        let raw_size = read_i32(data, pos);
        let header = CellHeader { raw_size };
        let cell_size = header.size() as usize;

        // A zero or sub-minimal size would not advance the walk — bail to avoid
        // an infinite loop on a corrupt size field.
        if cell_size < MIN_CELL_SIZE {
            break;
        }
        let cell_end = pos.saturating_add(cell_size).min(end);

        if header.is_allocated() {
            // Live cell: its record is reachable via navigation, so we do NOT
            // emit it. Its body *starts* with that live record's signature, so
            // begin the slack sweep past those two signature bytes — only
            // orphaned records deeper in the cell's slack should surface.
            scan_slack(data, pos + 4 + 2, cell_end, out);
        } else {
            // Free cell: try to parse it as a deleted record at the cell head,
            // then sweep the rest for additional orphaned signatures in slack.
            let body_start = pos + 4;
            let mut head_recovered = false;
            if let Some(rec) = try_record(
                data,
                body_start,
                cell_end,
                pos,
                false,
                RecoverySource::UnallocatedCell,
            ) {
                out.push(rec);
                head_recovered = true;
            }
            // Sweep remaining bytes for additional orphaned records (e.g. a
            // reused free cell that still holds a deeper record).
            let sweep_from = if head_recovered {
                body_start + 2
            } else {
                body_start
            };
            scan_slack(data, sweep_from, cell_end, out);
        }

        pos = pos.saturating_add(cell_size);
    }
}

/// Byte-scan `[start, end)` for orphaned `nk`/`vk` signatures (slack scanning).
fn scan_slack(data: &[u8], start: usize, end: usize, out: &mut Vec<RecoveredCell>) {
    if start >= end || end > data.len() {
        return;
    }
    let region = &data[start..end];
    let mut i = 0;
    while i + 2 <= region.len() && out.len() < MAX_RECOVERIES {
        let sig = [region[i], region[i + 1]];
        let is_sig = matches!(
            CellSignature::from_bytes(&sig),
            Some(CellSignature::KeyNode | CellSignature::KeyValue)
        );
        if is_sig {
            let abs = start + i;
            // The size field sits 4 bytes before the signature; clamp to region.
            let cell_off = abs.saturating_sub(4);
            if let Some(rec) = try_record(data, abs, end, cell_off, false, RecoverySource::Slack) {
                out.push(rec);
            }
        }
        i += 1;
    }
}

/// Attempt to parse the bytes at `body_start` as a deleted `nk`/`vk` record.
///
/// `body_start` points at the 2-byte signature; `region_end` bounds the read.
/// Returns `None` for anything that fails signature or structural validation —
/// this is what rejects garbage unallocated bytes.
fn try_record(
    data: &[u8],
    body_start: usize,
    region_end: usize,
    cell_offset: usize,
    allocated: bool,
    source: RecoverySource,
) -> Option<RecoveredCell> {
    if body_start + 2 > region_end || region_end > data.len() {
        return None;
    }
    let sig = [data[body_start], data[body_start + 1]];
    let after_sig = data.get(body_start + 2..region_end)?;
    let file_offset = u32::try_from(cell_offset).unwrap_or(u32::MAX);

    match CellSignature::from_bytes(&sig) {
        Some(CellSignature::KeyNode) => {
            let nk = RawKeyNode::parse(after_sig)?;
            if !nk_is_plausible(&nk) {
                return None;
            }
            let name = nk.key_name();
            if !name_is_plausible(&name) {
                return None;
            }
            let confidence = if source == RecoverySource::UnallocatedCell {
                Confidence::High
            } else {
                Confidence::Medium
            };
            Some(RecoveredCell::Key(RecoveredKey {
                name,
                last_written: nk.last_written,
                parent_offset: nk.parent.0,
                file_offset,
                allocated,
                source,
                confidence,
            }))
        }
        Some(CellSignature::KeyValue) => {
            let vk = RawKeyValue::parse(after_sig)?;
            if !vk_is_plausible(&vk) {
                return None;
            }
            let name = vk.value_name();
            // Unnamed default value is legitimate (empty name); otherwise the
            // name must be plausible text.
            if !name.is_empty() && !name_is_plausible(&name) {
                return None;
            }
            let data_bytes = if vk.is_resident() {
                vk.inline_data()
            } else {
                // Non-resident: the data cell may have been reused. Do not
                // fabricate data we cannot trust.
                Vec::new()
            };
            let raw_type = value_type_raw(vk.data_type);
            let confidence = if source == RecoverySource::UnallocatedCell {
                Confidence::High
            } else {
                Confidence::Medium
            };
            Some(RecoveredCell::Value(RecoveredValue {
                name,
                data_type: raw_type,
                data: data_bytes,
                file_offset,
                allocated,
                source,
                confidence,
            }))
        }
        _ => None,
    }
}

/// Structural sanity for a carved `nk`: reject obviously-garbage records.
fn nk_is_plausible(nk: &RawKeyNode) -> bool {
    // A real key name is 1..=255 chars; counts/offsets are bounded.
    nk.key_name_len > 0
        && usize::from(nk.key_name_len) <= 512
        && nk.subkey_count <= 1_000_000
        && nk.value_count <= 1_000_000
}

/// Structural sanity for a carved `vk`.
fn vk_is_plausible(vk: &RawKeyValue) -> bool {
    // Name length bounded; resident data ≤ 4 bytes; non-resident size bounded.
    usize::from(vk.name_len) <= 512 && vk.data_size() <= 16 * 1024 * 1024
}

/// Whether a decoded name looks like a real registry name rather than random
/// bytes that happened to follow a signature.
fn name_is_plausible(name: &str) -> bool {
    if name.is_empty() || name.len() > 1024 {
        return false;
    }
    // Reject control characters (other than none) and the U+FFFD replacement
    // char that lossy UTF-16 decoding emits for garbage.
    name.chars()
        .all(|c| c != '\u{FFFD}' && (c == ' ' || !c.is_control()))
}

/// Map a parsed [`ValueType`] back to its raw `REG_*` type number.
fn value_type_raw(t: ValueType) -> u32 {
    match t {
        ValueType::None => 0,
        ValueType::Sz => 1,
        ValueType::ExpandSz => 2,
        ValueType::Binary => 3,
        ValueType::Dword => 4,
        ValueType::DwordBigEndian => 5,
        ValueType::Link => 6,
        ValueType::MultiSz => 7,
        ValueType::ResourceList => 8,
        ValueType::FullResourceDescriptor => 9,
        ValueType::ResourceRequirementsList => 10,
        ValueType::Qword => 11,
        ValueType::Unknown(n) => n,
    }
}

/// Bounds-checked little-endian `i32` read; out-of-range yields 0.
fn read_i32(data: &[u8], off: usize) -> i32 {
    data.get(off..off.wrapping_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, i32::from_le_bytes)
}
