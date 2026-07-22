//! Whole-hive carving — recover a complete `regf` registry hive from an
//! unallocated-disk or memory sweep.
//!
//! This is distinct from [`recover_deleted`](crate::recover_deleted), which
//! salvages deleted `nk`/`vk` cells *inside* an already-located hive. Here the
//! hive itself is the artifact: a sweep dispatches a window anchored on the
//! `regf` magic, [`HiveCarver`] validates the base block and bounds the hive to
//! `4096 + HiveBinsDataSize`, and the emitted `ArtifactBytes` re-enter the normal
//! classify -> parse pipeline — the path by which Amcache/Shimcache hives are
//! recovered before the winreg parser extracts the sub-artifacts.
//!
//! The carver is medium-agnostic (ADR 0001): it sees only a `&[u8]` window and
//! echoes the driver's [`RecoveryMethod`](forensic_carve::RecoveryMethod), so the *same* carver stamps
//! `UnallocatedCarve` on a disk sweep and `MemoryCarve` on a memory sweep.

use forensic_carve::{CarveContext, CarvedItem, Carver, CarverRegistration, Signature};
use winreg_format::header::BaseBlock;

/// Upper bound on a single carved hive (also the `max_window` cap). Registry
/// hives (SOFTWARE on servers) reach hundreds of MiB; 512 MiB bounds a crafted
/// `HiveBinsDataSize` from claiming unbounded bytes.
const MAX_HIVE_SIZE: u64 = 512 * 1024 * 1024;

/// The full base block occupies the first 4096 bytes of a hive.
const BASE_BLOCK_SIZE: u64 = 4096;

/// hbins are 4096-aligned, so the total hive-bins data size is a multiple of it.
const HBIN_ALIGN: u32 = 4096;

/// The signatures this carver anchors on — the `regf` magic at offset 0.
static SIGNATURES: &[Signature] = &[Signature::new(b"regf", 0)];

/// Carves a whole `regf` registry hive from a signature-anchored sweep window.
pub struct HiveCarver;

/// The registered singleton (inventory holds a `'static` reference to it).
static HIVE_CARVER: HiveCarver = HiveCarver;

inventory::submit! { CarverRegistration::new(&HIVE_CARVER) }

impl Carver for HiveCarver {
    fn format(&self) -> &'static str {
        "registry-hive"
    }

    fn signatures(&self) -> &[Signature] {
        SIGNATURES
    }

    fn max_window(&self) -> u64 {
        MAX_HIVE_SIZE
    }

    fn carve(&self, window: &[u8], ctx: &CarveContext) -> Vec<CarvedItem> {
        // The checksum spans the first 508 bytes; without the full 512-byte
        // header there is no second independent check, so refuse to emit.
        if window.len() < 512 {
            return Vec::new();
        }
        // Hard gate 1: `regf` magic.
        if !window.starts_with(b"regf") {
            return Vec::new();
        }
        // Hard gate 2: XOR-32 base-block checksum (offsets 0x000-0x1FB vs 0x1FC).
        if !BaseBlock::validate_checksum(window) {
            return Vec::new();
        }
        // Hard gate 3: sane sequence numbers — a live hive's primary/secondary
        // are non-zero (bumped on first write) and never differ wildly.
        let primary = read_u32_le(window, 0x04);
        let secondary = read_u32_le(window, 0x08);
        if !sequence_sane(primary, secondary) {
            return Vec::new();
        }
        // Hard gate 4: sane HiveBinsDataSize — non-zero, 4096-aligned, capped.
        let hbds = read_u32_le(window, 0x28);
        if !hive_bins_size_sane(hbds) {
            return Vec::new();
        }

        // Bound the hive to 4096 + HiveBinsDataSize, clamped to the materialized
        // window and the max-window cap.
        let claimed = BASE_BLOCK_SIZE.saturating_add(u64::from(hbds));
        let cap = self.max_window().min(window.len() as u64);
        let hive_len = usize::try_from(claimed.min(cap)).unwrap_or(usize::MAX);
        let bytes = window.get(..hive_len).unwrap_or(window).to_vec();

        let confidence = grade(window);
        vec![CarvedItem::artifact_bytes(
            "registry-hive",
            ctx.base_offset(),
            confidence,
            ctx.recovery_method(),
            bytes,
        )]
    }
}

/// Grade confidence above the base (all four hard gates already passed) using
/// independent header fields that a random `regf`-checksum collision would miss.
fn grade(window: &[u8]) -> f32 {
    let mut score = 0.6_f32;
    if read_u32_le(window, 0x14) == 1 {
        score += 0.1; // major version is always 1 on known Windows
    }
    if read_u32_le(window, 0x1C) == 0 {
        score += 0.1; // file type 0 = primary hive
    }
    if read_u32_le(window, 0x20) == 1 {
        score += 0.1; // format 1 = direct memory load
    }
    score
}

/// Sequence numbers are plausible for a real hive: both non-zero and within a
/// small write-lag of each other (a dirty hive lags by a handful of writes).
fn sequence_sane(primary: u32, secondary: u32) -> bool {
    primary != 0 && secondary != 0 && primary.abs_diff(secondary) <= 1024
}

/// `HiveBinsDataSize` is plausible: non-zero, 4096-aligned, and the whole hive
/// stays within the carve cap.
fn hive_bins_size_sane(hbds: u32) -> bool {
    hbds != 0
        && hbds % HBIN_ALIGN == 0
        && BASE_BLOCK_SIZE.saturating_add(u64::from(hbds)) <= MAX_HIVE_SIZE
}

/// Bounds-checked little-endian `u32` read; out-of-range yields 0.
fn read_u32_le(data: &[u8], off: usize) -> u32 {
    data.get(off..off.wrapping_add(4))
        .and_then(|s| <[u8; 4]>::try_from(s).ok())
        .map_or(0, u32::from_le_bytes)
}
