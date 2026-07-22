//! RED: `HiveCarver` must satisfy the fleet `forensic-carve::Carver` contract so a
//! whole `regf` registry hive can be carved from an unallocated/memory sweep — the
//! path by which Amcache/Shimcache are recovered (carve the hive, then the winreg
//! parser extracts the sub-artifacts).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use forensic_carve::{CarveContext, CarvedPayload, Carver, RecoveryMethod};
use winreg_carve::HiveCarver;
use winreg_format::header::BaseBlock;

/// Build a minimal valid `regf` hive: a 4096-byte base block (correct `regf`
/// magic, plausible `HiveBinsDataSize`, correct XOR-32 checksum, sane sequence
/// numbers) followed by `hbds` bytes of hbin data.
fn build_hive(hbds: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 4096 + hbds as usize];
    buf[0..4].copy_from_slice(b"regf");
    buf[0x04..0x08].copy_from_slice(&1u32.to_le_bytes()); // primary sequence
    buf[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes()); // secondary sequence
    buf[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // major version
    buf[0x18..0x1C].copy_from_slice(&5u32.to_le_bytes()); // minor version
    buf[0x1C..0x20].copy_from_slice(&0u32.to_le_bytes()); // file type = primary
    buf[0x20..0x24].copy_from_slice(&1u32.to_le_bytes()); // format
    buf[0x24..0x28].copy_from_slice(&32u32.to_le_bytes()); // root cell offset
    buf[0x28..0x2C].copy_from_slice(&hbds.to_le_bytes()); // hive bins data size
    buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // clustering factor
    let checksum = BaseBlock::compute_checksum(&buf);
    buf[0x1FC..0x200].copy_from_slice(&checksum.to_le_bytes());
    buf
}

/// A scratch buffer of filler bytes with `hive` placed at byte `off`.
fn scratch_at(hive: &[u8], off: usize) -> Vec<u8> {
    let mut scratch = vec![0xABu8; off];
    scratch.extend_from_slice(hive);
    scratch
}

#[test]
fn carves_valid_hive_at_nonzero_offset() {
    let hbds = 4096u32;
    let hive = build_hive(hbds);
    let off = 0x5000usize;
    let scratch = scratch_at(&hive, off);
    let window = &scratch[off..];

    let ctx = CarveContext::at(off as u64).with_method(RecoveryMethod::UnallocatedCarve);
    let items = HiveCarver.carve(window, &ctx);

    assert_eq!(items.len(), 1, "exactly one hive carved");
    let item = &items[0];
    assert_eq!(item.format(), "registry-hive");
    assert_eq!(item.image_offset(), off as u64, "echoes ctx.base_offset()");
    // Recovery method is ECHOED from the context, never hardcoded.
    assert_eq!(item.recovery_method(), RecoveryMethod::UnallocatedCarve);
    match item.payload() {
        CarvedPayload::ArtifactBytes(b) => {
            assert_eq!(
                b.len(),
                4096 + hbds as usize,
                "bounded to base block + HiveBinsDataSize"
            );
        }
        CarvedPayload::Records => panic!("expected artifact bytes"),
    }
}

#[test]
fn recovery_method_is_echoed_not_hardcoded() {
    let hive = build_hive(4096);
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::MemoryCarve);
    let items = HiveCarver.carve(&hive, &ctx);
    assert_eq!(items.len(), 1);
    // Same carver, memory sweep -> MemoryCarve, proving the method is echoed.
    assert_eq!(items[0].recovery_method(), RecoveryMethod::MemoryCarve);
}

#[test]
fn bounds_hive_to_window_when_truncated() {
    // The base block claims 3 hbins (12288) but the window only carries 1.
    let mut hive = build_hive(12288);
    hive.truncate(4096 + 4096);
    let ctx = CarveContext::at(0).with_method(RecoveryMethod::UnallocatedCarve);
    let items = HiveCarver.carve(&hive, &ctx);
    assert_eq!(items.len(), 1);
    match items[0].payload() {
        CarvedPayload::ArtifactBytes(b) => assert_eq!(b.len(), 4096 + 4096, "clamped to window"),
        CarvedPayload::Records => panic!("expected artifact bytes"),
    }
}

#[test]
fn bad_magic_yields_nothing() {
    let mut hive = build_hive(4096);
    hive[0..4].copy_from_slice(b"nope");
    let ctx = CarveContext::at(0);
    assert!(HiveCarver.carve(&hive, &ctx).is_empty());
}

#[test]
fn bad_checksum_yields_nothing() {
    let mut hive = build_hive(4096);
    // Flip a header byte without recomputing the stored checksum.
    hive[0x14] ^= 0xFF;
    let ctx = CarveContext::at(0);
    assert!(HiveCarver.carve(&hive, &ctx).is_empty());
}

#[test]
fn signatures_anchor_on_regf() {
    let sigs = HiveCarver.signatures();
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].magic(), b"regf");
    assert_eq!(sigs[0].offset(), 0);
    assert_eq!(HiveCarver.format(), "registry-hive");
}

#[test]
fn registered_in_inventory() {
    // Discoverable through the fleet carver inventory once force-linked.
    let found = forensic_carve::registered_carvers()
        .iter()
        .any(|c| c.format() == "registry-hive");
    assert!(found, "HiveCarver registered via inventory::submit!");
}
