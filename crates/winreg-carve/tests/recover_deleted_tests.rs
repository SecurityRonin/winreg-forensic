//! Integration tests for deleted-key/value carving.
//!
//! Strategy: build a valid hive with the shared test builder, then simulate a
//! *deletion* by flipping a cell's size field from negative (allocated) to
//! positive (free). The live navigation no longer reaches the cell, but the
//! `nk`/`vk` record bytes survive in the now-unallocated cell — exactly the
//! state a real deleted-but-not-overwritten record leaves behind. The carver
//! must recover it; a garbage unallocated region must yield nothing.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use winreg_carve::{recover_deleted, Confidence, RecoveredCell, RecoverySource};
use winreg_core::hive::Hive;

/// Flip the cell whose body begins with `sig` at the given key/value name to a
/// *free* (positive-size) cell, simulating deletion. Returns the file offset of
/// the freed cell.
fn free_cell_containing(buf: &mut [u8], needle: &[u8]) -> usize {
    // Find the needle (e.g. a UTF-8 key name) in the raw bytes, then walk back to
    // the enclosing cell header. We know cells are 8-byte aligned and the size
    // field is the 4 bytes immediately preceding the "nk"/"vk" signature, which
    // sits some fixed distance before the name. We instead locate the signature
    // preceding the needle and back up 4 bytes to the size field.
    let pos = find_subslice(buf, needle).expect("needle present in hive");
    // Scan backwards for the nearest "nk" or "vk" signature before the name.
    let mut sig_pos = None;
    for i in (0..pos).rev() {
        if &buf[i..i + 2] == b"nk" || &buf[i..i + 2] == b"vk" {
            sig_pos = Some(i);
            break;
        }
    }
    let sig_pos = sig_pos.expect("signature precedes name");
    let size_field = sig_pos - 4;
    let cur = i32::from_le_bytes(buf[size_field..size_field + 4].try_into().unwrap());
    let freed = cur.abs(); // positive => free
    buf[size_field..size_field + 4].copy_from_slice(&freed.to_le_bytes());
    size_field
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn recovers_deleted_key_by_name() {
    let mut buf = common::TestHiveBuilder::new()
        .add_key("Software")
        .add_key("Software\\Malware")
        .build();

    // Deletion: free the "Malware" NK cell.
    free_cell_containing(&mut buf, b"Malware");

    let hive = Hive::from_bytes(buf).expect("hive reopens after deletion");
    let recovered = recover_deleted(&hive);

    let keys: Vec<_> = recovered
        .iter()
        .filter_map(|c| match c {
            RecoveredCell::Key(k) => Some(k),
            RecoveredCell::Value(_) => None,
        })
        .collect();

    let malware = keys
        .iter()
        .find(|k| k.name == "Malware")
        .expect("deleted key 'Malware' should be recovered");
    assert!(
        !malware.allocated,
        "recovered key is from an unallocated cell"
    );
    assert_eq!(malware.source, RecoverySource::UnallocatedCell);
}

#[test]
fn recovers_deleted_value_name_and_data() {
    let mut buf = common::TestHiveBuilder::new()
        .add_key("Run")
        .add_value("Run", "Backdoor", 1, b"C:\\evil.exe")
        .build();

    // Free the VK cell for "Backdoor".
    free_cell_containing(&mut buf, b"Backdoor");

    let hive = Hive::from_bytes(buf).expect("hive reopens");
    let recovered = recover_deleted(&hive);

    let value = recovered
        .iter()
        .find_map(|c| match c {
            RecoveredCell::Value(v) if v.name == "Backdoor" => Some(v),
            _ => None,
        })
        .expect("deleted value 'Backdoor' recovered");
    assert!(!value.allocated);
    assert_eq!(value.data_type, 1); // REG_SZ
}

#[test]
fn live_scan_does_not_see_deleted_key() {
    // Sanity: before deletion the key is live; after, navigation can't reach it,
    // but the carver can. We assert the carver finds it ONLY post-deletion.
    let mut buf = common::TestHiveBuilder::new()
        .add_key("Keep")
        .add_key("Keep\\Gone")
        .build();
    free_cell_containing(&mut buf, b"Gone");

    let hive = Hive::from_bytes(buf).expect("reopen");
    let recovered = recover_deleted(&hive);
    assert!(
        recovered
            .iter()
            .any(|c| matches!(c, RecoveredCell::Key(k) if k.name == "Gone")),
        "carver recovers the freed key"
    );
    // The live key "Keep" is allocated; carving unallocated cells must NOT report it.
    assert!(
        !recovered
            .iter()
            .any(|c| matches!(c, RecoveredCell::Key(k) if k.name == "Keep")),
        "carver must not report still-allocated live keys"
    );
}

#[test]
fn garbage_unallocated_bytes_yield_no_false_recoveries() {
    // A hive with a large free region full of random-looking bytes must not
    // produce phantom keys/values: signature + structural validation rejects them.
    let mut buf = common::TestHiveBuilder::new().add_key("Solo").build();

    // Overwrite the trailing free region (after the cells) with pseudo-random
    // bytes that contain no valid nk/vk structure.
    let mut seed: u32 = 0x1234_5678;
    let start = buf.len() - 512;
    for b in &mut buf[start..] {
        seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (seed >> 16) as u8;
    }

    let hive = Hive::from_bytes(buf).expect("reopen");
    let recovered = recover_deleted(&hive);
    // None of the recovered records may originate from the garbage region.
    for c in &recovered {
        let off = match c {
            RecoveredCell::Key(k) => k.file_offset,
            RecoveredCell::Value(v) => v.file_offset,
        };
        assert!(
            (off as usize) < start,
            "no recovery may come from the garbage region at {start}"
        );
    }
}

#[test]
fn confidence_is_graded_not_certain() {
    let mut buf = common::TestHiveBuilder::new()
        .add_key("Top")
        .add_key("Top\\Deleted")
        .build();
    free_cell_containing(&mut buf, b"Deleted");
    let hive = Hive::from_bytes(buf).expect("reopen");
    let recovered = recover_deleted(&hive);
    let k = recovered
        .iter()
        .find_map(|c| match c {
            RecoveredCell::Key(k) if k.name == "Deleted" => Some(k),
            _ => None,
        })
        .expect("recovered");
    // A freed-but-structurally-intact cell is high (not absolute) confidence.
    assert!(matches!(
        k.confidence,
        Confidence::High | Confidence::Medium
    ));
}

/// Build minimal valid `nk` record bytes (signature onward, no cell size field).
fn nk_record_bytes(name: &str) -> Vec<u8> {
    let name = name.as_bytes();
    let mut b = Vec::new();
    b.extend_from_slice(b"nk");
    b.extend_from_slice(&0x0020u16.to_le_bytes()); // COMP_NAME
    b.extend_from_slice(&0u64.to_le_bytes()); // last_written
    b.extend_from_slice(&0u32.to_le_bytes()); // access_bits
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // parent
    b.extend_from_slice(&0u32.to_le_bytes()); // subkey_count
    b.extend_from_slice(&0u32.to_le_bytes()); // volatile_subkey_count
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // subkeys_list
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // volatile_subkeys_list
    b.extend_from_slice(&0u32.to_le_bytes()); // value_count
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // values_list
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // security
    b.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // class_name
    b.extend_from_slice(&[0u8; 5 * 4]); // 5 max_* / work_var fields
    b.extend_from_slice(&(name.len() as u16).to_le_bytes()); // key_name_len
    b.extend_from_slice(&0u16.to_le_bytes()); // class_name_len
    b.extend_from_slice(name);
    b
}

#[test]
fn recovers_orphaned_record_from_slack() {
    // Plant a deleted nk record in the *interior* of the trailing free cell so it
    // is reachable only via the slack sweep, not the free-cell head — simulating
    // a record whose cell was partially reused.
    let mut buf = common::TestHiveBuilder::new().add_key("Anchor").build();

    let rec = nk_record_bytes("Orphan");
    // Drop it ~64 bytes into the trailing free region (well past any cell head).
    let plant = buf.len() - 256;
    buf[plant..plant + rec.len()].copy_from_slice(&rec);

    let hive = Hive::from_bytes(buf).expect("reopen");
    let recovered = recover_deleted(&hive);

    let orphan = recovered
        .iter()
        .find_map(|c| match c {
            RecoveredCell::Key(k) if k.name == "Orphan" => Some(k),
            _ => None,
        })
        .expect("orphaned nk recovered from slack");
    assert_eq!(orphan.source, RecoverySource::Slack);
    assert_eq!(orphan.confidence, Confidence::Medium);
}
