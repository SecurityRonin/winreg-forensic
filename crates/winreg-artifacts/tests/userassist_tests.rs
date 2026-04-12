//! Integration tests for `winreg_artifacts::userassist`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::userassist::{parse, rot13_decode, UserAssistEntry};
use winreg_core::hive::Hive;

// ── Well-known UserAssist GUIDs ───────────────────────────────────────────────

const GUID_EXE: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
const GUID_LNK: &str = "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}";

// ── Helper: build path to a UserAssist Count key ──────────────────────────────

fn count_path(guid: &str) -> String {
    format!(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{guid}\\Count"
    )
}

// ── Helper: build a 72-byte UserAssist value binary payload ──────────────────

fn ua_payload(run_count: u32, focus_count: u32, focus_duration_ms: u32, last_run_ft: u64) -> Vec<u8> {
    let mut data = vec![0u8; 72];
    // bytes 0-3: session ID (we'll leave as 0)
    data[0..4].copy_from_slice(&0u32.to_le_bytes());
    // bytes 4-7: run count
    data[4..8].copy_from_slice(&run_count.to_le_bytes());
    // bytes 8-11: focus count
    data[8..12].copy_from_slice(&focus_count.to_le_bytes());
    // bytes 12-15: focus duration ms
    data[12..16].copy_from_slice(&focus_duration_ms.to_le_bytes());
    // bytes 60-67: FILETIME
    data[60..68].copy_from_slice(&last_run_ft.to_le_bytes());
    data
}

// ── FILETIME for a known date: 2023-06-01 00:00:00 UTC ───────────────────────

/// Windows FILETIME for 2023-06-01 00:00:00 UTC.
const FILETIME_2023_06_01: u64 = 133_297_632_000_000_000;

// ── Test 1: parse_empty_hive_returns_empty ────────────────────────────────────

#[test]
fn parse_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "empty hive (no UserAssist key) should return empty Vec"
    );
}

// ── Test 2: rot13_decode_basic ────────────────────────────────────────────────

#[test]
fn rot13_decode_basic() {
    // "Uryyb" → "Hello"
    assert_eq!(rot13_decode("Uryyb"), "Hello");
    // "URYYB" → "HELLO"
    assert_eq!(rot13_decode("URYYB"), "HELLO");
    // "nop" → "abc"
    assert_eq!(rot13_decode("nop"), "abc");
}

// ── Test 3: rot13_decode_preserves_non_alpha ──────────────────────────────────

#[test]
fn rot13_decode_preserves_non_alpha() {
    // Numbers, spaces, backslashes, braces unchanged
    assert_eq!(rot13_decode("123"), "123");
    assert_eq!(rot13_decode("\\"), "\\");
    // "{GUID}" — only letters G,U,I,D rotate: G→T, U→H, I→V, D→Q
    assert_eq!(rot13_decode("{GUID}"), "{THVQ}");
    // Mixed: only letters rotated, backslashes and colon preserved
    // ROT13("P:\\Hfref\\") = "C:\\Users\\" — P→C, H→U, f→s, r→e, e→r, f→s
    assert_eq!(rot13_decode("P:\\Hfref\\"), "C:\\Users\\");
    // ROT13("Cebtenz Svyrf") = "Program Files"
    assert_eq!(rot13_decode("Cebtenz Svyrf"), "Program Files");
}

// ── Test 4: rot13_roundtrip ───────────────────────────────────────────────────

#[test]
fn rot13_roundtrip() {
    let original = "C:\\Users\\Alice\\AppData\\Roaming\\notepad.exe";
    let encoded = rot13_decode(original); // rot13 once
    let decoded = rot13_decode(&encoded); // rot13 twice = original
    assert_eq!(decoded, original, "applying ROT13 twice should return original");
}

// ── Test 5: parse_userassist_entry_decoded ────────────────────────────────────

#[test]
fn parse_userassist_entry_decoded() {
    // ROT13 of "notepad.exe" = "abgrcnq.rkr"
    let encoded_name = rot13_decode("notepad.exe"); // encode via rot13
    let path = count_path(GUID_EXE);
    let payload = ua_payload(3, 5, 2000, FILETIME_2023_06_01);
    let data = TestHiveBuilder::new()
        .add_key(&path)
        .add_value(&path, &encoded_name, 3, &payload) // REG_BINARY = 3
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "should find 1 entry");
    assert_eq!(
        entries[0].program, "notepad.exe",
        "program name should be ROT13-decoded"
    );
}

// ── Test 6: parse_run_count_extracted ─────────────────────────────────────────

#[test]
fn parse_run_count_extracted() {
    let encoded_name = rot13_decode("calc.exe");
    let path = count_path(GUID_EXE);
    let payload = ua_payload(7, 3, 500, FILETIME_2023_06_01);
    let data = TestHiveBuilder::new()
        .add_key(&path)
        .add_value(&path, &encoded_name, 3, &payload)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].run_count, 7, "run_count should be 7");
    assert_eq!(entries[0].focus_count, 3, "focus_count should be 3");
    assert_eq!(entries[0].focus_duration_ms, 500, "focus_duration_ms should be 500");
}

// ── Test 7: parse_last_run_filetime_converted ─────────────────────────────────

#[test]
fn parse_last_run_filetime_converted() {
    let encoded_name = rot13_decode("mspaint.exe");
    let path = count_path(GUID_EXE);
    let payload = ua_payload(1, 1, 100, FILETIME_2023_06_01);
    let data = TestHiveBuilder::new()
        .add_key(&path)
        .add_value(&path, &encoded_name, 3, &payload)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].last_run.is_some(),
        "last_run should be Some for non-zero FILETIME"
    );
    let ts = entries[0].last_run.as_ref().unwrap();
    assert!(ts.contains("2023"), "ISO timestamp should contain '2023'");
}

// ── Test 8: parse_zero_filetime_gives_none ────────────────────────────────────

#[test]
fn parse_zero_filetime_gives_none() {
    let encoded_name = rot13_decode("wordpad.exe");
    let path = count_path(GUID_EXE);
    let payload = ua_payload(2, 2, 200, 0); // zero FILETIME
    let data = TestHiveBuilder::new()
        .add_key(&path)
        .add_value(&path, &encoded_name, 3, &payload)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].last_run.is_none(),
        "last_run should be None when FILETIME is zero"
    );
}

// ── Test 9: guid field is populated ──────────────────────────────────────────

#[test]
fn parse_guid_field_populated() {
    let encoded_name = rot13_decode("explorer.exe");
    let path = count_path(GUID_EXE);
    let payload = ua_payload(1, 1, 0, FILETIME_2023_06_01);
    let data = TestHiveBuilder::new()
        .add_key(&path)
        .add_value(&path, &encoded_name, 3, &payload)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].guid, GUID_EXE,
        "guid field should contain the source GUID"
    );
}

// ── Test 10: LNK GUID also parsed ────────────────────────────────────────────

#[test]
fn parse_lnk_guid_entries_included() {
    let encoded_name = rot13_decode("notepad.lnk");
    let path = count_path(GUID_LNK);
    let payload = ua_payload(4, 4, 1000, FILETIME_2023_06_01);
    let data = TestHiveBuilder::new()
        .add_key(&path)
        .add_value(&path, &encoded_name, 3, &payload)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].guid, GUID_LNK);
    assert_eq!(entries[0].program, "notepad.lnk");
}

// ── Test 11: both GUIDs parsed together ──────────────────────────────────────

#[test]
fn parse_both_guids_combined() {
    let exe_name = rot13_decode("notepad.exe");
    let exe_path = count_path(GUID_EXE);
    let lnk_name = rot13_decode("notepad.lnk");
    let lnk_path = count_path(GUID_LNK);
    let payload = ua_payload(1, 1, 0, FILETIME_2023_06_01);
    let data = TestHiveBuilder::new()
        .add_key(&exe_path)
        .add_value(&exe_path, &exe_name, 3, &payload)
        .add_key(&lnk_path)
        .add_value(&lnk_path, &lnk_name, 3, &payload)
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 2, "should find entries from both GUIDs");
}

// ── Test 12: UserAssistEntry struct accessible ────────────────────────────────

#[test]
fn userassist_entry_struct_fields_accessible() {
    let entry = UserAssistEntry {
        program: "test.exe".to_string(),
        run_count: 3,
        focus_count: 2,
        focus_duration_ms: 500,
        last_run: None,
        guid: GUID_EXE.to_string(),
    };
    assert_eq!(entry.program, "test.exe");
    assert_eq!(entry.run_count, 3);
    assert_eq!(entry.guid, GUID_EXE);
}
