#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::com_hijacking`.
//!
//! RED phase: tests define expected behaviour and must FAIL until the
//! parse functions are implemented.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::com_hijacking::{classify_com_hijack, parse_hkcu_only, parse_pair};
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REG_SZ: u32 = 1;

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.push(0);
    out.push(0);
    out
}

/// Build an NTUSER.DAT hive with one CLSID under Software\Classes\CLSID
fn build_hku_hive(clsid: &str, dll: &str) -> Vec<u8> {
    let inproc_path = format!("Software\\Classes\\CLSID\\{clsid}\\InprocServer32");
    TestHiveBuilder::new()
        .add_key(&inproc_path)
        .add_value(&inproc_path, "", REG_SZ, &utf16le(dll))
        .build()
}

/// Build an HKCR hive with one CLSID under SOFTWARE\Classes\CLSID
fn build_hkcr_hive(clsid: &str, dll: &str) -> Vec<u8> {
    let inproc_path = format!("SOFTWARE\\Classes\\CLSID\\{clsid}\\InprocServer32");
    TestHiveBuilder::new()
        .add_key(&inproc_path)
        .add_value(&inproc_path, "", REG_SZ, &utf16le(dll))
        .build()
}

// ---------------------------------------------------------------------------
// Test 1: parse_hkcu_only_empty_hive_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_hkcu_only_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse_hkcu_only(&hive);
    assert!(
        results.is_empty(),
        "empty hive (no CLSID key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_hkcu_only_returns_clsid_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_hkcu_only_returns_clsid_entry() {
    let clsid = "{11111111-1111-1111-1111-111111111111}";
    let data = build_hku_hive(clsid, r"C:\Users\victim\AppData\Roaming\evil.dll");
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse_hkcu_only(&hive);
    assert_eq!(results.len(), 1, "should return one entry");
}

// ---------------------------------------------------------------------------
// Test 3: parse_hkcu_only_clsid_name_captured
// ---------------------------------------------------------------------------

#[test]
fn parse_hkcu_only_clsid_name_captured() {
    let clsid = "{DEADBEEF-1234-5678-ABCD-000000000001}";
    let data = build_hku_hive(clsid, r"C:\Users\victim\AppData\Local\evil.dll");
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse_hkcu_only(&hive);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].clsid.to_ascii_uppercase(),
        clsid.to_ascii_uppercase(),
        "clsid field should match the subkey name"
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_hkcu_only_inprocserver32_value_captured
// ---------------------------------------------------------------------------

#[test]
fn parse_hkcu_only_inprocserver32_value_captured() {
    let clsid = "{AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF}";
    let dll = r"C:\Users\victim\Downloads\payload.dll";
    let data = build_hku_hive(clsid, dll);
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse_hkcu_only(&hive);
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].hkcu_server, dll,
        "hkcu_server should be the DLL path from InprocServer32 default value"
    );
}

// ---------------------------------------------------------------------------
// Test 5: classify_appdata_path_is_suspicious
// ---------------------------------------------------------------------------

#[test]
fn classify_appdata_path_is_suspicious() {
    let (suspicious, reason) = classify_com_hijack(
        "",
        r"C:\Users\victim\AppData\Roaming\evil.dll",
    );
    assert!(suspicious, "AppData path should be suspicious");
    assert!(reason.is_some(), "should provide a reason");
}

// ---------------------------------------------------------------------------
// Test 6: classify_temp_path_is_suspicious
// ---------------------------------------------------------------------------

#[test]
fn classify_temp_path_is_suspicious() {
    let (suspicious, _) = classify_com_hijack("", r"C:\Windows\Temp\evil.dll");
    assert!(suspicious, "Temp path should be suspicious");
}

// ---------------------------------------------------------------------------
// Test 7: classify_system32_path_benign
// ---------------------------------------------------------------------------

#[test]
fn classify_system32_path_benign() {
    let (suspicious, _) =
        classify_com_hijack("", r"C:\Windows\System32\shell32.dll");
    assert!(!suspicious, "System32 path should NOT be suspicious");
}

// ---------------------------------------------------------------------------
// Test 8: classify_hkcu_differs_from_hkcr_is_suspicious
// ---------------------------------------------------------------------------

#[test]
fn classify_hkcu_differs_from_hkcr_is_suspicious() {
    let (suspicious, reason) = classify_com_hijack(
        r"C:\Windows\System32\shell32.dll",
        r"C:\Windows\System32\evil.dll",
    );
    assert!(
        suspicious,
        "HKCU path differing from HKCR should be suspicious"
    );
    assert!(reason.is_some());
}

// ---------------------------------------------------------------------------
// Test 9: parse_pair_matching_paths_not_suspicious
// ---------------------------------------------------------------------------

#[test]
fn parse_pair_matching_paths_not_suspicious() {
    let clsid = "{33333333-3333-3333-3333-333333333333}";
    let dll = r"C:\Windows\System32\shell32.dll";

    let hku_data = build_hku_hive(clsid, dll);
    let hkcr_data = build_hkcr_hive(clsid, dll);

    let hku_hive = Hive::from_bytes(hku_data).unwrap();
    let hkcr_hive = Hive::from_bytes(hkcr_data).unwrap();

    let results = parse_pair(&hku_hive, &hkcr_hive);
    // Either empty or all entries are not suspicious
    assert!(
        results.is_empty() || results.iter().all(|e| !e.is_suspicious),
        "matching HKCU/HKCR paths should not produce suspicious entries"
    );
}

// ---------------------------------------------------------------------------
// Test 10: parse_pair_detects_hkcu_override
// ---------------------------------------------------------------------------

#[test]
fn parse_pair_detects_hkcu_override() {
    let clsid = "{22222222-2222-2222-2222-222222222222}";
    let hkcu_dll = r"C:\Users\victim\AppData\Roaming\evil.dll";
    let hkcr_dll = r"C:\Windows\System32\shell32.dll";

    let hku_data = build_hku_hive(clsid, hkcu_dll);
    let hkcr_data = build_hkcr_hive(clsid, hkcr_dll);

    let hku_hive = Hive::from_bytes(hku_data).unwrap();
    let hkcr_hive = Hive::from_bytes(hkcr_data).unwrap();

    let results = parse_pair(&hku_hive, &hkcr_hive);
    assert_eq!(results.len(), 1, "should detect one hijack entry");
    assert!(results[0].is_suspicious, "override should be suspicious");
    assert_eq!(results[0].hkcu_server, hkcu_dll);
    assert_eq!(results[0].hkcr_server, hkcr_dll);
}

// ---------------------------------------------------------------------------
// Test 11: parse_hkcu_only_hkcr_server_is_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_hkcu_only_hkcr_server_is_empty() {
    let clsid = "{55555555-5555-5555-5555-555555555555}";
    let data = build_hku_hive(clsid, r"C:\Users\user\AppData\Local\test.dll");
    let hive = Hive::from_bytes(data).unwrap();
    let results = parse_hkcu_only(&hive);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].hkcr_server.is_empty(),
        "hkcr_server should be empty in parse_hkcu_only"
    );
}
