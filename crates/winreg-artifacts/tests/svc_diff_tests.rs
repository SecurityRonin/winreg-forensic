#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::svc_diff`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::svc_diff::{classify_service, parse};
use winreg_core::hive::Hive;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Root of the services key path in the SYSTEM hive.
const SERVICES_KEY: &str = "CurrentControlSet\\Services";

// Registry value types
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encode a string as UTF-16LE bytes (no null terminator — builder handles it).
fn reg_sz(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Encode a u32 as 4-byte little-endian (`REG_DWORD`).
fn reg_dword(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

/// Build a key path for a named service subkey.
fn svc_key(name: &str) -> String {
    format!("{SERVICES_KEY}\\{name}")
}

// ---------------------------------------------------------------------------
// Test 1: parse_empty_hive_returns_empty
// ---------------------------------------------------------------------------

#[test]
fn parse_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "empty hive (no Services key) should return empty Vec"
    );
}

// ---------------------------------------------------------------------------
// Test 2: parse_service_returns_entry
// ---------------------------------------------------------------------------

#[test]
fn parse_service_returns_entry() {
    let svc = svc_key("Dnscache");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\svchost.exe"),
        )
        .add_value(&svc, "DisplayName", REG_SZ, &reg_sz("DNS Client"))
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(32))
        .add_value(
            &svc,
            "ObjectName",
            REG_SZ,
            &reg_sz("NT AUTHORITY\\NetworkService"),
        )
        .add_value(&svc, "Description", REG_SZ, &reg_sz("Resolves DNS names."))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        !entries.is_empty(),
        "hive with one service subkey should return one entry"
    );
    assert_eq!(entries[0].name, "Dnscache");
}

#[test]
fn parse_surfaces_service_key_last_written() {
    // The service key's LastWriteTime ≈ the service install/modify time — the
    // forensic timestamp for "when was this service created" (e.g. coreupdater).
    // FILETIME for 2020-09-19T03:40:00Z (Case-001 era).
    const FT: u64 = 132_449_604_000_000_000;
    let svc = svc_key("coreupdater");
    let data = TestHiveBuilder::new()
        .with_key_times(FT)
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\System32\coreupdater.exe"),
        )
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    let e = entries
        .iter()
        .find(|e| e.name == "coreupdater")
        .expect("entry");
    let lw = e
        .last_written
        .expect("service entry must carry its key LastWriteTime");
    assert_eq!(
        lw.timestamp(),
        1_600_486_800,
        "decoded FILETIME → 2020-09-19T03:40:00Z"
    );
}

// ---------------------------------------------------------------------------
// Regression: real OFFLINE hive layout (no volatile CurrentControlSet)
//
// Offline SYSTEM hives have NO `CurrentControlSet` — it is a volatile symlink the
// running kernel materializes from `Select\Current`. A dead-box hive has
// `ControlSet001` (+ `Select\Current` = the active set number). `parse` must
// resolve `Select\Current` → `ControlSet00N\Services`, or it returns ZERO on
// every offline image (the primary forensic use case). The other tests build a
// synthetic `CurrentControlSet`, which masked this bug.
// ---------------------------------------------------------------------------

#[test]
fn parse_resolves_offline_controlset_via_select() {
    let svc = r"ControlSet001\Services\Dnscache";
    let data = TestHiveBuilder::new()
        .add_key("Select")
        .add_value("Select", "Current", REG_DWORD, &reg_dword(1))
        .add_key(svc)
        .add_value(
            svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\svchost.exe"),
        )
        .add_value(svc, "Start", REG_DWORD, &reg_dword(2))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        !entries.is_empty(),
        "offline layout (ControlSet001 + Select\\Current) must yield services"
    );
    assert_eq!(entries[0].name, "Dnscache");
}

// ---------------------------------------------------------------------------
// Test 3: parse_image_path_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_image_path_extracted() {
    let svc = svc_key("Spooler");
    let path = r"C:\Windows\system32\spoolsv.exe";
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(&svc, "ImagePath", REG_SZ, &reg_sz(path))
        .add_value(&svc, "DisplayName", REG_SZ, &reg_sz("Print Spooler"))
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .add_value(&svc, "Description", REG_SZ, &reg_sz("Manages print jobs."))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].image_path, path,
        "image_path should equal the ImagePath value"
    );
}

// ---------------------------------------------------------------------------
// Test 4: parse_start_type_extracted
// ---------------------------------------------------------------------------

#[test]
fn parse_start_type_extracted() {
    let svc = svc_key("WSearch");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\SearchIndexer.exe"),
        )
        .add_value(&svc, "DisplayName", REG_SZ, &reg_sz("Windows Search"))
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(3))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .add_value(&svc, "Description", REG_SZ, &reg_sz("Provides indexing."))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].start_type, 3,
        "start_type should equal 3 (Manual)"
    );
}

// ---------------------------------------------------------------------------
// Test 5: parse_missing_description_captured
// ---------------------------------------------------------------------------

#[test]
fn parse_missing_description_captured() {
    let svc = svc_key("EvilSvc");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        // No Description value
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\evil.exe"),
        )
        .add_value(&svc, "DisplayName", REG_SZ, &reg_sz("Evil Service"))
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(3))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert_eq!(
        entries[0].description, "",
        "missing Description value should produce empty string"
    );
}

// ---------------------------------------------------------------------------
// Test 6: classify_temp_path_is_suspicious
// ---------------------------------------------------------------------------

#[test]
fn classify_temp_path_is_suspicious() {
    let svc = svc_key("TempSvc");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\Temp\payload.exe"),
        )
        .add_value(&svc, "DisplayName", REG_SZ, &reg_sz("Temp Service"))
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .add_value(&svc, "Description", REG_SZ, &reg_sz("Temp svc."))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert!(
        entries[0].is_suspicious,
        "image path in \\temp\\ should be classified as suspicious"
    );
}

// ---------------------------------------------------------------------------
// Test 7: classify_powershell_image_is_suspicious
// ---------------------------------------------------------------------------

#[test]
fn classify_powershell_image_is_suspicious() {
    let svc = svc_key("PSSvc");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\powershell.exe -nop"),
        )
        .add_value(&svc, "DisplayName", REG_SZ, &reg_sz("PS Service"))
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .add_value(&svc, "Description", REG_SZ, &reg_sz("PS svc."))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(!entries.is_empty());
    assert!(
        entries[0].is_suspicious,
        "image path containing powershell.exe should be suspicious"
    );
}

// ---------------------------------------------------------------------------
// Test 8: classify_auto_start_no_description_non_system32_is_suspicious
// ---------------------------------------------------------------------------

#[test]
fn classify_auto_start_no_description_non_system32_is_suspicious() {
    let (is_suspicious, reason) = classify_service(
        r"C:\ProgramFiles\Vendor\service.exe",
        2,  // Auto
        "", // no description
        "LocalSystem",
    );
    assert!(
        is_suspicious,
        "auto-start with no description outside system32 should be suspicious"
    );
    assert!(reason.is_some());
}

// ---------------------------------------------------------------------------
// Test 9: classify_normal_system32_service_is_benign
// ---------------------------------------------------------------------------

#[test]
fn classify_normal_system32_service_is_benign() {
    let (is_suspicious, _reason) = classify_service(
        r"C:\Windows\system32\svchost.exe -k netsvcs",
        2,
        "Resolves and caches DNS names.",
        "NT AUTHORITY\\NetworkService",
    );
    assert!(
        !is_suspicious,
        "normal system32 auto-start service with description should be benign"
    );
}

// ---------------------------------------------------------------------------
// Test 10: parse_multiple_services_returns_all
// ---------------------------------------------------------------------------

#[test]
fn parse_multiple_services_returns_all() {
    let svc1 = svc_key("Dnscache");
    let svc2 = svc_key("Spooler");
    let svc3 = svc_key("WSearch");
    let data = TestHiveBuilder::new()
        .add_key(&svc1)
        .add_value(
            &svc1,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\svchost.exe"),
        )
        .add_value(&svc1, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc1, "Type", REG_DWORD, &reg_dword(32))
        .add_value(
            &svc1,
            "ObjectName",
            REG_SZ,
            &reg_sz("NT AUTHORITY\\NetworkService"),
        )
        .add_value(&svc1, "DisplayName", REG_SZ, &reg_sz("DNS Client"))
        .add_value(&svc1, "Description", REG_SZ, &reg_sz("DNS resolver."))
        .add_key(&svc2)
        .add_value(
            &svc2,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\spoolsv.exe"),
        )
        .add_value(&svc2, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc2, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc2, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .add_value(&svc2, "DisplayName", REG_SZ, &reg_sz("Print Spooler"))
        .add_value(&svc2, "Description", REG_SZ, &reg_sz("Manages printing."))
        .add_key(&svc3)
        .add_value(
            &svc3,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\SearchIndexer.exe"),
        )
        .add_value(&svc3, "Start", REG_DWORD, &reg_dword(3))
        .add_value(&svc3, "Type", REG_DWORD, &reg_dword(16))
        .add_value(&svc3, "ObjectName", REG_SZ, &reg_sz("LocalSystem"))
        .add_value(&svc3, "DisplayName", REG_SZ, &reg_sz("Windows Search"))
        .add_value(&svc3, "Description", REG_SZ, &reg_sz("Indexing service."))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 3, "should return all 3 service entries");
    // All three service names should be present
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"Dnscache"), "Dnscache should be in results");
    assert!(names.contains(&"Spooler"), "Spooler should be in results");
    assert!(names.contains(&"WSearch"), "WSearch should be in results");
}
