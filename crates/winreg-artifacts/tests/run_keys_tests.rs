#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::run_keys`.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! the implementation is complete.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::run_keys::{classify_run_entry, parse};
use winreg_core::hive::Hive;

// ── Helper: encode a string as UTF-16LE with null terminator ─────────────────

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.extend_from_slice(&[0x00, 0x00]); // null terminator
    out
}

// ── Test 1: empty hive returns empty ─────────────────────────────────────────

#[test]
fn parse_empty_hive_returns_empty() {
    let data = TestHiveBuilder::new().build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert!(
        entries.is_empty(),
        "empty hive (no Run keys) should return empty Vec"
    );
}

// ── Test 2: Run key entry is returned ────────────────────────────────────────

#[test]
fn parse_run_key_returns_entry() {
    let run_path = "Microsoft\\Windows\\CurrentVersion\\Run";
    let cmd = r"C:\Program Files\App\app.exe";
    let data = TestHiveBuilder::new()
        .add_key(run_path)
        .add_value(run_path, "MyApp", 1, &utf16le(cmd))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "expected 1 entry, got {}", entries.len());
    assert_eq!(entries[0].value_name, "MyApp");
    assert_eq!(entries[0].command, cmd);
    assert_eq!(
        entries[0].key_path,
        "Microsoft\\Windows\\CurrentVersion\\Run"
    );
}

// ── Test 3: RunOnce key is included ──────────────────────────────────────────

#[test]
fn parse_runonce_is_included() {
    let runonce_path = "Microsoft\\Windows\\CurrentVersion\\RunOnce";
    let cmd = r"C:\Temp\setup.exe /q";
    let data = TestHiveBuilder::new()
        .add_key(runonce_path)
        .add_value(runonce_path, "Setup", 1, &utf16le(cmd))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "expected 1 entry from RunOnce");
    assert_eq!(entries[0].value_name, "Setup");
    assert!(
        entries[0].key_path.contains("RunOnce"),
        "key_path should reference RunOnce"
    );
}

// ── Test 4: classify_run_entry — powershell -enc is suspicious ────────────────

#[test]
fn classify_powershell_enc_is_suspicious() {
    let reason = classify_run_entry("powershell.exe -enc ZQBjAGgAbwAgAEgAZQBsAGwAbwA=");
    assert!(
        reason.is_some(),
        "powershell -enc should be classified suspicious"
    );
}

// ── Test 5: classify_run_entry — mshta is suspicious ─────────────────────────

#[test]
fn classify_mshta_is_suspicious() {
    let reason = classify_run_entry("mshta vbscript:Execute(\"CreateObject(...)\")")  ;
    assert!(reason.is_some(), "mshta should be classified suspicious");
}

// ── Test 6: classify_run_entry — certutil -decode is suspicious ───────────────

#[test]
fn classify_certutil_decode_is_suspicious() {
    let reason = classify_run_entry(
        "certutil -decode C:\\Windows\\Temp\\payload.b64 C:\\Windows\\Temp\\payload.exe",
    );
    assert!(reason.is_some(), "certutil -decode should be classified suspicious");
}

// ── Test 7: classify_run_entry — rundll32 from temp is suspicious ─────────────

#[test]
fn classify_rundll32_from_temp_is_suspicious() {
    let reason = classify_run_entry(r"rundll32.exe C:\Users\victim\AppData\Local\Temp\evil.dll,EP");
    assert!(reason.is_some(), "rundll32 from temp should be classified suspicious");
}

// ── Test 8: classify_run_entry — normal path is benign ───────────────────────

#[test]
fn classify_normal_path_is_benign() {
    let reason = classify_run_entry(r"C:\Program Files\App\app.exe");
    assert!(reason.is_none(), "normal program path should not be suspicious");
}

// ── Test 9: suspicious entry sets is_suspicious flag ─────────────────────────

#[test]
fn parse_suspicious_entry_sets_flag() {
    let run_path = "Microsoft\\Windows\\CurrentVersion\\Run";
    let cmd = "powershell -enc ZQBjAGgAbwAgAHQAZQBzAHQA";
    let data = TestHiveBuilder::new()
        .add_key(run_path)
        .add_value(run_path, "EvilPersist", 1, &utf16le(cmd))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].is_suspicious,
        "powershell -enc entry must have is_suspicious=true"
    );
    assert!(
        entries[0].suspicious_reason.is_some(),
        "suspicious_reason must be Some for a flagged entry"
    );
}

// ── Test 10: Winlogon Userinit value is captured ──────────────────────────────

#[test]
fn parse_winlogon_userinit_is_captured() {
    let winlogon_path = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    let cmd = r"C:\Windows\system32\userinit.exe,";
    let data = TestHiveBuilder::new()
        .add_key(winlogon_path)
        .add_value(winlogon_path, "Userinit", 1, &utf16le(cmd))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1, "Winlogon Userinit should be captured");
    assert_eq!(entries[0].value_name, "Userinit");
    assert!(
        entries[0].key_path.contains("Winlogon"),
        "key_path should reference Winlogon"
    );
}

// ── Test 11: hive field is "HKLM" for a SOFTWARE-type hive ───────────────────

#[test]
fn hive_type_detected_for_hklm() {
    // Build a hive that looks like SOFTWARE: must have Microsoft + Classes subkeys
    // at root (see detect.rs detection logic).
    let run_path = "Microsoft\\Windows\\CurrentVersion\\Run";
    let data = TestHiveBuilder::new()
        .add_key("Microsoft")       // triggers SOFTWARE detection
        .add_key("Classes")         // triggers SOFTWARE detection
        .add_key(run_path)
        .add_value(run_path, "TestApp", 1, &utf16le(r"C:\test\app.exe"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].hive, "HKLM",
        "SOFTWARE hive should produce hive=\"HKLM\", got \"{}\"",
        entries[0].hive
    );
}
