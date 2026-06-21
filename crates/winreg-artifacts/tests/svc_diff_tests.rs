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
const REG_EXPAND_SZ: u32 = 2;
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
        None, // service_dll
        None, // failure_command
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
        Some(r"%SystemRoot%\System32\dnsrslvr.dll"),
        None,
    );
    assert!(
        !is_suspicious,
        "normal system32 auto-start service with description and benign ServiceDll should be benign"
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

// ---------------------------------------------------------------------------
// Test 11: parse_service_dll_from_parameters_subkey
//
// A svchost-hosted (ShareProcess) service loads its real code from a DLL named
// in `<service>\Parameters\ServiceDll`. `image_path` is just svchost.exe, so the
// DLL is the actual persistence/implant vector (T1543.003). `parse` must surface
// it as `service_dll`.
// ---------------------------------------------------------------------------

#[test]
fn parse_service_dll_from_parameters_subkey() {
    let svc = svc_key("Dnscache");
    let params = format!("{svc}\\Parameters");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\svchost.exe -k NetworkService"),
        )
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .add_value(&svc, "Type", REG_DWORD, &reg_dword(32))
        .add_value(
            &svc,
            "ObjectName",
            REG_SZ,
            &reg_sz("NT AUTHORITY\\NetworkService"),
        )
        .add_value(&svc, "Description", REG_SZ, &reg_sz("Resolves DNS names."))
        .add_key(&params)
        .add_value(
            &params,
            "ServiceDll",
            REG_EXPAND_SZ,
            &reg_sz(r"%SystemRoot%\System32\dnsrslvr.dll"),
        )
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    let e = entries
        .iter()
        .find(|e| e.name == "Dnscache")
        .expect("Dnscache entry");
    assert_eq!(
        e.service_dll.as_deref(),
        Some(r"%SystemRoot%\System32\dnsrslvr.dll"),
        "service_dll should be the raw (unexpanded) Parameters\\ServiceDll value"
    );
}

// ---------------------------------------------------------------------------
// Test 12: parse_service_without_servicedll_is_none
// ---------------------------------------------------------------------------

#[test]
fn parse_service_without_servicedll_is_none() {
    let svc = svc_key("Spooler");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\spoolsv.exe"),
        )
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    let e = entries.iter().find(|e| e.name == "Spooler").expect("entry");
    assert_eq!(
        e.service_dll, None,
        "a service with no Parameters\\ServiceDll must yield None, not empty string"
    );
}

// ---------------------------------------------------------------------------
// Test 13: parse_failure_command_extracted
//
// `<service>\FailureCommand` is a recovery-action command line; an attacker can
// point it at arbitrary code that runs when the service "fails". `parse` must
// surface it as `failure_command`.
// ---------------------------------------------------------------------------

#[test]
fn parse_failure_command_extracted() {
    let svc = svc_key("MSiSCSI");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\svchost.exe -k netsvcs"),
        )
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(3))
        .add_value(&svc, "FailureCommand", REG_SZ, &reg_sz("customScript.cmd"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    let e = entries.iter().find(|e| e.name == "MSiSCSI").expect("entry");
    assert_eq!(
        e.failure_command.as_deref(),
        Some("customScript.cmd"),
        "failure_command should equal the FailureCommand value"
    );
}

#[test]
fn parse_service_without_failure_command_is_none() {
    let svc = svc_key("Dnscache");
    let data = TestHiveBuilder::new()
        .add_key(&svc)
        .add_value(
            &svc,
            "ImagePath",
            REG_SZ,
            &reg_sz(r"C:\Windows\system32\svchost.exe"),
        )
        .add_value(&svc, "Start", REG_DWORD, &reg_dword(2))
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let entries = parse(&hive);
    let e = entries
        .iter()
        .find(|e| e.name == "Dnscache")
        .expect("entry");
    assert_eq!(e.failure_command, None);
}

// ---------------------------------------------------------------------------
// Test 14: classify applies user-writable / LOLBin rules to ServiceDll
// ---------------------------------------------------------------------------

#[test]
fn classify_servicedll_in_user_writable_dir_is_suspicious() {
    // ImagePath is benign svchost.exe; the DLL lives in a user-writable dir.
    let (is_suspicious, reason) = classify_service(
        r"C:\Windows\system32\svchost.exe -k netsvcs",
        2,
        "Looks legit.",
        "LocalSystem",
        Some(r"C:\Users\Public\evil.dll"),
        None,
    );
    assert!(
        is_suspicious,
        "ServiceDll in a user-writable directory must be flagged suspicious"
    );
    let reason = reason.expect("reason");
    assert!(
        reason.to_ascii_lowercase().contains("servicedll")
            || reason.to_ascii_lowercase().contains("service dll"),
        "reason should mention ServiceDll, got: {reason}"
    );
}

#[test]
fn classify_servicedll_lolbin_is_suspicious() {
    let (is_suspicious, _reason) = classify_service(
        r"C:\Windows\system32\svchost.exe -k netsvcs",
        2,
        "Looks legit.",
        "LocalSystem",
        Some(r"C:\Windows\Temp\rundll-payload\powershell.exe"),
        None,
    );
    assert!(
        is_suspicious,
        "a LOLBin / user-writable path in ServiceDll must be flagged"
    );
}

#[test]
fn classify_benign_servicedll_is_not_suspicious() {
    let (is_suspicious, _reason) = classify_service(
        r"C:\Windows\system32\svchost.exe -k netsvcs",
        2,
        "Resolves DNS.",
        "LocalSystem",
        Some(r"%SystemRoot%\System32\dnsrslvr.dll"),
        None,
    );
    assert!(
        !is_suspicious,
        "a normal system32 ServiceDll must not be flagged"
    );
}

#[test]
fn classify_non_empty_failure_command_is_noteworthy() {
    // Everything else benign; a configured FailureCommand alone is noteworthy.
    let (is_suspicious, reason) = classify_service(
        r"C:\Windows\system32\svchost.exe -k netsvcs",
        2,
        "Resolves DNS.",
        "LocalSystem",
        Some(r"%SystemRoot%\System32\dnsrslvr.dll"),
        Some("customScript.cmd"),
    );
    assert!(
        is_suspicious,
        "a non-empty FailureCommand should be flagged as noteworthy"
    );
    let reason = reason.expect("reason");
    assert!(
        reason.to_ascii_lowercase().contains("failurecommand")
            || reason.to_ascii_lowercase().contains("failure command")
            || reason.to_ascii_lowercase().contains("recovery"),
        "reason should mention FailureCommand, got: {reason}"
    );
}

// ---------------------------------------------------------------------------
// Real-data validation (env-gated): DC01 SYSTEM hive (DFIR Madness Szechuan).
//
// Set WINREG_DC01_SYSTEM to the extracted DC01 SYSTEM hive to run. Skips loudly
// when absent. This proves ServiceDll resolution works through the offline
// `Select\Current` → `ControlSet00N` indirection on REAL svchost services —
// something the synthetic fixtures (which build a flat layout) cannot prove.
// Ground truth captured 2026-06-22 from md5 05cd86230d5bdbcade8fd6da1d5313a4.
// ---------------------------------------------------------------------------

#[test]
fn dc01_real_hive_resolves_svchost_servicedlls() {
    let Ok(path) = std::env::var("WINREG_DC01_SYSTEM") else {
        eprintln!(
            "SKIP dc01_real_hive_resolves_svchost_servicedlls: \
             set WINREG_DC01_SYSTEM to the DC01 SYSTEM hive path"
        );
        return;
    };
    let hive = Hive::from_path(std::path::Path::new(&path))
        .expect("DC01 SYSTEM hive must open (check WINREG_DC01_SYSTEM path)");
    let entries = parse(&hive);

    let find = |name: &str| {
        entries
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("service {name} not found in DC01 hive"))
    };

    // (a) Well-known svchost-hosted services resolve their real ServiceDll
    // through the offline Select\Current indirection.
    let dns = find("Dnscache");
    assert_eq!(
        dns.service_dll.as_deref(),
        Some(r"%SystemRoot%\System32\dnsrslvr.dll"),
        "Dnscache ServiceDll"
    );
    let sched = find("Schedule");
    assert_eq!(
        sched.service_dll.as_deref(),
        Some(r"%systemroot%\system32\schedsvc.dll"),
        "Task Scheduler ServiceDll"
    );
    let bits = find("BITS");
    assert_eq!(
        bits.service_dll.as_deref(),
        Some(r"%SystemRoot%\System32\qmgr.dll"),
        "BITS ServiceDll"
    );

    // (b) The count of services with a ServiceDll is in the expected ballpark
    // (~111 svchost-hosted; this hive has 117 of 453).
    let with_dll = entries.iter().filter(|e| e.service_dll.is_some()).count();
    assert!(
        (90..=140).contains(&with_dll),
        "expected ~111 services with a ServiceDll, got {with_dll}"
    );

    // FailureCommand is present on a handful of services (3 on this hive).
    let with_fc = entries
        .iter()
        .filter(|e| e.failure_command.is_some())
        .count();
    assert!(
        with_fc >= 1,
        "expected at least one service with a FailureCommand, got {with_fc}"
    );
    let iscsi = find("MSiSCSI");
    assert_eq!(
        iscsi.failure_command.as_deref(),
        Some("customScript.cmd"),
        "MSiSCSI FailureCommand"
    );
}
