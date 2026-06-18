#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration tests for `winreg_artifacts::catalog_scan`.
//!
//! The catalog scanner is driven entirely by `forensicnomicon`'s registry
//! artifact catalog: it enumerates every registry descriptor whose hive matches
//! the hive under analysis, resolves the descriptor's key path, and emits the
//! decoded value(s). This proves coverage of artifacts winreg never hardcoded a
//! module for.
//!
//! RED phase: tests are written against the public API and must FAIL until
//! `catalog_scan` exists.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::catalog_scan::{scan, scan_users, CatalogHit, UserHive, UserIdentity};
use winreg_core::hive::Hive;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0x00, 0x00]); // NUL terminator
    out
}

const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

/// Add the root subkeys that make `detect_hive_type` classify a hive as SOFTWARE
/// (it looks for `Microsoft` + `Classes` at the root).
fn software_root(b: TestHiveBuilder) -> TestHiveBuilder {
    b.add_key("Classes")
}

/// Add the root subkeys that make `detect_hive_type` classify a hive as
/// NTUSER.DAT (it looks for `Software` plus a typical user-profile key).
fn ntuser_root(b: TestHiveBuilder) -> TestHiveBuilder {
    b.add_key("Software").add_key("Environment")
}

/// Find the hit whose catalog id matches.
fn find<'a>(hits: &'a [CatalogHit], id: &str) -> Option<&'a CatalogHit> {
    hits.iter().find(|h| h.catalog_id == id)
}

// ── Test 1: NEW COVERAGE — AppInit_DLLs (never had a winreg module) ──────────

#[test]
fn scan_surfaces_appinit_dlls_a_new_catalog_artifact() {
    // `appinit_dlls`: HklmSoftware, key `Microsoft\Windows NT\CurrentVersion\Windows`,
    // value `AppInit_DLLs`. winreg-artifacts has NO dedicated module for this —
    // it comes purely from the forensicnomicon catalog.
    let key = r"Microsoft\Windows NT\CurrentVersion\Windows";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(key)
        .add_value(key, "AppInit_DLLs", REG_SZ, &utf16le(r"C:\evil\inject.dll"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let hit = find(&hits, "appinit_dlls")
        .expect("catalog-driven scan must surface the AppInit_DLLs artifact");

    assert_eq!(hit.value_name.as_deref(), Some("AppInit_DLLs"));
    assert_eq!(hit.value_data, r"C:\evil\inject.dll");
    assert_eq!(hit.key_path, key);
}

// ── Test 2: empty hive yields no hits ────────────────────────────────────────

#[test]
fn scan_empty_software_hive_returns_no_hits() {
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    assert!(scan(&hive).is_empty());
}

// ── Test 3: regression — Run key still surfaces via the catalog ──────────────

#[test]
fn scan_still_surfaces_run_key_values() {
    let run = r"Microsoft\Windows\CurrentVersion\Run";
    let cmd = r"C:\Program Files\App\app.exe";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(run)
        .add_value(run, "MyApp", REG_SZ, &utf16le(cmd))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    // The Run key is a key-level descriptor (value_name: None) — its child values
    // must each become a hit.
    let run_hit = hits
        .iter()
        .find(|h| h.key_path == run && h.value_name.as_deref() == Some("MyApp"))
        .expect("Run-key value must surface via the catalog scan");
    assert_eq!(run_hit.value_data, cmd);
    assert_eq!(run_hit.catalog_id, "run_key_hklm");
}

// ── Test 4: DWORD decoder via catalog (InstallDate) ──────────────────────────

#[test]
fn scan_decodes_dword_value() {
    // `windows_install_date`: HklmSoftware, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
    // value `InstallDate`, decoder DwordLe. Catalog key_path carries an extra
    // leading `SOFTWARE\` (catalog quirk) — see notes.
    let key = r"Microsoft\Windows NT\CurrentVersion";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(key)
        .add_value(key, "InstallDate", REG_DWORD, &0x1234_5678u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    // Find any hit whose value_name is InstallDate under this key.
    let hit = hits
        .iter()
        .find(|h| h.value_name.as_deref() == Some("InstallDate"))
        .expect("InstallDate DWORD must surface via the catalog scan");
    assert_eq!(hit.value_data, "305419896"); // 0x12345678
}

// ── Test 5: hive-mismatched descriptors are not resolved ─────────────────────

#[test]
fn scan_only_resolves_matching_hive_descriptors() {
    // A SOFTWARE hive must never emit an NtUser-only artifact like `typed_urls`,
    // even if the key happens to exist.
    let key = r"Software\Microsoft\Internet Explorer\TypedURLs";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(key)
        .add_value(key, "url1", REG_SZ, &utf16le("https://example.com"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    assert!(
        find(&hits, "typed_urls").is_none(),
        "NtUser-only descriptor must not be resolved against a SOFTWARE hive"
    );
}

// ── Test 6: GLOB — trailing `*` expands a key family per child ───────────────

#[test]
fn scan_expands_trailing_star_into_one_hit_per_child_key() {
    // `fa_explorer_browser_helper_objects`: HklmSoftware, key-level descriptor
    // `Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\*`
    // (value_name: None). The trailing `*` is a *family*: every CLSID subkey
    // under "Browser Helper Objects" is a separate BHO registration. Glob
    // expansion must visit each child key and emit its value(s) — before glob
    // support these descriptors were skipped, yielding zero hits.
    let bho = r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
    let clsid_a = format!(r"{bho}\{{AAAAAAAA-0000-0000-0000-000000000001}}");
    let clsid_b = format!(r"{bho}\{{BBBBBBBB-0000-0000-0000-000000000002}}");
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(bho)
        .add_key(&clsid_a)
        .add_key(&clsid_b)
        .add_value(&clsid_a, "NoExplorer", REG_DWORD, &1u32.to_le_bytes())
        .add_value(&clsid_b, "NoExplorer", REG_DWORD, &0u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let bho_hits: Vec<&CatalogHit> = hits
        .iter()
        .filter(|h| h.catalog_id == "fa_explorer_browser_helper_objects")
        .collect();

    assert_eq!(
        bho_hits.len(),
        2,
        "trailing-* descriptor must expand to one hit per CLSID child key, got {bho_hits:?}"
    );
    // Each hit must carry the CONCRETE resolved child path, not the glob pattern.
    assert!(
        bho_hits.iter().any(|h| h.key_path == clsid_a),
        "expanded hit must carry the concrete child key path"
    );
    assert!(
        bho_hits.iter().any(|h| h.key_path == clsid_b),
        "expanded hit must carry the concrete child key path"
    );
    // The catalog id / name / meaning are preserved from the descriptor.
    assert!(bho_hits.iter().all(|h| !h.key_path.contains('*')));
}

// ── Test 7: GLOB — mid-segment `*` and `**` recursive descent ────────────────

#[test]
fn scan_expands_midsegment_star_and_double_star() {
    // `velociraptor_securityproviders_wdigest`: HklmSystem,
    // `SYSTEM\*ControlSet*\Control\SecurityProviders\WDigest\**`.
    // After hive-prefix normalization the path is `*ControlSet*\Control\
    // SecurityProviders\WDigest\**`. `*ControlSet*` matches `ControlSet001`
    // (mid-segment wildcard); `**` is recursive descent — it matches the WDigest
    // key itself and any nested subkeys. UseLogonCredential lives directly under
    // WDigest and must surface.
    let wdigest = r"ControlSet001\Control\SecurityProviders\WDigest";
    // The descriptor's decoder is Identity (text), so store the value as REG_SZ.
    let data = TestHiveBuilder::new()
        // Make detect_hive_type classify this as SYSTEM: needs Select + ControlSet001.
        .add_key("Select")
        .add_key(wdigest)
        .add_value(wdigest, "UseLogonCredential", REG_SZ, &utf16le("1"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let wdigest_hit = hits
        .iter()
        .find(|h| {
            h.catalog_id == "velociraptor_securityproviders_wdigest"
                && h.value_name.as_deref() == Some("UseLogonCredential")
        })
        .expect("`*ControlSet*` + `**` glob must resolve WDigest\\UseLogonCredential");
    assert_eq!(wdigest_hit.value_data, "1");
    assert!(wdigest_hit
        .key_path
        .starts_with(r"ControlSet001\Control\SecurityProviders\WDigest"));
}

// ── Test 8: MULTI-USER — per-user descriptor applies to every user hive ──────

/// Build an NTUSER hive carrying a single HKCU Run-key value.
fn ntuser_with_run(value_name: &str, cmd: &str) -> Vec<u8> {
    // `run_key_hkcu`: NtUser, key `Software\Microsoft\Windows\CurrentVersion\Run`
    // (the leading `Software\` is stripped to the hive-relative path).
    let run = r"Software\Microsoft\Windows\CurrentVersion\Run";
    ntuser_root(TestHiveBuilder::new())
        .add_key(r"Software\Microsoft")
        .add_key(r"Software\Microsoft\Windows")
        .add_key(r"Software\Microsoft\Windows\CurrentVersion")
        .add_key(run)
        .add_value(run, value_name, REG_SZ, &utf16le(cmd))
        .build()
}

#[test]
fn scan_users_applies_per_user_run_key_to_both_users() {
    let alice_cmd = r"C:\Users\alice\evil.exe";
    let bob_cmd = r"C:\Users\bob\backdoor.exe";

    let alice = UserHive {
        identity: UserIdentity {
            profile: Some("alice".to_string()),
            sid: Some("S-1-5-21-111-1001".to_string()),
        },
        hive: Hive::from_bytes(ntuser_with_run("AlicePersist", alice_cmd)).unwrap(),
    };
    let bob = UserHive {
        identity: UserIdentity {
            profile: Some("bob".to_string()),
            sid: Some("S-1-5-21-111-1002".to_string()),
        },
        hive: Hive::from_bytes(ntuser_with_run("BobPersist", bob_cmd)).unwrap(),
    };

    let hits = scan_users(&[alice, bob]);

    // The HKCU Run descriptor must resolve once per user, each tagged.
    let alice_hit = hits
        .iter()
        .find(|h| h.catalog_id == "run_key_hkcu" && h.value_name.as_deref() == Some("AlicePersist"))
        .expect("per-user Run descriptor must apply to alice's hive");
    let bob_hit = hits
        .iter()
        .find(|h| h.catalog_id == "run_key_hkcu" && h.value_name.as_deref() == Some("BobPersist"))
        .expect("per-user Run descriptor must apply to bob's hive");

    assert_eq!(alice_hit.value_data, alice_cmd);
    assert_eq!(
        alice_hit.user.as_ref().and_then(|u| u.profile.as_deref()),
        Some("alice")
    );
    assert_eq!(
        alice_hit.user.as_ref().and_then(|u| u.sid.as_deref()),
        Some("S-1-5-21-111-1001")
    );

    assert_eq!(bob_hit.value_data, bob_cmd);
    assert_eq!(
        bob_hit.user.as_ref().and_then(|u| u.profile.as_deref()),
        Some("bob")
    );

    // Cross-attribution must not happen: alice's hit is never tagged bob.
    assert!(hits.iter().all(|h| {
        let prof = h.user.as_ref().and_then(|u| u.profile.as_deref());
        !(h.value_name.as_deref() == Some("AlicePersist") && prof == Some("bob"))
    }));
}

// ── Test 9: MULTI-USER — formerly-`%%users.sid%%` descriptor resolves per user

#[test]
fn scan_users_resolves_users_sid_placeholder_descriptor() {
    // `fa_internet_explorer_main_noprotectedmodebanner` has `hive: None` and a
    // key_path of `HKEY_USERS\%%users.sid%%\Software\Microsoft\Internet Explorer\
    // Main\NoProtectedModeBanner` with `value_name: None`. After stripping the
    // `HKEY_USERS\<sid>\` per-user root, the scanner resolves the remainder as a
    // key and emits its child values; the proof is simply that the descriptor
    // now resolves against this user's hive (it was skipped before Build B).
    let resolved = r"Software\Microsoft\Internet Explorer\Main\NoProtectedModeBanner";
    let data = ntuser_root(TestHiveBuilder::new())
        .add_key(r"Software\Microsoft")
        .add_key(r"Software\Microsoft\Internet Explorer")
        .add_key(r"Software\Microsoft\Internet Explorer\Main")
        .add_key(resolved)
        .add_value(resolved, "Yes", REG_SZ, &utf16le("1"))
        .build();

    let user = UserHive {
        identity: UserIdentity {
            profile: Some("carol".to_string()),
            sid: None,
        },
        hive: Hive::from_bytes(data).unwrap(),
    };

    let hits = scan_users(&[user]);
    let hit = hits
        .iter()
        .find(|h| h.catalog_id == "fa_internet_explorer_main_noprotectedmodebanner")
        .expect("`%%users.sid%%` descriptor must resolve against a user's NTUSER hive");
    assert_eq!(
        hit.user.as_ref().and_then(|u| u.profile.as_deref()),
        Some("carol")
    );
    assert_eq!(hit.key_path, resolved);
}

// ── Test 10: machine scan() leaves the user field unset (no regression) ──────

#[test]
fn machine_scan_hits_have_no_user_attribution() {
    let run = r"Microsoft\Windows\CurrentVersion\Run";
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(run)
        .add_value(run, "MyApp", REG_SZ, &utf16le(r"C:\app.exe"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    assert!(
        hits.iter().all(|h| h.user.is_none()),
        "machine-hive scan() must not attribute hits to any user"
    );
}

// ── Test 11: catalog hit surfaces the resolved key's LastWriteTime ───────────

#[test]
fn scan_surfaces_key_last_written() {
    // Each hit's key carries a LastWriteTime ≈ when the artifact value was last
    // written — the forensic timestamp for the hit's source key.
    // FILETIME for 2020-09-19T03:40:00Z (Case-001 era).
    const FT: u64 = 132_449_604_000_000_000;
    let run = r"Microsoft\Windows\CurrentVersion\Run";
    let data = software_root(TestHiveBuilder::new())
        .with_key_times(FT)
        .add_key("Microsoft")
        .add_key(run)
        .add_value(run, "MyApp", REG_SZ, &utf16le(r"C:\app.exe"))
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let hit = hits
        .iter()
        .find(|h| h.key_path == run && h.value_name.as_deref() == Some("MyApp"))
        .expect("Run-key hit must surface via the catalog scan");
    let lw = hit
        .last_written
        .expect("catalog hit must carry its key LastWriteTime");
    assert_eq!(
        lw.timestamp(),
        1_600_486_800,
        "decoded FILETIME → 2020-09-19T03:40:00Z"
    );
}
