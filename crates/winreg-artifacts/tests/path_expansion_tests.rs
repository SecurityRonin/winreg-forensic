#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Characterization tests for the unified `path_expansion` engine.
//!
//! Glob, multi-user, and control-set resolution are the *same operation*: a
//! catalog path with variable segments, each ranging over an enumerable domain,
//! expanded to concrete paths each tagged with its `Binding`s.
//!
//! Build A (refactor) proves the engine reproduces the existing glob and
//! per-user behavior and that every hit now carries its `Binding` provenance.

mod common;

use common::hive_builder::TestHiveBuilder;
use winreg_artifacts::catalog_scan::{scan, scan_users, UserHive, UserIdentity};
use winreg_artifacts::path_expansion::{expand, resolve_control_sets, Binding, Segment, Wildcard};
use winreg_core::hive::Hive;

fn utf16le(s: &str) -> Vec<u8> {
    let mut out: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

fn software_root(b: TestHiveBuilder) -> TestHiveBuilder {
    b.add_key("Classes")
}

fn ntuser_root(b: TestHiveBuilder) -> TestHiveBuilder {
    b.add_key("Software").add_key("Environment")
}

// ── The engine: a Subkey-source `*` segment ranges over child keys ───────────

#[test]
fn expand_subkey_source_yields_concrete_paths_with_bindings() {
    // Template: Parent\* — the `*` is a Subkey-domain variable.
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(r"Parent")
        .add_key(r"Parent\ChildA")
        .add_key(r"Parent\ChildB")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();

    let segments = vec![
        Segment::Literal("Parent".to_string()),
        Segment::Variable(Wildcard::Subkey, "*".to_string()),
    ];

    let mut out: Vec<(Vec<Binding>, String)> = Vec::new();
    expand(&root, &segments, None, &mut |bindings, path, _key| {
        out.push((bindings.to_vec(), path.to_string()));
    });

    // Two children, each a concrete path tagged with a Subkey binding.
    let mut paths: Vec<String> = out.iter().map(|(_, p)| p.clone()).collect();
    paths.sort();
    assert_eq!(paths, vec![r"Parent\ChildA", r"Parent\ChildB"]);

    let child_a = out.iter().find(|(_, p)| p == r"Parent\ChildA").unwrap();
    assert_eq!(child_a.0.len(), 1);
    assert_eq!(child_a.0[0].kind, Wildcard::Subkey);
    assert_eq!(child_a.0[0].value, "ChildA");
}

// ── Characterization: glob scan() hits carry their Subkey bindings ───────────

#[test]
fn glob_scan_hits_carry_subkey_bindings() {
    // The BHO descriptor's trailing `*` expands per CLSID child; each hit must
    // now carry the concrete child name as a Subkey binding.
    let bho = r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
    let clsid_a = format!(r"{bho}\{{AAAAAAAA-0000-0000-0000-000000000001}}");
    let data = software_root(TestHiveBuilder::new())
        .add_key("Microsoft")
        .add_key(bho)
        .add_key(&clsid_a)
        .add_value(&clsid_a, "NoExplorer", REG_DWORD, &1u32.to_le_bytes())
        .build();
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let hit = hits
        .iter()
        .find(|h| h.catalog_id == "fa_explorer_browser_helper_objects")
        .expect("BHO glob descriptor must resolve");

    let sub = hit
        .bindings
        .iter()
        .find(|b| b.kind == Wildcard::Subkey)
        .expect("a trailing-* hit must carry a Subkey binding");
    assert_eq!(sub.value, "{AAAAAAAA-0000-0000-0000-000000000001}");
}

// ── Characterization: per-user scan_users() hits carry a User binding ────────

fn ntuser_with_run(value_name: &str, cmd: &str) -> Vec<u8> {
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
fn multi_user_hits_carry_user_binding() {
    let alice = UserHive {
        identity: UserIdentity {
            profile: Some("alice".to_string()),
            sid: Some("S-1-5-21-111-1001".to_string()),
        },
        hive: Hive::from_bytes(ntuser_with_run("AlicePersist", r"C:\evil.exe")).unwrap(),
    };

    let hits = scan_users(&[alice]);
    let hit = hits
        .iter()
        .find(|h| h.catalog_id == "run_key_hkcu" && h.value_name.as_deref() == Some("AlicePersist"))
        .expect("per-user Run descriptor must resolve");

    // The User binding identifies which user-domain element produced this hit;
    // it is the SID when known (else the profile name).
    let user_b = hit
        .bindings
        .iter()
        .find(|b| b.kind == Wildcard::User)
        .expect("a per-user hit must carry a User binding");
    assert_eq!(user_b.value, "S-1-5-21-111-1001");

    // The legacy `user` field is preserved for existing callers.
    assert_eq!(
        hit.user.as_ref().and_then(|u| u.profile.as_deref()),
        Some("alice")
    );
}

// ── Build B: CurrentControlSet resolves via Select\Current, not hardcoded 001 ─

/// Build a SYSTEM hive whose active control set is `Select\Current = current`.
/// `ControlSet001` exists (needed for SYSTEM detection) and carries a *decoy*
/// Lsa value; the real value lives under `ControlSet00{current}`.
fn system_hive_with_select_current(current: u32, real_dll: &str, decoy_dll: &str) -> Vec<u8> {
    let active = format!("ControlSet{current:03}");
    let active_lsa = format!(r"{active}\Control\Lsa");
    let cs001_lsa = r"ControlSet001\Control\Lsa";
    let mut b = TestHiveBuilder::new()
        // SYSTEM detection needs `Select` + `ControlSet001`.
        .add_key("Select")
        .add_value("Select", "Current", REG_DWORD, &current.to_le_bytes())
        .add_key("ControlSet001")
        .add_key(r"ControlSet001\Control")
        .add_key(cs001_lsa)
        // Decoy value under set 001 — surfaced only by the old hardcoded path.
        .add_value(
            cs001_lsa,
            "Authentication Packages",
            REG_SZ,
            &utf16le(decoy_dll),
        );
    if active != "ControlSet001" {
        b = b
            .add_key(&active)
            .add_key(&format!(r"{active}\Control"))
            .add_key(&active_lsa);
    }
    b.add_value(
        &active_lsa,
        "Authentication Packages",
        REG_SZ,
        &utf16le(real_dll),
    )
    .build()
}

#[test]
fn current_control_set_resolves_against_select_current() {
    // Select\Current = 2 → the `lsa_auth_packages` descriptor (concrete
    // `CurrentControlSet\Control\Lsa`) must resolve against ControlSet002, NOT
    // the hardcoded ControlSet001. The 001 Lsa carries a decoy that must NOT win.
    let data = system_hive_with_select_current(2, "evil.dll", "decoy_msv1_0.dll");
    let hive = Hive::from_bytes(data).unwrap();

    let hits = scan(&hive);
    let hit = hits
        .iter()
        .find(|h| h.catalog_id == "lsa_auth_packages")
        .expect("CurrentControlSet descriptor must resolve via Select\\Current");

    // Resolved against the ACTIVE set (002), so the real DLL — never the decoy.
    assert_eq!(hit.value_data, "evil.dll");
    assert!(hit.key_path.starts_with(r"ControlSet002\Control\Lsa"));

    // And it carries the {ControlSet, "ControlSet002"} binding for provenance.
    let cs = hit
        .bindings
        .iter()
        .find(|b| b.kind == Wildcard::ControlSet)
        .expect("a CurrentControlSet hit must carry a ControlSet binding");
    assert_eq!(cs.value, "ControlSet002");
}

#[test]
fn resolve_control_sets_reads_select_current() {
    // Direct unit-level proof the resolver reads Select\Current = 3.
    let data = system_hive_with_select_current(3, "x.dll", "decoy.dll");
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    let resolver = resolve_control_sets(&root);
    assert_eq!(resolver.sets, vec!["ControlSet003".to_string()]);
}

#[test]
fn resolve_control_sets_falls_back_to_001_when_select_absent() {
    // No Select key at all → degrade to ControlSet001, never panic.
    let data = TestHiveBuilder::new()
        .add_key("Select")
        .add_key("ControlSet001")
        .build();
    let hive = Hive::from_bytes(data).unwrap();
    let root = hive.root_key().unwrap();
    // Select exists for detection but has no `Current` value → fallback.
    let resolver = resolve_control_sets(&root);
    assert_eq!(resolver.sets, vec!["ControlSet001".to_string()]);
}
