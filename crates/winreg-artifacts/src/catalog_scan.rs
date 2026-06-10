//! Catalog-driven registry artifact scanner.
//!
//! The artifact *knowledge* — which keys matter, what they mean, and how to
//! decode them — comes entirely from [`forensicnomicon`]'s registry catalog,
//! never from constants hardcoded here. This module is the thin resolver that
//! walks an open [`Hive`], looks up every catalog descriptor whose hive matches
//! the hive under analysis, opens the descriptor's key, and emits the decoded
//! value(s).
//!
//! winreg-core owns the registry-specific byte mechanics (REG_SZ is UTF-16LE on
//! disk, REG_DWORD is little-endian, …); the catalog owns the *meaning*. The two
//! meet here: the catalog's [`Decoder`] selects how winreg-core renders the
//! bytes, and the catalog supplies the path, label, MITRE mapping, and id.
//!
//! ## Scope and catalog quirks
//!
//! Some catalog `key_path` values are not directly resolvable against an offline
//! hive and are skipped (they simply produce no hit):
//!
//! - **Wildcards** (`*`, `**`) — the descriptor matches a family of keys, not a
//!   single key. Glob expansion is out of scope for this resolver.
//! - **SID / variable placeholders** (`%%users.sid%%`, `HKEY_USERS\…`) — the
//!   Velociraptor/forensic-artifacts-sourced descriptors carry live-system
//!   placeholders with no offline-hive equivalent.
//!
//! Two normalizations are applied so curated descriptors resolve cleanly:
//!
//! - A redundant leading hive prefix (`HKLM\`, `HKCU\`, or a leading `SOFTWARE\`
//!   / `SYSTEM\` that merely repeats the hive name) is stripped — catalog paths
//!   are nominally hive-relative, but some entries repeat the hive.
//! - `CurrentControlSet` (the SYSTEM-hive symlink the live registry resolves) is
//!   rewritten to `ControlSet001`, which is what an offline SYSTEM hive actually
//!   stores. This is the common case; a hive booted from a different control set
//!   is not consulted here.
//!
//! Complex binary artifacts (UserAssist, Shimcache/AppCompatCache, Amcache,
//! ShellBags, SAM) keep their dedicated decoders in the sibling modules; this
//! scanner flags such hits via [`CatalogHit::needs_specialized_decoder`] and
//! renders a best-effort placeholder, so callers can route to the right module.

use std::io::Cursor;

use forensicnomicon::catalog::{ArtifactDescriptor, ArtifactType, Decoder, HiveTarget, CATALOG};
use winreg_core::detect::HiveType;
use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;
use winreg_core::value::{decode_multi_sz, decode_utf16le, Value};

/// A single decoded artifact value surfaced by the catalog-driven scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CatalogHit {
    /// The catalog descriptor id that produced this hit (e.g. `"run_key_hklm"`).
    pub catalog_id: &'static str,
    /// Human-readable artifact name from the catalog.
    pub artifact_name: &'static str,
    /// Forensic meaning / significance from the catalog.
    pub meaning: &'static str,
    /// Registry key path actually opened (post-normalization, hive-relative).
    pub key_path: String,
    /// Value name, or `None` for a key-level descriptor's default value.
    pub value_name: Option<String>,
    /// Decoded value rendered as a string per the descriptor's decoder.
    pub value_data: String,
    /// MITRE ATT&CK techniques associated with the artifact (catalog-supplied).
    pub mitre_techniques: &'static [&'static str],
    /// `true` when the artifact needs one of the specialized binary decoders
    /// (UserAssist, Shimcache, …) rather than this generic value renderer.
    pub needs_specialized_decoder: bool,
}

/// Scan an open hive against the forensicnomicon registry catalog.
///
/// Only descriptors whose hive matches the hive under analysis are resolved.
/// Descriptors whose key path is not present, or is a wildcard / SID-placeholder
/// path, simply produce no hit.
#[must_use]
pub fn scan(hive: &Hive<Cursor<Vec<u8>>>) -> Vec<CatalogHit> {
    let Some(target) = hive_target_for(hive.detect_hive_type()) else {
        return Vec::new();
    };

    let mut hits = Vec::new();
    for descriptor in CATALOG.list() {
        if !is_registry(descriptor.artifact_type) {
            continue;
        }
        if descriptor.hive != Some(target) {
            continue;
        }
        let Some(path) = normalize_key_path(descriptor.key_path) else {
            continue;
        };
        let key = match hive.open_key(&path) {
            Ok(Some(k)) => k,
            _ => continue,
        };

        match descriptor.value_name {
            // Single named value.
            Some(vname) => {
                if let Ok(Some(val)) = key.value(vname) {
                    hits.push(make_hit(descriptor, &path, Some(vname.to_string()), &val));
                }
            }
            // Key-level descriptor: every child value is a hit.
            None => {
                let Ok(values) = key.values() else { continue };
                for val in values {
                    hits.push(make_hit(descriptor, &path, Some(val.name()), &val));
                }
            }
        }
    }
    hits
}

/// Map winreg-core's detected hive type to a forensicnomicon hive target.
fn hive_target_for(hive_type: HiveType) -> Option<HiveTarget> {
    match hive_type {
        HiveType::Software => Some(HiveTarget::HklmSoftware),
        HiveType::System => Some(HiveTarget::HklmSystem),
        HiveType::NtUser => Some(HiveTarget::NtUser),
        HiveType::UsrClass => Some(HiveTarget::UsrClass),
        HiveType::Sam => Some(HiveTarget::HklmSam),
        HiveType::Security => Some(HiveTarget::HklmSecurity),
        HiveType::Amcache => Some(HiveTarget::Amcache),
        _ => None,
    }
}

fn is_registry(at: ArtifactType) -> bool {
    matches!(at, ArtifactType::RegistryKey | ArtifactType::RegistryValue)
}

/// Normalize a catalog key path into an offline-hive-relative path, or `None`
/// if the path cannot be resolved against a single key (wildcard / placeholder).
///
/// The catalog stores backslash separators; some forensic-artifacts-sourced
/// entries carry doubled backslashes (`\\`) as ordinary string contents — those
/// are collapsed here.
fn normalize_key_path(raw: &str) -> Option<String> {
    // Reject wildcard families and live-system variable placeholders outright.
    if raw.contains('*') || raw.contains('%') || raw.contains('/') {
        return None;
    }
    // Collapse any doubled backslashes to single separators.
    let collapsed = raw.replace("\\\\", "\\");

    // Drop a leading hive-name prefix that merely repeats the hive.
    let mut path = collapsed.as_str();
    for prefix in [
        "HKEY_LOCAL_MACHINE\\",
        "HKEY_CURRENT_USER\\",
        "HKEY_USERS\\",
        "HKLM\\",
        "HKCU\\",
        "HKU\\",
    ] {
        if let Some(stripped) = strip_prefix_ci(path, prefix) {
            path = stripped;
        }
    }
    // An `HK*`-prefixed path that wasn't stripped is a placeholder form we skip.
    if path.starts_with("HK") && path.contains('\\') && looks_like_hive_root(path) {
        return None;
    }
    // Strip a redundant leading SOFTWARE\ or SYSTEM\ that repeats the hive root.
    for prefix in ["SOFTWARE\\", "SYSTEM\\"] {
        if let Some(stripped) = strip_prefix_ci(path, prefix) {
            path = stripped;
        }
    }

    // Translate the SYSTEM-hive CurrentControlSet symlink to its stored form.
    let resolved = if let Some(rest) = strip_prefix_ci(path, "CurrentControlSet") {
        format!("ControlSet001{rest}")
    } else {
        path.to_string()
    };

    if resolved.is_empty() {
        None
    } else {
        Some(resolved)
    }
}

/// Case-insensitive prefix strip on `\`-delimited registry paths.
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Heuristic: the first segment looks like an `HKEY_*` root that survived
/// prefix-stripping (i.e. an unsupported placeholder root).
fn looks_like_hive_root(path: &str) -> bool {
    path.split('\\')
        .next()
        .is_some_and(|seg| seg.eq_ignore_ascii_case("HKEY_USERS") || seg.starts_with("HKEY_"))
}

/// Build a [`CatalogHit`], rendering the value per the descriptor's decoder.
fn make_hit(
    descriptor: &ArtifactDescriptor,
    key_path: &str,
    value_name: Option<String>,
    val: &Value<'_>,
) -> CatalogHit {
    let (value_data, specialized) = render_value(descriptor.decoder, val);
    CatalogHit {
        catalog_id: descriptor.id,
        artifact_name: descriptor.name,
        meaning: descriptor.meaning,
        key_path: key_path.to_string(),
        value_name,
        value_data,
        mitre_techniques: descriptor.mitre_techniques,
        needs_specialized_decoder: specialized,
    }
}

/// Render a registry value to a display string using the catalog's decoder to
/// select the interpretation, and winreg-core for the registry byte mechanics.
///
/// Returns `(rendered, needs_specialized_decoder)`.
fn render_value(decoder: Decoder, val: &Value<'_>) -> (String, bool) {
    let raw = val.raw_data().unwrap_or_default();
    match decoder {
        // REG_SZ / REG_EXPAND_SZ text — UTF-16LE on disk.
        Decoder::Identity | Decoder::Utf16Le => (decode_utf16le(&raw), false),
        Decoder::DwordLe => (val.as_u32().unwrap_or(0).to_string(), false),
        Decoder::MultiSz => (decode_multi_sz(&raw).join("; "), false),
        Decoder::FiletimeAt { offset } => {
            let ts = raw
                .get(offset..offset + 8)
                .map(|b| winreg_core::bytes::le_u64(b, 0))
                .and_then(filetime_to_datetime)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
            (ts.unwrap_or_default(), false)
        }
        // Binary record / ROT13 / ESE artifacts have dedicated decoders elsewhere.
        Decoder::Rot13Name
        | Decoder::Rot13NameWithBinaryValue(_)
        | Decoder::BinaryRecord(_)
        | Decoder::MruListEx
        | Decoder::EseDatabase
        | Decoder::PipeDelimited { .. } => {
            // Best-effort: surface the raw value as text so the hit is not empty,
            // and flag that a specialized decoder should be consulted.
            (decode_utf16le(&raw), true)
        }
        // `Decoder` is `#[non_exhaustive]`: degrade gracefully on future variants.
        _ => (decode_utf16le(&raw), true),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_redundant_software_prefix() {
        assert_eq!(
            normalize_key_path(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion").as_deref(),
            Some(r"Microsoft\Windows NT\CurrentVersion")
        );
    }

    #[test]
    fn normalize_translates_current_control_set() {
        assert_eq!(
            normalize_key_path(r"CurrentControlSet\Services").as_deref(),
            Some(r"ControlSet001\Services")
        );
    }

    #[test]
    fn normalize_rejects_wildcard_and_placeholder() {
        assert!(normalize_key_path(r"Software\Foo\*").is_none());
        assert!(normalize_key_path(r"HKEY_USERS\%%users.sid%%\Software\X").is_none());
    }

    #[test]
    fn normalize_collapses_doubled_backslashes() {
        assert_eq!(
            normalize_key_path(r"Microsoft\\Windows\\CurrentVersion\\Run").as_deref(),
            Some(r"Microsoft\Windows\CurrentVersion\Run")
        );
    }

    #[test]
    fn normalize_strips_hk_prefix() {
        assert_eq!(
            normalize_key_path(r"HKLM\Microsoft\Foo").as_deref(),
            Some(r"Microsoft\Foo")
        );
    }
}
