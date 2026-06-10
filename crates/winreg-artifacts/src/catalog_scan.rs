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
use std::path::Path;

use forensicnomicon::catalog::{ArtifactDescriptor, ArtifactType, Decoder, HiveTarget, CATALOG};
use winreg_core::detect::HiveType;
use winreg_core::hive::Hive;
use winreg_core::key::{filetime_to_datetime, Key};
use winreg_core::value::{decode_multi_sz, decode_utf16le, Value};

/// Maximum key-tree depth a `**` recursive-descent glob will walk.
///
/// Untrusted hives can be crafted with pathological nesting; this bounds the
/// recursion so a malicious image cannot drive unbounded stack/heap growth.
const MAX_GLOB_DEPTH: usize = 64;

/// Maximum number of concrete keys a single glob descriptor may expand to.
///
/// Caps breadth so a hive with millions of sibling keys under a `*` cannot make
/// one descriptor produce an unbounded result set (allocation bomb defence).
const MAX_GLOB_MATCHES: usize = 4096;

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
    /// The user this hit is attributed to, or `None` for machine-wide hives
    /// (SYSTEM/SOFTWARE/SAM/SECURITY) scanned via [`scan`].
    pub user: Option<UserIdentity>,
}

/// Identity of the user a per-user [`CatalogHit`] is attributed to.
///
/// Offline, a per-user artifact lives in one user's `NTUSER.DAT` / `UsrClass.dat`.
/// At least one of `profile` / `sid` is populated; both may be present when the
/// caller could resolve the SID (e.g. from `ProfileList` or the hive path).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct UserIdentity {
    /// Profile/account name, typically the profile directory name (e.g. `"alice"`).
    pub profile: Option<String>,
    /// Security identifier (e.g. `"S-1-5-21-…-1001"`) when known.
    pub sid: Option<String>,
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
    let Ok(root) = hive.root_key() else {
        return hits;
    };
    // HKLM SOFTWARE/SYSTEM paths sometimes repeat the hive name as a leading
    // `SOFTWARE\`/`SYSTEM\`; that redundancy is stripped only for those hives.
    let strip_hive_root = matches!(target, HiveTarget::HklmSoftware | HiveTarget::HklmSystem);
    for descriptor in CATALOG.list() {
        if !is_registry(descriptor.artifact_type) {
            continue;
        }
        if descriptor.hive != Some(target) {
            continue;
        }
        resolve_descriptor(
            &root,
            descriptor,
            descriptor.key_path,
            strip_hive_root,
            None,
            &mut hits,
        );
    }
    hits
}

/// A user's registry hive paired with the identity it belongs to.
///
/// Built by the caller (or [`discover_user_hives`]) for each `NTUSER.DAT` /
/// `UsrClass.dat` found under a mounted image's profile root.
pub struct UserHive {
    /// Who this hive belongs to (profile name and/or SID).
    pub identity: UserIdentity,
    /// The opened per-user hive.
    pub hive: Hive<Cursor<Vec<u8>>>,
}

/// Scan a set of per-user hives against the catalog, attributing every hit to
/// the user it came from.
///
/// For each hive this applies:
/// - the `NtUser` / `UsrClass` hive-tagged descriptors matching the hive's
///   detected type, and
/// - the `hive: None` registry descriptors whose path carries a live-system
///   per-user placeholder (`HKEY_USERS\%%users.sid%%\…`, `HKU\*\…`) — offline,
///   the placeholder segment *is* the user, so the remainder resolves against
///   this user's hive root.
///
/// Every resulting [`CatalogHit`] carries `user = Some(identity)`. Machine
/// hives (SYSTEM/SOFTWARE/SAM/SECURITY) are handled by [`scan`] instead and are
/// unaffected.
#[must_use]
pub fn scan_users(user_hives: &[UserHive]) -> Vec<CatalogHit> {
    let mut hits = Vec::new();
    for uh in user_hives {
        let target = hive_target_for(uh.hive.detect_hive_type());
        let Ok(root) = uh.hive.root_key() else {
            continue;
        };
        for descriptor in CATALOG.list() {
            if !is_registry(descriptor.artifact_type) {
                continue;
            }
            // Hive-tagged per-user descriptor whose target matches this hive.
            let raw_path = if descriptor.hive == target {
                Some(descriptor.key_path)
            } else if descriptor.hive.is_none() || descriptor.hive == Some(HiveTarget::None) {
                // Untagged descriptor that addresses a user via an HKU placeholder.
                strip_user_placeholder_prefix(descriptor.key_path)
            } else {
                None
            };
            if let Some(path) = raw_path {
                // Per-user hives keep `Software\…` literally — never strip it.
                resolve_descriptor(
                    &root,
                    descriptor,
                    path,
                    false,
                    Some(&uh.identity),
                    &mut hits,
                );
            }
        }
    }
    hits
}

/// Discover every per-user hive under a mounted-image root and open it into a
/// profile-tagged [`UserHive`], ready for [`scan_users`].
///
/// Delegates the filesystem walk to [`winreg_discover::discover_hives`], then
/// keeps only the `NTUSER.DAT` / `UsrClass.dat` sources, opening each and
/// deriving the profile name from its `Users/<name>/…` path. A hive that fails
/// to open (truncated, wrong format) is skipped rather than aborting the scan.
///
/// The SID is left `None` here — it is not recoverable from the profile path
/// alone; a caller that has the SOFTWARE hive's `ProfileList` can fill it in.
#[must_use]
pub fn discover_user_hives(evidence_root: &Path) -> Vec<UserHive> {
    let mut out = Vec::new();
    for source in winreg_discover::discover_hives(evidence_root) {
        if !matches!(source.hive_type, HiveType::NtUser | HiveType::UsrClass) {
            continue;
        }
        let Ok(hive) = Hive::from_path(&source.path) else {
            continue;
        };
        out.push(UserHive {
            identity: UserIdentity {
                profile: profile_name_from_path(&source.path),
                sid: None,
            },
            hive,
        });
    }
    out
}

/// Derive the profile/account name from a `…/Users/<name>/…` hive path.
fn profile_name_from_path(path: &Path) -> Option<String> {
    let components: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();
    let idx = components
        .iter()
        .position(|c| c.eq_ignore_ascii_case("Users"))?;
    components.get(idx + 1).cloned()
}

/// Strip a live-system per-user root prefix (`HKEY_USERS\<sid>\` or `HKU\<sid>\`)
/// from a descriptor path, returning the user-hive-relative remainder.
///
/// The `<sid>` segment is the SID placeholder the descriptor uses to address a
/// specific user (`%%users.sid%%`, `*`, or a literal SID); offline that segment
/// selects *which* hive, so we drop it and resolve the rest against the user's
/// own hive root. Returns `None` if the path does not start with such a root.
fn strip_user_placeholder_prefix(raw: &str) -> Option<&str> {
    let rest = strip_prefix_ci(raw, "HKEY_USERS\\").or_else(|| strip_prefix_ci(raw, "HKU\\"))?;
    // Drop the next segment (the SID / placeholder) and keep the remainder.
    let (_sid_segment, remainder) = rest.split_once('\\')?;
    if remainder.is_empty() {
        None
    } else {
        Some(remainder)
    }
}

/// Resolve a single descriptor against an already-open key tree rooted at
/// `root`, using `raw_path` as the (possibly wildcard, placeholder-free) key
/// path and pushing every produced [`CatalogHit`] (tagged with `user`) onto
/// `hits`. Wildcard (`*` / `**`) paths are glob-expanded; concrete paths open a
/// single key.
///
/// `raw_path` is taken explicitly rather than read from `descriptor.key_path`
/// so the multi-user scan can feed a SID-placeholder-stripped, hive-relative
/// path while still attributing the hit to the original descriptor.
fn resolve_descriptor(
    root: &Key<'_>,
    descriptor: &ArtifactDescriptor,
    raw_path: &str,
    strip_hive_root: bool,
    user: Option<&UserIdentity>,
    hits: &mut Vec<CatalogHit>,
) {
    // Wildcard family — glob-expand to concrete child keys.
    if let Some(segments) = normalize_glob_path(raw_path, strip_hive_root) {
        let mut matched = 0usize;
        expand_glob(root, &segments, "", 0, &mut matched, &mut |path, key| {
            emit_key(descriptor, path, key, user, hits);
        });
        return;
    }
    // Concrete single key.
    let Some(path) = normalize_concrete_path(raw_path, strip_hive_root) else {
        return;
    };
    if let Ok(Some(key)) = root.subkey_path(&path) {
        emit_key(descriptor, &path, &key, user, hits);
    }
}

/// Emit the descriptor's value(s) for one concrete, already-opened key.
fn emit_key(
    descriptor: &ArtifactDescriptor,
    key_path: &str,
    key: &Key<'_>,
    user: Option<&UserIdentity>,
    hits: &mut Vec<CatalogHit>,
) {
    if let Some(vname) = descriptor.value_name {
        // Single named value.
        if let Ok(Some(val)) = key.value(vname) {
            hits.push(make_hit(
                descriptor,
                key_path,
                Some(vname.to_string()),
                &val,
                user,
            ));
        }
    } else {
        // Key-level descriptor: every child value is a hit.
        let Ok(values) = key.values() else { return };
        for val in values {
            hits.push(make_hit(descriptor, key_path, Some(val.name()), &val, user));
        }
    }
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
fn normalize_concrete_path(raw: &str, strip_hive_root: bool) -> Option<String> {
    // Reject wildcard families and live-system variable placeholders outright.
    if raw.contains('*') || raw.contains('%') || raw.contains('/') {
        return None;
    }
    normalize_path_prefixes(raw, strip_hive_root)
}

/// Apply the hive-prefix / doubled-backslash / `CurrentControlSet` normalizations
/// shared by the concrete and glob resolvers, returning the hive-relative path
/// (or `None` for an unsupported placeholder root or empty result).
///
/// `strip_hive_root` controls whether a leading `SOFTWARE\` / `SYSTEM\` (which
/// merely repeats an HKLM hive name) is dropped. It must be `true` for HKLM
/// SOFTWARE/SYSTEM hives but `false` for per-user (`NtUser`/`UsrClass`) hives,
/// where `Software` is a genuine first-level subkey, not a redundant prefix.
///
/// Wildcard segments are preserved verbatim — callers gate on `*`/`%` themselves.
fn normalize_path_prefixes(raw: &str, strip_hive_root: bool) -> Option<String> {
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
    // Strip a redundant leading SOFTWARE\ or SYSTEM\ that repeats the hive root
    // — only for the HKLM hives where it is a duplicate, never for user hives.
    if strip_hive_root {
        for prefix in ["SOFTWARE\\", "SYSTEM\\"] {
            if let Some(stripped) = strip_prefix_ci(path, prefix) {
                path = stripped;
            }
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

// ── Glob expansion ───────────────────────────────────────────────────────────

/// One path component of a normalized wildcard descriptor path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobSegment {
    /// An exact key name to descend into.
    Literal(String),
    /// A single-level wildcard with optional literal context around the `*`
    /// (e.g. `*` matches any child, `*ControlSet*` matches `ControlSet001`).
    Star(String),
    /// `**` — recursive descent: matches this key and any nested descendant.
    DoubleStar,
}

/// Normalize a catalog key path that contains a wildcard into hive-relative
/// [`GlobSegment`]s, or `None` if the path is not a wildcard family or carries a
/// SID placeholder (`%`, handled by the multi-user scan instead).
///
/// Applies the same hive-prefix / `CurrentControlSet` normalizations as
/// [`normalize_key_path`], but preserves `*` / `**` segments.
fn normalize_glob_path(raw: &str, strip_hive_root: bool) -> Option<Vec<GlobSegment>> {
    if !raw.contains('*') || raw.contains('%') || raw.contains('/') {
        return None;
    }
    let normalized = normalize_path_prefixes(raw, strip_hive_root)?;
    let segments: Vec<GlobSegment> = normalized
        .split('\\')
        .filter(|s| !s.is_empty())
        .map(parse_glob_segment)
        .collect();
    if segments.is_empty() {
        None
    } else {
        Some(segments)
    }
}

/// Classify one raw path component as a [`GlobSegment`].
fn parse_glob_segment(seg: &str) -> GlobSegment {
    // A component containing `**` is recursive descent regardless of any
    // forensic-artifacts repeat suffix (e.g. `**5`).
    if seg.contains("**") {
        GlobSegment::DoubleStar
    } else if seg.contains('*') {
        GlobSegment::Star(seg.to_string())
    } else {
        GlobSegment::Literal(seg.to_string())
    }
}

/// Recursively expand `segments` against `key`, invoking `emit` with
/// `(concrete_path, &matched_key)` for every concrete key that matches the whole
/// pattern.
///
/// `prefix` is the hive-relative path already walked to reach `key`. `depth`
/// bounds recursion and `matched` (shared across the whole expansion) caps the
/// total number of matches at [`MAX_GLOB_MATCHES`] — both defend against
/// pathological untrusted hives.
fn expand_glob(
    key: &Key<'_>,
    segments: &[GlobSegment],
    prefix: &str,
    depth: usize,
    matched: &mut usize,
    emit: &mut dyn FnMut(&str, &Key<'_>),
) {
    if *matched >= MAX_GLOB_MATCHES || depth > MAX_GLOB_DEPTH {
        return;
    }
    let Some((head, rest)) = segments.split_first() else {
        // All segments consumed — `key` is itself the concrete match.
        *matched += 1;
        emit(prefix, key);
        return;
    };

    match head {
        GlobSegment::Literal(name) => {
            let Ok(children) = key.subkeys() else { return };
            for child in children {
                if child.name().eq_ignore_ascii_case(name) {
                    let child_prefix = join_path(prefix, &child.name());
                    expand_glob(&child, rest, &child_prefix, depth + 1, matched, emit);
                    break;
                }
            }
        }
        GlobSegment::Star(pattern) => {
            let Ok(children) = key.subkeys() else { return };
            for child in children {
                if *matched >= MAX_GLOB_MATCHES {
                    return;
                }
                if segment_matches(pattern, &child.name()) {
                    let child_prefix = join_path(prefix, &child.name());
                    expand_glob(&child, rest, &child_prefix, depth + 1, matched, emit);
                }
            }
        }
        GlobSegment::DoubleStar => {
            // `**` matches zero levels: try the remaining pattern against `key`.
            expand_glob(key, rest, prefix, depth, matched, emit);
            // …and any number of levels: descend into every child, keeping `**`.
            let Ok(children) = key.subkeys() else { return };
            for child in children {
                if *matched >= MAX_GLOB_MATCHES {
                    return;
                }
                let child_prefix = join_path(prefix, &child.name());
                expand_glob(&child, segments, &child_prefix, depth + 1, matched, emit);
            }
        }
    }
}

/// Join a hive-relative prefix with a child name using `\` separators.
fn join_path(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}\\{name}")
    }
}

/// Match a single path component against a glob `pattern` that may contain `*`
/// wildcards anywhere (case-insensitive). `*` matches any run of characters.
fn segment_matches(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let txt: Vec<char> = name.to_ascii_lowercase().chars().collect();
    glob_match(&pat, &txt)
}

/// Iterative `*`-only glob matcher over char slices (no backtracking blow-up).
fn glob_match(pat: &[char], txt: &[char]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while t < txt.len() {
        if p < pat.len() && pat[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if p < pat.len() && pat[p] == txt[t] {
            p += 1;
            t += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

/// Build a [`CatalogHit`], rendering the value per the descriptor's decoder.
fn make_hit(
    descriptor: &ArtifactDescriptor,
    key_path: &str,
    value_name: Option<String>,
    val: &Value<'_>,
    user: Option<&UserIdentity>,
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
        user: user.cloned(),
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
            normalize_concrete_path(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", true)
                .as_deref(),
            Some(r"Microsoft\Windows NT\CurrentVersion")
        );
    }

    #[test]
    fn normalize_keeps_software_for_user_hive() {
        // Per-user hives store `Software\…` literally — it must NOT be stripped.
        assert_eq!(
            normalize_concrete_path(r"Software\Microsoft\Windows\CurrentVersion\Run", false)
                .as_deref(),
            Some(r"Software\Microsoft\Windows\CurrentVersion\Run")
        );
    }

    #[test]
    fn normalize_translates_current_control_set() {
        assert_eq!(
            normalize_concrete_path(r"CurrentControlSet\Services", true).as_deref(),
            Some(r"ControlSet001\Services")
        );
    }

    #[test]
    fn normalize_rejects_wildcard_and_placeholder() {
        assert!(normalize_concrete_path(r"Software\Foo\*", true).is_none());
        assert!(normalize_concrete_path(r"HKEY_USERS\%%users.sid%%\Software\X", true).is_none());
    }

    #[test]
    fn normalize_collapses_doubled_backslashes() {
        assert_eq!(
            normalize_concrete_path(r"Microsoft\\Windows\\CurrentVersion\\Run", true).as_deref(),
            Some(r"Microsoft\Windows\CurrentVersion\Run")
        );
    }

    #[test]
    fn normalize_strips_hk_prefix() {
        assert_eq!(
            normalize_concrete_path(r"HKLM\Microsoft\Foo", true).as_deref(),
            Some(r"Microsoft\Foo")
        );
    }

    #[test]
    fn glob_path_parses_segments() {
        let segs = normalize_glob_path(r"Microsoft\Foo\*\Bar\**", true).unwrap();
        assert_eq!(
            segs,
            vec![
                GlobSegment::Literal("Microsoft".into()),
                GlobSegment::Literal("Foo".into()),
                GlobSegment::Star("*".into()),
                GlobSegment::Literal("Bar".into()),
                GlobSegment::DoubleStar,
            ]
        );
    }

    #[test]
    fn glob_path_rejects_non_wildcard_and_placeholder() {
        assert!(normalize_glob_path(r"Microsoft\Foo", true).is_none());
        assert!(normalize_glob_path(r"Foo\%%users.sid%%\*", true).is_none());
    }

    #[test]
    fn double_star_suffix_is_recursive_descent() {
        assert_eq!(parse_glob_segment("**5"), GlobSegment::DoubleStar);
        assert_eq!(parse_glob_segment("**"), GlobSegment::DoubleStar);
    }

    #[test]
    fn segment_match_handles_midsegment_wildcard() {
        assert!(segment_matches("*ControlSet*", "ControlSet001"));
        assert!(segment_matches("*", "anything"));
        assert!(segment_matches("ABC*", "abcdef"));
        assert!(!segment_matches("ABC*", "xyz"));
        assert!(!segment_matches("Foo", "Bar"));
    }

    #[test]
    fn strips_hku_and_users_placeholder_prefix() {
        assert_eq!(
            strip_user_placeholder_prefix(r"HKEY_USERS\%%users.sid%%\Software\X\Y"),
            Some(r"Software\X\Y")
        );
        assert_eq!(
            strip_user_placeholder_prefix(r"HKU\*\Software\Run"),
            Some(r"Software\Run")
        );
        // Not an HKU-rooted path.
        assert!(strip_user_placeholder_prefix(r"Software\X").is_none());
        // No remainder after the SID segment.
        assert!(strip_user_placeholder_prefix(r"HKEY_USERS\S-1-5-21").is_none());
    }
}
