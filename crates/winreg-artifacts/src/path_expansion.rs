//! Unified registry path-expansion engine.
//!
//! Glob (`*`/`**`), control-set (`CurrentControlSet`), and multi-user
//! (`HKU\%%sid%%`) resolution are the **same operation**: a catalog path with
//! one or more **variable segments**, each ranging over an **enumerable
//! domain**, expanded into concrete paths — each tagged with the [`Binding`]s
//! that record which domain element produced it. Only the domain differs:
//!
//! - [`Wildcard::Subkey`] (`*` / `**`) → the subkeys of a node (intra-hive).
//! - [`Wildcard::ControlSet`] (`CurrentControlSet`) → the `ControlSet00N` set
//!   selected by `Select\Current` (intra-SYSTEM-hive).
//! - [`Wildcard::User`] (`HKU\%%sid%%` / NtUser) → the per-user profile hives
//!   (cross-file; bound by the caller, [`crate::catalog_scan::scan_users`]).
//!
//! This module owns the intra-hive walk for the `Subkey` and `ControlSet`
//! domains; the `User` domain is bound one level up because it selects *which
//! hive file* to walk. The proven glob matching/caps live here unchanged — the
//! engine wraps them as the `Subkey` domain source rather than rewriting them.

use winreg_core::key::Key;

/// The domain a variable path segment ranges over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Wildcard {
    /// `*` / `**` — ranges over the subkeys of a node (intra-hive).
    Subkey,
    /// `CurrentControlSet` — ranges over the active `ControlSet00N`
    /// (intra-SYSTEM-hive), selected by `Select\Current`.
    ControlSet,
    /// `HKU\%%sid%%` / per-user NtUser — ranges over the profile hives
    /// (cross-file). Bound by the multi-user scan, not by this engine.
    User,
}

/// One variable resolution, carried on each hit for provenance.
///
/// For example `{Subkey, "{CLSID…}"}`, `{ControlSet, "ControlSet002"}`, or
/// `{User, "S-1-5-21-…-1001"}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Binding {
    /// Which domain this binding came from.
    pub kind: Wildcard,
    /// The concrete domain element selected (child-key name, control-set name,
    /// or user SID/profile).
    pub value: String,
}

impl Binding {
    /// Construct a binding for `kind` selecting `value`.
    pub fn new(kind: Wildcard, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
        }
    }
}

/// One component of an expansion template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Segment {
    /// An exact key name to descend into.
    Literal(String),
    /// A variable segment ranging over [`Wildcard`]'s domain. The string is the
    /// match pattern: a glob (`*`, `*ControlSet*`) for `Subkey`/`ControlSet`,
    /// otherwise contextual.
    Variable(Wildcard, String),
}

/// Maximum key-tree depth a `**` recursive-descent walk will visit.
///
/// Untrusted hives can be crafted with pathological nesting; this bounds the
/// recursion so a malicious image cannot drive unbounded stack/heap growth.
pub(crate) const MAX_GLOB_DEPTH: usize = 64;

/// Maximum number of concrete keys a single template may expand to.
///
/// Caps breadth so a hive with millions of sibling keys under a `*` cannot make
/// one template produce an unbounded result set (allocation-bomb defence).
pub(crate) const MAX_GLOB_MATCHES: usize = 4096;

/// The set of `ControlSet00N` names a `CurrentControlSet` segment expands to,
/// resolved from `SYSTEM\Select\Current`.
///
/// Normally a single active set; absent/unreadable `Select\Current` degrades to
/// `ControlSet001` (see [`resolve_control_sets`]).
#[derive(Debug, Clone)]
pub struct ControlSetResolver {
    /// The concrete `ControlSet00N` names the alias resolves to (in expansion
    /// order). At least one element.
    pub sets: Vec<String>,
}

/// Read `SYSTEM\Select\Current` (a `REG_DWORD`, value `N`) and resolve the
/// `CurrentControlSet` alias to `ControlSet00N`.
///
/// Uses `Current` (the control set that was *running*), never `Default`. If
/// `Select\Current` is absent, unreadable, or zero, falls back to
/// `ControlSet001` — degrade, never panic. Reads are bounds-checked against the
/// untrusted hive via winreg-core's value API.
#[must_use]
pub fn resolve_control_sets(root: &Key<'_>) -> ControlSetResolver {
    let n = current_control_set_number(root).unwrap_or(1);
    ControlSetResolver {
        sets: vec![format!("ControlSet{n:03}")],
    }
}

/// Read the active control-set number from `Select\Current`, or `None` when the
/// key/value is absent, unreadable, or zero.
fn current_control_set_number(root: &Key<'_>) -> Option<u32> {
    let select = root.subkey("Select").ok()??;
    let current = select.value("Current").ok()??;
    // `as_u32` is bounds-checked and infallible on short data (returns 0).
    let n = current.as_u32().ok()?;
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

/// Expand `segments` against the key tree rooted at `root`, invoking `emit` with
/// `(bindings, concrete_path, &matched_key)` for every concrete key that matches
/// the whole template.
///
/// `controlset` supplies the `ControlSet00N` names a [`Wildcard::ControlSet`]
/// segment ranges over; it may be `None` when the template contains no
/// `ControlSet` segment. `User` bindings are not produced here — the multi-user
/// scan binds them when it selects the hive.
pub fn expand(
    root: &Key<'_>,
    segments: &[Segment],
    controlset: Option<&ControlSetResolver>,
    emit: &mut dyn FnMut(&[Binding], &str, &Key<'_>),
) {
    let mut bindings: Vec<Binding> = Vec::new();
    let mut matched = 0usize;
    walk(
        root,
        segments,
        controlset,
        "",
        0,
        &mut matched,
        &mut bindings,
        emit,
    );
}

/// Recursive template walk shared by every domain source.
#[allow(clippy::too_many_arguments)]
fn walk(
    key: &Key<'_>,
    segments: &[Segment],
    controlset: Option<&ControlSetResolver>,
    prefix: &str,
    depth: usize,
    matched: &mut usize,
    bindings: &mut Vec<Binding>,
    emit: &mut dyn FnMut(&[Binding], &str, &Key<'_>),
) {
    if *matched >= MAX_GLOB_MATCHES || depth > MAX_GLOB_DEPTH {
        return;
    }
    let Some((head, rest)) = segments.split_first() else {
        // All segments consumed — `key` is itself the concrete match.
        *matched += 1;
        emit(bindings, prefix, key);
        return;
    };

    match head {
        Segment::Literal(name) => {
            let Ok(children) = key.subkeys() else { return };
            for child in children {
                if child.name().eq_ignore_ascii_case(name) {
                    let child_prefix = join_path(prefix, &child.name());
                    walk(
                        &child,
                        rest,
                        controlset,
                        &child_prefix,
                        depth + 1,
                        matched,
                        bindings,
                        emit,
                    );
                    break;
                }
            }
        }
        Segment::Variable(Wildcard::ControlSet, _) => {
            // Domain = the active control set(s) from Select\Current. Default to
            // ControlSet001 when no resolver was supplied (degrade, never panic).
            let fallback = ControlSetResolver {
                sets: vec!["ControlSet001".to_string()],
            };
            let resolver = controlset.unwrap_or(&fallback);
            let Ok(children) = key.subkeys() else { return };
            for set_name in &resolver.sets {
                if *matched >= MAX_GLOB_MATCHES {
                    return;
                }
                for child in &children {
                    if child.name().eq_ignore_ascii_case(set_name) {
                        let child_prefix = join_path(prefix, &child.name());
                        bindings.push(Binding::new(Wildcard::ControlSet, child.name()));
                        walk(
                            child,
                            rest,
                            controlset,
                            &child_prefix,
                            depth + 1,
                            matched,
                            bindings,
                            emit,
                        );
                        bindings.pop();
                        break;
                    }
                }
            }
        }
        Segment::Variable(Wildcard::Subkey, pattern) => {
            if pattern.contains("**") {
                // `**` matches zero levels: try the remaining pattern here…
                walk(
                    key, rest, controlset, prefix, depth, matched, bindings, emit,
                );
                // …and any number of levels: descend into every child, keeping `**`.
                let Ok(children) = key.subkeys() else { return };
                for child in children {
                    if *matched >= MAX_GLOB_MATCHES {
                        return;
                    }
                    let child_prefix = join_path(prefix, &child.name());
                    bindings.push(Binding::new(Wildcard::Subkey, child.name()));
                    walk(
                        &child,
                        segments,
                        controlset,
                        &child_prefix,
                        depth + 1,
                        matched,
                        bindings,
                        emit,
                    );
                    bindings.pop();
                }
            } else {
                let Ok(children) = key.subkeys() else { return };
                for child in children {
                    if *matched >= MAX_GLOB_MATCHES {
                        return;
                    }
                    if segment_matches(pattern, &child.name()) {
                        let child_prefix = join_path(prefix, &child.name());
                        bindings.push(Binding::new(Wildcard::Subkey, child.name()));
                        walk(
                            &child,
                            rest,
                            controlset,
                            &child_prefix,
                            depth + 1,
                            matched,
                            bindings,
                            emit,
                        );
                        bindings.pop();
                    }
                }
            }
        }
        // `User` is bound by the multi-user scan, never reached intra-hive.
        Segment::Variable(Wildcard::User, _) => {} // cov:unreachable: User segments are stripped to a User binding by scan_users before expand() is called.
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn segment_match_handles_midsegment_wildcard() {
        assert!(segment_matches("*ControlSet*", "ControlSet001"));
        assert!(segment_matches("*", "anything"));
        assert!(segment_matches("ABC*", "abcdef"));
        assert!(!segment_matches("ABC*", "xyz"));
        assert!(!segment_matches("Foo", "Bar"));
    }

    #[test]
    fn binding_new_constructs() {
        let b = Binding::new(Wildcard::ControlSet, "ControlSet002");
        assert_eq!(b.kind, Wildcard::ControlSet);
        assert_eq!(b.value, "ControlSet002");
    }
}
