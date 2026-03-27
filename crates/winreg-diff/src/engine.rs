//! Diff engine — compare two hives using BFS merge-join.

use std::io::Cursor;

use winreg_core::error::Result;
use winreg_core::hive::Hive;
use winreg_core::key::Key;

use crate::snapshot::value_to_snapshot;
use crate::types::{DiffEntry, DiffKind, DiffResult, DiffStats, ValueDiff, ValueDiffKind};

/// Compare two hives and produce a structured diff.
///
/// BFS-traverses both hives in parallel. At each level, subkey names are
/// sorted and merge-joined to detect added/removed keys. For keys present
/// in both hives, values are compared by name.
pub fn diff_hives(
    left: &Hive<Cursor<Vec<u8>>>,
    right: &Hive<Cursor<Vec<u8>>>,
    left_label: &str,
    right_label: &str,
) -> Result<DiffResult> {
    let mut entries = Vec::new();
    let mut stats = DiffStats::default();

    let left_root = left.root_key()?;
    let right_root = right.root_key()?;

    diff_key_recursive(&left_root, &right_root, "", &mut entries, &mut stats)?;

    Ok(DiffResult {
        left_label: left_label.into(),
        right_label: right_label.into(),
        entries,
        stats,
    })
}

/// Build a child path from the current path and a key name.
fn child_path(current: &str, name: &str) -> String {
    if current.is_empty() {
        name.to_string()
    } else {
        format!("{current}\\{name}")
    }
}

/// Recursively diff two keys and their subtrees.
fn diff_key_recursive(
    left: &Key<'_>,
    right: &Key<'_>,
    current_path: &str,
    entries: &mut Vec<DiffEntry>,
    stats: &mut DiffStats,
) -> Result<()> {
    // Compare values at this level
    let value_diffs = diff_values(left, right)?;
    if !value_diffs.is_empty() {
        let path = if current_path.is_empty() {
            left.name()
        } else {
            current_path.to_string()
        };
        for vd in &value_diffs {
            match &vd.kind {
                ValueDiffKind::Added { .. } => stats.values_added += 1,
                ValueDiffKind::Removed { .. } => stats.values_removed += 1,
                ValueDiffKind::Changed { .. } => stats.values_changed += 1,
            }
        }
        stats.keys_modified += 1;
        entries.push(DiffEntry {
            path,
            kind: DiffKind::KeyModified,
            details: value_diffs,
        });
    }

    // Get sorted subkey lists from both sides
    let left_subkeys = left.subkeys()?;
    let right_subkeys = right.subkeys()?;

    let mut left_sorted: Vec<_> = left_subkeys.iter().collect();
    left_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    let mut right_sorted: Vec<_> = right_subkeys.iter().collect();
    right_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    merge_join_subkeys(&left_sorted, &right_sorted, current_path, entries, stats)
}

/// Merge-join two sorted subkey slices and emit added/removed/recurse.
fn merge_join_subkeys(
    left_sorted: &[&Key<'_>],
    right_sorted: &[&Key<'_>],
    current_path: &str,
    entries: &mut Vec<DiffEntry>,
    stats: &mut DiffStats,
) -> Result<()> {
    let mut li = 0;
    let mut ri = 0;

    while li < left_sorted.len() && ri < right_sorted.len() {
        let left_name = left_sorted[li].name().to_ascii_uppercase();
        let right_name = right_sorted[ri].name().to_ascii_uppercase();

        match left_name.cmp(&right_name) {
            std::cmp::Ordering::Equal => {
                let path = child_path(current_path, &left_sorted[li].name());
                diff_key_recursive(left_sorted[li], right_sorted[ri], &path, entries, stats)?;
                li += 1;
                ri += 1;
            }
            std::cmp::Ordering::Less => {
                stats.keys_removed += 1;
                entries.push(DiffEntry {
                    path: child_path(current_path, &left_sorted[li].name()),
                    kind: DiffKind::KeyRemoved,
                    details: vec![],
                });
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                stats.keys_added += 1;
                entries.push(DiffEntry {
                    path: child_path(current_path, &right_sorted[ri].name()),
                    kind: DiffKind::KeyAdded,
                    details: vec![],
                });
                ri += 1;
            }
        }
    }

    // Remaining left keys — removed
    for key in &left_sorted[li..] {
        stats.keys_removed += 1;
        entries.push(DiffEntry {
            path: child_path(current_path, &key.name()),
            kind: DiffKind::KeyRemoved,
            details: vec![],
        });
    }

    // Remaining right keys — added
    for key in &right_sorted[ri..] {
        stats.keys_added += 1;
        entries.push(DiffEntry {
            path: child_path(current_path, &key.name()),
            kind: DiffKind::KeyAdded,
            details: vec![],
        });
    }

    Ok(())
}

/// Compare values between two keys.
fn diff_values(left: &Key<'_>, right: &Key<'_>) -> Result<Vec<ValueDiff>> {
    let left_vals = left.values()?;
    let right_vals = right.values()?;

    let mut left_sorted: Vec<_> = left_vals.iter().collect();
    left_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    let mut right_sorted: Vec<_> = right_vals.iter().collect();
    right_sorted.sort_by(|a, b| {
        a.name()
            .to_ascii_uppercase()
            .cmp(&b.name().to_ascii_uppercase())
    });

    let mut diffs = Vec::new();
    let mut li = 0;
    let mut ri = 0;

    while li < left_sorted.len() && ri < right_sorted.len() {
        let left_name = left_sorted[li].name().to_ascii_uppercase();
        let right_name = right_sorted[ri].name().to_ascii_uppercase();

        match left_name.cmp(&right_name) {
            std::cmp::Ordering::Equal => {
                let left_raw = left_sorted[li].raw_data().unwrap_or_default();
                let right_raw = right_sorted[ri].raw_data().unwrap_or_default();
                if left_raw != right_raw
                    || left_sorted[li].data_type() != right_sorted[ri].data_type()
                {
                    diffs.push(ValueDiff {
                        name: left_sorted[li].name(),
                        kind: ValueDiffKind::Changed {
                            left: value_to_snapshot(left_sorted[li]),
                            right: value_to_snapshot(right_sorted[ri]),
                        },
                    });
                }
                li += 1;
                ri += 1;
            }
            std::cmp::Ordering::Less => {
                diffs.push(ValueDiff {
                    name: left_sorted[li].name(),
                    kind: ValueDiffKind::Removed {
                        value: value_to_snapshot(left_sorted[li]),
                    },
                });
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                diffs.push(ValueDiff {
                    name: right_sorted[ri].name(),
                    kind: ValueDiffKind::Added {
                        value: value_to_snapshot(right_sorted[ri]),
                    },
                });
                ri += 1;
            }
        }
    }

    for v in &left_sorted[li..] {
        diffs.push(ValueDiff {
            name: v.name(),
            kind: ValueDiffKind::Removed {
                value: value_to_snapshot(v),
            },
        });
    }

    for v in &right_sorted[ri..] {
        diffs.push(ValueDiff {
            name: v.name(),
            kind: ValueDiffKind::Added {
                value: value_to_snapshot(v),
            },
        });
    }

    Ok(diffs)
}
