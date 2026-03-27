//! Diff result types — structured representation of changes between two hives.

use serde::Serialize;

/// Complete result of comparing two hives.
#[derive(Debug, Clone, Serialize)]
pub struct DiffResult {
    /// Label for the left (older) hive.
    pub left_label: String,
    /// Label for the right (newer) hive.
    pub right_label: String,
    /// All detected changes, sorted by key path.
    pub entries: Vec<DiffEntry>,
    /// Summary statistics.
    pub stats: DiffStats,
}

/// Aggregate counts of changes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DiffStats {
    pub keys_added: usize,
    pub keys_removed: usize,
    pub keys_modified: usize,
    pub values_added: usize,
    pub values_removed: usize,
    pub values_changed: usize,
}

/// A single key-level change.
#[derive(Debug, Clone, Serialize)]
pub struct DiffEntry {
    /// Full key path from root (e.g., `"ControlSet001\\Services\\SharedAccess"`).
    pub path: String,
    /// What happened at this key.
    pub kind: DiffKind,
    /// Value-level changes within this key.
    pub details: Vec<ValueDiff>,
}

/// Classification of key-level change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DiffKind {
    /// Key exists in right hive but not left.
    KeyAdded,
    /// Key exists in left hive but not right.
    KeyRemoved,
    /// Key exists in both hives but has different values.
    KeyModified,
}

/// A single value-level change within a key.
#[derive(Debug, Clone, Serialize)]
pub struct ValueDiff {
    /// Value name (empty string for the default value).
    pub name: String,
    /// What happened to this value.
    pub kind: ValueDiffKind,
}

/// Classification of value-level change.
#[derive(Debug, Clone, Serialize)]
pub enum ValueDiffKind {
    /// Value exists in right hive but not left.
    Added { value: ValueSnapshot },
    /// Value exists in left hive but not right.
    Removed { value: ValueSnapshot },
    /// Value exists in both but differs.
    Changed {
        left: ValueSnapshot,
        right: ValueSnapshot,
    },
}

/// Snapshot of a registry value at a point in time.
#[derive(Debug, Clone, Serialize)]
pub struct ValueSnapshot {
    /// Registry value type (`REG_SZ`, `REG_DWORD`, etc.).
    pub data_type: String,
    /// Human-readable representation of the value.
    pub display: String,
    /// Raw bytes (for optional byte-level diff).
    #[serde(skip)]
    pub raw: Vec<u8>,
}

impl std::fmt::Display for DiffKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyAdded => write!(f, "ADDED"),
            Self::KeyRemoved => write!(f, "REMOVED"),
            Self::KeyModified => write!(f, "MODIFIED"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_kind_display() {
        assert_eq!(DiffKind::KeyAdded.to_string(), "ADDED");
        assert_eq!(DiffKind::KeyRemoved.to_string(), "REMOVED");
        assert_eq!(DiffKind::KeyModified.to_string(), "MODIFIED");
    }

    #[test]
    fn diff_stats_default_is_zero() {
        let stats = DiffStats::default();
        assert_eq!(stats.keys_added, 0);
        assert_eq!(stats.keys_removed, 0);
        assert_eq!(stats.keys_modified, 0);
        assert_eq!(stats.values_added, 0);
        assert_eq!(stats.values_removed, 0);
        assert_eq!(stats.values_changed, 0);
    }

    #[test]
    fn diff_result_serializes_to_json() {
        let result = DiffResult {
            left_label: "left".into(),
            right_label: "right".into(),
            entries: vec![DiffEntry {
                path: "TestKey".into(),
                kind: DiffKind::KeyAdded,
                details: vec![],
            }],
            stats: DiffStats {
                keys_added: 1,
                ..DiffStats::default()
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"left_label\":\"left\""));
        assert!(json.contains("\"KeyAdded\""));
    }
}
