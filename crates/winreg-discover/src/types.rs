//! Types for hive source discovery.

use std::path::PathBuf;

use jiff::Timestamp;
use serde::Serialize;
use winreg_core::detect::HiveType;

/// A discovered registry hive file with provenance metadata.
#[derive(Debug, Clone, Serialize)]
pub struct HiveSource {
    /// Filesystem path to the hive file.
    pub path: PathBuf,
    /// Detected hive type (SYSTEM, SOFTWARE, etc.).
    pub hive_type: HiveType,
    /// Where this copy came from.
    pub origin: SourceOrigin,
    /// Timestamp from the `BaseBlock` header (last write time).
    pub timestamp: Option<Timestamp>,
    /// File size in bytes.
    pub size: u64,
    /// Whether the hive is clean (no pending transaction logs).
    pub is_clean: bool,
}

/// Provenance of a discovered hive.
#[derive(Debug, Clone, Serialize)]
pub enum SourceOrigin {
    /// Live hive from `Windows/System32/config/`.
    Live,
    /// `RegBack` copy from `Windows/System32/config/RegBack/`.
    RegBack,
    /// Volume Shadow Copy snapshot.
    Vsc { snapshot_id: String },
    /// Transaction log file (`.LOG1` or `.LOG2`).
    TransactionLog { log_num: u8 },
}

impl std::fmt::Display for SourceOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Live => write!(f, "Live"),
            Self::RegBack => write!(f, "RegBack"),
            Self::Vsc { snapshot_id } => write!(f, "VSC({snapshot_id})"),
            Self::TransactionLog { log_num } => write!(f, "LOG{log_num}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_origin_display() {
        assert_eq!(SourceOrigin::Live.to_string(), "Live");
        assert_eq!(SourceOrigin::RegBack.to_string(), "RegBack");
        assert_eq!(
            SourceOrigin::Vsc {
                snapshot_id: "abc".into()
            }
            .to_string(),
            "VSC(abc)"
        );
        assert_eq!(
            SourceOrigin::TransactionLog { log_num: 1 }.to_string(),
            "LOG1"
        );
    }

    #[test]
    fn hive_source_serializes() {
        let source = HiveSource {
            path: PathBuf::from("/evidence/SYSTEM"),
            hive_type: HiveType::System,
            origin: SourceOrigin::Live,
            timestamp: None,
            size: 4096,
            is_clean: true,
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("\"Live\""));
        assert!(json.contains("\"System\""));
    }
}
