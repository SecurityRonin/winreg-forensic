//! REGF hive version enumeration.

/// Registry hive format version, determined by the minor version field
/// in the base block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegfVersion {
    /// Version 1.0-1.2: Windows NT 3.x. LI index only.
    V1_0,
    /// Version 1.3: Windows NT 4.0. Adds LF (fast leaf).
    V1_3,
    /// Version 1.4: Windows XP beta. Adds big data (DB).
    V1_4,
    /// Version 1.5: Windows XP release+. Adds LH (hash leaf).
    V1_5,
    /// Version 1.6: Windows 10+. Differencing/layered hives.
    V1_6,
}

impl RegfVersion {
    /// Determine version from minor version number.
    pub fn from_minor(minor: u32) -> Option<Self> {
        match minor {
            0..=2 => Some(Self::V1_0),
            3 => Some(Self::V1_3),
            4 => Some(Self::V1_4),
            5 => Some(Self::V1_5),
            6 => Some(Self::V1_6),
            _ => None,
        }
    }

    /// Whether this version supports LH (hash leaf) index cells.
    pub fn has_hash_leaf(self) -> bool {
        self >= Self::V1_5
    }

    /// Whether this version supports DB (big data) cells.
    pub fn has_big_data(self) -> bool {
        self >= Self::V1_4
    }

    /// Whether this version supports LF (fast leaf) index cells.
    pub fn has_fast_leaf(self) -> bool {
        self >= Self::V1_3
    }

    /// Whether this version supports differencing/layered keys.
    pub fn has_layered_keys(self) -> bool {
        self >= Self::V1_6
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_from_minor() {
        assert_eq!(RegfVersion::from_minor(0), Some(RegfVersion::V1_0));
        assert_eq!(RegfVersion::from_minor(2), Some(RegfVersion::V1_0));
        assert_eq!(RegfVersion::from_minor(3), Some(RegfVersion::V1_3));
        assert_eq!(RegfVersion::from_minor(5), Some(RegfVersion::V1_5));
        assert_eq!(RegfVersion::from_minor(6), Some(RegfVersion::V1_6));
        assert_eq!(RegfVersion::from_minor(99), None);
    }

    #[test]
    fn version_feature_gates() {
        assert!(!RegfVersion::V1_0.has_fast_leaf());
        assert!(RegfVersion::V1_3.has_fast_leaf());
        assert!(!RegfVersion::V1_3.has_big_data());
        assert!(RegfVersion::V1_4.has_big_data());
        assert!(!RegfVersion::V1_4.has_hash_leaf());
        assert!(RegfVersion::V1_5.has_hash_leaf());
        assert!(RegfVersion::V1_6.has_layered_keys());
    }

    #[test]
    fn versions_are_ordered() {
        assert!(RegfVersion::V1_0 < RegfVersion::V1_3);
        assert!(RegfVersion::V1_3 < RegfVersion::V1_5);
        assert!(RegfVersion::V1_5 < RegfVersion::V1_6);
    }
}
