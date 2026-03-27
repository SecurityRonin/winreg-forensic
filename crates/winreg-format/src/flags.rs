//! Bitflags and enums for registry cell fields.

use bitflags::bitflags;

bitflags! {
    /// NK cell flags (offset 0x02 in NK cell, u16).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KeyFlags: u16 {
        const VOLATILE      = 0x0001;
        const HIVE_EXIT     = 0x0002;
        const HIVE_ENTRY    = 0x0004;
        const NO_DELETE     = 0x0008;
        const SYM_LINK      = 0x0010;
        const COMP_NAME     = 0x0020;
        const PREDEF_HANDLE = 0x0040;
        const VIRT_MIRRORED = 0x0080;
        const VIRT_TARGET   = 0x0100;
        const VIRTUAL_STORE = 0x0200;
    }
}

bitflags! {
    /// VK cell flags (offset 0x10 in VK cell, u16).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ValueFlags: u16 {
        const COMP_NAME = 0x0001;
    }
}

/// Registry value data type (offset 0x0C in VK cell, u32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ValueType {
    None = 0,
    Sz = 1,
    ExpandSz = 2,
    Binary = 3,
    Dword = 4,
    DwordBigEndian = 5,
    Link = 6,
    MultiSz = 7,
    ResourceList = 8,
    FullResourceDescriptor = 9,
    ResourceRequirementsList = 10,
    Qword = 11,
    Unknown(u32),
}

impl ValueType {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            8 => Self::ResourceList,
            9 => Self::FullResourceDescriptor,
            10 => Self::ResourceRequirementsList,
            11 => Self::Qword,
            other => Self::Unknown(other),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::None => "REG_NONE",
            Self::Sz => "REG_SZ",
            Self::ExpandSz => "REG_EXPAND_SZ",
            Self::Binary => "REG_BINARY",
            Self::Dword => "REG_DWORD",
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN",
            Self::Link => "REG_LINK",
            Self::MultiSz => "REG_MULTI_SZ",
            Self::ResourceList => "REG_RESOURCE_LIST",
            Self::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR",
            Self::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST",
            Self::Qword => "REG_QWORD",
            Self::Unknown(_) => "REG_UNKNOWN",
        }
    }
}

impl std::fmt::Display for ValueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_flags_comp_name() {
        let flags = KeyFlags::COMP_NAME | KeyFlags::HIVE_ENTRY;
        assert!(flags.contains(KeyFlags::COMP_NAME));
        assert!(flags.contains(KeyFlags::HIVE_ENTRY));
        assert!(!flags.contains(KeyFlags::VOLATILE));
    }

    #[test]
    fn value_type_roundtrip() {
        for raw in 0..=11 {
            let vt = ValueType::from_raw(raw);
            assert_ne!(vt.name(), "REG_UNKNOWN");
        }
        assert!(matches!(ValueType::from_raw(99), ValueType::Unknown(99)));
    }

    #[test]
    fn value_type_display() {
        assert_eq!(ValueType::Sz.to_string(), "REG_SZ");
        assert_eq!(ValueType::Dword.to_string(), "REG_DWORD");
        assert_eq!(ValueType::MultiSz.to_string(), "REG_MULTI_SZ");
    }
}
