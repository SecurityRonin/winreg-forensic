//! Hive type auto-detection from root key structure.

use std::io::Cursor;

use crate::hive::Hive;

/// Known hive types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum HiveType {
    System,
    Software,
    NtUser,
    UsrClass,
    Sam,
    Security,
    Amcache,
    Bcd,
    Default,
    Components,
    Unknown,
}

impl std::fmt::Display for HiveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => write!(f, "SYSTEM"),
            Self::Software => write!(f, "SOFTWARE"),
            Self::NtUser => write!(f, "NTUSER.DAT"),
            Self::UsrClass => write!(f, "UsrClass.dat"),
            Self::Sam => write!(f, "SAM"),
            Self::Security => write!(f, "SECURITY"),
            Self::Amcache => write!(f, "Amcache.hve"),
            Self::Bcd => write!(f, "BCD"),
            Self::Default => write!(f, "DEFAULT"),
            Self::Components => write!(f, "COMPONENTS"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Hive<Cursor<Vec<u8>>> {
    /// Auto-detect the hive type by examining the root key structure.
    ///
    /// Detection strategy:
    /// - SYSTEM: has `Select` and `ControlSet001` subkeys
    /// - SOFTWARE: has `Microsoft` and `Classes` subkeys at root
    /// - SAM: has `SAM` subkey with `Domains` subkey
    /// - SECURITY: has `Policy` subkey
    /// - NTUSER.DAT: has `Software` subkey plus typical user-profile keys
    /// - UsrClass.dat: root name contains "Classes" or has `CLSID` subkey
    /// - Amcache: has `Root` or `InventoryApplicationFile` subkey
    /// - BCD: has `Description` and `Objects` subkeys
    /// - DEFAULT: has `AppEvents` at root without `Software`
    pub fn detect_hive_type(&self) -> HiveType {
        let Ok(root) = self.root_key() else {
            return HiveType::Unknown;
        };

        let Ok(subkeys) = root.subkeys() else {
            return HiveType::Unknown;
        };

        let names: Vec<String> = subkeys
            .iter()
            .map(|k| k.name().to_ascii_uppercase())
            .collect();

        // SYSTEM: has Select + ControlSet001
        if names.contains(&"SELECT".to_string()) && names.contains(&"CONTROLSET001".to_string()) {
            return HiveType::System;
        }

        // SAM: has SAM subkey with Domains underneath
        if names.contains(&"SAM".to_string()) {
            if let Ok(Some(sam)) = root.subkey("SAM") {
                if let Ok(Some(_)) = sam.subkey("Domains") {
                    return HiveType::Sam;
                }
            }
        }

        // SECURITY: has Policy
        if names.contains(&"POLICY".to_string()) {
            return HiveType::Security;
        }

        // Amcache: has Root or InventoryApplicationFile
        if names.contains(&"ROOT".to_string())
            || names.contains(&"INVENTORYAPPLICATIONFILE".to_string())
        {
            return HiveType::Amcache;
        }

        // BCD: has Description + Objects
        if names.contains(&"DESCRIPTION".to_string()) && names.contains(&"OBJECTS".to_string()) {
            return HiveType::Bcd;
        }

        // SOFTWARE: has Microsoft + Classes subkeys at root
        if names.contains(&"MICROSOFT".to_string()) && names.contains(&"CLASSES".to_string()) {
            return HiveType::Software;
        }

        // NTUSER.DAT: has Software subkey plus typical user-profile keys
        if names.contains(&"SOFTWARE".to_string())
            && (names.contains(&"APPEVENTS".to_string())
                || names.contains(&"CONSOLE".to_string())
                || names.contains(&"ENVIRONMENT".to_string()))
        {
            return HiveType::NtUser;
        }

        // DEFAULT: has AppEvents at root but no Software
        if names.contains(&"APPEVENTS".to_string()) && !names.contains(&"SOFTWARE".to_string()) {
            return HiveType::Default;
        }

        // UsrClass.dat: root name contains "Classes"
        if root.name().to_ascii_uppercase().contains("CLASSES") {
            return HiveType::UsrClass;
        }

        HiveType::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hive_type_display() {
        assert_eq!(HiveType::System.to_string(), "SYSTEM");
        assert_eq!(HiveType::NtUser.to_string(), "NTUSER.DAT");
        assert_eq!(HiveType::Amcache.to_string(), "Amcache.hve");
        assert_eq!(HiveType::Software.to_string(), "SOFTWARE");
        assert_eq!(HiveType::Sam.to_string(), "SAM");
        assert_eq!(HiveType::Security.to_string(), "SECURITY");
        assert_eq!(HiveType::Bcd.to_string(), "BCD");
        assert_eq!(HiveType::Default.to_string(), "DEFAULT");
        assert_eq!(HiveType::Components.to_string(), "COMPONENTS");
        assert_eq!(HiveType::UsrClass.to_string(), "UsrClass.dat");
        assert_eq!(HiveType::Unknown.to_string(), "Unknown");
    }
}
