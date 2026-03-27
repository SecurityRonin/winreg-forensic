//! Filesystem scanner — find registry hives in evidence directories.

use std::fs;
use std::path::Path;

use winreg_core::detect::HiveType;
use winreg_core::hive::Hive;

use crate::types::{HiveSource, SourceOrigin};

/// Well-known hive filenames in `Windows/System32/config/`.
const CONFIG_HIVES: &[&str] = &["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT"];

/// Scan an evidence root directory for registry hive files.
///
/// Checks standard Windows paths for live hives, `RegBack` copies,
/// user hives (`NTUSER.DAT`, `UsrClass.dat`), and transaction logs.
/// Returns discovered hives sorted by (hive type, timestamp).
pub fn discover_hives(evidence_root: &Path) -> Vec<HiveSource> {
    let mut sources = Vec::new();

    // 1. System config hives
    let config_dir = evidence_root
        .join("Windows")
        .join("System32")
        .join("config");
    if config_dir.is_dir() {
        for name in CONFIG_HIVES {
            try_probe_hive(&config_dir.join(name), SourceOrigin::Live, &mut sources);
            // Check for transaction logs
            try_probe_log(&config_dir.join(format!("{name}.LOG1")), 1, &mut sources);
            try_probe_log(&config_dir.join(format!("{name}.LOG2")), 2, &mut sources);
        }
    }

    // 2. RegBack
    let regback_dir = config_dir.join("RegBack");
    if regback_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&regback_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    try_probe_hive(&path, SourceOrigin::RegBack, &mut sources);
                }
            }
        }
    }

    // 3. User hives
    let users_dir = evidence_root.join("Users");
    if users_dir.is_dir() {
        if let Ok(entries) = fs::read_dir(&users_dir) {
            for entry in entries.flatten() {
                let profile = entry.path();
                if !profile.is_dir() {
                    continue;
                }
                // NTUSER.DAT
                try_probe_hive(
                    &profile.join("NTUSER.DAT"),
                    SourceOrigin::Live,
                    &mut sources,
                );
                // UsrClass.dat
                let usrclass = profile
                    .join("AppData")
                    .join("Local")
                    .join("Microsoft")
                    .join("Windows")
                    .join("UsrClass.dat");
                try_probe_hive(&usrclass, SourceOrigin::Live, &mut sources);
            }
        }
    }

    // Sort by hive type name, then timestamp
    sources.sort_by(|a, b| {
        a.hive_type
            .to_string()
            .cmp(&b.hive_type.to_string())
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });

    sources
}

/// Try to open a file as a registry hive and add it to the sources list.
fn try_probe_hive(path: &Path, origin: SourceOrigin, sources: &mut Vec<HiveSource>) {
    if !path.is_file() {
        return;
    }

    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size < 4096 {
        return; // Too small for a valid hive
    }

    let Ok(hive) = Hive::from_path(path) else {
        return; // Not a valid REGF file
    };

    let hive_type = hive.detect_hive_type();
    let timestamp = hive.root_key().ok().and_then(|k| k.last_written());
    let is_clean = hive.is_clean();

    sources.push(HiveSource {
        path: path.to_path_buf(),
        hive_type,
        origin,
        timestamp,
        size,
        is_clean,
    });
}

/// Try to probe a transaction log file.
fn try_probe_log(path: &Path, log_num: u8, sources: &mut Vec<HiveSource>) {
    if !path.is_file() {
        return;
    }

    let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if size < 512 {
        return;
    }

    // Check for "regf" signature
    let Ok(data) = fs::read(path) else {
        return;
    };
    if data.len() < 4 || &data[0..4] != b"regf" {
        return;
    }

    sources.push(HiveSource {
        path: path.to_path_buf(),
        hive_type: HiveType::Unknown,
        origin: SourceOrigin::TransactionLog { log_num },
        timestamp: None,
        size,
        is_clean: false,
    });
}
