//! `reg4n6 --version` must print `reg4n6 X.Y.Z` and exit 0 (fleet release standard).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

#[test]
fn version_flag_prints_name_and_version_and_exits_zero() {
    let bin = env!("CARGO_BIN_EXE_reg4n6");
    let expected = format!("reg4n6 {}", env!("CARGO_PKG_VERSION"));

    for flag in ["--version", "-V"] {
        let output = Command::new(bin).arg(flag).output().expect("run reg4n6");

        assert!(
            output.status.success(),
            "{flag} should exit 0, got {:?}",
            output.status
        );

        let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
        assert_eq!(
            stdout.trim(),
            expected,
            "{flag} stdout should be exactly `{expected}`"
        );
    }
}
