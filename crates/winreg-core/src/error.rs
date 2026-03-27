//! Error types for registry hive parsing.

use miette::Diagnostic;
use thiserror::Error;
use winreg_format::cells::CellOffset;

/// All errors from winreg-core.
#[derive(Debug, Error, Diagnostic)]
pub enum HiveError {
    #[error("Invalid regf signature — not a registry hive file")]
    #[diagnostic(code(winreg::invalid_signature))]
    InvalidSignature,

    #[error("Base block checksum mismatch: expected {expected:#010X}, computed {computed:#010X}")]
    #[diagnostic(code(winreg::checksum_mismatch))]
    ChecksumMismatch { expected: u32, computed: u32 },

    #[error("Unsupported REGF version: {major}.{minor}")]
    #[diagnostic(code(winreg::unsupported_version))]
    UnsupportedVersion { major: u32, minor: u32 },

    #[error("Cell at offset {offset} extends beyond hbin boundary (cell size: {cell_size}, hbin ends at: {hbin_end})")]
    #[diagnostic(code(winreg::cell_overflow))]
    CellOverflow {
        offset: CellOffset,
        cell_size: u32,
        hbin_end: u64,
    },

    #[error("Invalid cell signature at offset {offset}: expected {expected}, got [{byte0:#04X}, {byte1:#04X}]")]
    #[diagnostic(code(winreg::invalid_cell_signature))]
    InvalidCellSignature {
        offset: CellOffset,
        expected: &'static str,
        byte0: u8,
        byte1: u8,
    },

    #[error("Cell at offset {offset} is unallocated (free cell)")]
    #[diagnostic(code(winreg::unallocated_cell))]
    UnallocatedCell { offset: CellOffset },

    #[error("Null cell offset encountered where a valid offset was expected")]
    #[diagnostic(code(winreg::null_offset))]
    NullOffset,

    #[error("Hive bins data is truncated: expected {expected} bytes, got {actual}")]
    #[diagnostic(code(winreg::truncated_hive))]
    TruncatedHive { expected: u64, actual: u64 },

    #[error("Invalid hbin at file offset {file_offset}: bad signature")]
    #[diagnostic(code(winreg::invalid_hbin))]
    InvalidHbin { file_offset: u64 },

    #[error("Key not found: {path}")]
    #[diagnostic(code(winreg::key_not_found))]
    KeyNotFound { path: String },

    #[error("Value not found: {name} under key {key_path}")]
    #[diagnostic(code(winreg::value_not_found))]
    ValueNotFound { name: String, key_path: String },

    #[error("I/O error: {0}")]
    #[diagnostic(code(winreg::io))]
    Io(#[from] std::io::Error),
}

/// Result type alias for winreg-core.
pub type Result<T> = std::result::Result<T, HiveError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = HiveError::ChecksumMismatch {
            expected: 0x1234_5678,
            computed: 0xDEAD_BEEF,
        };
        let msg = format!("{err}");
        assert!(msg.contains("0x12345678"));
        assert!(msg.contains("0xDEADBEEF"));
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HiveError>();
    }

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let hive_err: HiveError = io_err.into();
        assert!(matches!(hive_err, HiveError::Io(_)));
    }
}
