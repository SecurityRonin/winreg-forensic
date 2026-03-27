//! Value snapshot — capture a registry value's state for comparison.

use winreg_core::value::Value;
use winreg_format::flags::ValueType;

use crate::types::ValueSnapshot;

/// Capture a `Value` into a `ValueSnapshot` for comparison.
pub fn value_to_snapshot(val: &Value<'_>) -> ValueSnapshot {
    let raw = val.raw_data().unwrap_or_default();
    let data_type = val.data_type();
    let display = format_value(data_type, &raw, val);

    ValueSnapshot {
        data_type: data_type.to_string(),
        display,
        raw,
    }
}

/// Format a value for human-readable display.
fn format_value(data_type: ValueType, raw: &[u8], val: &Value<'_>) -> String {
    match data_type {
        ValueType::Sz | ValueType::ExpandSz => {
            val.as_string().unwrap_or_else(|_| "<decode error>".into())
        }
        ValueType::Dword => {
            if raw.len() >= 4 {
                let v = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                format!("0x{v:08X}")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
        ValueType::DwordBigEndian => {
            if raw.len() >= 4 {
                let v = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                format!("0x{v:08X}")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
        ValueType::Qword => {
            if raw.len() >= 8 {
                let v = u64::from_le_bytes([
                    raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
                ]);
                format!("0x{v:016X}")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
        ValueType::MultiSz => val
            .as_multi_string()
            .map_or_else(|_| "<decode error>".into(), |strings| strings.join(" | ")),
        _ => {
            if raw.len() <= 16 {
                raw.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                format!("[{} bytes]", raw.len())
            }
        }
    }
}
