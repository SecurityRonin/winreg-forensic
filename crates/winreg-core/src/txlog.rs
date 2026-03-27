//! Transaction log replay — apply dirty pages from .LOG1/.LOG2 files.
//!
//! Two log formats:
//! - **Old format** (Vista and earlier): DIRT bitmap + dirty pages
//! - **New format** (Vista+): `HvLE` (Hive Log Entry) records with Marvin32 checksums
//!
//! The `OverlayBuffer` applies dirty pages on top of original hive bytes
//! without modifying the original — forensic purity.

use std::collections::BTreeMap;

use crate::error::Result;

/// Overlay buffer: original hive bytes + patched dirty pages.
/// Implements transparent read-through with patches applied.
pub struct OverlayBuffer {
    base: Vec<u8>,
    /// Map from page offset → replacement page bytes.
    dirty_pages: BTreeMap<u64, Vec<u8>>,
}

impl OverlayBuffer {
    /// Create a new overlay from base hive data.
    pub fn new(base: Vec<u8>) -> Self {
        Self {
            base,
            dirty_pages: BTreeMap::new(),
        }
    }

    /// Apply a dirty page at the given offset.
    pub fn apply_page(&mut self, offset: u64, data: Vec<u8>) {
        self.dirty_pages.insert(offset, data);
    }

    /// Read bytes at the given offset, with dirty pages overlaid.
    pub fn read_at(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let pos = offset + i as u64;
            // Check if this byte falls within a dirty page.
            let byte = self
                .dirty_pages
                .iter()
                .rev()
                .find(|(&page_offset, page_data)| {
                    pos >= page_offset && pos < page_offset + page_data.len() as u64
                })
                .map_or_else(
                    || {
                        usize::try_from(pos)
                            .ok()
                            .and_then(|idx| self.base.get(idx))
                            .copied()
                            .unwrap_or(0)
                    },
                    |(&page_offset, page_data)| {
                        let idx = usize::try_from(pos - page_offset).unwrap_or(0);
                        page_data[idx]
                    },
                );
            result.push(byte);
        }
        result
    }

    /// Get the total size (same as base).
    pub fn len(&self) -> usize {
        self.base.len()
    }

    /// Returns true if the base buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.base.is_empty()
    }

    /// Materialize the full overlaid buffer as a `Vec<u8>`.
    pub fn materialize(&self) -> Vec<u8> {
        self.read_at(0, self.base.len())
    }

    /// Number of dirty pages applied.
    pub fn dirty_page_count(&self) -> usize {
        self.dirty_pages.len()
    }
}

/// Replay transaction logs onto a hive.
///
/// Reads the hive file and all log files, applies dirty pages from the logs,
/// returns an `OverlayBuffer` that can be used with `Hive::from_bytes(overlay.materialize())`.
pub fn replay_transaction_logs(hive_data: Vec<u8>, log_datas: &[Vec<u8>]) -> Result<OverlayBuffer> {
    let mut overlay = OverlayBuffer::new(hive_data);

    for log_data in log_datas {
        if log_data.len() < 512 {
            continue; // Too small to be a valid log
        }

        // Check for log file signature (same "regf" header but file_type != 0)
        if &log_data[0..4] != b"regf" {
            continue;
        }

        let file_type = u32::from_le_bytes(log_data[0x1C..0x20].try_into().unwrap());

        match file_type {
            1 | 6 => {
                // Transaction log file — check for old or new format.
                // New format: scan for HvLE entries starting after the 512/1024-byte header.
                parse_new_format_log(log_data, &mut overlay);
            }
            _ => {}
        }
    }

    Ok(overlay)
}

/// Parse new-format (`HvLE`) transaction log entries.
fn parse_new_format_log(log_data: &[u8], overlay: &mut OverlayBuffer) {
    // HvLE entries start after the log header (typically 512 bytes for logs).
    // Each HvLE entry: signature "HvLE" (4 bytes), then structured data.
    let mut pos = 512; // Start scanning after header

    while pos + 4 <= log_data.len() {
        if &log_data[pos..pos + 4] == b"HvLE" {
            // Parse HvLE entry
            if pos + 40 > log_data.len() {
                break;
            }

            let size = u32::from_le_bytes(log_data[pos + 4..pos + 8].try_into().unwrap());
            // dirty_page_count at offset +16 relative to HvLE start
            let page_count =
                u32::from_le_bytes(log_data[pos + 16..pos + 20].try_into().unwrap()) as usize;

            // Dirty page references start at offset +40
            let ref_start = pos + 40;
            let data_start = ref_start + page_count * 8;

            for i in 0..page_count {
                let ref_offset = ref_start + i * 8;
                if ref_offset + 8 > log_data.len() {
                    break;
                }
                let page_offset =
                    u32::from_le_bytes(log_data[ref_offset..ref_offset + 4].try_into().unwrap());
                let page_size = u32::from_le_bytes(
                    log_data[ref_offset + 4..ref_offset + 8].try_into().unwrap(),
                );

                // Calculate where the page data is in the log file.
                // Pages are stored sequentially after all page references.
                let accumulated_size: u32 = (0..i)
                    .map(|j| {
                        let r = ref_start + j * 8 + 4;
                        u32::from_le_bytes(log_data[r..r + 4].try_into().unwrap_or([0; 4]))
                    })
                    .sum();

                let data_offset = data_start + accumulated_size as usize;
                let data_end = data_offset + page_size as usize;

                if data_end <= log_data.len() {
                    // Apply to file offset: 4096 (base block) + page_offset
                    let file_offset = 4096u64 + u64::from(page_offset);
                    overlay.apply_page(file_offset, log_data[data_offset..data_end].to_vec());
                }
            }

            pos += size as usize;
        } else {
            pos += 1; // Scan forward
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_read_through() {
        let base = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let overlay = OverlayBuffer::new(base);
        assert_eq!(overlay.read_at(0, 4), vec![1, 2, 3, 4]);
    }

    #[test]
    fn overlay_applies_dirty_page() {
        let base = vec![0; 16];
        let mut overlay = OverlayBuffer::new(base);
        overlay.apply_page(4, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let result = overlay.materialize();
        assert_eq!(result[0..4], [0, 0, 0, 0]);
        assert_eq!(result[4..8], [0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(result[8..12], [0, 0, 0, 0]);
    }

    #[test]
    fn overlay_multiple_pages() {
        let base = vec![0; 32];
        let mut overlay = OverlayBuffer::new(base);
        overlay.apply_page(0, vec![1, 1, 1, 1]);
        overlay.apply_page(16, vec![2, 2, 2, 2]);
        let result = overlay.materialize();
        assert_eq!(result[0], 1);
        assert_eq!(result[16], 2);
        assert_eq!(result[8], 0);
    }

    #[test]
    fn overlay_dirty_page_count() {
        let mut overlay = OverlayBuffer::new(vec![0; 16]);
        assert_eq!(overlay.dirty_page_count(), 0);
        overlay.apply_page(0, vec![1]);
        assert_eq!(overlay.dirty_page_count(), 1);
    }
}
