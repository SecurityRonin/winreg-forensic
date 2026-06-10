//! `TestHiveBuilder` — constructs valid in-memory REGF hive byte vectors for testing.
//!
//! Produces bytes that pass `winreg_core::hive::Hive::from_bytes()` validation,
//! enabling TDD for all hive-reading features.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;

use winreg_format::cells::lh_hash;
use winreg_format::header::BaseBlock;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Builds a synthetic REGF hive in memory.
pub struct TestHiveBuilder {
    keys: Vec<String>,
    values: Vec<TestValue>,
}

struct TestValue {
    key_path: String,
    name: String,
    data_type: u32,
    data: Vec<u8>,
}

impl TestHiveBuilder {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            values: Vec::new(),
        }
    }

    /// Add a key by backslash-separated path. Parents are created automatically.
    pub fn add_key(mut self, path: &str) -> Self {
        self.keys.push(path.to_string());
        self
    }

    /// Add a value under the given key path.
    pub fn add_value(mut self, key_path: &str, name: &str, data_type: u32, data: &[u8]) -> Self {
        self.values.push(TestValue {
            key_path: key_path.to_string(),
            name: name.to_string(),
            data_type,
            data: data.to_vec(),
        });
        self
    }

    /// Produce a valid REGF hive byte vector.
    pub fn build(self) -> Vec<u8> {
        // --- Step 1: Build key tree -------------------------------------------
        let tree = KeyTree::from_paths(&self.keys, &self.values);

        // --- Step 2: First pass — allocate cells ------------------------------
        let mut alloc = Allocator::new();

        // SK cell (single, shared by all keys)
        let sk_id = alloc.alloc_sk(&MINIMAL_SD);

        // Root NK cell
        let root_name = b"CMI-root";
        let root_id = alloc.alloc_nk(root_name, true);

        // Child NK cells (depth-first)
        let mut nk_ids: BTreeMap<String, CellId> = BTreeMap::new();
        Self::alloc_children(&tree.root_children, "", &mut alloc, &mut nk_ids, &tree);

        // VK + data + values-list cells per key
        let mut vk_map: BTreeMap<String, Vec<CellId>> = BTreeMap::new();
        let mut values_list_ids: BTreeMap<String, CellId> = BTreeMap::new();
        let mut data_cell_ids: BTreeMap<CellId, CellId> = BTreeMap::new();

        for (key_path, vals) in &tree.values {
            let mut vk_ids = Vec::new();
            for v in vals {
                let vk_id = alloc.alloc_vk(v.name.as_bytes(), v.data_type, v.data.len() as u32);
                // Non-resident data (> 4 bytes): allocate a data cell
                if v.data.len() > 4 {
                    let data_id = alloc.alloc_data(&v.data);
                    data_cell_ids.insert(vk_id, data_id);
                }
                vk_ids.push(vk_id);
            }
            // Values list cell
            let vl_id = alloc.alloc_values_list(vk_ids.len());
            values_list_ids.insert(key_path.clone(), vl_id);
            vk_map.insert(key_path.clone(), vk_ids);
        }

        // LH subkey index cells for keys that have children
        let mut lh_ids: BTreeMap<String, CellId> = BTreeMap::new();
        // Root level
        if !tree.root_children.is_empty() {
            let lh_id = alloc.alloc_lh(tree.root_children.len());
            lh_ids.insert(String::new(), lh_id);
        }
        Self::alloc_lh_cells(&tree.root_children, "", &mut alloc, &mut lh_ids, &tree);

        // --- Step 3: Write cells into hbin ------------------------------------
        let hbin_data_start: usize = 32; // after hbin header
        let total_cells_size = alloc.pos;
        // hbin must be a multiple of 4096 (including the 32-byte header)
        let hbin_content = hbin_data_start + total_cells_size;
        let hbin_size = align_4096(hbin_content);
        let free_size = hbin_size - hbin_content;

        let total_file_size = BaseBlock::SIZE + hbin_size;
        let mut buf = vec![0u8; total_file_size];

        let hbin_file_start = BaseBlock::SIZE;

        // Write cells into buffer
        for cell in &alloc.cells {
            let file_pos = hbin_file_start + hbin_data_start + cell.offset;
            let neg_size = -(cell.aligned_size as i32);
            buf[file_pos..file_pos + 4].copy_from_slice(&neg_size.to_le_bytes());
            buf[file_pos + 4..file_pos + 4 + cell.body.len()].copy_from_slice(&cell.body);
        }

        // --- Step 4: Second pass — link cells ---------------------------------

        // Helper: get cell offset (relative to hive bins data start)
        let cell_offset = |id: CellId| -> u32 {
            let cell = &alloc.cells[id.0];
            (hbin_data_start + cell.offset) as u32
        };

        // Root NK linkage
        {
            let root_off = cell_offset(root_id);
            let sk_off = cell_offset(sk_id);
            let root_cell_file = hbin_file_start + hbin_data_start + alloc.cells[root_id.0].offset;

            // security_offset
            write_u32(&mut buf, root_cell_file + 4 + NK_SECURITY_OFFSET, sk_off);
            // subkeys_list_offset
            if let Some(lh_id) = lh_ids.get("") {
                let lh_off = cell_offset(*lh_id);
                write_u32(
                    &mut buf,
                    root_cell_file + 4 + NK_SUBKEYS_LIST_OFFSET,
                    lh_off,
                );
                write_u32(
                    &mut buf,
                    root_cell_file + 4 + NK_SUBKEY_COUNT_OFFSET,
                    tree.root_children.len() as u32,
                );
            }
            // parent of root points to itself (by convention)
            write_u32(&mut buf, root_cell_file + 4 + NK_PARENT_OFFSET, root_off);

            // SK flink/blink point to self
            let sk_cell_file = hbin_file_start + hbin_data_start + alloc.cells[sk_id.0].offset;
            write_u32(&mut buf, sk_cell_file + 4 + SK_FLINK_OFFSET, sk_off);
            write_u32(&mut buf, sk_cell_file + 4 + SK_BLINK_OFFSET, sk_off);
        }

        // Child NK linkage
        Self::link_children(
            &tree.root_children,
            "",
            cell_offset(root_id),
            cell_offset(sk_id),
            &nk_ids,
            &lh_ids,
            &vk_map,
            &values_list_ids,
            &alloc,
            &tree,
            hbin_file_start,
            hbin_data_start,
            &cell_offset,
            &mut buf,
        );

        // Fill LH cells with subkey entries
        // Root LH
        if let Some(lh_id) = lh_ids.get("") {
            Self::fill_lh(
                *lh_id,
                &tree.root_children,
                "",
                &nk_ids,
                &alloc,
                hbin_file_start,
                hbin_data_start,
                &cell_offset,
                &mut buf,
            );
        }
        Self::fill_lh_recursive(
            &tree.root_children,
            "",
            &nk_ids,
            &lh_ids,
            &alloc,
            &tree,
            hbin_file_start,
            hbin_data_start,
            &cell_offset,
            &mut buf,
        );

        // Fill values list cells
        for (key_path, vk_ids) in &vk_map {
            if let Some(vl_id) = values_list_ids.get(key_path) {
                let vl_cell = &alloc.cells[vl_id.0];
                let vl_file = hbin_file_start + hbin_data_start + vl_cell.offset + 4;
                for (i, vk_id) in vk_ids.iter().enumerate() {
                    let vk_off = cell_offset(*vk_id);
                    write_u32(&mut buf, vl_file + i * 4, vk_off);
                }
            }
        }

        // Fill VK data offsets for non-resident values
        for (vk_id, data_id) in &data_cell_ids {
            let vk_cell = &alloc.cells[vk_id.0];
            let vk_file = hbin_file_start + hbin_data_start + vk_cell.offset;
            let data_off = cell_offset(*data_id);
            // data_offset is at VK body offset 6..10 (after sig(2) + name_len(2) + data_size(4))
            // In cell: [size(4)][sig(2)][name_len(2)][data_size_raw(4)][data_offset_raw(4)]
            write_u32(&mut buf, vk_file + 4 + VK_DATA_OFFSET_OFFSET, data_off);
        }

        // Write resident value data inline
        for (key_path, vals) in &tree.values {
            if let Some(vk_ids) = vk_map.get(key_path) {
                for (i, v) in vals.iter().enumerate() {
                    if v.data.len() <= 4 {
                        let vk_id = vk_ids[i];
                        let vk_cell = &alloc.cells[vk_id.0];
                        let vk_file = hbin_file_start + hbin_data_start + vk_cell.offset;
                        // Set resident bit on data_size
                        let resident_size = (v.data.len() as u32) | 0x8000_0000;
                        write_u32(&mut buf, vk_file + 4 + VK_DATA_SIZE_OFFSET, resident_size);
                        // Write inline data into data_offset field
                        let inline_pos = vk_file + 4 + VK_DATA_OFFSET_OFFSET;
                        buf[inline_pos..inline_pos + v.data.len()].copy_from_slice(&v.data);
                    }
                }
            }
        }

        // Free cell at end of hbin (if any space)
        if free_size >= 8 {
            let free_file = hbin_file_start + hbin_content;
            buf[free_file..free_file + 4].copy_from_slice(&(free_size as i32).to_le_bytes());
        }

        // --- Step 5: Write hbin header ----------------------------------------
        buf[hbin_file_start..hbin_file_start + 4].copy_from_slice(b"hbin");
        write_u32(&mut buf, hbin_file_start + 4, 0); // offset = 0
        write_u32(&mut buf, hbin_file_start + 8, hbin_size as u32);

        // --- Step 6: Write base block -----------------------------------------
        let root_cell_off = cell_offset(root_id);
        buf[0..4].copy_from_slice(b"regf");
        write_u32(&mut buf, 0x04, 1); // primary seq
        write_u32(&mut buf, 0x08, 1); // secondary seq
        write_u32(&mut buf, 0x14, 1); // major version
        write_u32(&mut buf, 0x18, 5); // minor version (1.5)
        write_u32(&mut buf, 0x20, 1); // format
        write_u32(&mut buf, 0x24, root_cell_off);
        write_u32(&mut buf, 0x28, hbin_size as u32);
        write_u32(&mut buf, 0x2C, 1); // clustering factor

        let checksum = BaseBlock::compute_checksum(&buf);
        write_u32(&mut buf, 0x1FC, checksum);

        buf
    }

    /// Recursively allocate NK cells for all children in the tree.
    fn alloc_children(
        children: &[String],
        parent_path: &str,
        alloc: &mut Allocator,
        nk_ids: &mut BTreeMap<String, CellId>,
        tree: &KeyTree,
    ) {
        for child_name in children {
            let full_path = if parent_path.is_empty() {
                child_name.clone()
            } else {
                format!("{parent_path}\\{child_name}")
            };
            let nk_id = alloc.alloc_nk(child_name.as_bytes(), false);
            nk_ids.insert(full_path.clone(), nk_id);

            // Recurse into grandchildren
            if let Some(grandchildren) = tree.children.get(&full_path) {
                if !grandchildren.is_empty() {
                    Self::alloc_children(grandchildren, &full_path, alloc, nk_ids, tree);
                }
            }
        }
    }

    /// Recursively allocate LH cells for keys that have children.
    fn alloc_lh_cells(
        children: &[String],
        parent_path: &str,
        alloc: &mut Allocator,
        lh_ids: &mut BTreeMap<String, CellId>,
        tree: &KeyTree,
    ) {
        for child_name in children {
            let full_path = if parent_path.is_empty() {
                child_name.clone()
            } else {
                format!("{parent_path}\\{child_name}")
            };
            if let Some(grandchildren) = tree.children.get(&full_path) {
                if !grandchildren.is_empty() {
                    let lh_id = alloc.alloc_lh(grandchildren.len());
                    lh_ids.insert(full_path.clone(), lh_id);
                    Self::alloc_lh_cells(grandchildren, &full_path, alloc, lh_ids, tree);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn link_children(
        children: &[String],
        parent_path: &str,
        parent_nk_offset: u32,
        sk_offset: u32,
        nk_ids: &BTreeMap<String, CellId>,
        lh_ids: &BTreeMap<String, CellId>,
        vk_map: &BTreeMap<String, Vec<CellId>>,
        values_list_ids: &BTreeMap<String, CellId>,
        alloc: &Allocator,
        tree: &KeyTree,
        hbin_file_start: usize,
        hbin_data_start: usize,
        cell_offset: &dyn Fn(CellId) -> u32,
        buf: &mut [u8],
    ) {
        for child_name in children {
            let full_path = if parent_path.is_empty() {
                child_name.clone()
            } else {
                format!("{parent_path}\\{child_name}")
            };
            let nk_id = nk_ids[&full_path];
            let nk_cell = &alloc.cells[nk_id.0];
            let nk_file = hbin_file_start + hbin_data_start + nk_cell.offset;

            // parent
            write_u32(buf, nk_file + 4 + NK_PARENT_OFFSET, parent_nk_offset);
            // security_offset
            write_u32(buf, nk_file + 4 + NK_SECURITY_OFFSET, sk_offset);

            // subkeys
            if let Some(grandchildren) = tree.children.get(&full_path) {
                if !grandchildren.is_empty() {
                    if let Some(lh_id) = lh_ids.get(&full_path) {
                        write_u32(
                            buf,
                            nk_file + 4 + NK_SUBKEYS_LIST_OFFSET,
                            cell_offset(*lh_id),
                        );
                        write_u32(
                            buf,
                            nk_file + 4 + NK_SUBKEY_COUNT_OFFSET,
                            grandchildren.len() as u32,
                        );
                    }
                }
            }

            // values
            if let Some(vk_ids) = vk_map.get(&full_path) {
                if !vk_ids.is_empty() {
                    if let Some(vl_id) = values_list_ids.get(&full_path) {
                        write_u32(
                            buf,
                            nk_file + 4 + NK_VALUES_LIST_OFFSET,
                            cell_offset(*vl_id),
                        );
                        write_u32(
                            buf,
                            nk_file + 4 + NK_VALUE_COUNT_OFFSET,
                            vk_ids.len() as u32,
                        );
                    }
                }
            }

            // Recurse into grandchildren
            if let Some(grandchildren) = tree.children.get(&full_path) {
                if !grandchildren.is_empty() {
                    let child_nk_offset = cell_offset(nk_id);
                    Self::link_children(
                        grandchildren,
                        &full_path,
                        child_nk_offset,
                        sk_offset,
                        nk_ids,
                        lh_ids,
                        vk_map,
                        values_list_ids,
                        alloc,
                        tree,
                        hbin_file_start,
                        hbin_data_start,
                        cell_offset,
                        buf,
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_lh(
        lh_id: CellId,
        children: &[String],
        parent_path: &str,
        nk_ids: &BTreeMap<String, CellId>,
        alloc: &Allocator,
        hbin_file_start: usize,
        hbin_data_start: usize,
        cell_offset: &dyn Fn(CellId) -> u32,
        buf: &mut [u8],
    ) {
        let lh_cell = &alloc.cells[lh_id.0];
        let lh_file = hbin_file_start + hbin_data_start + lh_cell.offset;
        // LH body: [sig(2)][count(2)][elements: (offset(4) + hash(4)) * count]
        // Count is already written in alloc. Elements start at body offset 4.
        let elements_start = lh_file + 4 + 4; // +4 cell size, +4 body (sig+count)

        for (i, child_name) in children.iter().enumerate() {
            let full_path = if parent_path.is_empty() {
                child_name.clone()
            } else {
                format!("{parent_path}\\{child_name}")
            };
            let nk_id = nk_ids[&full_path];
            let nk_off = cell_offset(nk_id);
            let hash = lh_hash(child_name);
            let elem_pos = elements_start + i * 8;
            write_u32(buf, elem_pos, nk_off);
            write_u32(buf, elem_pos + 4, hash);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn fill_lh_recursive(
        children: &[String],
        parent_path: &str,
        nk_ids: &BTreeMap<String, CellId>,
        lh_ids: &BTreeMap<String, CellId>,
        alloc: &Allocator,
        tree: &KeyTree,
        hbin_file_start: usize,
        hbin_data_start: usize,
        cell_offset: &dyn Fn(CellId) -> u32,
        buf: &mut [u8],
    ) {
        for child_name in children {
            let full_path = if parent_path.is_empty() {
                child_name.clone()
            } else {
                format!("{parent_path}\\{child_name}")
            };
            if let Some(grandchildren) = tree.children.get(&full_path) {
                if !grandchildren.is_empty() {
                    if let Some(lh_id) = lh_ids.get(&full_path) {
                        Self::fill_lh(
                            *lh_id,
                            grandchildren,
                            &full_path,
                            nk_ids,
                            alloc,
                            hbin_file_start,
                            hbin_data_start,
                            cell_offset,
                            buf,
                        );
                    }
                    Self::fill_lh_recursive(
                        grandchildren,
                        &full_path,
                        nk_ids,
                        lh_ids,
                        alloc,
                        tree,
                        hbin_file_start,
                        hbin_data_start,
                        cell_offset,
                        buf,
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Key tree built from flat paths
// ---------------------------------------------------------------------------

struct KeyTree {
    /// Direct children of the root key.
    root_children: Vec<String>,
    /// Map from full path -> direct child names.
    children: BTreeMap<String, Vec<String>>,
    /// Map from full path -> values.
    values: BTreeMap<String, Vec<TreeValue>>,
}

struct TreeValue {
    name: String,
    data_type: u32,
    data: Vec<u8>,
}

impl KeyTree {
    fn from_paths(keys: &[String], values: &[TestValue]) -> Self {
        let mut all_paths: Vec<String> = Vec::new();

        // Collect all paths (including auto-created parents)
        for path in keys {
            let parts: Vec<&str> = path.split('\\').collect();
            for i in 1..=parts.len() {
                let prefix = parts[..i].join("\\");
                if !all_paths.contains(&prefix) {
                    all_paths.push(prefix);
                }
            }
        }
        // Also ensure value key paths exist
        for v in values {
            let parts: Vec<&str> = v.key_path.split('\\').collect();
            for i in 1..=parts.len() {
                let prefix = parts[..i].join("\\");
                if !all_paths.contains(&prefix) {
                    all_paths.push(prefix);
                }
            }
        }

        // Build parent-child relationships
        let mut root_children: Vec<String> = Vec::new();
        let mut children_map: BTreeMap<String, Vec<String>> = BTreeMap::new();

        for path in &all_paths {
            if let Some(pos) = path.rfind('\\') {
                let parent = &path[..pos];
                let child_name = &path[pos + 1..];
                children_map
                    .entry(parent.to_string())
                    .or_default()
                    .push(child_name.to_string());
            } else {
                // Top-level key (direct child of root)
                if !root_children.contains(path) {
                    root_children.push(path.clone());
                }
            }
        }

        // Deduplicate children
        for v in children_map.values_mut() {
            v.dedup();
        }

        // Build values map
        let mut values_map: BTreeMap<String, Vec<TreeValue>> = BTreeMap::new();
        for v in values {
            values_map
                .entry(v.key_path.clone())
                .or_default()
                .push(TreeValue {
                    name: v.name.clone(),
                    data_type: v.data_type,
                    data: v.data.clone(),
                });
        }

        Self {
            root_children,
            children: children_map,
            values: values_map,
        }
    }
}

// ---------------------------------------------------------------------------
// Cell allocator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct CellId(usize);

struct AllocatedCell {
    offset: usize,
    aligned_size: usize,
    body: Vec<u8>,
}

struct Allocator {
    pos: usize,
    cells: Vec<AllocatedCell>,
}

impl Allocator {
    fn new() -> Self {
        Self {
            pos: 0,
            cells: Vec::new(),
        }
    }

    /// Allocate a cell with the given body bytes. Returns the cell id.
    fn alloc(&mut self, body: Vec<u8>) -> CellId {
        let content_size = 4 + body.len(); // 4 for cell size field
        let aligned = align8(content_size);
        let id = CellId(self.cells.len());
        self.cells.push(AllocatedCell {
            offset: self.pos,
            aligned_size: aligned,
            body,
        });
        self.pos += aligned;
        id
    }

    /// Allocate an SK cell with minimal security descriptor.
    fn alloc_sk(&mut self, descriptor: &[u8]) -> CellId {
        // Body: "sk" + reserved(2) + flink(4) + blink(4) + ref_count(4) + desc_size(4) + descriptor
        let mut body = Vec::with_capacity(2 + 2 + 4 + 4 + 4 + 4 + descriptor.len());
        body.extend_from_slice(b"sk");
        body.extend_from_slice(&0u16.to_le_bytes()); // reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // flink (placeholder)
        body.extend_from_slice(&0u32.to_le_bytes()); // blink (placeholder)
        body.extend_from_slice(&1u32.to_le_bytes()); // reference_count
        body.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
        body.extend_from_slice(descriptor);
        self.alloc(body)
    }

    /// Allocate an NK cell.
    fn alloc_nk(&mut self, name: &[u8], is_root: bool) -> CellId {
        // Body: "nk" + flags(2) + last_written(8) + access_bits(4) + parent(4)
        //   + subkey_count(4) + volatile_subkey_count(4) + subkeys_list_offset(4)
        //   + volatile_subkeys_list_offset(4) + value_count(4) + values_list_offset(4)
        //   + security_offset(4) + class_name_offset(4) + max_subkey_name_compound(4)
        //   + max_subkey_class_len(4) + max_value_name_len(4) + max_value_data_size(4)
        //   + work_var(4) + key_name_len(2) + class_name_len(2) + key_name(N)
        let flags: u16 = if is_root {
            0x0004 | 0x0020 // HIVE_ENTRY | COMP_NAME
        } else {
            0x0020 // COMP_NAME
        };

        let mut body = Vec::with_capacity(2 + 74 + name.len());
        body.extend_from_slice(b"nk");
        body.extend_from_slice(&flags.to_le_bytes()); // flags
        body.extend_from_slice(&0u64.to_le_bytes()); // last_written
        body.extend_from_slice(&0u32.to_le_bytes()); // access_bits
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // parent (placeholder)
        body.extend_from_slice(&0u32.to_le_bytes()); // subkey_count (placeholder)
        body.extend_from_slice(&0u32.to_le_bytes()); // volatile_subkey_count
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // subkeys_list_offset (placeholder)
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // volatile_subkeys_list_offset
        body.extend_from_slice(&0u32.to_le_bytes()); // value_count (placeholder)
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // values_list_offset (placeholder)
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // security_offset (placeholder)
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // class_name_offset
        body.extend_from_slice(&0u32.to_le_bytes()); // max_subkey_name_compound
        body.extend_from_slice(&0u32.to_le_bytes()); // max_subkey_class_len
        body.extend_from_slice(&0u32.to_le_bytes()); // max_value_name_len
        body.extend_from_slice(&0u32.to_le_bytes()); // max_value_data_size
        body.extend_from_slice(&0u32.to_le_bytes()); // work_var
        body.extend_from_slice(&(name.len() as u16).to_le_bytes()); // key_name_len
        body.extend_from_slice(&0u16.to_le_bytes()); // class_name_len
        body.extend_from_slice(name); // key_name
        self.alloc(body)
    }

    /// Allocate a VK cell (`data_offset` is a placeholder; set in linking pass).
    fn alloc_vk(&mut self, name: &[u8], data_type: u32, data_size: u32) -> CellId {
        // Body: "vk" + name_len(2) + data_size_raw(4) + data_offset_raw(4)
        //   + data_type(4) + flags(2) + spare(2) + name(N)
        let flags: u16 = u16::from(!name.is_empty()); // COMP_NAME

        let mut body = Vec::with_capacity(2 + 18 + name.len());
        body.extend_from_slice(b"vk");
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&data_size.to_le_bytes()); // data_size_raw (placeholder, fixed in link pass for resident)
        body.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // data_offset_raw (placeholder)
        body.extend_from_slice(&data_type.to_le_bytes());
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // spare
        body.extend_from_slice(name);
        self.alloc(body)
    }

    /// Allocate a data cell (raw bytes, no signature).
    fn alloc_data(&mut self, data: &[u8]) -> CellId {
        self.alloc(data.to_vec())
    }

    /// Allocate a values list cell (array of VK offsets, filled in linking pass).
    fn alloc_values_list(&mut self, count: usize) -> CellId {
        let body = vec![0u8; count * 4]; // placeholder offsets
        self.alloc(body)
    }

    /// Allocate an LH cell with space for `count` elements.
    fn alloc_lh(&mut self, count: usize) -> CellId {
        // Body: "lh" + count(2) + elements(count * 8)
        let mut body = Vec::with_capacity(2 + 2 + count * 8);
        body.extend_from_slice(b"lh");
        body.extend_from_slice(&(count as u16).to_le_bytes());
        body.extend_from_slice(&vec![0u8; count * 8]); // placeholder elements
        self.alloc(body)
    }
}

// ---------------------------------------------------------------------------
// Constants — byte offsets within NK cell body (after "nk" signature)
// These match `RawKeyNode::parse()` which reads from after the 2-byte sig.
// But in our buffer, body starts at "nk", so add 2 for the sig bytes.
// ---------------------------------------------------------------------------

/// Offset of `parent` field within NK body (from start of body including "nk" sig).
const NK_PARENT_OFFSET: usize = 2 + 14; // sig(2) + flags(2) + last_written(8) + access_bits(4) = 16
/// Offset of `subkey_count` within NK body.
const NK_SUBKEY_COUNT_OFFSET: usize = 2 + 18; // + parent(4) = 20
/// Offset of `subkeys_list_offset` within NK body.
const NK_SUBKEYS_LIST_OFFSET: usize = 2 + 26; // + subkey_count(4) + volatile_subkey_count(4) = 28
/// Offset of `value_count` within NK body.
const NK_VALUE_COUNT_OFFSET: usize = 2 + 34; // + subkeys_list(4) + volatile_subkeys_list(4) + ... = 36
/// Offset of `values_list_offset` within NK body.
const NK_VALUES_LIST_OFFSET: usize = 2 + 38; // + value_count(4) = 40
/// Offset of `security_offset` within NK body.
const NK_SECURITY_OFFSET: usize = 2 + 42; // + values_list(4) = 44

/// Offset of `data_size_raw` within VK body.
const VK_DATA_SIZE_OFFSET: usize = 2 + 2; // sig(2) + name_len(2)
/// Offset of `data_offset_raw` within VK body.
const VK_DATA_OFFSET_OFFSET: usize = 2 + 6; // sig(2) + name_len(2) + data_size(4)

/// Offset of flink within SK body
const SK_FLINK_OFFSET: usize = 2 + 2; // sig(2) + reserved(2)
/// Offset of blink within SK body
const SK_BLINK_OFFSET: usize = 2 + 6; // sig(2) + reserved(2) + flink(4)

// ---------------------------------------------------------------------------
// Minimal security descriptor (NT SECURITY_DESCRIPTOR, self-relative)
// ---------------------------------------------------------------------------

/// Minimal self-relative security descriptor (20 bytes).
/// Revision=1, Control=0x8000 (self-relative), no DACL/SACL/owner/group.
const MINIMAL_SD: [u8; 20] = [
    0x01, 0x00, // Revision=1, Sbz1=0
    0x00, 0x80, // Control = SE_SELF_RELATIVE
    0x00, 0x00, 0x00, 0x00, // OwnerOffset = 0 (no owner)
    0x00, 0x00, 0x00, 0x00, // GroupOffset = 0 (no group)
    0x00, 0x00, 0x00, 0x00, // SaclOffset = 0
    0x00, 0x00, 0x00, 0x00, // DaclOffset = 0
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn align8(size: usize) -> usize {
    (size + 7) & !7
}

fn align_4096(size: usize) -> usize {
    (size + 4095) & !4095
}

fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}
