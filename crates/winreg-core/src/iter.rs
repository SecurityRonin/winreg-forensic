//! Key iterators — BFS and DFS traversal of the registry tree.

use std::collections::VecDeque;
use std::io::Cursor;

use crate::error::Result;
use crate::hive::Hive;
use crate::key::Key;

/// Breadth-first iterator over all keys in the hive.
pub struct BfsIter<'h> {
    queue: VecDeque<Key<'h>>,
}

impl<'h> BfsIter<'h> {
    pub fn new(hive: &'h Hive<Cursor<Vec<u8>>>) -> Result<Self> {
        let root = hive.root_key()?;
        let mut queue = VecDeque::new();
        queue.push_back(root);
        Ok(Self { queue })
    }
}

impl<'h> Iterator for BfsIter<'h> {
    type Item = Result<Key<'h>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.queue.pop_front()?;
        match key.subkeys() {
            Ok(children) => {
                for child in children {
                    self.queue.push_back(child);
                }
                Some(Ok(key))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

/// Depth-first (pre-order) iterator over all keys in the hive.
pub struct DfsIter<'h> {
    stack: Vec<Key<'h>>,
}

impl<'h> DfsIter<'h> {
    pub fn new(hive: &'h Hive<Cursor<Vec<u8>>>) -> Result<Self> {
        let root = hive.root_key()?;
        Ok(Self { stack: vec![root] })
    }
}

impl<'h> Iterator for DfsIter<'h> {
    type Item = Result<Key<'h>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.stack.pop()?;
        match key.subkeys() {
            Ok(children) => {
                for child in children.into_iter().rev() {
                    self.stack.push(child);
                }
                Some(Ok(key))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

impl Hive<Cursor<Vec<u8>>> {
    /// Iterate all keys in breadth-first order.
    pub fn iter_bfs(&self) -> Result<BfsIter<'_>> {
        BfsIter::new(self)
    }

    /// Iterate all keys in depth-first (pre-order) order.
    pub fn iter_dfs(&self) -> Result<DfsIter<'_>> {
        DfsIter::new(self)
    }
}
