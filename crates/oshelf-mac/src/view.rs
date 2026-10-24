//! A read-only copy of the verified tree, swapped in whole after every
//! change, so NFS lookups and listings never wait on the network or on a
//! commit in flight.

use std::collections::HashMap;

use oshelf_core::manifest::{Id, Tree, ROOT};

/// NFS file id of the shelf root.
pub const ROOT_FILEID: u64 = 1;

/// Stable 64-bit NFS file id for a node: the same on every launch and every
/// Mac, so file handles survive restarts. 0 and 1 are reserved.
pub fn fileid(id: &Id) -> u64 {
    if *id == ROOT {
        return ROOT_FILEID;
    }
    let v = u64::from_le_bytes(id[..8].try_into().expect("8 bytes")) >> 1;
    if v < 2 {
        v + 2
    } else {
        v
    }
}

pub struct View {
    pub tree: Tree,
    pub revision: u64,
    ids: HashMap<u64, Id>,
}

impl View {
    pub fn new(tree: Tree, revision: u64) -> Self {
        let ids = tree.nodes_sorted().iter().map(|n| (fileid(&n.id), n.id)).collect();
        Self { tree, revision, ids }
    }

    pub fn id(&self, fileid: u64) -> Option<Id> {
        if fileid == ROOT_FILEID {
            return Some(ROOT);
        }
        self.ids.get(&fileid).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fileids_avoid_reserved() {
        assert_eq!(fileid(&ROOT), ROOT_FILEID);
        let mut id = [0u8; 16];
        id[15] = 9;
        assert!(fileid(&id) >= 2);
        id[0] = 0xff;
        assert_eq!(fileid(&id), 0x7f);
    }
}
