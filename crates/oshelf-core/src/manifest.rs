//! The encrypted manifest: tree nodes, sealed log entries with their hash
//! chain, and snapshots (spec: "Encrypted manifest").

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::keys::{self, bytes_n, Key};
use crate::{chunk, CHUNK_SIZE};

pub type Id = [u8; 16];
pub type Hash = [u8; 32];

/// Parent id of top-level entries.
pub const ROOT: Id = [0; 16];
pub const LOG_MAGIC: [u8; 4] = *b"OSL1";
pub const SNAPSHOT_MAGIC: [u8; 4] = *b"OSN1";
const ZSTD_LEVEL: i32 = 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("malformed sealed object")]
    Malformed,
    #[error("failed authentication (wrong key, revision or chain)")]
    Auth,
    #[error("chain broken: entry claims revision {got}, expected {expected}")]
    WrongRevision { expected: u64, got: u64 },
    #[error("snapshot segment {0} does not match its id")]
    BadSegment(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

/// One file, folder or symlink. Field order is the deterministic CBOR key
/// order (shorter keys first, then bytewise).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    #[serde(with = "bytes_n")]
    pub id: Id,
    pub kind: Kind,
    pub mode: u32,
    pub name: String,
    pub size: u64,
    #[serde(with = "bytes_n::vec", default, skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<Hash>,
    #[serde(with = "bytes_n")]
    pub parent: Id,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(with = "bytes_n::opt", default, skip_serializing_if = "Option::is_none")]
    pub file_key: Option<Key>,
    pub mtime_ns: i64,
    #[serde(with = "bytes_n::opt", default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<Id>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
}

impl Node {
    pub fn dir(id: Id, parent: Id, name: &str, mtime_ns: i64) -> Self {
        Node {
            id,
            kind: Kind::Dir,
            mode: 0o755,
            name: nfc(name),
            size: 0,
            chunks: vec![],
            parent,
            target: None,
            file_key: None,
            mtime_ns,
            object_id: None,
            chunk_size: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn file(
        id: Id,
        parent: Id,
        name: &str,
        size: u64,
        mtime_ns: i64,
        file_key: Key,
        object_id: Id,
        chunks: Vec<Hash>,
    ) -> Self {
        Node {
            id,
            kind: Kind::File,
            mode: 0o644,
            name: nfc(name),
            size,
            chunks,
            parent,
            target: None,
            file_key: Some(file_key),
            mtime_ns,
            object_id: Some(object_id),
            chunk_size: Some(CHUNK_SIZE),
        }
    }
}

/// Names are stored NFC normalized so "é" typed two ways is one name.
pub fn nfc(name: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    name.nfc().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Put(Node),
    Delete(#[serde(with = "bytes_n")] Id),
    Move {
        #[serde(with = "bytes_n")]
        id: Id,
        name: String,
        #[serde(with = "bytes_n")]
        parent: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub ops: Vec<Op>,
    pub time_ms: i64,
    pub revision: u64,
    #[serde(with = "bytes_n")]
    pub device_id: Id,
    #[serde(with = "bytes_n")]
    pub prev_hash: Hash,
}

fn compress(b: &[u8]) -> Vec<u8> {
    zstd::bulk::compress(b, ZSTD_LEVEL).expect("zstd compression of an in-memory buffer")
}

/// Largest decompressed size accepted, to bound memory on hostile input.
const MAX_PLAINTEXT: usize = 1 << 30;

fn decompress(b: &[u8]) -> Result<Vec<u8>, ManifestError> {
    zstd::stream::decode_all(std::io::Read::take(b, MAX_PLAINTEXT as u64)).map_err(|_| ManifestError::Malformed)
}

fn log_aad(revision: u64, prev_hash: &Hash) -> Vec<u8> {
    let mut a = LOG_MAGIC.to_vec();
    a.extend_from_slice(&revision.to_le_bytes());
    a.extend_from_slice(prev_hash);
    a
}

/// `"OSL1" || nonce || XChaCha20-Poly1305(KM, zstd(cbor(entry)))`.
pub fn seal_entry(km: &Key, entry: &LogEntry) -> Vec<u8> {
    seal_entry_with_nonce(km, entry, keys::random())
}

pub fn seal_entry_with_nonce(km: &Key, entry: &LogEntry, nonce: [u8; 24]) -> Vec<u8> {
    let pt = compress(&keys::to_cbor(entry));
    let mut out = LOG_MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend(keys::seal(km, &nonce, &log_aad(entry.revision, &entry.prev_hash), &pt));
    out
}

pub fn entry_hash(sealed: &[u8]) -> Hash {
    *blake3::hash(sealed).as_bytes()
}

/// The verified end of the hash chain a client has reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chain {
    pub revision: u64,
    pub hash: Hash,
}

impl Chain {
    pub const GENESIS: Chain = Chain {
        revision: 0,
        hash: [0; 32],
    };

    /// Opens the entry that must come next, checking it extends this chain.
    pub fn open_next(&self, km: &Key, sealed: &[u8]) -> Result<(LogEntry, Chain), ManifestError> {
        if sealed.len() < 4 + 24 + 16 || sealed[0..4] != LOG_MAGIC {
            return Err(ManifestError::Malformed);
        }
        let revision = self.revision + 1;
        let nonce: [u8; 24] = sealed[4..28].try_into().expect("checked length");
        let pt = keys::open(km, &nonce, &log_aad(revision, &self.hash), &sealed[28..]).ok_or(ManifestError::Auth)?;
        let entry: LogEntry = keys::from_cbor(&decompress(&pt)?).ok_or(ManifestError::Malformed)?;
        if entry.revision != revision || entry.prev_hash != self.hash {
            return Err(ManifestError::WrongRevision {
                expected: revision,
                got: entry.revision,
            });
        }
        Ok((
            entry,
            Chain {
                revision,
                hash: entry_hash(sealed),
            },
        ))
    }

    /// The entry a client would write next on top of this chain.
    pub fn next_entry(&self, device_id: Id, time_ms: i64, ops: Vec<Op>) -> LogEntry {
        LogEntry {
            ops,
            time_ms,
            revision: self.revision + 1,
            device_id,
            prev_hash: self.hash,
        }
    }
}

/// The whole tree in memory, built from a snapshot plus log entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    nodes: HashMap<Id, Node>,
    children: HashMap<Id, BTreeMap<String, Id>>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, id: &Id) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Children of a folder (or of the root), sorted by name.
    pub fn list(&self, dir: &Id) -> Vec<&Node> {
        self.children
            .get(dir)
            .map(|c| c.values().filter_map(|id| self.nodes.get(id)).collect())
            .unwrap_or_default()
    }

    pub fn child(&self, dir: &Id, name: &str) -> Option<&Node> {
        self.children
            .get(dir)?
            .get(&nfc(name))
            .and_then(|id| self.nodes.get(id))
    }

    /// Resolves `a/b/c`; `""` or `"/"` is the root (returns `None` node, `ROOT` id).
    pub fn resolve(&self, path: &str) -> Option<Id> {
        let mut cur = ROOT;
        for part in path.split('/').filter(|p| !p.is_empty()) {
            cur = self.child(&cur, part)?.id;
        }
        Some(cur)
    }

    pub fn path_of(&self, id: &Id) -> Option<String> {
        let mut parts = Vec::new();
        let mut cur = *id;
        while cur != ROOT {
            let n = self.nodes.get(&cur)?;
            parts.push(n.name.clone());
            cur = n.parent;
            if parts.len() > 4096 {
                return None;
            }
        }
        parts.reverse();
        Some(parts.join("/"))
    }

    /// All file nodes under `dir`, depth first.
    pub fn walk(&self, dir: &Id) -> Vec<&Node> {
        let mut out = Vec::new();
        for n in self.list(dir) {
            out.push(n);
            if n.kind == Kind::Dir {
                out.extend(self.walk(&n.id));
            }
        }
        out
    }

    fn unlink(&mut self, id: &Id) {
        if let Some(old) = self.nodes.get(id) {
            if let Some(c) = self.children.get_mut(&old.parent) {
                if c.get(&old.name) == Some(id) {
                    c.remove(&old.name);
                }
            }
        }
    }

    fn link(&mut self, node: Node) {
        let slot = self.children.entry(node.parent).or_default();
        // Last writer wins on a path: whatever held the name is dropped.
        if let Some(prev) = slot.insert(node.name.clone(), node.id) {
            if prev != node.id {
                self.remove(&prev);
            }
        }
        self.nodes.insert(node.id, node);
    }

    fn remove(&mut self, id: &Id) {
        self.unlink(id);
        if let Some(kids) = self.children.remove(id) {
            for kid in kids.values() {
                self.remove(kid);
            }
        }
        self.nodes.remove(id);
    }

    pub fn apply(&mut self, op: &Op) {
        match op {
            Op::Put(node) => {
                self.unlink(&node.id);
                self.link(node.clone());
            }
            Op::Delete(id) => self.remove(id),
            Op::Move { id, name, parent } => {
                if let Some(mut n) = self.nodes.get(id).cloned() {
                    self.unlink(id);
                    n.name = nfc(name);
                    n.parent = *parent;
                    self.link(n);
                }
            }
        }
    }

    pub fn apply_entry(&mut self, entry: &LogEntry) {
        entry.ops.iter().for_each(|op| self.apply(op));
    }

    /// Nodes sorted by id, the order snapshots store them in.
    pub fn nodes_sorted(&self) -> Vec<&Node> {
        let mut v: Vec<&Node> = self.nodes.values().collect();
        v.sort_by_key(|n| n.id);
        v
    }

    pub fn from_nodes(nodes: Vec<Node>) -> Self {
        let mut t = Tree::new();
        // Parents may come after children in id order; link() doesn't care.
        for n in nodes {
            t.children.entry(n.parent).or_default().insert(n.name.clone(), n.id);
            t.nodes.insert(n.id, n);
        }
        t
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub revision: u64,
    #[serde(with = "bytes_n::vec")]
    pub segments: Vec<Hash>,
    #[serde(with = "bytes_n")]
    pub entry_hash: Hash,
    pub node_count: u64,
    #[serde(with = "bytes_n")]
    pub snapshot_id: Id,
}

/// A sealed snapshot ready to upload: the segments go up as chunks and are
/// registered as one object, then the header is stored for its revision.
pub struct SealedSnapshot {
    pub header: Vec<u8>,
    pub segments: Vec<Vec<u8>>,
    pub segment_ids: Vec<Hash>,
}

fn snapshot_aad(revision: u64) -> Vec<u8> {
    let mut a = SNAPSHOT_MAGIC.to_vec();
    a.extend_from_slice(&revision.to_le_bytes());
    a
}

/// Seals `tree` as the snapshot at `chain`.
pub fn seal_snapshot(master_key: &Key, vault_id: &Id, tree: &Tree, chain: Chain) -> SealedSnapshot {
    let key = keys::snapshot_key(master_key, vault_id, chain.revision);
    let snapshot_id: Id = keys::random();
    let body = compress(&keys::to_cbor(&tree.nodes_sorted()));
    let segments: Vec<Vec<u8>> = body
        .chunks(CHUNK_SIZE as usize)
        .enumerate()
        .map(|(i, seg)| chunk::seal_chunk(&key, &snapshot_id, i as u64, seg))
        .collect();
    let segment_ids: Vec<Hash> = segments.iter().map(|s| chunk::chunk_id(s)).collect();
    let header = SnapshotHeader {
        revision: chain.revision,
        segments: segment_ids.clone(),
        entry_hash: chain.hash,
        node_count: tree.len() as u64,
        snapshot_id,
    };
    let nonce: [u8; 24] = keys::random();
    let mut sealed = SNAPSHOT_MAGIC.to_vec();
    sealed.extend_from_slice(&nonce);
    sealed.extend(keys::seal(
        &key,
        &nonce,
        &snapshot_aad(chain.revision),
        &keys::to_cbor(&header),
    ));
    SealedSnapshot {
        header: sealed,
        segments,
        segment_ids,
    }
}

pub fn open_snapshot_header(
    master_key: &Key,
    vault_id: &Id,
    revision: u64,
    sealed: &[u8],
) -> Result<SnapshotHeader, ManifestError> {
    if sealed.len() < 4 + 24 + 16 || sealed[0..4] != SNAPSHOT_MAGIC {
        return Err(ManifestError::Malformed);
    }
    let key = keys::snapshot_key(master_key, vault_id, revision);
    let nonce: [u8; 24] = sealed[4..28].try_into().expect("checked length");
    let pt = keys::open(&key, &nonce, &snapshot_aad(revision), &sealed[28..]).ok_or(ManifestError::Auth)?;
    let h: SnapshotHeader = keys::from_cbor(&pt).ok_or(ManifestError::Malformed)?;
    if h.revision != revision {
        return Err(ManifestError::WrongRevision {
            expected: revision,
            got: h.revision,
        });
    }
    Ok(h)
}

/// Rebuilds the tree from a verified header and its segments, and returns
/// the chain position the log continues from.
pub fn open_snapshot(
    master_key: &Key,
    vault_id: &Id,
    header: &SnapshotHeader,
    segments: &[Vec<u8>],
) -> Result<(Tree, Chain), ManifestError> {
    if segments.len() != header.segments.len() {
        return Err(ManifestError::Malformed);
    }
    let key = keys::snapshot_key(master_key, vault_id, header.revision);
    let mut body = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if chunk::chunk_id(seg) != header.segments[i] {
            return Err(ManifestError::BadSegment(i));
        }
        body.extend(
            chunk::open_chunk(&key, &header.snapshot_id, i as u64, seg).map_err(|_| ManifestError::BadSegment(i))?,
        );
    }
    let nodes: Vec<Node> = keys::from_cbor(&decompress(&body)?).ok_or(ManifestError::Malformed)?;
    if nodes.len() as u64 != header.node_count {
        return Err(ManifestError::Malformed);
    }
    Ok((
        Tree::from_nodes(nodes),
        Chain {
            revision: header.revision,
            hash: header.entry_hash,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Id {
        [n; 16]
    }

    fn file(n: u8, parent: Id, name: &str) -> Node {
        Node::file(id(n), parent, name, 5, 1, [n; 32], [n; 16], vec![[n; 32]])
    }

    #[test]
    fn node_and_entry_cbor_is_canonical() {
        let entry = LogEntry {
            ops: vec![
                Op::Put(file(1, ROOT, "a.txt")),
                Op::Put(Node::dir(id(2), ROOT, "docs", 0)),
                Op::Move {
                    id: id(1),
                    name: "b.txt".into(),
                    parent: id(2),
                },
                Op::Delete(id(3)),
            ],
            time_ms: 1,
            revision: 1,
            device_id: id(9),
            prev_hash: [0; 32],
        };
        let bytes = keys::to_cbor(&entry);
        keys::assert_canonical_maps(&bytes);
        assert_eq!(keys::from_cbor::<LogEntry>(&bytes).unwrap(), entry);
    }

    #[test]
    fn chain_detects_reorder_rollback_and_tamper() {
        let km = [5u8; 32];
        let mut chain = Chain::GENESIS;
        let mut sealed = Vec::new();
        for i in 0..3u8 {
            let e = chain.next_entry(id(9), i as i64, vec![Op::Put(file(i + 1, ROOT, &format!("f{i}")))]);
            let s = seal_entry(&km, &e);
            chain = Chain {
                revision: e.revision,
                hash: entry_hash(&s),
            };
            sealed.push(s);
        }
        let mut c = Chain::GENESIS;
        let mut tree = Tree::new();
        for s in &sealed {
            let (e, next) = c.open_next(&km, s).unwrap();
            tree.apply_entry(&e);
            c = next;
        }
        assert_eq!(c, chain);
        assert_eq!(tree.list(&ROOT).len(), 3);

        assert_eq!(
            Chain::GENESIS.open_next(&km, &sealed[1]),
            Err(ManifestError::Auth),
            "skipped entry"
        );
        let (_, after1) = Chain::GENESIS.open_next(&km, &sealed[0]).unwrap();
        assert_eq!(
            after1.open_next(&km, &sealed[0]),
            Err(ManifestError::Auth),
            "replayed entry"
        );
        let mut bad = sealed[0].clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(Chain::GENESIS.open_next(&km, &bad), Err(ManifestError::Auth));
        assert_eq!(
            Chain::GENESIS.open_next(&[6; 32], &sealed[0]),
            Err(ManifestError::Auth),
            "wrong key"
        );
    }

    #[test]
    fn tree_ops() {
        let mut t = Tree::new();
        t.apply(&Op::Put(Node::dir(id(1), ROOT, "Photos", 0)));
        t.apply(&Op::Put(file(2, id(1), "cat.jpg")));
        t.apply(&Op::Put(file(3, ROOT, "notes.txt")));
        assert_eq!(t.resolve("Photos/cat.jpg"), Some(id(2)));
        assert_eq!(t.path_of(&id(2)).unwrap(), "Photos/cat.jpg");
        assert_eq!(t.walk(&ROOT).len(), 3);

        t.apply(&Op::Move {
            id: id(3),
            name: "todo.txt".into(),
            parent: id(1),
        });
        assert_eq!(t.resolve("notes.txt"), None);
        assert_eq!(t.resolve("Photos/todo.txt"), Some(id(3)));

        // Same path, new id: last writer wins.
        t.apply(&Op::Put(file(4, id(1), "cat.jpg")));
        assert_eq!(t.resolve("Photos/cat.jpg"), Some(id(4)));
        assert!(t.get(&id(2)).is_none());

        // NFC: decomposed é finds the composed name.
        t.apply(&Op::Put(file(5, ROOT, "caf\u{e9}")));
        assert_eq!(t.resolve("cafe\u{301}"), Some(id(5)));

        t.apply(&Op::Delete(id(1)));
        assert_eq!(t.list(&ROOT).len(), 1);
        assert_eq!(t.len(), 1, "children of a deleted folder go too");
    }

    #[test]
    fn snapshot_round_trip() {
        let mk = [7u8; 32];
        let vault = id(8);
        let mut t = Tree::new();
        for i in 1..=50u8 {
            t.apply(&Op::Put(file(i, ROOT, &format!("file{i}"))));
        }
        let chain = Chain {
            revision: 42,
            hash: [3; 32],
        };
        let s = seal_snapshot(&mk, &vault, &t, chain);
        let h = open_snapshot_header(&mk, &vault, 42, &s.header).unwrap();
        assert_eq!(h.segments, s.segment_ids);
        assert_eq!(
            open_snapshot_header(&mk, &vault, 41, &s.header),
            Err(ManifestError::Auth)
        );
        let (t2, c2) = open_snapshot(&mk, &vault, &h, &s.segments).unwrap();
        assert_eq!(t2, t);
        assert_eq!(c2, chain);

        let mut bad = s.segments.clone();
        bad[0][40] ^= 1;
        assert_eq!(open_snapshot(&mk, &vault, &h, &bad), Err(ManifestError::BadSegment(0)));
    }
}
