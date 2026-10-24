//! The web app's engine, compiled to WebAssembly. Everything that touches a
//! key runs here, through `oshelf-core`; the TypeScript side only moves bytes
//! between `fetch` and these functions.
//!
//! The API is sans-IO: JS fetches, hands the bytes in, and posts what comes
//! back. Commits are staged (`stage_*`), posted with `If-Match`, then either
//! confirmed or, after a 409 and a catch-up, staged again on the newer tree.

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use oshelf_core::keys::{self, Key};
use oshelf_core::manifest::{self, Chain, Hash, Id, Kind, LogEntry, Node, Op, SnapshotHeader, Tree, ROOT};
use oshelf_core::vault::VaultHeader;
use oshelf_core::{auth, chunk, CHUNK_SIZE};
use serde::Serialize;
use wasm_bindgen::prelude::*;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

type Result<T> = std::result::Result<T, JsError>;

fn err(msg: impl std::fmt::Display) -> JsError {
    JsError::new(&msg.to_string())
}

fn arr<const N: usize>(b: &[u8], what: &str) -> Result<[u8; N]> {
    b.try_into().map_err(|_| err(format!("{what} must be {N} bytes")))
}

fn hex_arr<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| err(format!("{what} must be {} hex characters", N * 2)))?;
    Ok(out)
}

/// Accepts `""` for the root as well as 32 hex characters.
fn dir_id(s: &str) -> Result<Id> {
    if s.is_empty() {
        Ok(ROOT)
    } else {
        hex_arr(s, "id")
    }
}

fn to_js<T: Serialize>(v: &T) -> Result<JsValue> {
    v.serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(err)
}

// ---- devices and requests --------------------------------------------------

/// A fresh Ed25519 seed for a new browser device.
#[wasm_bindgen]
pub fn new_device_seed() -> Vec<u8> {
    keys::random::<32>().to_vec()
}

#[wasm_bindgen]
pub fn random_bytes(n: usize) -> Vec<u8> {
    (0..n.div_ceil(32)).flat_map(|_| keys::random::<32>()).take(n).collect()
}

#[wasm_bindgen]
pub fn device_pubkey(seed: &[u8]) -> Result<String> {
    Ok(hex::encode(
        SigningKey::from_bytes(&arr(seed, "seed")?).verifying_key().to_bytes(),
    ))
}

/// MAC proving this device knows the pairing code.
#[wasm_bindgen]
pub fn pairing_client_mac(code: &str, pubkey_hex: &str, nonce_hex: &str) -> Result<String> {
    Ok(hex::encode(auth::pairing_client_mac(
        code,
        &hex_arr(pubkey_hex, "pubkey")?,
        &hex_arr(nonce_hex, "nonce")?,
    )))
}

/// Checks the Pi's pairing answer: it must know the code too.
#[wasm_bindgen]
pub fn pairing_server_ok(
    code: &str,
    server_pub_hex: &str,
    device_id_hex: &str,
    nonce_hex: &str,
    mac_hex: &str,
) -> Result<bool> {
    let server: [u8; 32] = hex_arr(server_pub_hex, "server key")?;
    VerifyingKey::from_bytes(&server).map_err(|_| err("server key is not valid"))?;
    let want = auth::pairing_server_mac(
        code,
        &server,
        &hex_arr(device_id_hex, "device id")?,
        &hex_arr(nonce_hex, "nonce")?,
    );
    Ok(auth::macs_equal(&want, &hex_arr(mac_hex, "mac")?))
}

/// Signs requests as this device and checks the Pi's signed answers.
#[wasm_bindgen]
pub struct Signer {
    key: SigningKey,
    device_hex: String,
    server: VerifyingKey,
}

#[wasm_bindgen]
pub struct Signed {
    authorization: String,
    sig: [u8; 64],
}

#[wasm_bindgen]
impl Signed {
    #[wasm_bindgen(getter)]
    pub fn authorization(&self) -> String {
        self.authorization.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn sig(&self) -> Vec<u8> {
        self.sig.to_vec()
    }
}

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new(seed: &[u8], device_id_hex: &str, server_pub_hex: &str) -> Result<Signer> {
        let _: Id = hex_arr(device_id_hex, "device id")?;
        Ok(Signer {
            key: SigningKey::from_bytes(&arr(seed, "seed")?),
            device_hex: device_id_hex.to_string(),
            server: VerifyingKey::from_bytes(&hex_arr(server_pub_hex, "server key")?)
                .map_err(|_| err("server key is not valid"))?,
        })
    }

    /// `ts_ms` must be unique per request; the Pi rejects replays.
    pub fn sign(&self, method: &str, path_and_query: &str, ts_ms: f64, body: &[u8]) -> Signed {
        let ts = ts_ms as i64;
        let sig = auth::sign_request(&self.key, method, path_and_query, ts, body);
        Signed {
            authorization: format!(
                "{} device={}, ts={ts}, sig={}",
                auth::SCHEME,
                self.device_hex,
                B64.encode(sig)
            ),
            sig,
        }
    }

    /// Checks `X-Oshelf-Sig` on a buffered response to the request signed `sig`.
    pub fn verify(&self, sig: &[u8], status: u16, body: &[u8], header_b64: &str) -> bool {
        let (Ok(req), Ok(Ok(resp))) = (
            <[u8; 64]>::try_from(sig),
            B64.decode(header_b64.trim()).map(<[u8; 64]>::try_from),
        ) else {
            return false;
        };
        auth::verify_response(&self.server, &req, status, body, &resp)
    }
}

// ---- vault -----------------------------------------------------------------

fn decode_vault(vault: &[u8]) -> Result<VaultHeader> {
    VaultHeader::decode(vault).map_err(err)
}

/// Argon2id with the vault's parameters (256 MiB); run it in a worker.
#[wasm_bindgen]
pub fn unlock_passphrase(vault: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    Ok(decode_vault(vault)?.unlock(passphrase).map_err(err)?.to_vec())
}

#[wasm_bindgen]
pub fn unlock_recovery(vault: &[u8], words: &str) -> Result<Vec<u8>> {
    Ok(decode_vault(vault)?.unlock_with_recovery(words).map_err(err)?.to_vec())
}

/// The vault header re-wrapped under a new passphrase.
#[wasm_bindgen]
pub fn change_passphrase(vault: &[u8], master_key: &[u8], new_passphrase: &str) -> Result<Vec<u8>> {
    let mk: Key = arr(master_key, "master key")?;
    Ok(decode_vault(vault)?
        .change_passphrase(&mk, new_passphrase)
        .map_err(err)?
        .encode())
}

/// Seals a small secret (the master key, for "stay unlocked") under a local
/// key, bound to `label`.
#[wasm_bindgen]
pub fn seal_local(key: &[u8], label: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; 24] = keys::random();
    let mut out = nonce.to_vec();
    out.extend(keys::seal(&arr(key, "key")?, &nonce, label.as_bytes(), plaintext));
    Ok(out)
}

#[wasm_bindgen]
pub fn open_local(key: &[u8], label: &str, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 24 + 16 {
        return Err(err("sealed blob too short"));
    }
    let nonce: [u8; 24] = arr(&sealed[..24], "nonce")?;
    keys::open(&arr(key, "key")?, &nonce, label.as_bytes(), &sealed[24..]).ok_or_else(|| err("could not open"))
}

// ---- frames ----------------------------------------------------------------

/// `u32le len || bytes`, repeated (ranged chunk reads).
fn chunk_frames(b: &[u8]) -> std::result::Result<Vec<&[u8]>, &'static str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let len = u32::from_le_bytes(take(b, i)?) as usize;
        i += 4;
        out.push(b.get(i..i + len).ok_or(TRUNCATED)?);
        i += len;
    }
    Ok(out)
}

const TRUNCATED: &str = "truncated frame";

fn take<const N: usize>(b: &[u8], at: usize) -> std::result::Result<[u8; N], &'static str> {
    b.get(at..at + N).and_then(|s| s.try_into().ok()).ok_or(TRUNCATED)
}

/// `u64le revision || u32le len || bytes`, repeated (log pages).
fn log_frames(b: &[u8]) -> std::result::Result<Vec<(u64, &[u8])>, &'static str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let rev = u64::from_le_bytes(take(b, i)?);
        let len = u32::from_le_bytes(take(b, i + 8)?) as usize;
        i += 12;
        out.push((rev, b.get(i..i + len).ok_or(TRUNCATED)?));
        i += len;
    }
    Ok(out)
}

// ---- the shelf -------------------------------------------------------------

#[derive(Serialize)]
struct NodeView<'a> {
    id: String,
    parent: String,
    name: &'a str,
    kind: Kind,
    size: f64,
    mtime_ms: f64,
    chunks: usize,
    /// Plaintext bytes under a folder (or the file's size).
    total: f64,
}

#[derive(Serialize)]
struct Crumb {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct Totals {
    files: u64,
    folders: u64,
    bytes: f64,
}

/// A commit waiting for the Pi's answer.
struct Pending {
    entry: LogEntry,
    sealed: Vec<u8>,
    /// Objects the commit makes unreachable; deleted once it lands.
    drops: Vec<Id>,
    /// The node the commit is about (new folder, uploaded file), for the UI.
    subject: Option<Id>,
}

/// An unlocked, verified view of the shelf: keys, tree and chain position.
#[wasm_bindgen]
pub struct Shelf {
    master_key: Key,
    vault_id: Id,
    km: Key,
    device_id: Id,
    device_name: String,
    tree: Tree,
    chain: Chain,
    snapshot: Option<SnapshotHeader>,
    pending: Option<Pending>,
}

fn now_ms() -> i64 {
    js_sys_now() as i64
}

#[cfg(target_arch = "wasm32")]
fn js_sys_now() -> f64 {
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = Date, js_name = now)]
        fn date_now() -> f64;
    }
    date_now()
}

#[cfg(not(target_arch = "wasm32"))]
fn js_sys_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0)
}

/// `"Name (conflict, Device).ext"`, the same rule as the CLI and the Mac.
pub fn conflict_name(name: &str, device: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} (conflict, {device}).{ext}"),
        _ => format!("{name} (conflict, {device})"),
    }
}

fn valid_name(name: &str) -> std::result::Result<String, &'static str> {
    let n = manifest::nfc(name.trim());
    if n.is_empty() || n == "." || n == ".." || n.contains('/') || n.contains('\0') {
        return Err("That name can't be used.");
    }
    if n.len() > 255 {
        return Err("That name is too long.");
    }
    Ok(n)
}

fn check_name(name: &str) -> Result<String> {
    valid_name(name).map_err(err)
}

#[wasm_bindgen]
impl Shelf {
    #[wasm_bindgen(constructor)]
    pub fn new(master_key: &[u8], vault: &[u8], device_id_hex: &str, device_name: &str) -> Result<Shelf> {
        let header = decode_vault(vault)?;
        let master_key: Key = arr(master_key, "master key")?;
        Ok(Shelf {
            km: keys::manifest_key(&master_key, &header.vault_id),
            master_key,
            vault_id: header.vault_id,
            device_id: hex_arr(device_id_hex, "device id")?,
            device_name: device_name.to_string(),
            tree: Tree::new(),
            chain: Chain::GENESIS,
            snapshot: None,
            pending: None,
        })
    }

    /// Seals the shared host list (`[{name, url, ssids}]` as JSON).
    pub fn seal_hosts(&self, json: &str) -> Result<Vec<u8>> {
        let hosts: Vec<oshelf_core::hosts::Host> = serde_json::from_str(json).map_err(err)?;
        Ok(oshelf_core::hosts::seal_hosts(
            &self.master_key,
            &self.vault_id,
            &oshelf_core::hosts::HostList { hosts },
        ))
    }

    /// Opens the shared host list; returns it as JSON.
    pub fn open_hosts(&self, sealed: &[u8]) -> Result<String> {
        let list = oshelf_core::hosts::open_hosts(&self.master_key, &self.vault_id, sealed)
            .ok_or_else(|| err("The host list didn't open with this shelf's key."))?;
        serde_json::to_string(&list.hosts).map_err(err)
    }

    pub fn vault_id(&self) -> String {
        hex::encode(self.vault_id)
    }

    pub fn revision(&self) -> f64 {
        self.chain.revision as f64
    }

    pub fn head_hash(&self) -> String {
        hex::encode(self.chain.hash)
    }

    /// True when the Pi's reported head is exactly where the verified chain is.
    pub fn matches_head(&self, revision: f64, hash_hex: &str) -> bool {
        self.chain.revision as f64 == revision && hash_hex == hex::encode(self.chain.hash)
    }

    /// Opens the latest snapshot header; returns how many segments to fetch.
    pub fn open_snapshot_header(&mut self, revision: f64, sealed: &[u8]) -> Result<u32> {
        let h =
            manifest::open_snapshot_header(&self.master_key, &self.vault_id, revision as u64, sealed).map_err(err)?;
        let n = h.segments.len() as u32;
        self.snapshot = Some(h);
        Ok(n)
    }

    /// Replaces the tree with the snapshot whose header was just opened.
    /// `frames` are its segments as served by the ranged chunk read.
    pub fn load_snapshot(&mut self, frames: &[u8]) -> Result<()> {
        let h = self
            .snapshot
            .take()
            .ok_or_else(|| err("open the snapshot header first"))?;
        let segments: Vec<Vec<u8>> = chunk_frames(frames)
            .map_err(err)?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        let (tree, chain) = manifest::open_snapshot(&self.master_key, &self.vault_id, &h, &segments).map_err(err)?;
        self.tree = tree;
        self.chain = chain;
        self.pending = None;
        Ok(())
    }

    /// Starts over from nothing (the log was compacted past this tree).
    pub fn reset(&mut self) {
        self.tree = Tree::new();
        self.chain = Chain::GENESIS;
        self.pending = None;
    }

    /// Applies one page of sealed log entries, verifying every link.
    /// Returns how many were applied.
    pub fn apply_log(&mut self, frames: &[u8]) -> Result<u32> {
        let mut n = 0;
        for (rev, sealed) in log_frames(frames).map_err(err)? {
            if rev != self.chain.revision + 1 {
                return Err(err(format!("the Pi sent revision {rev} out of order")));
            }
            let (entry, next) = self.chain.open_next(&self.km, sealed).map_err(err)?;
            self.tree.apply_entry(&entry);
            self.chain = next;
            n += 1;
        }
        if n > 0 {
            self.pending = None;
        }
        Ok(n)
    }

    // ---- reading the tree --------------------------------------------------

    fn view<'a>(&self, n: &'a Node) -> NodeView<'a> {
        NodeView {
            id: hex::encode(n.id),
            parent: hex::encode(n.parent),
            name: &n.name,
            kind: n.kind,
            size: n.size as f64,
            mtime_ms: (n.mtime_ns / 1_000_000) as f64,
            chunks: n.chunks.len(),
            total: if n.kind == Kind::Dir {
                self.bytes_under(&n.id) as f64
            } else {
                n.size as f64
            },
        }
    }

    fn bytes_under(&self, dir: &Id) -> u64 {
        self.tree
            .walk(dir)
            .iter()
            .filter(|n| n.kind == Kind::File)
            .map(|n| n.size)
            .sum()
    }

    fn node_ref(&self, id_hex: &str) -> Result<&Node> {
        self.tree
            .get(&hex_arr(id_hex, "id")?)
            .ok_or_else(|| err("That item is no longer on the shelf."))
    }

    /// Children of a folder (`""` is the root), folders first then by name.
    pub fn list(&self, dir_hex: &str) -> Result<JsValue> {
        let mut kids = self.tree.list(&dir_id(dir_hex)?);
        kids.sort_by_key(|n| (n.kind != Kind::Dir, n.name.to_lowercase()));
        to_js(&kids.into_iter().map(|n| self.view(n)).collect::<Vec<_>>())
    }

    /// One node, or `null`.
    pub fn node(&self, id_hex: &str) -> Result<JsValue> {
        match self.tree.get(&hex_arr(id_hex, "id")?) {
            Some(n) => to_js(&self.view(n)),
            None => Ok(JsValue::NULL),
        }
    }

    pub fn is_dir(&self, id_hex: &str) -> bool {
        id_hex.is_empty()
            || hex_arr::<16>(id_hex, "id")
                .ok()
                .and_then(|id| self.tree.get(&id))
                .is_some_and(|n| n.kind == Kind::Dir)
    }

    /// Folders from the root down to `id`, the root excluded.
    pub fn crumbs(&self, id_hex: &str) -> Result<JsValue> {
        let mut out = Vec::new();
        let mut cur = dir_id(id_hex)?;
        while cur != ROOT && out.len() < 4096 {
            let Some(n) = self.tree.get(&cur) else { break };
            out.push(Crumb {
                id: hex::encode(n.id),
                name: n.name.clone(),
            });
            cur = n.parent;
        }
        out.reverse();
        to_js(&out)
    }

    /// Case-insensitive substring search over names, best matches first.
    pub fn search(&self, query: &str, limit: usize) -> Result<JsValue> {
        let q = manifest::nfc(query.trim()).to_lowercase();
        if q.is_empty() {
            return to_js(&Vec::<NodeView>::new());
        }
        let mut hits: Vec<(&Node, bool)> = self
            .tree
            .walk(&ROOT)
            .into_iter()
            .filter_map(|n| {
                let name = n.name.to_lowercase();
                name.contains(&q).then(|| (n, name.starts_with(&q)))
            })
            .collect();
        hits.sort_by_key(|(n, prefix)| (!prefix, n.kind != Kind::Dir, n.name.to_lowercase()));
        to_js(
            &hits
                .into_iter()
                .take(limit)
                .map(|(n, _)| self.view(n))
                .collect::<Vec<_>>(),
        )
    }

    pub fn totals(&self) -> Result<JsValue> {
        let all = self.tree.walk(&ROOT);
        let files = all.iter().filter(|n| n.kind == Kind::File).count() as u64;
        to_js(&Totals {
            files,
            folders: all.iter().filter(|n| n.kind == Kind::Dir).count() as u64,
            bytes: all.iter().filter(|n| n.kind == Kind::File).map(|n| n.size).sum::<u64>() as f64,
        })
    }

    // ---- reading files -----------------------------------------------------

    /// The server object holding a file's current version.
    pub fn object_of(&self, id_hex: &str) -> Result<String> {
        let n = self.node_ref(id_hex)?;
        n.object_id.map(hex::encode).ok_or_else(|| err("not a file"))
    }

    /// Chunk indexes `[first, last]` plus trim for bytes `[start, end)`, or
    /// `null` for an empty range.
    pub fn span(&self, id_hex: &str, start: f64, end: f64) -> Result<JsValue> {
        #[derive(Serialize)]
        struct Span {
            first: f64,
            last: f64,
            skip: f64,
            len: f64,
        }
        let n = self.node_ref(id_hex)?;
        match oshelf_core::chunk_span(start as u64, end as u64, n.size, n.chunk_size.unwrap_or(CHUNK_SIZE)) {
            Some(s) => to_js(&Span {
                first: s.first as f64,
                last: s.last as f64,
                skip: s.skip as f64,
                len: s.len as f64,
            }),
            None => Ok(JsValue::NULL),
        }
    }

    /// Checks one stored chunk against the manifest and decrypts it.
    pub fn open_chunk(&self, id_hex: &str, index: u32, stored: &[u8]) -> Result<Vec<u8>> {
        let n = self.node_ref(id_hex)?;
        let want = n
            .chunks
            .get(index as usize)
            .ok_or_else(|| err(format!("{} has no chunk {index}", n.name)))?;
        if chunk::chunk_id(stored) != *want {
            return Err(err(format!("chunk {index} of {} doesn't match the manifest", n.name)));
        }
        let key = n.file_key.ok_or_else(|| err("file has no key"))?;
        chunk::open_chunk(&key, &n.id, index as u64, stored).map_err(err)
    }

    /// Decrypts a framed run of chunks starting at `first` into one buffer.
    pub fn open_frames(&self, id_hex: &str, first: u32, frames: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for (i, f) in chunk_frames(frames).map_err(err)?.into_iter().enumerate() {
            out.extend(self.open_chunk(id_hex, first + i as u32, f)?);
        }
        Ok(out)
    }

    // ---- writing -----------------------------------------------------------

    /// Starts sealing a file to upload as `name` in `parent`. An existing file
    /// at that path keeps its id and key (an edit); chunks get fresh nonces.
    pub fn begin_upload(&self, parent_hex: &str, name: &str) -> Result<Upload> {
        let parent = dir_id(parent_hex)?;
        let name = check_name(name)?;
        let existing = self.tree.child(&parent, &name).filter(|n| n.kind == Kind::File);
        Ok(Upload {
            node_id: existing.map(|n| n.id).unwrap_or_else(keys::random),
            file_key: existing.and_then(|n| n.file_key).unwrap_or_else(keys::random),
            object_id: keys::random(),
            chunk_ids: Vec::new(),
            size: 0,
        })
    }

    fn stage(&mut self, ops: Vec<Op>, drops: Vec<Id>, subject: Option<Id>) -> Option<Vec<u8>> {
        if ops.is_empty() {
            self.pending = None;
            return None;
        }
        let entry = self.chain.next_entry(self.device_id, now_ms(), ops);
        let sealed = manifest::seal_entry(&self.km, &entry);
        self.pending = Some(Pending {
            entry,
            sealed: sealed.clone(),
            drops,
            subject,
        });
        Some(sealed)
    }

    /// The `If-Match` revision for the staged commit.
    pub fn base_revision(&self) -> f64 {
        self.chain.revision as f64
    }

    /// Stages the upload as a file in `parent`. If another file took the name
    /// since, ours becomes a conflict copy. Returns the sealed entry.
    pub fn stage_upload(
        &mut self,
        upload: &Upload,
        parent_hex: &str,
        name: &str,
        mtime_ms: f64,
    ) -> Result<Option<Vec<u8>>> {
        let parent = dir_id(parent_hex)?;
        if parent != ROOT && self.tree.get(&parent).map(|n| n.kind) != Some(Kind::Dir) {
            return Err(err("The folder was removed."));
        }
        let mut name = check_name(name)?;
        let mut drops = Vec::new();
        if let Some(cur) = self.tree.child(&parent, &name) {
            if cur.id == upload.node_id {
                drops.extend(cur.object_id);
            } else {
                name = conflict_name(&name, &self.device_name);
            }
        }
        let node = Node::file(
            upload.node_id,
            parent,
            &name,
            upload.size,
            (mtime_ms as i64).saturating_mul(1_000_000),
            upload.file_key,
            upload.object_id,
            upload.chunk_ids.clone(),
        );
        Ok(self.stage(vec![Op::Put(node)], drops, Some(upload.node_id)))
    }

    /// Stages a new folder; `null` when one by that name already exists.
    pub fn stage_mkdir(&mut self, parent_hex: &str, name: &str) -> Result<Option<Vec<u8>>> {
        let parent = dir_id(parent_hex)?;
        let name = check_name(name)?;
        if let Some(n) = self.tree.child(&parent, &name) {
            if n.kind == Kind::Dir {
                self.pending = None;
                return Ok(None);
            }
            return Err(err("Something with that name is already here."));
        }
        let id: Id = keys::random();
        Ok(self.stage(
            vec![Op::Put(Node::dir(id, parent, &name, now_ms() * 1_000_000))],
            vec![],
            Some(id),
        ))
    }

    /// Stages a rename or move of `id` to `name` in `parent`.
    pub fn stage_move(&mut self, id_hex: &str, parent_hex: &str, name: &str) -> Result<Option<Vec<u8>>> {
        let id: Id = hex_arr(id_hex, "id")?;
        let parent = dir_id(parent_hex)?;
        let name = check_name(name)?;
        let node = self
            .tree
            .get(&id)
            .ok_or_else(|| err("That item is no longer on the shelf."))?;
        if node.parent == parent && node.name == name {
            self.pending = None;
            return Ok(None);
        }
        if parent != ROOT && self.tree.get(&parent).map(|n| n.kind) != Some(Kind::Dir) {
            return Err(err("The folder was removed."));
        }
        if self.tree.child(&parent, &name).is_some_and(|n| n.id != id) {
            return Err(err("Something with that name is already here."));
        }
        let mut cur = parent;
        while cur != ROOT {
            if cur == id {
                return Err(err("A folder can't go inside itself."));
            }
            cur = self.tree.get(&cur).map(|n| n.parent).unwrap_or(ROOT);
        }
        Ok(self.stage(vec![Op::Move { id, name, parent }], vec![], Some(id)))
    }

    /// Stages deleting items (folders with everything in them). `ids` is a
    /// list of hex ids; ones already gone are skipped.
    pub fn stage_delete(&mut self, ids: Vec<String>) -> Result<Option<Vec<u8>>> {
        let mut ops = Vec::new();
        let mut drops = Vec::new();
        for h in &ids {
            let id: Id = hex_arr(h, "id")?;
            let Some(n) = self.tree.get(&id) else { continue };
            drops.extend(n.object_id);
            drops.extend(self.tree.walk(&id).into_iter().filter_map(|n| n.object_id));
            ops.push(Op::Delete(id));
        }
        Ok(self.stage(ops, drops, None))
    }

    /// The Pi took the staged entry: apply it and move the chain on. Returns
    /// the object ids (hex) that are now unreferenced, to delete.
    pub fn confirm(&mut self, revision: f64, hash_hex: &str) -> Result<Vec<String>> {
        let p = self.pending.take().ok_or_else(|| err("nothing staged"))?;
        let hash: Hash = *blake3::hash(&p.sealed).as_bytes();
        if revision as u64 != p.entry.revision || hash_hex != hex::encode(hash) {
            return Err(err("the Pi acknowledged a different entry"));
        }
        self.tree.apply_entry(&p.entry);
        self.chain = Chain {
            revision: p.entry.revision,
            hash,
        };
        Ok(p.drops.iter().map(hex::encode).collect())
    }

    /// The node the last confirmed or staged commit is about.
    pub fn staged_subject(&self) -> Option<String> {
        self.pending.as_ref().and_then(|p| p.subject).map(hex::encode)
    }
}

/// A file being sealed chunk by chunk before upload.
#[wasm_bindgen]
pub struct Upload {
    node_id: Id,
    file_key: Key,
    object_id: Id,
    chunk_ids: Vec<Hash>,
    size: u64,
}

#[wasm_bindgen]
impl Upload {
    /// Seals the next chunk (at most 1 MiB of plaintext). Returns the stored
    /// bytes; their id is `last_chunk_id()`.
    pub fn seal_next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > CHUNK_SIZE as usize {
            return Err(err("chunk too large"));
        }
        let stored = chunk::seal_chunk(&self.file_key, &self.node_id, self.chunk_ids.len() as u64, plaintext);
        self.chunk_ids.push(chunk::chunk_id(&stored));
        self.size += plaintext.len() as u64;
        Ok(stored)
    }

    pub fn last_chunk_id(&self) -> Option<String> {
        self.chunk_ids.last().map(hex::encode)
    }

    pub fn object_id(&self) -> String {
        hex::encode(self.object_id)
    }

    pub fn node_id(&self) -> String {
        hex::encode(self.node_id)
    }

    /// `{ "id", "chunks" }` for `POST /v1/objects`.
    pub fn object_json(&self) -> String {
        format!(
            "{{\"id\":\"{}\",\"chunks\":[{}]}}",
            hex::encode(self.object_id),
            self.chunk_ids
                .iter()
                .map(|c| format!("\"{}\"", hex::encode(c)))
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

// ---- spec vectors ------------------------------------------------------------
// Raw primitives, exported so the WebAssembly build can be checked against
// spec/vectors in CI like every other implementation.

#[wasm_bindgen]
pub fn vector_seal_chunk(key: &[u8], file_id: &[u8], index: u32, plaintext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    Ok(chunk::seal_chunk_with_nonce(
        &arr(key, "key")?,
        &arr(file_id, "file id")?,
        index as u64,
        plaintext,
        arr(nonce, "nonce")?,
    ))
}

#[wasm_bindgen]
pub fn vector_open_chunk(key: &[u8], file_id: &[u8], index: u32, stored: &[u8]) -> Result<Vec<u8>> {
    chunk::open_chunk(&arr(key, "key")?, &arr(file_id, "file id")?, index as u64, stored)
        .map_err(|e| err(format!("{e:?}")))
}

#[wasm_bindgen]
pub fn vector_chunk_id(stored: &[u8]) -> String {
    hex::encode(chunk::chunk_id(stored))
}

/// Opens the entry after (`revision`, `hash_hex`); returns the new hash.
#[wasm_bindgen]
pub fn vector_open_entry(km: &[u8], revision: f64, hash_hex: &str, sealed: &[u8]) -> Result<String> {
    let chain = Chain {
        revision: revision as u64,
        hash: hex_arr(hash_hex, "hash")?,
    };
    let (_, next) = chain.open_next(&arr(km, "key")?, sealed).map_err(err)?;
    Ok(hex::encode(next.hash))
}

#[wasm_bindgen]
pub fn vector_span(start: f64, end: f64, size: f64, chunk_size: u32) -> Result<JsValue> {
    #[derive(Serialize)]
    struct Span {
        first: f64,
        last: f64,
        skip: f64,
        len: f64,
    }
    match oshelf_core::chunk_span(start as u64, end as u64, size as u64, chunk_size) {
        Some(s) => to_js(&Span {
            first: s.first as f64,
            last: s.last as f64,
            skip: s.skip as f64,
            len: s.len as f64,
        }),
        None => Ok(JsValue::NULL),
    }
}

#[wasm_bindgen]
pub fn vector_sign_request(seed: &[u8], method: &str, path_and_query: &str, ts_ms: f64, body: &[u8]) -> Result<String> {
    let key = SigningKey::from_bytes(&arr(seed, "seed")?);
    Ok(hex::encode(auth::sign_request(
        &key,
        method,
        path_and_query,
        ts_ms as i64,
        body,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_names_match_the_cli() {
        assert_eq!(conflict_name("report.pdf", "Safari"), "report (conflict, Safari).pdf");
        assert_eq!(conflict_name(".env", "Safari"), ".env (conflict, Safari)");
    }

    #[test]
    fn names() {
        assert!(valid_name("..").is_err());
        assert!(valid_name("a/b").is_err());
        assert_eq!(valid_name(" ok.txt ").unwrap(), "ok.txt");
    }

    #[test]
    fn frames_parse() {
        let mut b = Vec::new();
        b.extend_from_slice(&3u32.to_le_bytes());
        b.extend_from_slice(b"abc");
        b.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(chunk_frames(&b).unwrap(), vec![&b"abc"[..], &b""[..]]);
        assert!(chunk_frames(&b[..5]).is_err());
        let mut l = Vec::new();
        l.extend_from_slice(&7u64.to_le_bytes());
        l.extend_from_slice(&1u32.to_le_bytes());
        l.push(9);
        assert_eq!(log_frames(&l).unwrap(), vec![(7, &[9u8][..])]);
    }
}
