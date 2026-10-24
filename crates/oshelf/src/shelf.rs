//! What the commands do: pairing, vault setup, and a `Shelf` session that
//! loads the verified tree and reads or changes it.

use std::io::{Read, Write};
use std::path::Path;

use anyhow::{bail, ensure, Context};
use ed25519_dalek::{SigningKey, VerifyingKey};
use oshelf_core::keys::{self, Key};
use oshelf_core::manifest::{self, Chain, Id, Kind, Node, Op, Tree, ROOT};
use oshelf_core::vault::{Kdf, VaultHeader};
use oshelf_core::{auth, chunk, CHUNK_SIZE};

use crate::client::{self, Client};
use crate::config::{Config, Home};

/// Chunks fetched per ranged read (the server allows 64).
const READ_BATCH: u64 = 16;
/// Times a commit is rebuilt on a newer head before giving up.
const COMMIT_RETRIES: usize = 8;

fn hex16(s: &str) -> anyhow::Result<[u8; 16]> {
    let mut b = [0u8; 16];
    hex::decode_to_slice(s, &mut b).context("bad id")?;
    Ok(b)
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Pairs this device with the Pi at `url` using a code from `oshelfd pair`.
pub fn pair(home: &Home, url: &str, code: &str, name: &str) -> anyhow::Result<Config> {
    ensure!(
        !home.is_paired(),
        "already paired; remove {} to pair again",
        home.dir().display()
    );
    let key = SigningKey::from_bytes(&keys::random());
    let pubkey = key.verifying_key().to_bytes();
    let nonce: [u8; 16] = keys::random();
    let reply = client::post_json(
        url,
        "/v1/pair",
        &serde_json::json!({
            "name": name,
            "pubkey": hex::encode(pubkey),
            "client_nonce": hex::encode(nonce),
            "mac": hex::encode(auth::pairing_client_mac(code, &pubkey, &nonce)),
        }),
    )?
    .ok()?;
    let v = reply.json()?;
    let device_id = hex16(v["device_id"].as_str().context("no device_id")?)?;
    let mut server_pub = [0u8; 32];
    hex::decode_to_slice(
        v["server_pubkey"].as_str().context("no server_pubkey")?,
        &mut server_pub,
    )?;
    let mut mac = [0u8; 32];
    hex::decode_to_slice(v["mac"].as_str().context("no mac")?, &mut mac)?;
    ensure!(
        auth::macs_equal(&mac, &auth::pairing_server_mac(code, &server_pub, &device_id, &nonce)),
        "the server could not prove it knows the pairing code; not pairing"
    );
    VerifyingKey::from_bytes(&server_pub).context("server key is not valid")?;
    let config = Config {
        server_url: url.trim_end_matches('/').to_string(),
        device_id: hex::encode(device_id),
        device_name: name.to_string(),
        server_pubkey: hex::encode(server_pub),
    };
    home.save_device_key(&key)?;
    home.save_config(&config)?;
    Ok(config)
}

pub fn connect(home: &Home) -> anyhow::Result<(Config, Client)> {
    let config = home.config()?;
    let mut server_pub = [0u8; 32];
    hex::decode_to_slice(&config.server_pubkey, &mut server_pub)?;
    let client = Client::new(
        &config.server_url,
        hex16(&config.device_id)?,
        home.device_key()?,
        VerifyingKey::from_bytes(&server_pub)?,
    );
    Ok((config, client))
}

/// Creates the vault on a Pi that has none yet. Returns the recovery words.
pub fn init(client: &Client, passphrase: &str, kdf: Kdf) -> anyhow::Result<String> {
    let existing = client.get("/v1/vault")?;
    ensure!(
        existing.status == 404,
        "this Pi already has a vault; use `oshelf status`"
    );
    let v = VaultHeader::create(passphrase, kdf)?;
    client.put("/v1/vault", &[], &v.header.encode())?.ok()?;
    Ok(v.recovery_words)
}

pub enum Unlock<'a> {
    Passphrase(&'a str),
    Recovery(&'a str),
}

pub fn fetch_vault(client: &Client) -> anyhow::Result<(VaultHeader, String)> {
    let r = client.get("/v1/vault")?;
    ensure!(r.status != 404, "this Pi has no vault yet; run `oshelf init`");
    let r = r.ok()?;
    let etag = r.header("etag").unwrap_or_default().trim_matches('"').to_string();
    Ok((VaultHeader::decode(&r.body)?, etag))
}

/// Re-wraps the master key under a new passphrase.
pub fn change_passphrase(client: &Client, old: Unlock, new: &str) -> anyhow::Result<()> {
    let (header, etag) = fetch_vault(client)?;
    let mk = match old {
        Unlock::Passphrase(p) => header.unlock(p)?,
        Unlock::Recovery(w) => header.unlock_with_recovery(w)?,
    };
    let changed = header.change_passphrase(&mk, new)?;
    client
        .put("/v1/vault", &[("if-match", etag)], &changed.encode())?
        .ok()?;
    Ok(())
}

/// An unlocked, verified view of the shelf.
pub struct Shelf<'a> {
    home: &'a Home,
    client: &'a Client,
    device_id: Id,
    device_name: String,
    master_key: Key,
    vault_id: Id,
    km: Key,
    pub tree: Tree,
    pub chain: Chain,
}

/// One file added by `put`.
pub struct Uploaded {
    pub path: String,
    pub size: u64,
}

impl<'a> Shelf<'a> {
    pub fn open(home: &'a Home, config: &Config, client: &'a Client, unlock: Unlock) -> anyhow::Result<Self> {
        let (header, _) = fetch_vault(client)?;
        let master_key = match unlock {
            Unlock::Passphrase(p) => header.unlock(p)?,
            Unlock::Recovery(w) => header.unlock_with_recovery(w)?,
        };
        let km = keys::manifest_key(&master_key, &header.vault_id);
        let mut shelf = Shelf {
            home,
            client,
            device_id: hex16(&config.device_id)?,
            device_name: config.device_name.clone(),
            master_key,
            vault_id: header.vault_id,
            km,
            tree: Tree::new(),
            chain: Chain::GENESIS,
        };
        shelf.load_snapshot()?;
        shelf.catch_up()?;
        Ok(shelf)
    }

    fn load_snapshot(&mut self) -> anyhow::Result<()> {
        let r = self.client.get("/v1/manifest/snapshot")?;
        if r.status == 404 {
            return Ok(());
        }
        let r = r.ok()?;
        let revision: u64 = r
            .header("x-oshelf-revision")
            .context("snapshot without revision")?
            .parse()?;
        let object = r
            .header("x-oshelf-object")
            .context("snapshot without object")?
            .to_string();
        let header = manifest::open_snapshot_header(&self.master_key, &self.vault_id, revision, &r.body)?;
        let segments = self.read_chunks(&object, header.segments.len() as u64)?;
        let (tree, chain) = manifest::open_snapshot(&self.master_key, &self.vault_id, &header, &segments)?;
        self.tree = tree;
        self.chain = chain;
        Ok(())
    }

    /// Applies every log entry after the current chain position, verifying
    /// each link, then checks the Pi's reported head matches.
    pub fn catch_up(&mut self) -> anyhow::Result<()> {
        loop {
            let r = self
                .client
                .get(&format!("/v1/manifest/log?since={}", self.chain.revision))?;
            if r.status == 410 {
                // Compacted past us: start again from the latest snapshot.
                self.tree = Tree::new();
                self.chain = Chain::GENESIS;
                self.load_snapshot()?;
                continue;
            }
            let entries = client::log_frames(&r.ok()?.body)?;
            if entries.is_empty() {
                break;
            }
            for (rev, sealed) in entries {
                ensure!(
                    rev == self.chain.revision + 1,
                    "the Pi sent revision {rev} out of order"
                );
                let (entry, next) = self.chain.open_next(&self.km, &sealed)?;
                self.tree.apply_entry(&entry);
                self.chain = next;
            }
        }
        let head = self.client.get("/v1/manifest/head")?.ok()?.json()?;
        let head_rev = head["revision"].as_u64().context("bad head")?;
        ensure!(
            head_rev == self.chain.revision && head["hash"] == hex::encode(self.chain.hash),
            "the Pi's head ({head_rev}) doesn't match the verified log ({})",
            self.chain.revision
        );
        self.home
            .advance_seen(self.chain.revision, &hex::encode(self.chain.hash))
    }

    /// Commits ops built by `build` against the newest head. `build` runs
    /// again on the fresh tree after every lost race.
    fn commit(&mut self, mut build: impl FnMut(&Tree, &str) -> anyhow::Result<Vec<Op>>) -> anyhow::Result<()> {
        for _ in 0..COMMIT_RETRIES {
            let ops = build(&self.tree, &self.device_name)?;
            if ops.is_empty() {
                return Ok(());
            }
            let now_ms = now_ns() / 1_000_000;
            let entry = self.chain.next_entry(self.device_id, now_ms, ops);
            let sealed = manifest::seal_entry(&self.km, &entry);
            let r = self.client.post(
                "/v1/manifest/log",
                &[("if-match", self.chain.revision.to_string())],
                &sealed,
            )?;
            if r.status == 409 {
                self.catch_up()?;
                continue;
            }
            r.ok()?;
            self.tree.apply_entry(&entry);
            self.chain = Chain {
                revision: entry.revision,
                hash: manifest::entry_hash(&sealed),
            };
            return self
                .home
                .advance_seen(self.chain.revision, &hex::encode(self.chain.hash));
        }
        bail!("the shelf kept changing underneath; try again")
    }

    fn read_chunks(&self, object: &str, count: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(count as usize);
        let mut first = 0;
        while first < count {
            let last = (first + READ_BATCH - 1).min(count - 1);
            let r = self
                .client
                .get_streamed(&format!("/v1/objects/{object}/chunks?first={first}&last={last}"))?
                .ok()?;
            let frames = client::frames(&r.body)?;
            ensure!(
                frames.len() as u64 == last - first + 1,
                "the Pi returned the wrong number of chunks"
            );
            out.extend(frames);
            first = last + 1;
        }
        Ok(out)
    }

    fn upload_object(&self, object_id: &Id, chunks: &[Vec<u8>]) -> anyhow::Result<Vec<[u8; 32]>> {
        let mut ids = Vec::with_capacity(chunks.len());
        for c in chunks {
            let id = chunk::chunk_id(c);
            self.client
                .put(&format!("/v1/chunks/{}", hex::encode(id)), &[], c)?
                .ok()?;
            ids.push(id);
        }
        self.client
            .post_json(
                "/v1/objects",
                &serde_json::json!({
                    "id": hex::encode(object_id),
                    "chunks": ids.iter().map(hex::encode).collect::<Vec<_>>(),
                }),
            )?
            .ok()?;
        Ok(ids)
    }

    fn drop_objects(&self, objects: &[Id]) {
        for o in objects {
            // Best effort: an object left behind only costs space until the next
            // overwrite or a server side cleanup.
            let _ = self.client.delete(&format!("/v1/objects/{}", hex::encode(o)));
        }
    }

    fn require_dir(tree: &Tree, path: &str) -> anyhow::Result<Id> {
        let id = tree.resolve(path).with_context(|| format!("{path}: no such folder"))?;
        if id != ROOT {
            ensure!(tree.get(&id).map(|n| n.kind) == Some(Kind::Dir), "{path}: not a folder");
        }
        Ok(id)
    }

    /// Uploads one local file to `remote` (a full path on the shelf).
    pub fn put_file(&mut self, local: &Path, remote: &str) -> anyhow::Result<Uploaded> {
        let (parent_path, name) = split(remote)?;
        let existing = self
            .tree
            .resolve(remote)
            .and_then(|id| self.tree.get(&id))
            .filter(|n| n.kind == Kind::File)
            .cloned();
        // An edit keeps the node id and file key; chunks get fresh nonces.
        let node_id = existing.as_ref().map(|n| n.id).unwrap_or_else(keys::random);
        let file_key = existing.as_ref().and_then(|n| n.file_key).unwrap_or_else(keys::random);
        let object_id: Id = keys::random();

        let mut f = std::fs::File::open(local).with_context(|| format!("open {}", local.display()))?;
        let mtime_ns = f
            .metadata()?
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos() as i64)
            .unwrap_or_else(now_ns);
        let mut sealed = Vec::new();
        let mut size = 0u64;
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        loop {
            let n = read_full(&mut f, &mut buf)?;
            if n == 0 {
                break;
            }
            sealed.push(chunk::seal_chunk(&file_key, &node_id, sealed.len() as u64, &buf[..n]));
            size += n as u64;
            if n < buf.len() {
                break;
            }
        }
        let chunk_ids = self.upload_object(&object_id, &sealed)?;

        let mut replaced = Vec::new();
        let device = self.device_name.clone();
        let remote_owned = remote.to_string();
        self.commit(|tree, _| {
            replaced.clear();
            let parent = Self::require_dir(tree, &parent_path)?;
            let mut name = name.clone();
            if let Some(cur) = tree.child(&parent, &name) {
                if cur.id == node_id {
                    replaced.extend(cur.object_id);
                } else {
                    // Something else took this path since we looked: keep
                    // theirs, save ours as a conflict copy.
                    name = conflict_name(&name, &device);
                }
            }
            Ok(vec![Op::Put(Node::file(
                node_id,
                parent,
                &name,
                size,
                mtime_ns,
                file_key,
                object_id,
                chunk_ids.clone(),
            ))])
        })?;
        self.drop_objects(&replaced);
        let path = self.tree.path_of(&node_id).unwrap_or(remote_owned);
        Ok(Uploaded { path, size })
    }

    /// Uploads a file or a whole folder into the shelf folder `remote_dir`.
    pub fn put(&mut self, local: &Path, remote_dir: &str) -> anyhow::Result<Vec<Uploaded>> {
        let name = local
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| format!("{}: no file name", local.display()))?
            .to_string();
        let target = join(remote_dir, &name);
        if local.is_dir() {
            self.mkdir(&target)?;
            let mut entries: Vec<_> = std::fs::read_dir(local)?.collect::<Result<_, _>>()?;
            entries.sort_by_key(|e| e.file_name());
            let mut out = Vec::new();
            for e in entries {
                out.extend(self.put(&e.path(), &target)?);
            }
            Ok(out)
        } else {
            Ok(vec![self.put_file(local, &target)?])
        }
    }

    /// Downloads and decrypts one file node into `out`.
    pub fn read_file(&self, node: &Node, out: &mut impl Write) -> anyhow::Result<()> {
        ensure!(node.kind == Kind::File, "{}: not a file", node.name);
        let object = node.object_id.context("file has no object")?;
        let key = node.file_key.context("file has no key")?;
        let chunks = self.read_chunks(&hex::encode(object), node.chunks.len() as u64)?;
        let mut written = 0u64;
        for (i, stored) in chunks.iter().enumerate() {
            ensure!(
                chunk::chunk_id(stored) == node.chunks[i],
                "chunk {i} of {} doesn't match the manifest",
                node.name
            );
            let pt = chunk::open_chunk(&key, &node.id, i as u64, stored)?;
            written += pt.len() as u64;
            out.write_all(&pt)?;
        }
        ensure!(
            written == node.size,
            "{}: expected {} bytes, got {written}",
            node.name,
            node.size
        );
        Ok(())
    }

    pub fn node(&self, path: &str) -> anyhow::Result<&Node> {
        let id = self.tree.resolve(path).with_context(|| format!("{path}: not found"))?;
        self.tree.get(&id).with_context(|| format!("{path}: is the root"))
    }

    /// Writes `remote` (file or folder) under the local folder `local_dir`.
    pub fn get(&self, remote: &str, local_dir: &Path) -> anyhow::Result<u64> {
        let node = self.node(remote)?;
        let mut count = 0;
        self.export_node(node, local_dir, &mut count)?;
        Ok(count)
    }

    fn export_node(&self, node: &Node, dir: &Path, count: &mut u64) -> anyhow::Result<()> {
        let safe = safe_name(&node.name)?;
        let path = dir.join(safe);
        match node.kind {
            Kind::Dir => {
                std::fs::create_dir_all(&path)?;
                for child in self.tree.list(&node.id) {
                    self.export_node(child, &path, count)?;
                }
            }
            Kind::File => {
                let tmp = dir.join(format!(".{safe}.oshelf-part"));
                let mut f = std::fs::File::create(&tmp)?;
                self.read_file(node, &mut f)?;
                f.sync_all()?;
                std::fs::rename(&tmp, &path)?;
                *count += 1;
            }
            Kind::Symlink => {}
        }
        Ok(())
    }

    /// Decrypts the whole shelf into `local_dir`.
    pub fn export(&self, local_dir: &Path) -> anyhow::Result<u64> {
        std::fs::create_dir_all(local_dir)?;
        let mut count = 0;
        for n in self.tree.list(&ROOT) {
            self.export_node(n, local_dir, &mut count)?;
        }
        Ok(count)
    }

    /// `mkdir -p`.
    pub fn mkdir(&mut self, path: &str) -> anyhow::Result<()> {
        let now = now_ns();
        let path = path.to_string();
        self.commit(|tree, _| {
            let mut ops = Vec::new();
            let mut parent = ROOT;
            let mut pending = false;
            for part in path.split('/').filter(|p| !p.is_empty()) {
                if !pending {
                    if let Some(n) = tree.child(&parent, part) {
                        ensure!(n.kind == Kind::Dir, "{part}: exists and is not a folder");
                        parent = n.id;
                        continue;
                    }
                }
                pending = true;
                let id: Id = keys::random();
                ops.push(Op::Put(Node::dir(id, parent, part, now)));
                parent = id;
            }
            Ok(ops)
        })
    }

    /// Deletes a file or folder (with everything in it).
    pub fn rm(&mut self, path: &str) -> anyhow::Result<usize> {
        let node = self.node(path)?.clone();
        let mut objects: Vec<Id> = node.object_id.into_iter().collect();
        objects.extend(self.tree.walk(&node.id).into_iter().filter_map(|n| n.object_id));
        self.commit(|tree, _| {
            Ok(if tree.get(&node.id).is_some() {
                vec![Op::Delete(node.id)]
            } else {
                vec![]
            })
        })?;
        self.drop_objects(&objects);
        Ok(objects.len())
    }

    /// Renames or moves. If `to` is an existing folder, moves into it.
    pub fn mv(&mut self, from: &str, to: &str) -> anyhow::Result<()> {
        let node = self.node(from)?.clone();
        let to = to.to_string();
        self.commit(|tree, _| {
            ensure!(tree.get(&node.id).is_some(), "{}: was deleted meanwhile", node.name);
            let (parent, name) = match tree
                .resolve(&to)
                .and_then(|id| if id == ROOT { None } else { tree.get(&id) })
            {
                Some(n) if n.kind == Kind::Dir => (n.id, node.name.clone()),
                Some(_) => bail!("{to}: already exists"),
                None if tree.resolve(&to) == Some(ROOT) => (ROOT, node.name.clone()),
                None => {
                    let (p, name) = split(&to)?;
                    (Self::require_dir(tree, &p)?, name)
                }
            };
            let mut cur = parent;
            while cur != ROOT {
                ensure!(cur != node.id, "can't move a folder into itself");
                cur = tree.get(&cur).map(|n| n.parent).unwrap_or(ROOT);
            }
            Ok(vec![Op::Move {
                id: node.id,
                name,
                parent,
            }])
        })
    }

    /// Seals the current tree as a snapshot so new devices load fast and the
    /// Pi can prune the log.
    pub fn compact(&mut self) -> anyhow::Result<u64> {
        self.catch_up()?;
        ensure!(self.chain.revision > 0, "nothing to compact yet");
        let snap = manifest::seal_snapshot(&self.master_key, &self.vault_id, &self.tree, self.chain);
        let object_id: Id = keys::random();
        self.upload_object(&object_id, &snap.segments)?;
        self.client
            .put(
                &format!(
                    "/v1/manifest/snapshots/{}?object={}",
                    self.chain.revision,
                    hex::encode(object_id)
                ),
                &[],
                &snap.header,
            )?
            .ok()?;
        Ok(self.chain.revision)
    }
}

/// `"Name (conflict, Device).ext"`.
pub fn conflict_name(name: &str, device: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => format!("{stem} (conflict, {device}).{ext}"),
        _ => format!("{name} (conflict, {device})"),
    }
}

fn split(path: &str) -> anyhow::Result<(String, String)> {
    let trimmed = path.trim_matches('/');
    ensure!(!trimmed.is_empty(), "need a file name, not the root");
    Ok(match trimmed.rsplit_once('/') {
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), trimmed.to_string()),
    })
}

fn join(dir: &str, name: &str) -> String {
    let d = dir.trim_matches('/');
    if d.is_empty() {
        name.to_string()
    } else {
        format!("{d}/{name}")
    }
}

/// Names come from the decrypted manifest, so a hostile writer could try
/// `..` or slashes; never let one escape the export folder.
fn safe_name(name: &str) -> anyhow::Result<&str> {
    ensure!(
        !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\0'),
        "refusing unsafe name {name:?}"
    );
    Ok(name)
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflict_names() {
        assert_eq!(conflict_name("report.pdf", "MacBook"), "report (conflict, MacBook).pdf");
        assert_eq!(conflict_name("Makefile", "Pi"), "Makefile (conflict, Pi)");
        assert_eq!(conflict_name(".env", "Pi"), ".env (conflict, Pi)");
    }

    #[test]
    fn paths() {
        assert_eq!(split("a/b/c.txt").unwrap(), ("a/b".into(), "c.txt".into()));
        assert_eq!(split("/c.txt").unwrap(), ("".into(), "c.txt".into()));
        assert!(split("/").is_err());
        assert_eq!(join("", "x"), "x");
        assert_eq!(join("/a/", "x"), "a/x");
        assert!(safe_name("..").is_err());
        assert!(safe_name("a/b").is_err());
        assert!(safe_name("ok.txt").is_ok());
    }
}
