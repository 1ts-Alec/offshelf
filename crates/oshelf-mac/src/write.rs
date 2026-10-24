//! The write path. Files written through the mount land in a local staging
//! file first, show up in Finder at once, and upload in the background once
//! writes go quiet. Folder changes, renames and deletes commit right away.
//!
//! Finder's own bookkeeping files (`.DS_Store`, `._*` AppleDouble files)
//! stay on this Mac and never upload.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use oshelf::shelf::conflict_name;
use oshelf_core::keys::{self, Key};
use oshelf_core::manifest::{nfc, Id, Kind, Node, Op};
use oshelf_core::{chunk, CHUNK_SIZE};
use serde::{Deserialize, Serialize};

use crate::activity::Kind as EventKind;
use crate::engine::{human, now_ns, Attr, Engine, Errno, Res};
use crate::view::fileid;

/// Writes must be quiet this long before a file uploads.
const SETTLE: Duration = Duration::from_secs(2);

/// A file with content this Mac hasn't sent to the Pi yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    #[serde(with = "hex16")]
    pub id: Id,
    #[serde(with = "hex16")]
    pub parent: Id,
    pub name: String,
    pub mtime_ns: i64,
    pub mode: u32,
    pub file_key: Key,
    /// The shelf's current version of this file, dropped after the upload.
    #[serde(default, with = "hex16::opt")]
    pub replaces: Option<Id>,
    #[serde(skip)]
    pub size: u64,
    /// Bumped on every write, so an upload knows if it raced one.
    #[serde(skip)]
    pub generation: u64,
    #[serde(skip)]
    pub uploading: bool,
    #[serde(skip, default = "Instant::now")]
    pub touched: Instant,
    #[serde(skip)]
    pub data: PathBuf,
}

impl Pending {
    pub fn attr(&self) -> Attr {
        Attr {
            fileid: fileid(&self.id),
            kind: Kind::File,
            size: self.size,
            local: self.size,
            mtime_ns: self.mtime_ns,
            mode: self.mode,
        }
    }

    pub fn local_only(&self) -> bool {
        local_only(&self.name)
    }
}

pub fn local_only(name: &str) -> bool {
    name == ".DS_Store" || name.starts_with("._") || name == ".localized"
}

fn bad_name(name: &str) -> bool {
    name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') || name.len() > 255
}

fn io(e: impl std::fmt::Display) -> Errno {
    tracing::warn!("{e}");
    Errno::Io
}

impl Engine {
    fn meta_path(&self, id: &Id) -> PathBuf {
        self.staging.join(format!("{}.json", hex::encode(id)))
    }

    fn save_pending(&self, p: &Pending) {
        if let Ok(json) = serde_json::to_vec(p) {
            let _ = std::fs::write(self.meta_path(&p.id), json);
        }
    }

    /// Restores unsent writes from an earlier run; they upload as usual.
    pub(crate) fn load_pending(&self) {
        let Ok(dir) = std::fs::read_dir(&self.staging) else {
            return;
        };
        let mut pending = self.pending.lock().expect("pending");
        for e in dir.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let Some(mut p) = std::fs::read(&path)
                .ok()
                .and_then(|b| serde_json::from_slice::<Pending>(&b).ok())
            else {
                continue;
            };
            p.data = path.with_extension("data");
            let Ok(meta) = std::fs::metadata(&p.data) else {
                let _ = std::fs::remove_file(&path);
                continue;
            };
            p.size = meta.len();
            p.generation = 1;
            pending.insert(fileid(&p.id), p);
        }
    }

    pub(crate) fn pending_child(&self, parent: &Id, name: &str) -> Option<u64> {
        let name = nfc(name);
        self.pending
            .lock()
            .expect("pending")
            .iter()
            .find(|(_, p)| p.parent == *parent && p.name == name)
            .map(|(k, _)| *k)
    }

    pub(crate) fn read_pending(&self, id: u64, offset: u64, count: u32) -> Option<Res<(Vec<u8>, bool)>> {
        let (path, size) = {
            let p = self.pending.lock().expect("pending");
            let p = p.get(&id)?;
            (p.data.clone(), p.size)
        };
        Some((|| {
            let mut f = std::fs::File::open(&path).map_err(io)?;
            f.seek(SeekFrom::Start(offset)).map_err(io)?;
            let mut buf = Vec::with_capacity(count as usize);
            f.take(u64::from(count)).read_to_end(&mut buf).map_err(io)?;
            let eof = offset + buf.len() as u64 >= size;
            Ok((buf, eof))
        })())
    }

    /// Starts a staged copy of a shelf file so it can be edited in place.
    /// `with_content: false` is for truncation to zero: nothing to download.
    fn stage_existing(&self, id: u64) -> Res<()> {
        self.stage(id, true)
    }

    fn stage(&self, id: u64, with_content: bool) -> Res<()> {
        if self.pending.lock().expect("pending").contains_key(&id) {
            return Ok(());
        }
        let node = self.node(id)?.ok_or(Errno::IsDir)?;
        if node.kind != Kind::File {
            return Err(Errno::IsDir);
        }
        let data = self.staging.join(format!("{}.data", hex::encode(node.id)));
        let mut f = std::fs::File::create(&data).map_err(io)?;
        if with_content && !node.chunks.is_empty() {
            self.fetch(&node, 0, node.chunks.len() as u64 - 1).map_err(|e| {
                self.note_offline(&e);
                Errno::Io
            })?;
            let key = node.file_key.ok_or(Errno::Io)?;
            for (i, c) in node.chunks.iter().enumerate() {
                let stored = self.cache.get(c).ok_or(Errno::Io)?;
                let pt = chunk::open_chunk(&key, &node.id, i as u64, &stored).map_err(io)?;
                f.write_all(&pt).map_err(io)?;
            }
        }
        f.sync_all().map_err(io)?;
        let p = Pending {
            id: node.id,
            parent: node.parent,
            name: node.name.clone(),
            mtime_ns: node.mtime_ns,
            mode: node.mode,
            file_key: node.file_key.unwrap_or_else(keys::random),
            replaces: node.object_id,
            size: if with_content { node.size } else { 0 },
            generation: 0,
            uploading: false,
            touched: Instant::now(),
            data,
        };
        self.save_pending(&p);
        self.pending.lock().expect("pending").insert(id, p);
        Ok(())
    }

    pub fn create(&self, dir: u64, name: &str, mode: Option<u32>, exclusive: bool) -> Res<(u64, Attr)> {
        if bad_name(name) {
            return Err(Errno::Inval);
        }
        let parent = self.dir_id(dir)?;
        if let Ok(existing) = self.lookup(dir, name) {
            if exclusive {
                return Err(Errno::Exist);
            }
            // Plain CREATE on an existing file truncates it.
            self.setattr(existing, Some(0), None, mode)?;
            return Ok((existing, self.getattr(existing)?));
        }
        let id: Id = keys::random();
        let data = self.staging.join(format!("{}.data", hex::encode(id)));
        std::fs::File::create(&data).map_err(io)?;
        let p = Pending {
            id,
            parent,
            name: nfc(name),
            mtime_ns: now_ns(),
            mode: mode.unwrap_or(0o644) & 0o7777,
            file_key: keys::random(),
            replaces: None,
            size: 0,
            generation: 1,
            uploading: false,
            touched: Instant::now(),
            data,
        };
        self.save_pending(&p);
        let attr = p.attr();
        self.pending.lock().expect("pending").insert(fileid(&id), p);
        Ok((fileid(&id), attr))
    }

    pub fn write(&self, id: u64, offset: u64, bytes: &[u8]) -> Res<Attr> {
        self.stage_existing(id)?;
        let mut pending = self.pending.lock().expect("pending");
        let p = pending.get_mut(&id).ok_or(Errno::Stale)?;
        let mut f = std::fs::OpenOptions::new().write(true).open(&p.data).map_err(io)?;
        f.seek(SeekFrom::Start(offset)).map_err(io)?;
        f.write_all(bytes).map_err(io)?;
        p.size = p.size.max(offset + bytes.len() as u64);
        p.mtime_ns = now_ns();
        p.generation += 1;
        p.touched = Instant::now();
        Ok(p.attr())
    }

    /// Size, mtime and mode changes. Changing a shelf file's size stages
    /// it; mtime or mode alone just commit new metadata.
    pub fn setattr(&self, id: u64, size: Option<u64>, mtime_ns: Option<i64>, mode: Option<u32>) -> Res<Attr> {
        if let Some(sz) = size {
            self.stage(id, sz != 0)?;
        }
        {
            let mut pending = self.pending.lock().expect("pending");
            if let Some(p) = pending.get_mut(&id) {
                if let Some(sz) = size {
                    let f = std::fs::OpenOptions::new().write(true).open(&p.data).map_err(io)?;
                    f.set_len(sz).map_err(io)?;
                    p.size = sz;
                    p.generation += 1;
                    p.touched = Instant::now();
                }
                if let Some(t) = mtime_ns {
                    p.mtime_ns = t;
                }
                if let Some(m) = mode {
                    p.mode = m & 0o7777;
                }
                let p = p.clone();
                drop(pending);
                self.save_pending(&p);
                return Ok(p.attr());
            }
        }
        let Some(node) = self.node(id)? else {
            return Ok(self.root_attr());
        };
        if mtime_ns.is_none() && mode.is_none() {
            return self.getattr(id);
        }
        let nid = node.id;
        self.commit(|tree, _| {
            let Some(cur) = tree.get(&nid) else { return Ok(vec![]) };
            let mut n = cur.clone();
            if let Some(t) = mtime_ns {
                n.mtime_ns = t;
            }
            if let Some(m) = mode {
                n.mode = m & 0o7777;
            }
            Ok(if n == *cur { vec![] } else { vec![Op::Put(n)] })
        })
        .map_err(|e| self.commit_error(e))?;
        self.getattr(id)
    }

    fn commit_error(&self, e: anyhow::Error) -> Errno {
        tracing::warn!("commit failed: {e:#}");
        self.note_offline(&e);
        Errno::Io
    }

    pub fn mkdir(&self, dir: u64, name: &str) -> Res<(u64, Attr)> {
        if bad_name(name) {
            return Err(Errno::Inval);
        }
        let parent = self.dir_id(dir)?;
        if self.lookup(dir, name).is_ok() {
            return Err(Errno::Exist);
        }
        let id: Id = keys::random();
        let name = nfc(name);
        let now = now_ns();
        self.commit(|tree, _| {
            anyhow::ensure!(tree.child(&parent, &name).is_none(), "exists");
            Ok(vec![Op::Put(Node::dir(id, parent, &name, now))])
        })
        .map_err(|e| self.commit_error(e))?;
        let fid = fileid(&id);
        Ok((fid, self.getattr(fid)?))
    }

    pub fn symlink(&self, dir: u64, name: &str, target: &str) -> Res<(u64, Attr)> {
        if bad_name(name) {
            return Err(Errno::Inval);
        }
        let parent = self.dir_id(dir)?;
        if self.lookup(dir, name).is_ok() {
            return Err(Errno::Exist);
        }
        let mut node = Node::dir(keys::random(), parent, name, now_ns());
        node.kind = Kind::Symlink;
        node.mode = 0o777;
        node.target = Some(target.to_string());
        let n = node.clone();
        self.commit(move |_, _| Ok(vec![Op::Put(n.clone())]))
            .map_err(|e| self.commit_error(e))?;
        let fid = fileid(&node.id);
        Ok((fid, self.getattr(fid)?))
    }

    pub fn remove(&self, dir: u64, name: &str) -> Res<()> {
        let id = self.lookup(dir, name)?;
        if let Some(p) = self.pending.lock().expect("pending").remove(&id) {
            let _ = std::fs::remove_file(&p.data);
            let _ = std::fs::remove_file(self.meta_path(&p.id));
            if self.node(id).ok().flatten().is_none() {
                return Ok(());
            }
        }
        let node = self.node(id)?.ok_or(Errno::Inval)?;
        if node.kind == Kind::Dir && (!self.view().tree.list(&node.id).is_empty() || self.has_pending_under(&node.id)) {
            return Err(Errno::NotEmpty);
        }
        let objects: Vec<Id> = node.object_id.into_iter().collect();
        let nid = node.id;
        self.commit(|tree, _| {
            Ok(if tree.get(&nid).is_some() {
                vec![Op::Delete(nid)]
            } else {
                vec![]
            })
        })
        .map_err(|e| self.commit_error(e))?;
        for c in &node.chunks {
            self.cache.remove(c);
        }
        self.shelf.lock().expect("shelf").drop_objects(&objects);
        Ok(())
    }

    fn has_pending_under(&self, dir: &Id) -> bool {
        self.pending.lock().expect("pending").values().any(|p| p.parent == *dir)
    }

    pub fn rename(&self, from_dir: u64, from: &str, to_dir: u64, to: &str) -> Res<()> {
        if bad_name(to) {
            return Err(Errno::Inval);
        }
        let id = self.lookup(from_dir, from)?;
        let to_parent = self.dir_id(to_dir)?;
        let to = nfc(to);
        // Whatever holds the target name goes, as rename(2) says.
        if let Ok(victim) = self.lookup(to_dir, &to) {
            if victim == id {
                return Ok(());
            }
            let va = self.getattr(victim)?;
            if va.kind == Kind::Dir && !self.readdir(victim)?.is_empty() {
                return Err(Errno::NotEmpty);
            }
            self.remove(to_dir, &to)?;
        }
        let in_tree = self.node(id).ok().flatten();
        {
            let mut pending = self.pending.lock().expect("pending");
            if let Some(p) = pending.get_mut(&id) {
                p.parent = to_parent;
                p.name = to.clone();
                let p = p.clone();
                drop(pending);
                self.save_pending(&p);
                if in_tree.is_none() {
                    return Ok(());
                }
            }
        }
        let node = in_tree.ok_or(Errno::Stale)?;
        if node.kind == Kind::Dir {
            // No folder into itself.
            let v = self.view();
            let mut cur = to_parent;
            while cur != oshelf_core::manifest::ROOT {
                if cur == node.id {
                    return Err(Errno::Inval);
                }
                cur = v
                    .tree
                    .get(&cur)
                    .map(|n| n.parent)
                    .unwrap_or(oshelf_core::manifest::ROOT);
            }
        }
        let nid = node.id;
        self.commit(|tree, _| {
            Ok(if tree.get(&nid).is_some() {
                vec![Op::Move {
                    id: nid,
                    name: to.clone(),
                    parent: to_parent,
                }]
            } else {
                vec![]
            })
        })
        .map_err(|e| self.commit_error(e))
    }

    // ---- uploads -----------------------------------------------------------

    /// Uploads every staged file whose writes have settled. Returns how many
    /// went up.
    pub fn upload_settled(&self) -> usize {
        let ready: Vec<u64> = self
            .pending
            .lock()
            .expect("pending")
            .iter()
            .filter(|(_, p)| !p.uploading && !p.local_only() && p.generation > 0 && p.touched.elapsed() >= SETTLE)
            .map(|(k, _)| *k)
            .collect();
        let mut done = 0;
        for id in ready {
            match self.upload(id) {
                Ok(true) => done += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!("upload failed: {e:#}");
                    self.note_offline(&e);
                    if let Some(p) = self.pending.lock().expect("pending").get_mut(&id) {
                        p.uploading = false;
                    }
                    break;
                }
            }
        }
        done
    }

    /// Bytes and file count still waiting to upload.
    pub fn upload_backlog(&self) -> (u64, u64) {
        let p = self.pending.lock().expect("pending");
        let waiting: Vec<&Pending> = p.values().filter(|p| !p.local_only()).collect();
        (waiting.iter().map(|p| p.size).sum(), waiting.len() as u64)
    }

    fn upload(&self, id: u64) -> anyhow::Result<bool> {
        let snap = {
            let mut pending = self.pending.lock().expect("pending");
            let Some(p) = pending.get_mut(&id) else {
                return Ok(false);
            };
            p.uploading = true;
            p.clone()
        };
        let started = Instant::now();
        let object_id: Id = keys::random();
        let mut f = std::fs::File::open(&snap.data).context("open staged file")?;
        let mut buf = vec![0u8; CHUNK_SIZE as usize];
        let mut ids = Vec::new();
        let mut size = 0u64;
        let client = self.client.clone();
        loop {
            let n = read_full(&mut f, &mut buf)?;
            if n == 0 {
                break;
            }
            let sealed = chunk::seal_chunk(&snap.file_key, &snap.id, ids.len() as u64, &buf[..n]);
            let cid = chunk::chunk_id(&sealed);
            client
                .put(&format!("/v1/chunks/{}", hex::encode(cid)), &[], &sealed)?
                .ok()?;
            self.counters.uploaded.fetch_add(sealed.len() as u64, Ordering::Relaxed);
            // The sealed chunk is exactly what the Pi now holds: keep it, so
            // the file stays on this Mac without downloading it again.
            self.cache.put(&cid, &sealed)?;
            ids.push(cid);
            size += n as u64;
            if n < buf.len() {
                break;
            }
        }
        client
            .post_json(
                "/v1/objects",
                &serde_json::json!({
                    "id": hex::encode(object_id),
                    "chunks": ids.iter().map(hex::encode).collect::<Vec<_>>(),
                }),
            )?
            .ok()?;

        let device = self.device_name().to_string();
        let mut conflict = None;
        let mut replaced: Vec<Id> = snap.replaces.into_iter().collect();
        self.commit(|tree, _| {
            conflict = None;
            replaced.truncate(snap.replaces.is_some() as usize);
            // Use the latest name and folder: a rename may have happened
            // while the bytes went up.
            let (parent, mut name, mtime, mode) = {
                let pending = self.pending.lock().expect("pending");
                match pending.get(&id) {
                    Some(p) => (p.parent, p.name.clone(), p.mtime_ns, p.mode),
                    None => (snap.parent, snap.name.clone(), snap.mtime_ns, snap.mode),
                }
            };
            let parent = if parent == oshelf_core::manifest::ROOT || tree.get(&parent).is_some() {
                parent
            } else {
                // The folder was deleted elsewhere meanwhile; keep the file at the top.
                oshelf_core::manifest::ROOT
            };
            if let Some(cur) = tree.child(&parent, &name) {
                if cur.id == snap.id {
                    replaced.extend(cur.object_id.filter(|o| Some(*o) != snap.replaces));
                } else {
                    name = conflict_name(&name, &device);
                    conflict = Some(name.clone());
                }
            }
            let mut node = Node::file(
                snap.id,
                parent,
                &name,
                size,
                mtime,
                snap.file_key,
                object_id,
                ids.clone(),
            );
            node.mode = mode;
            Ok(vec![Op::Put(node)])
        })?;
        self.shelf.lock().expect("shelf").drop_objects(&replaced);

        let mut pending = self.pending.lock().expect("pending");
        let still_dirty = pending.get(&id).is_some_and(|p| p.generation != snap.generation);
        if still_dirty {
            let p = pending.get_mut(&id).expect("checked above");
            p.uploading = false;
            p.replaces = Some(object_id);
            let p = p.clone();
            drop(pending);
            self.save_pending(&p);
        } else if let Some(p) = pending.remove(&id) {
            drop(pending);
            let _ = std::fs::remove_file(&p.data);
            let _ = std::fs::remove_file(self.meta_path(&p.id));
        }
        let what = conflict.clone().unwrap_or(snap.name.clone());
        match conflict {
            Some(c) => self.activity.push(
                EventKind::Conflict,
                "Edited on two devices",
                &format!("{}: this Mac's copy saved as {c}", snap.name),
            ),
            None => self.activity.push(
                EventKind::Uploaded,
                &format!("Uploaded {what}"),
                &format!("{} in {:.1} s", human(size), started.elapsed().as_secs_f32()),
            ),
        }
        Ok(true)
    }

    /// Runs the upload loop on its own thread.
    pub fn spawn_uploader(self: &Arc<Self>) {
        let me = Arc::downgrade(self);
        std::thread::Builder::new()
            .name("oshelf-upload".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(700));
                let Some(e) = me.upgrade() else { return };
                if e.link.lock().expect("link").online {
                    e.upload_settled();
                }
            })
            .expect("spawn upload thread");
    }

    /// Staged files by fileid, for tests and status.
    pub fn pending_names(&self) -> HashMap<u64, String> {
        self.pending
            .lock()
            .expect("pending")
            .iter()
            .map(|(k, p)| (*k, p.name.clone()))
            .collect()
    }
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

mod hex16 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let s = String::deserialize(d)?;
        let mut out = [0u8; 16];
        hex::decode_to_slice(&s, &mut out).map_err(serde::de::Error::custom)?;
        Ok(out)
    }

    pub mod opt {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &Option<[u8; 16]>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(v) => s.serialize_some(&hex::encode(v)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 16]>, D::Error> {
            let s: Option<String> = Option::deserialize(d)?;
            s.map(|s| {
                let mut out = [0u8; 16];
                hex::decode_to_slice(&s, &mut out).map_err(serde::de::Error::custom)?;
                Ok(out)
            })
            .transpose()
        }
    }
}
