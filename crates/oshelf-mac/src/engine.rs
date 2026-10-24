//! The engine behind the mount: an unlocked shelf, the verified tree, the
//! chunk cache and the range read pipeline. Everything here blocks; the NFS
//! adapter runs it on Tokio's blocking pool.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::Instant;

use anyhow::{ensure, Context};
use oshelf::client::{self, Client};
use oshelf::config::{Config, Home};
use oshelf::shelf::{Shelf, Unlock};
use oshelf_core::chunk;
use oshelf_core::manifest::{Hash, Id, Kind, Node, Op, Tree, ROOT};
use oshelf_core::range::chunk_span;

use crate::activity::{Activity, Kind as EventKind};
use crate::cache::Cache;
use crate::settings::Settings;
use crate::view::{fileid, View, ROOT_FILEID};
use crate::write::Pending;

/// Most chunks fetched in one ranged request (the Pi allows 64).
const MAX_BATCH: u64 = 32;
/// Readahead window bounds, in chunks.
const AHEAD_MIN: u64 = 1;
const AHEAD_MAX: u64 = 16;

/// Why an operation failed, in the terms NFS needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Errno {
    NoEnt,
    Exist,
    NotDir,
    IsDir,
    NotEmpty,
    Inval,
    Stale,
    Io,
}

pub type Res<T> = Result<T, Errno>;

/// What `getattr` reports.
#[derive(Debug, Clone, Copy)]
pub struct Attr {
    pub fileid: u64,
    pub kind: Kind,
    pub size: u64,
    /// Bytes of this file held on this Mac (cached chunks or unsent writes).
    pub local: u64,
    pub mtime_ns: i64,
    pub mode: u32,
}

/// One in-flight chunk download that other readers can wait on.
#[derive(Default)]
struct Flight {
    done: Mutex<Option<bool>>,
    cv: Condvar,
}

impl Flight {
    fn finish(&self, ok: bool) {
        *self.done.lock().expect("flight") = Some(ok);
        self.cv.notify_all();
    }

    fn wait(&self) -> bool {
        let mut d = self.done.lock().expect("flight");
        while d.is_none() {
            d = self.cv.wait(d).expect("flight");
        }
        d.expect("set above")
    }
}

/// Per-file read pattern, to size the readahead.
#[derive(Clone, Copy)]
struct Stream {
    next: u64,
    /// Bytes read in order since the last seek.
    run: u64,
}

#[derive(Default)]
pub struct Counters {
    /// Plaintext bytes handed to apps through the mount.
    pub served: AtomicU64,
    /// Sealed bytes downloaded from the Pi.
    pub fetched: AtomicU64,
    /// Sealed bytes uploaded to the Pi.
    pub uploaded: AtomicU64,
}

/// Network state for the status UI.
#[derive(Debug, Clone, Default)]
pub struct Link {
    pub online: bool,
    pub host: String,
    pub host_name: String,
    pub latency_ms: Option<u32>,
    /// Wi-Fi network name, as the app last reported it.
    pub ssid: Option<String>,
    pub last_verified_ms: i64,
    pub error: Option<String>,
}

pub struct Engine {
    pub(crate) home: Home,
    pub(crate) config: Config,
    pub(crate) client: Arc<Client>,
    pub(crate) shelf: Mutex<Shelf>,
    view: RwLock<Arc<View>>,
    pub(crate) pending: Mutex<HashMap<u64, Pending>>,
    flights: Mutex<HashMap<Hash, Arc<Flight>>>,
    streams: Mutex<HashMap<u64, Stream>>,
    pub cache: Cache,
    pub(crate) settings: Mutex<Settings>,
    pub counters: Counters,
    pub activity: Activity,
    pub(crate) link: Mutex<Link>,
    pub(crate) staging: PathBuf,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

pub(crate) fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

impl Engine {
    /// Unlocks the shelf paired in `home` and loads the verified tree.
    /// `data_dir` holds the chunk cache, unsent writes and settings.
    pub fn open(home: Home, data_dir: PathBuf, unlock: Unlock) -> anyhow::Result<Arc<Self>> {
        let (config, client) = oshelf::shelf::connect(&home)?;
        let shelf = Shelf::open(&home, &config, &client, unlock)?;
        let view = View::new(shelf.tree.clone(), shelf.chain.revision);
        let cache = Cache::open(&data_dir).context("open the chunk cache")?;
        let staging = data_dir.join("staging");
        std::fs::create_dir_all(&staging)?;
        let settings = Settings::load(&data_dir);
        // SAFETY: getuid and getgid cannot fail.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let engine = Arc::new(Self {
            home: home.clone(),
            link: Mutex::new(Link {
                online: true,
                host: client.base(),
                last_verified_ms: now_ns() / 1_000_000,
                ..Link::default()
            }),
            config,
            client,
            shelf: Mutex::new(shelf),
            view: RwLock::new(Arc::new(view)),
            pending: Mutex::new(HashMap::new()),
            flights: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            cache,
            settings: Mutex::new(settings),
            counters: Counters::default(),
            activity: Activity::default(),
            staging,
            uid,
            gid,
        });
        engine.load_pending();
        Ok(engine)
    }

    pub fn view(&self) -> Arc<View> {
        self.view.read().expect("view lock").clone()
    }

    pub(crate) fn publish(&self, shelf: &Shelf) {
        let v = View::new(shelf.tree.clone(), shelf.chain.revision);
        *self.view.write().expect("view lock") = Arc::new(v);
    }

    pub fn device_name(&self) -> &str {
        &self.config.device_name
    }

    pub fn master_key(&self) -> [u8; 32] {
        *self.shelf.lock().expect("shelf").master_key()
    }

    /// Commits ops against the newest head (see `Shelf::commit`) and
    /// publishes the new tree.
    pub(crate) fn commit(&self, build: impl FnMut(&Tree, &str) -> anyhow::Result<Vec<Op>>) -> anyhow::Result<()> {
        let mut s = self.shelf.lock().expect("shelf");
        let r = s.commit(build);
        self.publish(&s);
        r
    }

    /// Pulls entries the Pi has that this Mac hasn't verified yet.
    pub fn refresh(&self) -> anyhow::Result<u64> {
        let mut s = self.shelf.lock().expect("shelf");
        let before = s.chain.revision;
        s.catch_up()?;
        if s.chain.revision != before {
            self.publish(&s);
        }
        Ok(s.chain.revision - before)
    }

    // ---- lookups -----------------------------------------------------------

    /// The node behind an NFS file id, or `None` for the root.
    pub(crate) fn node(&self, id: u64) -> Res<Option<Node>> {
        if id == ROOT_FILEID {
            return Ok(None);
        }
        let v = self.view();
        let nid = v.id(id).ok_or(Errno::Stale)?;
        Ok(Some(v.tree.get(&nid).cloned().ok_or(Errno::Stale)?))
    }

    /// Resolves a folder file id to its node id, failing if it is a file.
    pub(crate) fn dir_id(&self, id: u64) -> Res<Id> {
        if id == ROOT_FILEID {
            return Ok(ROOT);
        }
        match self.node(id)? {
            Some(n) if n.kind == Kind::Dir => Ok(n.id),
            Some(_) => Err(Errno::NotDir),
            None => Ok(ROOT),
        }
    }

    fn node_attr(&self, n: &Node) -> Attr {
        Attr {
            fileid: fileid(&n.id),
            kind: n.kind,
            size: n.size,
            local: if n.kind == Kind::File {
                self.cache.cached_bytes(&n.chunks)
            } else {
                0
            },
            mtime_ns: n.mtime_ns,
            mode: n.mode,
        }
    }

    pub fn root_attr(&self) -> Attr {
        Attr {
            fileid: ROOT_FILEID,
            kind: Kind::Dir,
            size: 0,
            local: 0,
            mtime_ns: 0,
            mode: 0o755,
        }
    }

    pub fn getattr(&self, id: u64) -> Res<Attr> {
        if let Some(p) = self.pending.lock().expect("pending").get(&id) {
            return Ok(p.attr());
        }
        Ok(match self.node(id)? {
            None => self.root_attr(),
            Some(n) => self.node_attr(&n),
        })
    }

    pub fn lookup(&self, dir: u64, name: &str) -> Res<u64> {
        let parent = self.dir_id(dir)?;
        if name == "." {
            return Ok(dir);
        }
        if name == ".." {
            let v = self.view();
            return Ok(v.tree.get(&parent).map(|n| fileid(&n.parent)).unwrap_or(ROOT_FILEID));
        }
        if let Some(p) = self.pending_child(&parent, name) {
            return Ok(p);
        }
        let v = self.view();
        v.tree.child(&parent, name).map(|n| fileid(&n.id)).ok_or(Errno::NoEnt)
    }

    /// Folder contents, merged with files written here but not sent yet,
    /// sorted by file id so paging with `start_after` is stable.
    pub fn readdir(&self, dir: u64) -> Res<Vec<(String, Attr)>> {
        let parent = self.dir_id(dir)?;
        let v = self.view();
        let mut out: HashMap<String, Attr> = v
            .tree
            .list(&parent)
            .into_iter()
            .map(|n| (n.name.clone(), self.node_attr(n)))
            .collect();
        for p in self.pending.lock().expect("pending").values() {
            if p.parent == parent {
                out.insert(p.name.clone(), p.attr());
            }
        }
        let mut out: Vec<(String, Attr)> = out.into_iter().collect();
        out.sort_by_key(|(_, a)| a.fileid);
        Ok(out)
    }

    pub fn readlink(&self, id: u64) -> Res<String> {
        match self.node(id)? {
            Some(n) if n.kind == Kind::Symlink => Ok(n.target.unwrap_or_default()),
            _ => Err(Errno::Inval),
        }
    }

    // ---- reads -------------------------------------------------------------

    pub fn read(self: &Arc<Self>, id: u64, offset: u64, count: u32) -> Res<(Vec<u8>, bool)> {
        if let Some(r) = self.read_pending(id, offset, count) {
            return r;
        }
        let node = self.node(id)?.ok_or(Errno::IsDir)?;
        if node.kind != Kind::File {
            return Err(Errno::IsDir);
        }
        let cs = node.chunk_size.unwrap_or(oshelf_core::CHUNK_SIZE);
        let end = offset.saturating_add(u64::from(count));
        let Some(span) = chunk_span(offset, end, node.size, cs) else {
            return Ok((Vec::new(), true));
        };
        let ahead = self.readahead(id, offset, end, u64::from(cs));
        self.fetch(&node, span.first, span.last).map_err(|e| {
            tracing::warn!("read {} failed: {e:#}", node.name);
            self.note_offline(&e);
            Errno::Io
        })?;
        if ahead > 0 && span.last + 1 < node.chunks.len() as u64 {
            let me = self.clone();
            let n = node.clone();
            let from = span.last + 1;
            let to = (span.last + ahead).min(n.chunks.len() as u64 - 1);
            std::thread::spawn(move || {
                if let Err(e) = me.fetch(&n, from, to) {
                    tracing::debug!("readahead of {} failed: {e:#}", n.name);
                }
            });
        }
        let mut out = Vec::with_capacity(span.len as usize);
        let mut skip = span.skip as usize;
        for idx in span.first..=span.last {
            let pt = self.plaintext(&node, idx).map_err(|e| {
                tracing::warn!("chunk {idx} of {}: {e:#}", node.name);
                Errno::Io
            })?;
            let want = (span.len as usize - out.len()).min(pt.len().saturating_sub(skip));
            out.extend_from_slice(&pt[skip..skip + want]);
            skip = 0;
        }
        self.counters.served.fetch_add(out.len() as u64, Ordering::Relaxed);
        let eof = offset + out.len() as u64 >= node.size;
        Ok((out, eof))
    }

    /// Updates the read pattern of a file and returns how many chunks to
    /// read past this request (0: nothing new to start). The window is a quarter
    /// of what has been read in order since the last seek, so a scrub that
    /// grabs one frame moves little, and steady playback builds a deep
    /// buffer.
    fn readahead(&self, id: u64, start: u64, end: u64, cs: u64) -> u64 {
        let mut streams = self.streams.lock().expect("streams");
        if streams.len() > 256 {
            streams.clear();
        }
        let s = streams.entry(id).or_insert(Stream { next: u64::MAX, run: 0 });
        // The NFS client keeps several reads in flight, so "in order" allows
        // some slack around where the last read ended.
        let sequential = start <= s.next.saturating_add(2 * cs) && start + 2 * cs >= s.next;
        s.run = if sequential { s.run + (end - start) } else { 0 };
        s.next = end;
        // Start new readahead only when a read enters a new chunk, not on
        // every 128 KiB read inside one.
        let new_chunk = start.is_multiple_of(cs) || start / cs != (end - 1) / cs;
        if sequential && !new_chunk {
            return 0;
        }
        (s.run / cs / 4).clamp(AHEAD_MIN, AHEAD_MAX)
    }

    /// Decrypted contents of chunk `idx`, from memory or disk.
    fn plaintext(&self, node: &Node, idx: u64) -> anyhow::Result<Arc<Vec<u8>>> {
        let id = node.chunks[idx as usize];
        if let Some(p) = self.cache.plain(&id) {
            return Ok(p);
        }
        let stored = match self.cache.get(&id) {
            Some(s) => s,
            None => {
                self.fetch(node, idx, idx)?;
                self.cache.get(&id).context("chunk vanished from the cache")?
            }
        };
        let key = node.file_key.context("file without a key")?;
        let pt = Arc::new(chunk::open_chunk(&key, &node.id, idx, &stored)?);
        self.cache.keep_plain(id, pt.clone());
        Ok(pt)
    }

    /// Makes sure chunks `first..=last` of a file are in the cache, sharing
    /// downloads with any other reader that wants the same chunks.
    pub fn fetch(&self, node: &Node, first: u64, last: u64) -> anyhow::Result<()> {
        let object = hex::encode(node.object_id.context("file without an object")?);
        let mut mine: Vec<(u64, Arc<Flight>)> = Vec::new();
        let mut theirs: Vec<Arc<Flight>> = Vec::new();
        {
            let mut flights = self.flights.lock().expect("flights");
            for idx in first..=last {
                let id = node.chunks[idx as usize];
                if self.cache.contains(&id) {
                    continue;
                }
                match flights.get(&id) {
                    Some(f) => theirs.push(f.clone()),
                    None => {
                        let f = Arc::new(Flight::default());
                        flights.insert(id, f.clone());
                        mine.push((idx, f));
                    }
                }
            }
        }
        let mut result = Ok(());
        let mut i = 0;
        while i < mine.len() {
            // Contiguous run of chunk indices, capped per request.
            let mut j = i;
            while j + 1 < mine.len() && mine[j + 1].0 == mine[j].0 + 1 && (j + 1 - i) < MAX_BATCH as usize {
                j += 1;
            }
            if result.is_ok() {
                result = self.download(node, &object, mine[i].0, mine[j].0);
            }
            let ok = result.is_ok();
            let mut flights = self.flights.lock().expect("flights");
            for (idx, f) in &mine[i..=j] {
                flights.remove(&node.chunks[*idx as usize]);
                f.finish(ok);
            }
            i = j + 1;
        }
        result?;
        for f in theirs {
            ensure!(f.wait(), "a shared chunk download failed");
        }
        Ok(())
    }

    fn download(&self, node: &Node, object: &str, first: u64, last: u64) -> anyhow::Result<()> {
        let started = Instant::now();
        let r = self
            .client
            .get_streamed(&format!("/v1/objects/{object}/chunks?first={first}&last={last}"))?
            .ok()?;
        let frames = client::frames(&r.body)?;
        ensure!(
            frames.len() as u64 == last - first + 1,
            "the Pi returned the wrong number of chunks"
        );
        let mut bytes = 0;
        for (k, stored) in frames.iter().enumerate() {
            let idx = first + k as u64;
            let want = node.chunks[idx as usize];
            ensure!(
                chunk::chunk_id(stored) == want,
                "chunk {idx} of {} doesn't match the manifest",
                node.name
            );
            self.cache.put(&want, stored)?;
            bytes += stored.len() as u64;
        }
        self.counters.fetched.fetch_add(bytes, Ordering::Relaxed);
        self.activity
            .streamed(&node.id, &node.name, node.size, bytes, started.elapsed());
        tracing::debug!(
            "fetched chunks {first}..={last} of {} ({} KiB) in {:?}",
            node.name,
            bytes >> 10,
            started.elapsed()
        );
        Ok(())
    }

    pub(crate) fn note_offline(&self, e: &anyhow::Error) {
        let mut l = self.link.lock().expect("link");
        if l.online {
            self.activity
                .push(EventKind::Offline, "Can't reach your shelf", &format!("{e:#}"));
        }
        l.online = false;
        l.error = Some(format!("{e:#}"));
    }

    // ---- pins, offload, cache size -------------------------------------------

    /// Chunk ids of every file at or under `id`.
    pub(crate) fn chunks_under(tree: &Tree, id: &Id) -> Vec<Hash> {
        let mut out = Vec::new();
        if let Some(n) = tree.get(id) {
            out.extend(n.chunks.iter().copied());
        }
        for n in tree.walk(id) {
            out.extend(n.chunks.iter().copied());
        }
        out
    }

    /// Chunks that pinned folders and files need to keep.
    pub(crate) fn pinned_chunks(&self) -> HashSet<Hash> {
        let pins = self.settings.lock().expect("settings").pins.clone();
        let v = self.view();
        pins.iter().flat_map(|p| Self::chunks_under(&v.tree, p)).collect()
    }

    pub fn is_pinned(&self, id: &Id) -> bool {
        let pins = self.settings.lock().expect("settings").pins.clone();
        let v = self.view();
        let mut cur = *id;
        loop {
            if pins.contains(&cur) {
                return true;
            }
            match v.tree.get(&cur) {
                Some(n) if cur != ROOT => cur = n.parent,
                _ => return false,
            }
        }
    }

    /// Keeps a file or folder on this Mac and downloads what's missing.
    pub fn pin(self: &Arc<Self>, id: Id) -> anyhow::Result<()> {
        {
            let mut s = self.settings.lock().expect("settings");
            if !s.pins.contains(&id) {
                s.pins.push(id);
                s.save();
            }
        }
        let v = self.view();
        let name = v.tree.get(&id).map(|n| n.name.clone()).unwrap_or_default();
        let files: Vec<Node> = std::iter::once(v.tree.get(&id))
            .flatten()
            .chain(v.tree.walk(&id))
            .filter(|n| n.kind == Kind::File && !n.chunks.is_empty())
            .cloned()
            .collect();
        let total: u64 = files.iter().map(|n| n.size).sum();
        let me = self.clone();
        std::thread::spawn(move || {
            for f in &files {
                let n = f.chunks.len() as u64;
                let mut first = 0;
                while first < n {
                    let last = (first + MAX_BATCH - 1).min(n - 1);
                    if let Err(e) = me.fetch(f, first, last) {
                        me.activity
                            .push(EventKind::Error, &format!("Pinning {name} stopped"), &format!("{e:#}"));
                        return;
                    }
                    first = last + 1;
                }
            }
            me.activity.push(
                EventKind::Pinned,
                &format!("Pinned {name}"),
                &format!("{} downloaded", human(total)),
            );
        });
        Ok(())
    }

    pub fn unpin(&self, id: &Id) {
        let mut s = self.settings.lock().expect("settings");
        s.pins.retain(|p| p != id);
        s.save();
    }

    /// Drops this Mac's copy of a file or folder. It stays on the shelf and
    /// streams on open. Unsent writes are never dropped.
    pub fn offload(&self, id: &Id) -> u64 {
        {
            let v = self.view();
            let mut s = self.settings.lock().expect("settings");
            s.pins
                .retain(|p| p != id && !v.tree.walk(id).iter().any(|n| n.id == *p));
            s.save();
        }
        let keep = self.pinned_chunks();
        let v = self.view();
        let freed: u64 = Self::chunks_under(&v.tree, id)
            .iter()
            .filter(|c| !keep.contains(*c))
            .map(|c| self.cache.remove(c))
            .sum();
        freed
    }

    pub fn set_auto_offload(&self, on: bool, threshold_pct: u8, order: crate::settings::OffloadOrder) {
        let mut s = self.settings.lock().expect("settings");
        s.auto_offload = on;
        s.threshold_pct = threshold_pct;
        s.offload_order = order;
        s.save();
    }

    pub fn set_cache_cap(&self, bytes: u64) {
        let mut s = self.settings.lock().expect("settings");
        s.cache_cap = bytes;
        s.save();
    }

    /// Keeps the streaming cache under its cap, never touching pinned chunks.
    pub fn trim_cache(&self) -> u64 {
        let cap = self.settings.lock().expect("settings").cache_cap;
        let keep = self.pinned_chunks();
        let pinned_bytes = self.cache.cached_bytes(&keep.iter().copied().collect::<Vec<_>>());
        self.cache.trim(cap.saturating_add(pinned_bytes), &keep)
    }
}

pub fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}
