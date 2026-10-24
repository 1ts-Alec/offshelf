//! The engine against a real oshelfd on localhost, through the same calls
//! the NFS layer makes.

use std::sync::atomic::Ordering;
use std::time::Duration;

use oshelf::config::Home;
use oshelf::shelf::{self, Shelf, Unlock};
use oshelf_core::vault::Kdf;
use oshelf_mac::view::ROOT_FILEID;
use oshelf_mac::Engine;

struct Pi {
    url: String,
    state: oshelfd::AppState,
    rt: tokio::runtime::Runtime,
    _dir: tempfile::TempDir,
}

fn start_pi() -> Pi {
    let dir = tempfile::tempdir().unwrap();
    let state = oshelfd::AppState::open(dir.path()).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = oshelfd::router(state.clone());
    rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
    Pi {
        url,
        state,
        rt,
        _dir: dir,
    }
}

impl Pi {
    fn code(&self) -> String {
        let code = oshelfd::auth::new_pairing_code();
        let c = code.clone();
        self.rt
            .block_on(self.state.db.call(move |db| db.add_pairing_code(&c, 600, 5)))
            .unwrap();
        oshelfd::auth::display_code(&code)
    }
}

const PASS: &str = "correct horse";

/// A paired, initialised shelf with one 3.5 MiB video and a note.
fn shelf_with_files(pi: &Pi, local: &std::path::Path) -> (Home, Vec<u8>) {
    let home = Home::open(local.join("home"));
    let cfg = shelf::pair(&home, &pi.url, &pi.code(), "Mac").unwrap();
    let (_, client) = shelf::connect(&home).unwrap();
    let kdf = Kdf {
        m_kib: 1024,
        t: 1,
        ..Kdf::new_default()
    };
    shelf::init(&client, PASS, kdf).unwrap();
    let video: Vec<u8> = (0..(7 << 19))
        .map(|i: u32| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let src = local.join("src/Movies");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("reel.mov"), &video).unwrap();
    std::fs::write(local.join("src/note.txt"), b"hi").unwrap();
    let mut s = Shelf::open(&home, &cfg, &client, Unlock::Passphrase(PASS)).unwrap();
    s.put(&src, "").unwrap();
    s.put(&local.join("src/note.txt"), "").unwrap();
    (home, video)
}

#[test]
fn browse_and_range_read_fetch_only_what_is_needed() {
    let pi = start_pi();
    let local = tempfile::tempdir().unwrap();
    let (home, video) = shelf_with_files(&pi, local.path());
    let e = Engine::open(home, local.path().join("data"), Unlock::Passphrase(PASS)).unwrap();

    let names: Vec<String> = e.readdir(ROOT_FILEID).unwrap().into_iter().map(|(n, _)| n).collect();
    assert_eq!(names.len(), 2);
    let movies = e.lookup(ROOT_FILEID, "Movies").unwrap();
    let reel = e.lookup(movies, "reel.mov").unwrap();
    assert_eq!(e.getattr(reel).unwrap().size, video.len() as u64);
    assert_eq!(e.getattr(reel).unwrap().local, 0, "nothing cached yet");

    // A read in the middle that straddles a chunk boundary.
    let at = (1 << 20) * 2 - 100;
    let (got, eof) = e.read(reel, at, 4096).unwrap();
    assert!(!eof);
    assert_eq!(got, &video[at as usize..at as usize + 4096]);
    let fetched = e.counters.fetched.load(Ordering::Relaxed);
    assert!(fetched < 4 << 20, "fetched {fetched} bytes for a 4 KiB read");

    // The tail, including EOF.
    let (got, eof) = e.read(reel, video.len() as u64 - 10, 100).unwrap();
    assert!(eof);
    assert_eq!(got, &video[video.len() - 10..]);
}

#[test]
fn writes_upload_and_survive_a_restart() {
    let pi = start_pi();
    let local = tempfile::tempdir().unwrap();
    let (home, _) = shelf_with_files(&pi, local.path());
    let data = local.path().join("data");
    let e = Engine::open(home.clone(), data.clone(), Unlock::Passphrase(PASS)).unwrap();

    let docs = e.mkdir(ROOT_FILEID, "Docs").unwrap().0;
    let (f, _) = e.create(docs, "draft.txt", Some(0o644), false).unwrap();
    e.write(f, 0, b"hello ").unwrap();
    e.write(f, 6, b"world").unwrap();
    assert_eq!(e.read(f, 0, 100).unwrap().0, b"hello world", "readable before upload");
    let (ds, _) = e.create(docs, ".DS_Store", None, false).unwrap();
    e.write(ds, 0, b"finder junk").unwrap();
    e.rename(docs, "draft.txt", docs, "final.txt").unwrap();

    // Edit a file that is already on the shelf.
    let note = e.lookup(ROOT_FILEID, "note.txt").unwrap();
    e.write(note, 2, b" there").unwrap();

    std::thread::sleep(Duration::from_millis(2100));
    assert_eq!(e.upload_settled(), 2);
    assert_eq!(e.upload_backlog(), (0, 0));
    drop(e);

    // A fresh engine sees the uploads in the tree, and the local-only
    // Finder file is still there but was never sent.
    let e = Engine::open(home.clone(), data, Unlock::Passphrase(PASS)).unwrap();
    let docs = e.lookup(ROOT_FILEID, "Docs").unwrap();
    let fin = e.lookup(docs, "final.txt").unwrap();
    assert_eq!(e.read(fin, 0, 100).unwrap().0, b"hello world");
    assert_eq!(
        e.getattr(fin).unwrap().local,
        e.getattr(fin).unwrap().size + 48,
        "uploads stay cached"
    );
    assert!(e.lookup(docs, ".DS_Store").is_ok());
    let v = e.view();
    assert!(v.tree.resolve("Docs/.DS_Store").is_none());
    let note = e.lookup(ROOT_FILEID, "note.txt").unwrap();
    assert_eq!(e.read(note, 0, 100).unwrap().0, b"hi there");

    // Deletes commit straight away.
    e.remove(docs, "final.txt").unwrap();
    assert!(e.view().tree.resolve("Docs/final.txt").is_none());
}

#[test]
fn pin_and_offload() {
    let pi = start_pi();
    let local = tempfile::tempdir().unwrap();
    let (home, video) = shelf_with_files(&pi, local.path());
    let e = Engine::open(home, local.path().join("data"), Unlock::Passphrase(PASS)).unwrap();
    let movies = e.view().tree.resolve("Movies").unwrap();
    let reel = e.lookup(e.lookup(ROOT_FILEID, "Movies").unwrap(), "reel.mov").unwrap();

    e.pin(movies).unwrap();
    for _ in 0..100 {
        if e.getattr(reel).unwrap().local >= video.len() as u64 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        e.getattr(reel).unwrap().local >= video.len() as u64,
        "pinned files download"
    );
    assert!(e.is_pinned(&movies));

    // Pinned chunks survive a cache trim down to nothing.
    e.set_cache_cap(0);
    e.trim_cache();
    assert!(e.getattr(reel).unwrap().local >= video.len() as u64);

    let freed = e.offload(&movies);
    assert!(freed >= video.len() as u64);
    assert_eq!(e.getattr(reel).unwrap().local, 0);
    assert!(!e.is_pinned(&movies), "offloading unpins");
}

#[test]
fn auto_offload_drops_unpinned_files_and_keeps_pinned_ones() {
    let pi = start_pi();
    let local = tempfile::tempdir().unwrap();
    let (home, video) = shelf_with_files(&pi, local.path());
    let e = Engine::open(home, local.path().join("data"), Unlock::Passphrase(PASS)).unwrap();
    let movies = e.lookup(ROOT_FILEID, "Movies").unwrap();
    let reel = e.lookup(movies, "reel.mov").unwrap();
    let note = e.lookup(ROOT_FILEID, "note.txt").unwrap();

    // The note is read (cached, unpinned); the video is pinned.
    e.read(note, 0, 10).unwrap();
    assert!(e.getattr(note).unwrap().local > 0);
    e.pin(e.view().tree.resolve("Movies").unwrap()).unwrap();
    for _ in 0..100 {
        if e.getattr(reel).unwrap().local >= video.len() as u64 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Off: nothing happens even when the disk counts as full.
    e.set_auto_offload(false, 100, oshelf_mac::settings::OffloadOrder::Oldest);
    assert_eq!(e.auto_offload(), 0);

    // A 100% threshold means "always low on space".
    e.set_auto_offload(true, 100, oshelf_mac::settings::OffloadOrder::Biggest);
    assert!(e.auto_offload() > 0);
    assert_eq!(e.getattr(note).unwrap().local, 0, "unpinned file offloaded");
    assert!(e.getattr(reel).unwrap().local >= video.len() as u64, "pinned file kept");
}
