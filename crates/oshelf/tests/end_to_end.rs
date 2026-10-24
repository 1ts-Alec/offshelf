//! Runs the real client against a real oshelfd on localhost.

use std::path::Path;

use oshelf::config::Home;
use oshelf::shelf::{self, Shelf, Unlock};
use oshelf_core::manifest::{Kind, ROOT};
use oshelf_core::vault::Kdf;

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

fn fast_kdf() -> Kdf {
    Kdf {
        m_kib: 1024,
        t: 1,
        ..Kdf::new_default()
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn full_flow_across_two_devices() {
    let pi = start_pi();
    let local = tempfile::tempdir().unwrap();

    // Device A pairs, creates the shelf, uploads.
    let home_a = Home::open(local.path().join("a"));
    let cfg_a = shelf::pair(&home_a, &pi.url, &pi.code(), "MacBook").unwrap();
    assert!(
        shelf::pair(&home_a, &pi.url, &pi.code(), "again").is_err(),
        "already paired"
    );
    let (_, client_a) = shelf::connect(&home_a).unwrap();
    let words = shelf::init(&client_a, "correct horse", fast_kdf()).unwrap();
    assert!(shelf::init(&client_a, "x", fast_kdf()).is_err(), "only once");

    let big: Vec<u8> = (0..(1 << 20) * 2 + 12345).map(|i| (i * 7 % 256) as u8).collect();
    let src = local.path().join("src");
    write(&src, "Photos/cat.jpg", &big);
    write(&src, "Photos/raw/dog.raw", b"woof");
    let notes = write(&src, "notes.txt", b"v1");

    {
        let mut a = Shelf::open(&home_a, &cfg_a, &client_a, Unlock::Passphrase("correct horse")).unwrap();
        assert!(Shelf::open(&home_a, &cfg_a, &client_a, Unlock::Passphrase("wrong")).is_err());
        let up = a.put(&src.join("Photos"), "").unwrap();
        assert_eq!(up.len(), 2);
        a.put(&notes, "").unwrap();
        std::fs::write(&notes, b"version two").unwrap();
        a.put(&notes, "").unwrap();

        let names: Vec<_> = a.tree.list(&ROOT).iter().map(|n| n.name.clone()).collect();
        assert_eq!(names, vec!["Photos", "notes.txt"]);
        let mut out = Vec::new();
        let n = a.node("notes.txt").unwrap().clone();
        a.read_file(&n, &mut out).unwrap();
        assert_eq!(out, b"version two", "edit replaced the content");

        a.mkdir("Docs/2026").unwrap();
        a.mv("notes.txt", "Docs/2026").unwrap();
        a.mv("Docs/2026/notes.txt", "Docs/2026/todo.txt").unwrap();
        assert!(a.mv("Docs", "Docs/2026").is_err(), "no folder into itself");
        a.rm("Photos/raw").unwrap();
        assert_eq!(a.compact().unwrap(), a.chain.revision);
    }

    // Device B pairs from a code made on A, unlocks with the recovery words,
    // and sees the same tree (loaded from the snapshot).
    let code_b = client_a
        .post("/v1/pairing-codes", &[], &[])
        .unwrap()
        .ok()
        .unwrap()
        .json()
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string();
    let home_b = Home::open(local.path().join("b"));
    let cfg_b = shelf::pair(&home_b, &pi.url, &code_b, "Pi box").unwrap();
    let (_, client_b) = shelf::connect(&home_b).unwrap();
    let b = Shelf::open(&home_b, &cfg_b, &client_b, Unlock::Recovery(&words)).unwrap();
    assert!(b.tree.resolve("Docs/2026/todo.txt").is_some());
    assert_eq!(b.tree.resolve("Photos/raw"), None);

    let out = local.path().join("export");
    assert_eq!(b.export(&out).unwrap(), 2);
    assert_eq!(std::fs::read(out.join("Photos/cat.jpg")).unwrap(), big);
    assert_eq!(std::fs::read(out.join("Docs/2026/todo.txt")).unwrap(), b"version two");

    // Both devices write the same new path from the same starting point:
    // the second one keeps the first one's file and saves a conflict copy.
    let mut a = Shelf::open(&home_a, &cfg_a, &client_a, Unlock::Passphrase("correct horse")).unwrap();
    let mut b = b;
    let from_a = write(&src, "a/plan.md", b"from A");
    let from_b = write(&src, "b/plan.md", b"from B");
    a.put(&from_a, "Docs").unwrap();
    let up = b.put(&from_b, "Docs").unwrap();
    assert_eq!(up[0].path, "Docs/plan (conflict, Pi box).md");
    let mut got = Vec::new();
    let n = b.node("Docs/plan.md").unwrap().clone();
    b.read_file(&n, &mut got).unwrap();
    assert_eq!(got, b"from A");

    // Passphrase change: old one stops working, recovery still does.
    shelf::change_passphrase(&client_a, Unlock::Passphrase("correct horse"), "battery staple").unwrap();
    assert!(Shelf::open(&home_a, &cfg_a, &client_a, Unlock::Passphrase("correct horse")).is_err());
    let a2 = Shelf::open(&home_a, &cfg_a, &client_a, Unlock::Passphrase("battery staple")).unwrap();
    assert_eq!(a2.tree.walk(&ROOT).iter().filter(|n| n.kind == Kind::File).count(), 4);

    // Revoked devices are locked out.
    client_a
        .delete(&format!("/v1/devices/{}", cfg_b.device_id))
        .unwrap()
        .ok()
        .unwrap();
    assert!(client_b.get("/v1/usage").is_err());
}

#[test]
fn rollback_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::open(dir.path().to_path_buf());
    home.advance_seen(5, "aa").unwrap();
    home.advance_seen(6, "bb").unwrap();
    assert!(home.advance_seen(4, "cc").is_err(), "older revision");
    assert!(home.advance_seen(6, "zz").is_err(), "same revision, different hash");
    home.advance_seen(6, "bb").unwrap();
}
