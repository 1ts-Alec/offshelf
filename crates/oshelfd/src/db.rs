//! SQLite metadata. Everything here is opaque to the server: random object
//! ids, chunk ids, and sealed manifest blobs.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

pub type Id32 = [u8; 32];
pub type Id16 = [u8; 16];

/// Hash reported for revision 0, before any log entry exists.
pub const GENESIS_HASH: Id32 = [0; 32];

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chunks (
    id          BLOB PRIMARY KEY,
    stored_size INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS objects (
    id          BLOB PRIMARY KEY,
    chunk_count INTEGER NOT NULL,
    created_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS object_chunks (
    object_id   BLOB NOT NULL REFERENCES objects(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    chunk_id    BLOB NOT NULL REFERENCES chunks(id),
    PRIMARY KEY (object_id, chunk_index)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS object_chunks_by_chunk ON object_chunks(chunk_id);

CREATE TABLE IF NOT EXISTS manifest_log (
    revision    INTEGER PRIMARY KEY,
    hash        BLOB NOT NULL,
    blob        BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    revision    INTEGER PRIMARY KEY,
    object_id   BLOB NOT NULL REFERENCES objects(id),
    hash        BLOB NOT NULL,
    blob        BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id          BLOB PRIMARY KEY,
    name        TEXT NOT NULL,
    pubkey      BLOB NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS pairing_codes (
    code          TEXT PRIMARY KEY,
    expires_at    INTEGER NOT NULL,
    attempts_left INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS vault (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    hash        BLOB NOT NULL,
    blob        BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS sealed_settings (
    name        TEXT PRIMARY KEY,
    hash        BLOB NOT NULL,
    blob        BLOB NOT NULL
) WITHOUT ROWID;
"#;

#[derive(Debug, PartialEq, Eq)]
pub enum CommitResult {
    Committed { revision: u64, hash: Id32 },
    Stale { revision: u64, hash: Id32 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ObjectResult {
    Created,
    AlreadyExists,
    MissingChunks(Vec<Id32>),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Device {
    #[serde(serialize_with = "hex_ser")]
    pub id: Id16,
    pub name: String,
    pub created_at: i64,
}

fn hex_ser<S: serde::Serializer>(v: &Id16, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}

#[derive(Debug, PartialEq, Eq)]
pub enum SnapshotResult {
    Stored {
        hash: Id32,
    },
    /// Not newer than the latest snapshot, or past the head.
    BadRevision {
        latest_snapshot: u64,
        head: u64,
    },
    MissingObject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub revision: u64,
    pub object_id: Id16,
    pub hash: Id32,
    pub blob: Vec<u8>,
}

/// Snapshots the Pi keeps; the log is kept from the oldest of them onward.
pub const SNAPSHOTS_KEPT: usize = 2;

#[derive(Debug, Default, serde::Serialize)]
pub struct Usage {
    pub chunks: u64,
    pub stored_bytes: u64,
    /// Chunks no file version references: what the next gc frees.
    pub unreferenced_bytes: u64,
    pub objects: u64,
    pub revision: u64,
}

pub struct Inner {
    conn: Connection,
}

#[derive(Clone)]
pub struct Db(Arc<Mutex<Inner>>);

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn to32(v: Vec<u8>) -> Id32 {
    v.try_into().expect("ids in the db are 32 bytes")
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        Self::from_conn(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> rusqlite::Result<Self> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self(Arc::new(Mutex::new(Inner { conn }))))
    }

    /// Runs `f` on the blocking pool with the connection locked.
    pub async fn call<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Inner) -> rusqlite::Result<T> + Send + 'static,
    {
        let db = self.0.clone();
        let out = tokio::task::spawn_blocking(move || {
            let mut guard = db.lock().unwrap_or_else(|p| p.into_inner());
            f(&mut guard)
        })
        .await??;
        Ok(out)
    }
}

impl Inner {
    pub fn insert_chunk(&mut self, id: &Id32, stored_size: u64) -> rusqlite::Result<bool> {
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO chunks (id, stored_size, created_at) VALUES (?1, ?2, ?3)",
            params![&id[..], stored_size as i64, now()],
        )?;
        Ok(n == 1)
    }

    pub fn has_chunk(&mut self, id: &Id32) -> rusqlite::Result<bool> {
        self.conn
            .query_row("SELECT 1 FROM chunks WHERE id = ?1", [&id[..]], |_| Ok(()))
            .optional()
            .map(|r| r.is_some())
    }

    pub fn delete_chunk(&mut self, id: &Id32) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM chunks WHERE id = ?1", [&id[..]])?;
        Ok(())
    }

    /// Registers one file version. Every chunk must already be uploaded.
    pub fn insert_object(&mut self, object_id: &Id16, chunks: &[Id32]) -> rusqlite::Result<ObjectResult> {
        let tx = self.conn.transaction()?;
        let exists = tx
            .query_row("SELECT 1 FROM objects WHERE id = ?1", [&object_id[..]], |_| Ok(()))
            .optional()?
            .is_some();
        if exists {
            return Ok(ObjectResult::AlreadyExists);
        }
        let mut missing = Vec::new();
        {
            let mut q = tx.prepare_cached("SELECT 1 FROM chunks WHERE id = ?1")?;
            for c in chunks {
                if q.query_row([&c[..]], |_| Ok(())).optional()?.is_none() && !missing.contains(c) {
                    missing.push(*c);
                }
            }
        }
        if !missing.is_empty() {
            return Ok(ObjectResult::MissingChunks(missing));
        }
        tx.execute(
            "INSERT INTO objects (id, chunk_count, created_at) VALUES (?1, ?2, ?3)",
            params![&object_id[..], chunks.len() as i64, now()],
        )?;
        {
            let mut ins =
                tx.prepare_cached("INSERT INTO object_chunks (object_id, chunk_index, chunk_id) VALUES (?1, ?2, ?3)")?;
            for (i, c) in chunks.iter().enumerate() {
                ins.execute(params![&object_id[..], i as i64, &c[..]])?;
            }
        }
        tx.commit()?;
        Ok(ObjectResult::Created)
    }

    pub fn object_chunk_count(&mut self, object_id: &Id16) -> rusqlite::Result<Option<u64>> {
        self.conn
            .query_row("SELECT chunk_count FROM objects WHERE id = ?1", [&object_id[..]], |r| {
                r.get::<_, i64>(0)
            })
            .optional()
            .map(|o| o.map(|n| n as u64))
    }

    /// Chunk ids at positions `first..=last` of an object.
    pub fn object_chunks(&mut self, object_id: &Id16, first: u64, last: u64) -> rusqlite::Result<Vec<Id32>> {
        let mut q = self.conn.prepare_cached(
            "SELECT chunk_id FROM object_chunks WHERE object_id = ?1 AND chunk_index BETWEEN ?2 AND ?3 ORDER BY chunk_index",
        )?;
        let rows = q.query_map(params![&object_id[..], first as i64, last as i64], |r| {
            r.get::<_, Vec<u8>>(0)
        })?;
        rows.map(|r| r.map(to32)).collect()
    }

    pub fn delete_object(&mut self, object_id: &Id16) -> rusqlite::Result<bool> {
        Ok(self
            .conn
            .execute("DELETE FROM objects WHERE id = ?1", [&object_id[..]])?
            == 1)
    }

    pub fn head(&mut self) -> rusqlite::Result<(u64, Id32)> {
        let row = self
            .conn
            .query_row(
                "SELECT revision, hash FROM manifest_log ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, to32(r.get(1)?))),
            )
            .optional()?;
        Ok(row.unwrap_or((0, GENESIS_HASH)))
    }

    /// Appends a sealed log entry if the client built it on the current head.
    pub fn append_log(&mut self, expected_head: u64, blob: &[u8]) -> rusqlite::Result<CommitResult> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (revision, hash) = tx
            .query_row(
                "SELECT revision, hash FROM manifest_log ORDER BY revision DESC LIMIT 1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, to32(r.get(1)?))),
            )
            .optional()?
            .unwrap_or((0, GENESIS_HASH));
        if revision != expected_head {
            return Ok(CommitResult::Stale { revision, hash });
        }
        let new_rev = revision + 1;
        let new_hash = *blake3::hash(blob).as_bytes();
        tx.execute(
            "INSERT INTO manifest_log (revision, hash, blob, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![new_rev as i64, &new_hash[..], blob, now()],
        )?;
        tx.commit()?;
        Ok(CommitResult::Committed {
            revision: new_rev,
            hash: new_hash,
        })
    }

    /// Sealed entries with revision greater than `since`, oldest first.
    pub fn log_since(&mut self, since: u64, limit: u32) -> rusqlite::Result<Vec<(u64, Vec<u8>)>> {
        let mut q = self
            .conn
            .prepare_cached("SELECT revision, blob FROM manifest_log WHERE revision > ?1 ORDER BY revision LIMIT ?2")?;
        let rows = q.query_map(params![since as i64, limit], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get(1)?))
        })?;
        rows.collect()
    }

    pub fn vault(&mut self) -> rusqlite::Result<Option<(Id32, Vec<u8>)>> {
        self.conn
            .query_row("SELECT hash, blob FROM vault WHERE id = 1", [], |r| {
                Ok((to32(r.get(0)?), r.get(1)?))
            })
            .optional()
    }

    /// Stores the vault header. `expected` is the hash of the current header,
    /// or `None` when creating it. Returns `None` if that doesn't match.
    pub fn put_vault(&mut self, expected: Option<Id32>, blob: &[u8]) -> rusqlite::Result<Option<Id32>> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<Vec<u8>> = tx
            .query_row("SELECT hash FROM vault WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        if current.map(to32) != expected {
            return Ok(None);
        }
        let hash = *blake3::hash(blob).as_bytes();
        tx.execute(
            "INSERT INTO vault (id, hash, blob) VALUES (1, ?1, ?2)
             ON CONFLICT(id) DO UPDATE SET hash = excluded.hash, blob = excluded.blob",
            params![&hash[..], blob],
        )?;
        tx.commit()?;
        Ok(Some(hash))
    }

    /// A sealed setting blob (the shared host list) and its hash.
    pub fn setting(&mut self, name: &str) -> rusqlite::Result<Option<(Id32, Vec<u8>)>> {
        self.conn
            .query_row("SELECT hash, blob FROM sealed_settings WHERE name = ?1", [name], |r| {
                Ok((to32(r.get(0)?), r.get(1)?))
            })
            .optional()
    }

    /// Replaces a sealed setting if `expected` is the current hash (`None`
    /// when there is none yet). Returns the new hash, or `None` on a race.
    pub fn put_setting(&mut self, name: &str, expected: Option<Id32>, blob: &[u8]) -> rusqlite::Result<Option<Id32>> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<Vec<u8>> = tx
            .query_row("SELECT hash FROM sealed_settings WHERE name = ?1", [name], |r| r.get(0))
            .optional()?;
        if current.map(to32) != expected {
            return Ok(None);
        }
        let hash = *blake3::hash(blob).as_bytes();
        tx.execute(
            "INSERT INTO sealed_settings (name, hash, blob) VALUES (?1, ?2, ?3)
             ON CONFLICT(name) DO UPDATE SET hash = excluded.hash, blob = excluded.blob",
            params![name, &hash[..], blob],
        )?;
        tx.commit()?;
        Ok(Some(hash))
    }

    pub fn delete_pairing_code(&mut self, code: &str) -> rusqlite::Result<bool> {
        Ok(self.conn.execute("DELETE FROM pairing_codes WHERE code = ?1", [code])? > 0)
    }

    /// Folds the write-ahead log into the main file (before copying it).
    /// Writes a consistent copy of the database to `path`, which must not
    /// exist yet. Safe while the server keeps running, unlike copying the
    /// file (and its -wal and -shm) byte by byte.
    pub fn snapshot_to(&mut self, path: &Path) -> rusqlite::Result<()> {
        let path = path
            .to_str()
            .ok_or_else(|| rusqlite::Error::InvalidPath(path.to_path_buf()))?;
        self.conn.execute("VACUUM INTO ?1", [path])?;
        Ok(())
    }

    pub fn usage(&mut self) -> rusqlite::Result<Usage> {
        let (chunks, stored_bytes): (i64, i64) =
            self.conn
                .query_row("SELECT COUNT(*), COALESCE(SUM(stored_size), 0) FROM chunks", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        let objects: i64 = self.conn.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
        let unreferenced_bytes: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(c.stored_size), 0) FROM chunks c
             WHERE NOT EXISTS (SELECT 1 FROM object_chunks oc WHERE oc.chunk_id = c.id)",
            [],
            |r| r.get(0),
        )?;
        let (revision, _) = self.head()?;
        Ok(Usage {
            chunks: chunks as u64,
            stored_bytes: stored_bytes as u64,
            unreferenced_bytes: unreferenced_bytes as u64,
            objects: objects as u64,
            revision,
        })
    }

    /// Chunks referenced by no object and older than `grace_secs`.
    pub fn unreferenced_chunks(&mut self, grace_secs: i64) -> rusqlite::Result<Vec<Id32>> {
        let mut q = self.conn.prepare(
            "SELECT c.id FROM chunks c
             WHERE c.created_at <= ?1
               AND NOT EXISTS (SELECT 1 FROM object_chunks oc WHERE oc.chunk_id = c.id)",
        )?;
        let rows = q.query_map([now() - grace_secs], |r| r.get::<_, Vec<u8>>(0))?;
        rows.map(|r| r.map(to32)).collect()
    }
}

/// Manifest snapshots and log pruning.
impl Inner {
    /// Stores a sealed snapshot header for `revision` whose segments live in
    /// `object_id`. Keeps the newest [`SNAPSHOTS_KEPT`]; older snapshots lose
    /// their object (so gc reclaims the segments) and the log before the
    /// oldest kept snapshot is pruned.
    pub fn put_snapshot(&mut self, revision: u64, object_id: &Id16, blob: &[u8]) -> rusqlite::Result<SnapshotResult> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let head: i64 = tx.query_row("SELECT COALESCE(MAX(revision), 0) FROM manifest_log", [], |r| r.get(0))?;
        let latest: i64 = tx.query_row("SELECT COALESCE(MAX(revision), 0) FROM snapshots", [], |r| r.get(0))?;
        if revision == 0 || revision as i64 <= latest || revision as i64 > head {
            return Ok(SnapshotResult::BadRevision {
                latest_snapshot: latest as u64,
                head: head as u64,
            });
        }
        let has_object = tx
            .query_row("SELECT 1 FROM objects WHERE id = ?1", [&object_id[..]], |_| Ok(()))
            .optional()?
            .is_some();
        if !has_object {
            return Ok(SnapshotResult::MissingObject);
        }
        let hash = *blake3::hash(blob).as_bytes();
        tx.execute(
            "INSERT INTO snapshots (revision, object_id, hash, blob, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![revision as i64, &object_id[..], &hash[..], blob, now()],
        )?;

        let old: Vec<(i64, Vec<u8>)> = {
            let mut q =
                tx.prepare("SELECT revision, object_id FROM snapshots ORDER BY revision DESC LIMIT -1 OFFSET ?1")?;
            let rows = q.query_map([SNAPSHOTS_KEPT as i64], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        for (rev, obj) in &old {
            tx.execute("DELETE FROM snapshots WHERE revision = ?1", [rev])?;
            tx.execute("DELETE FROM objects WHERE id = ?1", [obj])?;
        }
        if !old.is_empty() {
            let oldest_kept: i64 = tx.query_row("SELECT MIN(revision) FROM snapshots", [], |r| r.get(0))?;
            // The head entry always survives: head >= newest snapshot > oldest kept.
            tx.execute("DELETE FROM manifest_log WHERE revision <= ?1", [oldest_kept])?;
        }
        tx.commit()?;
        Ok(SnapshotResult::Stored { hash })
    }

    pub fn latest_snapshot(&mut self) -> rusqlite::Result<Option<Snapshot>> {
        self.conn
            .query_row(
                "SELECT revision, object_id, hash, blob FROM snapshots ORDER BY revision DESC LIMIT 1",
                [],
                |r| {
                    let obj: Vec<u8> = r.get(1)?;
                    Ok(Snapshot {
                        revision: r.get::<_, i64>(0)? as u64,
                        object_id: obj.try_into().expect("object ids are 16 bytes"),
                        hash: to32(r.get(2)?),
                        blob: r.get(3)?,
                    })
                },
            )
            .optional()
    }

    /// Oldest revision still in the log, if any.
    pub fn oldest_log_revision(&mut self) -> rusqlite::Result<Option<u64>> {
        self.conn
            .query_row("SELECT MIN(revision) FROM manifest_log", [], |r| {
                r.get::<_, Option<i64>>(0)
            })
            .map(|o| o.map(|v| v as u64))
    }
}

/// Devices and pairing codes.
impl Inner {
    pub fn add_pairing_code(&mut self, code: &str, ttl_secs: i64, attempts: i64) -> rusqlite::Result<i64> {
        let expires_at = now() + ttl_secs;
        self.conn.execute(
            "INSERT INTO pairing_codes (code, expires_at, attempts_left) VALUES (?1, ?2, ?3)",
            params![code, expires_at, attempts],
        )?;
        Ok(expires_at)
    }

    /// Codes that are neither expired nor out of attempts. Prunes the rest.
    pub fn live_pairing_codes(&mut self) -> rusqlite::Result<Vec<String>> {
        self.conn.execute(
            "DELETE FROM pairing_codes WHERE expires_at < ?1 OR attempts_left <= 0",
            [now()],
        )?;
        let mut q = self.conn.prepare("SELECT code FROM pairing_codes")?;
        let rows = q.query_map([], |r| r.get(0))?;
        rows.collect()
    }

    /// A pairing attempt matched no code: every live code loses an attempt,
    /// so guessing is capped no matter which code an attacker aims at.
    pub fn record_failed_pairing(&mut self) -> rusqlite::Result<()> {
        self.conn
            .execute("UPDATE pairing_codes SET attempts_left = attempts_left - 1", [])?;
        Ok(())
    }

    /// Uses up `code` and registers the device in one transaction.
    pub fn pair_device(&mut self, code: &str, id: &Id16, name: &str, pubkey: &[u8; 32]) -> rusqlite::Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if tx.execute(
            "DELETE FROM pairing_codes WHERE code = ?1 AND expires_at >= ?2",
            params![code, now()],
        )? != 1
        {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO devices (id, name, pubkey, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![&id[..], name, &pubkey[..], now()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn device_pubkey(&mut self, id: &Id16) -> rusqlite::Result<Option<[u8; 32]>> {
        self.conn
            .query_row("SELECT pubkey FROM devices WHERE id = ?1", [&id[..]], |r| {
                r.get::<_, Vec<u8>>(0)
            })
            .optional()
            .map(|o| o.and_then(|v| v.try_into().ok()))
    }

    pub fn devices(&mut self) -> rusqlite::Result<Vec<Device>> {
        let mut q = self
            .conn
            .prepare("SELECT id, name, created_at FROM devices ORDER BY created_at")?;
        let rows = q.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            Ok(Device {
                id: id.try_into().expect("device ids are 16 bytes"),
                name: r.get(1)?,
                created_at: r.get(2)?,
            })
        })?;
        rows.collect()
    }

    pub fn revoke_device(&mut self, id: &Id16) -> rusqlite::Result<bool> {
        Ok(self.conn.execute("DELETE FROM devices WHERE id = ?1", [&id[..]])? == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Inner {
        let Db(arc) = Db::open_in_memory().unwrap();
        Arc::try_unwrap(arc).ok().unwrap().into_inner().unwrap()
    }

    #[test]
    fn log_compare_and_swap() {
        let mut d = db();
        assert_eq!(d.head().unwrap(), (0, GENESIS_HASH));
        let CommitResult::Committed { revision, hash } = d.append_log(0, b"one").unwrap() else {
            panic!()
        };
        assert_eq!(revision, 1);
        assert_eq!(hash, *blake3::hash(b"one").as_bytes());
        assert_eq!(
            d.append_log(0, b"late").unwrap(),
            CommitResult::Stale { revision: 1, hash }
        );
        d.append_log(1, b"two").unwrap();
        assert_eq!(
            d.log_since(0, 10).unwrap(),
            vec![(1, b"one".to_vec()), (2, b"two".to_vec())]
        );
        assert_eq!(d.log_since(1, 10).unwrap(), vec![(2, b"two".to_vec())]);
    }

    #[test]
    fn objects_need_chunks_and_gc_finds_orphans() {
        let mut d = db();
        let (a, b) = ([1u8; 32], [2u8; 32]);
        d.insert_chunk(&a, 100).unwrap();
        assert_eq!(
            d.insert_object(&[9; 16], &[a, b]).unwrap(),
            ObjectResult::MissingChunks(vec![b])
        );
        d.insert_chunk(&b, 100).unwrap();
        assert_eq!(d.insert_object(&[9; 16], &[a, b, a]).unwrap(), ObjectResult::Created);
        assert_eq!(d.insert_object(&[9; 16], &[a]).unwrap(), ObjectResult::AlreadyExists);
        assert_eq!(d.object_chunks(&[9; 16], 1, 2).unwrap(), vec![b, a]);
        assert!(d.unreferenced_chunks(0).unwrap().is_empty());
        assert!(d.delete_object(&[9; 16]).unwrap());
        let mut orphans = d.unreferenced_chunks(0).unwrap();
        orphans.sort();
        assert_eq!(orphans, vec![a, b]);
        assert!(d.unreferenced_chunks(3600).unwrap().is_empty());
    }

    #[test]
    fn sealed_settings_compare_and_swap() {
        let mut d = db();
        assert_eq!(d.setting("hosts").unwrap(), None);
        let h1 = d.put_setting("hosts", None, b"a").unwrap().unwrap();
        assert_eq!(d.put_setting("hosts", None, b"b"), Ok(None));
        let h2 = d.put_setting("hosts", Some(h1), b"b").unwrap().unwrap();
        assert_eq!(d.setting("hosts").unwrap(), Some((h2, b"b".to_vec())));
    }

    #[test]
    fn vault_create_then_rewrap() {
        let mut d = db();
        let h1 = d.put_vault(None, b"v1").unwrap().unwrap();
        assert_eq!(d.put_vault(None, b"again"), Ok(None));
        assert_eq!(d.put_vault(Some([0; 32]), b"wrong"), Ok(None));
        let h2 = d.put_vault(Some(h1), b"v2").unwrap().unwrap();
        assert_eq!(d.vault().unwrap(), Some((h2, b"v2".to_vec())));
    }

    #[test]
    fn pairing_codes_are_single_use_and_attempt_limited() {
        let mut d = db();
        d.add_pairing_code("AAAABBBB", 600, 2).unwrap();
        d.add_pairing_code("CCCCDDDD", -1, 5).unwrap();
        assert_eq!(d.live_pairing_codes().unwrap(), vec!["AAAABBBB".to_string()]);
        assert!(d.pair_device("AAAABBBB", &[1; 16], "Mac", &[7; 32]).unwrap());
        assert!(!d.pair_device("AAAABBBB", &[2; 16], "Again", &[8; 32]).unwrap());
        assert_eq!(d.device_pubkey(&[1; 16]).unwrap(), Some([7; 32]));

        d.add_pairing_code("EEEEFFFF", 600, 2).unwrap();
        d.record_failed_pairing().unwrap();
        assert_eq!(d.live_pairing_codes().unwrap().len(), 1);
        d.record_failed_pairing().unwrap();
        assert!(d.live_pairing_codes().unwrap().is_empty());

        assert!(d.revoke_device(&[1; 16]).unwrap());
        assert_eq!(d.device_pubkey(&[1; 16]).unwrap(), None);
    }

    #[test]
    fn snapshots_keep_two_and_prune_the_log() {
        let mut d = db();
        for i in 0..10u64 {
            d.append_log(i, format!("OSL1{i}").as_bytes()).unwrap();
        }
        d.insert_chunk(&[1; 32], 10).unwrap();
        for obj in [[1u8; 16], [2; 16], [3; 16]] {
            d.insert_object(&obj, &[[1; 32]]).unwrap();
        }
        assert_eq!(
            d.put_snapshot(3, &[9; 16], b"x").unwrap(),
            SnapshotResult::MissingObject
        );
        assert!(matches!(
            d.put_snapshot(11, &[1; 16], b"x").unwrap(),
            SnapshotResult::BadRevision { head: 10, .. }
        ));
        assert!(matches!(
            d.put_snapshot(3, &[1; 16], b"s3").unwrap(),
            SnapshotResult::Stored { .. }
        ));
        assert!(matches!(
            d.put_snapshot(3, &[2; 16], b"again").unwrap(),
            SnapshotResult::BadRevision { latest_snapshot: 3, .. }
        ));
        d.put_snapshot(6, &[2; 16], b"s6").unwrap();
        assert_eq!(
            d.oldest_log_revision().unwrap(),
            Some(1),
            "nothing pruned with two snapshots"
        );
        d.put_snapshot(8, &[3; 16], b"s8").unwrap();

        let latest = d.latest_snapshot().unwrap().unwrap();
        assert_eq!(
            (latest.revision, latest.object_id, latest.blob),
            (8, [3; 16], b"s8".to_vec())
        );
        assert_eq!(
            d.oldest_log_revision().unwrap(),
            Some(7),
            "log kept after the oldest kept snapshot (6)"
        );
        assert_eq!(d.head().unwrap().0, 10);
        assert_eq!(
            d.object_chunk_count(&[1; 16]).unwrap(),
            None,
            "dropped snapshot's object is gone"
        );
        assert!(d.object_chunk_count(&[2; 16]).unwrap().is_some());
    }
}
