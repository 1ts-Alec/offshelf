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

CREATE TABLE IF NOT EXISTS vault (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    hash        BLOB NOT NULL,
    blob        BLOB NOT NULL
);
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

#[derive(Debug, Default, serde::Serialize)]
pub struct Usage {
    pub chunks: u64,
    pub stored_bytes: u64,
    pub objects: u64,
    pub revision: u64,
}

pub struct Inner {
    conn: Connection,
}

#[derive(Clone)]
pub struct Db(Arc<Mutex<Inner>>);

fn now() -> i64 {
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

    pub fn usage(&mut self) -> rusqlite::Result<Usage> {
        let (chunks, stored_bytes): (i64, i64) =
            self.conn
                .query_row("SELECT COUNT(*), COALESCE(SUM(stored_size), 0) FROM chunks", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
        let objects: i64 = self.conn.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
        let (revision, _) = self.head()?;
        Ok(Usage {
            chunks: chunks as u64,
            stored_bytes: stored_bytes as u64,
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
    fn vault_create_then_rewrap() {
        let mut d = db();
        let h1 = d.put_vault(None, b"v1").unwrap().unwrap();
        assert_eq!(d.put_vault(None, b"again"), Ok(None));
        assert_eq!(d.put_vault(Some([0; 32]), b"wrong"), Ok(None));
        let h2 = d.put_vault(Some(h1), b"v2").unwrap().unwrap();
        assert_eq!(d.vault().unwrap(), Some((h2, b"v2".to_vec())));
    }
}
