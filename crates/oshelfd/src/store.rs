//! Content addressed chunk files on the SSD: `chunks/ab/cd/<64 hex>`.

use std::io::{ErrorKind, Write};
use std::path::PathBuf;

pub struct ChunkStore {
    root: PathBuf,
}

impl ChunkStore {
    pub fn open(root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(root.join("tmp"))?;
        Ok(Self { root })
    }

    fn path(&self, id: &[u8; 32]) -> PathBuf {
        let h = hex::encode(id);
        self.root.join(&h[0..2]).join(&h[2..4]).join(h)
    }

    /// Writes a chunk atomically (temp file, fsync, rename). Writing an id
    /// that already exists is a no-op, since the bytes are identical.
    pub async fn put(&self, id: &[u8; 32], bytes: bytes::Bytes) -> std::io::Result<()> {
        let dest = self.path(id);
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.{}", hex::encode(id), rand::random::<u64>()));
        tokio::task::spawn_blocking(move || {
            if dest.exists() {
                return Ok(());
            }
            std::fs::create_dir_all(dest.parent().expect("chunk path has a parent"))?;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &dest)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn get(&self, id: &[u8; 32]) -> std::io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(id)).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub async fn delete(&self, id: &[u8; 32]) -> std::io::Result<()> {
        match tokio::fs::remove_file(self.path(id)).await {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}
