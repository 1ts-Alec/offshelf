//! The NFSv3 face of the engine. macOS mounts this over loopback; every call
//! runs on Tokio's blocking pool because the engine blocks.

use std::sync::Arc;

use async_trait::async_trait;
use nfsserve::nfs::{
    fattr3, fileid3, filename3, ftype3, nfs_fh3, nfspath3, nfsstat3, nfstime3, sattr3, set_mode3, set_mtime, set_size3,
    specdata3,
};
use nfsserve::vfs::{DirEntry, NFSFileSystem, ReadDirResult, VFSCapabilities};
use oshelf_core::manifest::Kind;

use crate::engine::{now_ns, Attr, Engine, Errno, Res};
use crate::view::ROOT_FILEID;

/// File handles carry this instead of the server start time, so handles
/// Finder holds stay valid across app restarts.
const HANDLE_GENERATION: u64 = 0x4f53_4846_0001;

pub struct ShelfFs {
    engine: Arc<Engine>,
}

impl ShelfFs {
    pub fn new(engine: Arc<Engine>) -> Self {
        Self { engine }
    }

    async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Arc<Engine>) -> Res<T> + Send + 'static,
    ) -> Result<T, nfsstat3> {
        let e = self.engine.clone();
        tokio::task::spawn_blocking(move || f(&e))
            .await
            .map_err(|_| nfsstat3::NFS3ERR_IO)?
            .map_err(stat)
    }

    fn fattr(&self, a: Attr) -> fattr3 {
        let time = nfstime3 {
            seconds: (a.mtime_ns.max(0) / 1_000_000_000) as u32,
            nseconds: (a.mtime_ns.max(0) % 1_000_000_000) as u32,
        };
        fattr3 {
            ftype: match a.kind {
                Kind::File => ftype3::NF3REG,
                Kind::Dir => ftype3::NF3DIR,
                Kind::Symlink => ftype3::NF3LNK,
            },
            mode: a.mode,
            nlink: if a.kind == Kind::Dir { 2 } else { 1 },
            uid: self.engine.uid,
            gid: self.engine.gid,
            size: a.size,
            used: a.local,
            rdev: specdata3::default(),
            fsid: 0x4f5348,
            fileid: a.fileid,
            atime: time,
            mtime: time,
            ctime: time,
        }
    }
}

fn stat(e: Errno) -> nfsstat3 {
    match e {
        Errno::NoEnt => nfsstat3::NFS3ERR_NOENT,
        Errno::Exist => nfsstat3::NFS3ERR_EXIST,
        Errno::NotDir => nfsstat3::NFS3ERR_NOTDIR,
        Errno::IsDir => nfsstat3::NFS3ERR_ISDIR,
        Errno::NotEmpty => nfsstat3::NFS3ERR_NOTEMPTY,
        Errno::Inval => nfsstat3::NFS3ERR_INVAL,
        Errno::Stale => nfsstat3::NFS3ERR_STALE,
        Errno::Io => nfsstat3::NFS3ERR_IO,
    }
}

fn name(f: &filename3) -> Result<String, nfsstat3> {
    String::from_utf8(f.0.clone()).map_err(|_| nfsstat3::NFS3ERR_INVAL)
}

fn time_ns(t: &nfstime3) -> i64 {
    i64::from(t.seconds) * 1_000_000_000 + i64::from(t.nseconds)
}

#[async_trait]
impl NFSFileSystem for ShelfFs {
    fn capabilities(&self) -> VFSCapabilities {
        VFSCapabilities::ReadWrite
    }

    fn root_dir(&self) -> fileid3 {
        ROOT_FILEID
    }

    fn id_to_fh(&self, id: fileid3) -> nfs_fh3 {
        let mut data = HANDLE_GENERATION.to_le_bytes().to_vec();
        data.extend_from_slice(&id.to_le_bytes());
        nfs_fh3 { data }
    }

    fn fh_to_id(&self, fh: &nfs_fh3) -> Result<fileid3, nfsstat3> {
        if fh.data.len() != 16 {
            return Err(nfsstat3::NFS3ERR_BADHANDLE);
        }
        if fh.data[..8] != HANDLE_GENERATION.to_le_bytes() {
            return Err(nfsstat3::NFS3ERR_STALE);
        }
        Ok(u64::from_le_bytes(fh.data[8..16].try_into().expect("8 bytes")))
    }

    async fn lookup(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let n = name(filename)?;
        self.run(move |e| e.lookup(dirid, &n)).await
    }

    async fn getattr(&self, id: fileid3) -> Result<fattr3, nfsstat3> {
        let a = self.run(move |e| e.getattr(id)).await?;
        Ok(self.fattr(a))
    }

    async fn setattr(&self, id: fileid3, s: sattr3) -> Result<fattr3, nfsstat3> {
        let size = match s.size {
            set_size3::size(v) => Some(v),
            set_size3::Void => None,
        };
        let mtime = match s.mtime {
            set_mtime::SET_TO_CLIENT_TIME(t) => Some(time_ns(&t)),
            set_mtime::SET_TO_SERVER_TIME => Some(now_ns()),
            set_mtime::DONT_CHANGE => None,
        };
        let mode = match s.mode {
            set_mode3::mode(m) => Some(m),
            set_mode3::Void => None,
        };
        let a = self.run(move |e| e.setattr(id, size, mtime, mode)).await?;
        Ok(self.fattr(a))
    }

    async fn read(&self, id: fileid3, offset: u64, count: u32) -> Result<(Vec<u8>, bool), nfsstat3> {
        self.run(move |e| e.read(id, offset, count)).await
    }

    async fn write(&self, id: fileid3, offset: u64, data: &[u8]) -> Result<fattr3, nfsstat3> {
        let data = data.to_vec();
        let a = self.run(move |e| e.write(id, offset, &data)).await?;
        Ok(self.fattr(a))
    }

    async fn create(&self, dirid: fileid3, filename: &filename3, attr: sattr3) -> Result<(fileid3, fattr3), nfsstat3> {
        let n = name(filename)?;
        let mode = match attr.mode {
            set_mode3::mode(m) => Some(m),
            set_mode3::Void => None,
        };
        let (id, a) = self.run(move |e| e.create(dirid, &n, mode, false)).await?;
        Ok((id, self.fattr(a)))
    }

    async fn create_exclusive(&self, dirid: fileid3, filename: &filename3) -> Result<fileid3, nfsstat3> {
        let n = name(filename)?;
        Ok(self.run(move |e| e.create(dirid, &n, None, true)).await?.0)
    }

    async fn mkdir(&self, dirid: fileid3, dirname: &filename3) -> Result<(fileid3, fattr3), nfsstat3> {
        let n = name(dirname)?;
        let (id, a) = self.run(move |e| e.mkdir(dirid, &n)).await?;
        Ok((id, self.fattr(a)))
    }

    async fn remove(&self, dirid: fileid3, filename: &filename3) -> Result<(), nfsstat3> {
        let n = name(filename)?;
        self.run(move |e| e.remove(dirid, &n)).await
    }

    async fn rename(
        &self,
        from_dirid: fileid3,
        from_filename: &filename3,
        to_dirid: fileid3,
        to_filename: &filename3,
    ) -> Result<(), nfsstat3> {
        let from = name(from_filename)?;
        let to = name(to_filename)?;
        self.run(move |e| e.rename(from_dirid, &from, to_dirid, &to)).await
    }

    async fn readdir(
        &self,
        dirid: fileid3,
        start_after: fileid3,
        max_entries: usize,
    ) -> Result<ReadDirResult, nfsstat3> {
        let all = self.run(move |e| e.readdir(dirid)).await?;
        let skip = if start_after == 0 {
            0
        } else {
            all.iter()
                .position(|(_, a)| a.fileid == start_after)
                .map(|p| p + 1)
                .ok_or(nfsstat3::NFS3ERR_BAD_COOKIE)?
        };
        let rest = &all[skip..];
        let take = rest.len().min(max_entries);
        Ok(ReadDirResult {
            entries: rest[..take]
                .iter()
                .map(|(n, a)| DirEntry {
                    fileid: a.fileid,
                    name: n.as_bytes().to_vec().into(),
                    attr: self.fattr(*a),
                })
                .collect(),
            end: take == rest.len(),
        })
    }

    async fn symlink(
        &self,
        dirid: fileid3,
        linkname: &filename3,
        symlink: &nfspath3,
        _attr: &sattr3,
    ) -> Result<(fileid3, fattr3), nfsstat3> {
        let n = name(linkname)?;
        let target = String::from_utf8(symlink.0.clone()).map_err(|_| nfsstat3::NFS3ERR_INVAL)?;
        let (id, a) = self.run(move |e| e.symlink(dirid, &n, &target)).await?;
        Ok((id, self.fattr(a)))
    }

    async fn readlink(&self, id: fileid3) -> Result<nfspath3, nfsstat3> {
        let t = self.run(move |e| e.readlink(id)).await?;
        Ok(t.into_bytes().into())
    }
}
