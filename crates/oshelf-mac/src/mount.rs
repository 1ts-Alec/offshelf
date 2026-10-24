//! Serving the engine over loopback NFS and mounting it with the system's
//! own NFS client: no kernel extension, nothing to install.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{bail, Context};
use nfsserve::tcp::{NFSTcp, NFSTcpListener};

use crate::engine::Engine;
use crate::nfs::ShelfFs;

/// A running loopback server. Dropping it does not unmount; call
/// [`Served::unmount`].
pub struct Served {
    pub port: u16,
    pub mountpoint: Option<PathBuf>,
    rt: tokio::runtime::Runtime,
}

/// Starts the NFS server on 127.0.0.1 on a free port.
pub fn serve(engine: Arc<Engine>) -> anyhow::Result<Served> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(64)
        .enable_all()
        .thread_name("oshelf-nfs")
        .build()?;
    let listener = rt.block_on(NFSTcpListener::bind("127.0.0.1:0", ShelfFs::new(engine)))?;
    let port = listener.get_listen_port();
    rt.spawn(async move {
        if let Err(e) = listener.handle_forever().await {
            tracing::error!("nfs server stopped: {e}");
        }
    });
    tracing::info!("nfs server on 127.0.0.1:{port}");
    Ok(Served {
        port,
        mountpoint: None,
        rt,
    })
}

/// Mount options tuned for streaming: big reads, short attribute caching
/// (the tree is live), soft so a dead link returns an error instead of
/// hanging Finder.
pub fn mount_options(port: u16) -> String {
    format!(
        "nolocks,locallocks,vers=3,tcp,port={port},mountport={port},rsize=1048576,wsize=1048576,readahead=16,soft,intr,timeo=100,retrans=3,actimeo=2,noquota,nobrowse"
    )
}

impl Served {
    /// Mounts at `at` (created if missing) with the system NFS client.
    pub fn mount(&mut self, at: &Path, name: &str) -> anyhow::Result<()> {
        std::fs::create_dir_all(at).with_context(|| format!("create {}", at.display()))?;
        if is_mounted(at) {
            unmount(at, true)?;
        }
        // Without nobrowse Finder lists it under Locations like a disk.
        let opts = mount_options(self.port).replace(",nobrowse", "");
        let out = Command::new("/sbin/mount_nfs")
            .args(["-o", &opts, &format!("127.0.0.1:/{name}")])
            .arg(at)
            .output()
            .context("run mount_nfs")?;
        if !out.status.success() {
            bail!("mount_nfs failed: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        self.mountpoint = Some(at.to_path_buf());
        Ok(())
    }

    pub fn unmount(&mut self, force: bool) -> anyhow::Result<()> {
        if let Some(at) = self.mountpoint.take() {
            unmount(&at, force)?;
        }
        Ok(())
    }

    pub fn runtime(&self) -> &tokio::runtime::Runtime {
        &self.rt
    }
}

pub fn is_mounted(at: &Path) -> bool {
    let Ok(out) = Command::new("/sbin/mount").output() else {
        return false;
    };
    let needle = format!(" on {} (", at.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.contains(&needle))
}

pub fn unmount(at: &Path, force: bool) -> anyhow::Result<()> {
    let mut cmd = Command::new("/sbin/umount");
    if force {
        cmd.arg("-f");
    }
    let out = cmd.arg(at).output().context("run umount")?;
    if !out.status.success() && is_mounted(at) {
        bail!("umount failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
