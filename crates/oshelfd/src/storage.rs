//! Where the shelf lives. The server starts in its home folder
//! (`/var/lib/offshelf`), which is enough to pair the first device. The web
//! app then picks a drive in first-run setup; the server copies its data
//! there, records the choice in `<home>/location` and restarts on it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::AppState;

/// File in the home folder naming the folder the shelf lives in.
const LOCATION_FILE: &str = "location";
/// Folder made on a chosen drive.
pub const SHELF_FOLDER: &str = "offshelf";
/// Where removable and data drives are mounted; the systemd unit lets the
/// server write only here (and in its home).
pub const DRIVE_ROOTS: &[&str] = &["/mnt", "/media", "/run/media", "/srv"];
/// Filesystems that keep POSIX permissions and handle large files.
const GOOD_FS: &[&str] = &["ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs"];
/// Exit code that asks systemd to restart the server on the new location.
pub const RESTART_CODE: i32 = 75;

/// The folder the shelf lives in: the recorded location, else `home`.
pub fn resolve(home: &Path) -> PathBuf {
    std::fs::read_to_string(home.join(LOCATION_FILE))
        .ok()
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home.to_path_buf())
}

/// Whether first-run setup has picked a location yet.
pub fn configured(home: &Path) -> bool {
    home.join(LOCATION_FILE).exists()
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Drive {
    /// Mount point.
    pub path: String,
    /// The folder the shelf would live in on it.
    pub folder: String,
    pub fs: String,
    pub device: String,
    pub total: u64,
    pub free: u64,
    /// The shelf is here now.
    pub current: bool,
    /// Why it can't be used, if it can't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unusable: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Moving {
    pub to: String,
    pub copied: u64,
    pub total: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Shared move state, so the API can report progress.
pub type MoveState = Arc<Mutex<Option<Moving>>>;

pub fn space(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: c is a valid C string and s a zeroed out parameter.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let f = s.f_frsize as u64;
    Some((s.f_bavail as u64 * f, s.f_blocks as u64 * f))
}

/// `/proc/self/mounts` decodes spaces and the like as octal escapes.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            out.push(u8::from_str_radix(&s[i + 1..i + 4], 8).unwrap_or(b'?'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn under_roots(path: &str) -> bool {
    DRIVE_ROOTS
        .iter()
        .any(|r| path == *r || path.starts_with(&format!("{r}/")))
}

/// Drives the shelf could live on: mounted filesystems under the drive
/// roots, plus the disk the home folder is on.
pub fn drives(mounts: &str, home: &Path, current: &Path) -> Vec<Drive> {
    let mut out: Vec<Drive> = Vec::new();
    for line in mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(dev), Some(mp), Some(fs)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let mp = unescape(mp);
        if !under_roots(&mp) || out.iter().any(|d| d.path == mp) {
            continue;
        }
        let folder = Path::new(&mp).join(SHELF_FOLDER);
        let unusable = if GOOD_FS.contains(&fs) {
            None
        } else {
            Some(format!("{fs} can't keep the shelf's permissions; use an ext4 drive"))
        };
        let (free, total) = space(Path::new(&mp)).unwrap_or((0, 0));
        out.push(Drive {
            current: current.starts_with(&folder),
            folder: folder.display().to_string(),
            path: mp,
            fs: fs.into(),
            device: dev.into(),
            total,
            free,
            unusable,
        });
    }
    // The server's own disk (the SD card on a Pi), always listed first.
    let (free, total) = space(home).unwrap_or((0, 0));
    out.insert(
        0,
        Drive {
            path: "/".into(),
            folder: home.display().to_string(),
            fs: "system".into(),
            device: "This server's main disk".into(),
            total,
            free,
            current: current == home,
            unusable: None,
        },
    );
    out
}

/// The usable drive with the most free space, preferring a separate drive
/// over the server's own disk when it has room.
pub fn recommend(drives: &[Drive]) -> Option<String> {
    drives
        .iter()
        .filter(|d| d.unusable.is_none())
        .max_by_key(|d| (d.path != "/", d.free))
        .map(|d| d.path.clone())
}

pub fn list(state: &AppState) -> Vec<Drive> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    drives(&mounts, &state.home, &state.data_dir)
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(_) => e.metadata().map(|m| m.len()).unwrap_or(0),
            Err(_) => 0,
        })
        .sum()
}

/// Copies `from` into `to`, skipping the home's own bookkeeping. Reports
/// bytes copied as it goes.
fn copy_tree(from: &Path, to: &Path, progress: &dyn Fn(u64)) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let name = e.file_name();
        if name == LOCATION_FILE || name == "oshelfd.sock" {
            continue;
        }
        let (src, dst) = (e.path(), to.join(&name));
        if e.file_type()?.is_dir() {
            copy_tree(&src, &dst, progress)?;
        } else {
            let n = std::fs::copy(&src, &dst)?;
            std::fs::File::open(&dst)?.sync_all()?;
            progress(n);
        }
    }
    Ok(())
}

/// Picks `drive` (a mount point from [`list`], or `/` for the main disk),
/// copies the shelf there and records it. Writes are refused meanwhile. The
/// caller restarts the server once this returns `Ok`.
pub async fn move_to(state: &AppState, drive: &str) -> anyhow::Result<PathBuf> {
    let d = list(state)
        .into_iter()
        .find(|d| d.path == drive)
        .ok_or_else(|| anyhow::anyhow!("{drive} isn't one of the drives this server can use"))?;
    if let Some(why) = d.unusable {
        anyhow::bail!(why);
    }
    let target = PathBuf::from(&d.folder);
    if target == state.data_dir {
        // Already there: just record the choice.
        write_location(&state.home, &target)?;
        return Ok(target);
    }
    if target.exists() && std::fs::read_dir(&target)?.next().is_some() {
        anyhow::bail!(
            "{} already has files in it; empty it or pick another drive",
            target.display()
        );
    }
    let need = dir_size(&state.data_dir);
    anyhow::ensure!(d.free > need + (64 << 20), "not enough space on {drive}");

    *state.moving.lock().expect("move lock") = Some(Moving {
        to: target.display().to_string(),
        copied: 0,
        total: need,
        error: None,
    });
    // Fold the write-ahead log into the database so the copy is complete.
    state.db.call(|db| db.checkpoint()).await?;
    let from = state.data_dir.clone();
    let to = target.clone();
    let moving = state.moving.clone();
    let r = tokio::task::spawn_blocking(move || {
        copy_tree(&from, &to, &|n| {
            if let Some(m) = moving.lock().expect("move lock").as_mut() {
                m.copied += n;
            }
        })
    })
    .await?;
    if let Err(e) = r {
        let _ = std::fs::remove_dir_all(&target);
        if let Some(m) = state.moving.lock().expect("move lock").as_mut() {
            m.error = Some(e.to_string());
        }
        anyhow::bail!("copying the shelf failed: {e}");
    }
    write_location(&state.home, &target)?;
    Ok(target)
}

fn write_location(home: &Path, target: &Path) -> std::io::Result<()> {
    let tmp = home.join(".location.tmp");
    std::fs::write(&tmp, format!("{}\n", target.display()))?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(tmp, home.join(LOCATION_FILE))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTS: &str = "\
/dev/mmcblk0p2 / ext4 rw,noatime 0 0
proc /proc proc rw 0 0
/dev/sda4 /mnt/drive-data ext4 rw,noatime 0 0
/dev/sda5 /media/alec/My\\040Disk ntfs3 rw 0 0
tmpfs /run tmpfs rw 0 0
";

    #[test]
    fn lists_drives_under_the_roots() {
        let home = Path::new("/var/lib/offshelf");
        let d = drives(MOUNTS, home, home);
        let paths: Vec<_> = d.iter().map(|d| d.path.as_str()).collect();
        assert_eq!(paths, ["/", "/mnt/drive-data", "/media/alec/My Disk"]);
        assert!(d[0].current);
        assert_eq!(d[1].folder, "/mnt/drive-data/offshelf");
        assert!(d[1].unusable.is_none());
        assert!(d[2].unusable.is_some(), "ntfs can't hold the shelf");

        assert_eq!(recommend(&d).as_deref(), Some("/mnt/drive-data"));

        let d = drives(MOUNTS, home, Path::new("/mnt/drive-data/offshelf"));
        assert!(!d[0].current && d[1].current);
    }

    #[test]
    fn copies_the_shelf_but_not_the_bookkeeping() {
        let from = tempfile::tempdir().unwrap();
        let to = tempfile::tempdir().unwrap();
        std::fs::write(from.path().join("oshelf.db"), b"db").unwrap();
        std::fs::write(from.path().join("location"), b"/x").unwrap();
        std::fs::create_dir_all(from.path().join("chunks/ab")).unwrap();
        std::fs::write(from.path().join("chunks/ab/c1"), vec![7u8; 1000]).unwrap();
        let copied = std::sync::atomic::AtomicU64::new(0);
        let dst = to.path().join("offshelf");
        copy_tree(from.path(), &dst, &|n| {
            copied.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        })
        .unwrap();
        assert_eq!(std::fs::read(dst.join("chunks/ab/c1")).unwrap().len(), 1000);
        assert_eq!(std::fs::read(dst.join("oshelf.db")).unwrap(), b"db");
        assert!(!dst.join("location").exists());
        assert_eq!(copied.into_inner(), 1002);
    }

    #[test]
    fn location_round_trip() {
        let t = tempfile::tempdir().unwrap();
        assert!(!configured(t.path()));
        assert_eq!(resolve(t.path()), t.path());
        write_location(t.path(), Path::new("/mnt/x/offshelf")).unwrap();
        assert!(configured(t.path()));
        assert_eq!(resolve(t.path()), Path::new("/mnt/x/offshelf"));
    }
}
