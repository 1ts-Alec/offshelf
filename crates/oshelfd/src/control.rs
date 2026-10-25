//! A local control socket, so `oshelfd pair` and `oshelfd devices` work for
//! any user on the Pi without sudo. The running server owns the database;
//! the CLI asks it over a Unix socket instead of opening the files itself.
//!
//! The socket is reachable by every local account on purpose (a Pi usually
//! has one person on it). It only mints pairing codes and lists device
//! names. A code alone can't read anything: the shelf still needs the
//! passphrase.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::AppState;

/// Made by the systemd unit (`RuntimeDirectory=offshelf`).
pub const RUN_DIR: &str = "/run/offshelf";

/// `$OSHELF_SOCKET`, else `/run/offshelf/oshelfd.sock` when that folder
/// exists, else `oshelfd.sock` in the data folder (development).
pub fn socket_path(data_dir: &Path) -> PathBuf {
    if let Some(p) = std::env::var_os("OSHELF_SOCKET") {
        return PathBuf::from(p);
    }
    let run = Path::new(RUN_DIR);
    if run.is_dir() {
        return run.join("oshelfd.sock");
    }
    data_dir.join("oshelfd.sock")
}

/// Answers control requests until the process exits.
pub async fn serve(state: AppState, path: PathBuf) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    tracing::info!(socket = %path.display(), "control socket ready");
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(state, stream).await {
                tracing::warn!("control request failed: {e}");
            }
        });
    }
}

async fn handle(state: AppState, stream: UnixStream) -> anyhow::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    BufReader::new(read).read_line(&mut line).await?;
    let reply = match run(&state, line.trim()).await {
        Ok(body) => body,
        Err(e) => format!("error: {e:#}\n"),
    };
    write.write_all(reply.as_bytes()).await?;
    Ok(())
}

/// Runs one command against the open state. Shared by the socket and the
/// direct (root) path, so both print the same thing.
pub async fn run(state: &AppState, command: &str) -> anyhow::Result<String> {
    match command {
        "pair" => {
            let code = crate::auth::new_pairing_code();
            let c = code.clone();
            state
                .db
                .call(move |db| db.add_pairing_code(&c, crate::auth::PAIRING_TTL_SECS, crate::auth::PAIRING_ATTEMPTS))
                .await?;
            Ok(format!("{}\n", crate::auth::display_code(&code)))
        }
        "devices" => Ok(state
            .db
            .call(|db| db.devices())
            .await?
            .into_iter()
            .map(|d| format!("{}  {}\n", hex::encode(d.id), d.name))
            .collect()),
        other => anyhow::bail!("unknown command {other:?}"),
    }
}

/// Asks the running server. `Ok(None)` means no server is listening.
pub async fn ask(path: &Path, command: &str) -> anyhow::Result<Option<String>> {
    let mut stream = match UnixStream::connect(path).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    stream.write_all(format!("{command}\n").as_bytes()).await?;
    stream.shutdown().await?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply).await?;
    if let Some(msg) = reply.strip_prefix("error: ") {
        anyhow::bail!("{}", msg.trim());
    }
    Ok(Some(reply))
}
