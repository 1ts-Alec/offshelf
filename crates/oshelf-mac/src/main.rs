//! `oshelf-mount`: the engine without the app, for development. Uses the
//! device the `oshelf` CLI paired (`~/.config/oshelf` or `OSHELF_HOME`).

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use oshelf::config::Home;
use oshelf::shelf::Unlock;
use oshelf_mac::engine::human;
use oshelf_mac::{mount, Engine};

#[derive(Parser)]
#[command(about = "Mount an Offshelf shelf over loopback NFS")]
struct Cli {
    /// Where to mount.
    #[arg(long, default_value = "~/OffshelfMount")]
    at: String,
    /// Cache, staging and settings.
    #[arg(long, env = "OSHELF_DATA", default_value = "~/Library/Application Support/Offshelf")]
    data: String,
    /// Serve only; print the mount command instead of mounting.
    #[arg(long)]
    no_mount: bool,
}

fn expand(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rest),
        None => PathBuf::from(p),
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "oshelf_mac=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let pass = match std::env::var("OSHELF_PASSPHRASE") {
        Ok(p) => p,
        Err(_) => rpassword::prompt_password("Passphrase: ")?,
    };
    let home = Home::open(Home::default_dir()?);
    let engine = Engine::open(home, expand(&cli.data), Unlock::Passphrase(&pass))?;
    engine.spawn_sync();
    engine.spawn_uploader();
    let mut served = mount::serve(engine.clone())?;
    let at = expand(&cli.at);
    if cli.no_mount {
        println!(
            "mount_nfs -o {} 127.0.0.1:/ {}",
            mount::mount_options(served.port),
            at.display()
        );
    } else {
        served.mount(&at, "")?;
        println!("Mounted at {}", at.display());
    }
    let (tx, rx) = std::sync::mpsc::channel();
    ctrlc_channel(tx);
    loop {
        if rx.recv_timeout(Duration::from_secs(5)).is_ok() {
            break;
        }
        let c = &engine.counters;
        let (streaming, rate) = engine.activity.streaming();
        for s in streaming {
            tracing::info!(
                "streaming {}: {} fetched of {} ({}/s)",
                s.name,
                human(s.fetched),
                human(s.size),
                human(rate)
            );
        }
        tracing::debug!(
            "served {} · fetched {} · uploaded {}",
            human(c.served.load(std::sync::atomic::Ordering::Relaxed)),
            human(c.fetched.load(std::sync::atomic::Ordering::Relaxed)),
            human(c.uploaded.load(std::sync::atomic::Ordering::Relaxed)),
        );
    }
    served.unmount(true)?;
    println!("Unmounted.");
    Ok(())
}

fn ctrlc_channel(tx: std::sync::mpsc::Sender<()>) {
    static TX: std::sync::OnceLock<std::sync::Mutex<std::sync::mpsc::Sender<()>>> = std::sync::OnceLock::new();
    TX.get_or_init(|| std::sync::Mutex::new(tx));
    extern "C" fn on_signal(_: libc::c_int) {
        if let Some(tx) = TX.get() {
            if let Ok(tx) = tx.try_lock() {
                let _ = tx.send(());
            }
        }
    }
    // SAFETY: installing a handler that only sends on a channel.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}
