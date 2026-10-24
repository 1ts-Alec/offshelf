use std::path::PathBuf;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use oshelf::config::Home;
use oshelf::shelf::{self, Shelf, Unlock};
use oshelf_core::manifest::{Kind, ROOT};
use oshelf_core::vault::Kdf;

#[derive(Parser)]
#[command(
    name = "oshelf",
    version,
    about = "Offshelf client: your files on your own Pi, end to end encrypted"
)]
struct Cli {
    /// Unlock with the 24 recovery words instead of the passphrase.
    #[arg(long, global = true)]
    recovery: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Pair this device with a Pi, using a code from `oshelfd pair`.
    Pair {
        /// The Pi's address, e.g. http://192.168.1.20:8740
        url: String,
        /// The pairing code, e.g. 7KQ2-M9XD
        code: String,
        /// Name shown in the device list and in conflict copies.
        #[arg(long, default_value_t = default_device_name())]
        name: String,
    },
    /// Create the encrypted shelf on a freshly paired Pi.
    Init,
    /// Connection, revision, and what's stored.
    Status,
    /// Storage used on the Pi.
    Usage,
    /// List paired devices.
    Devices,
    /// Make a code for pairing another device.
    PairCode,
    /// Revoke a paired device.
    Revoke { device_id: String },
    /// Change the passphrase (the recovery words stay the same).
    Passwd,
    /// List a folder.
    Ls {
        #[arg(default_value = "")]
        path: String,
    },
    /// Upload files or folders into a shelf folder.
    Put {
        #[arg(required = true)]
        local: Vec<PathBuf>,
        /// Destination folder on the shelf.
        #[arg(long, short, default_value = "")]
        to: String,
    },
    /// Download a file or folder.
    Get {
        remote: String,
        #[arg(default_value = ".")]
        local_dir: PathBuf,
    },
    /// Print a file to stdout.
    Cat { remote: String },
    /// Make a folder (and its parents).
    Mkdir { path: String },
    /// Delete a file or folder.
    Rm { path: String },
    /// Rename or move.
    Mv { from: String, to: String },
    /// Decrypt the whole shelf into a local folder (a plain backup).
    Export { local_dir: PathBuf },
    /// Snapshot the tree so new devices load fast and the Pi can prune its log.
    Compact,
}

fn default_device_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "oshelf CLI".into())
}

/// `OSHELF_PASSPHRASE` for scripts, otherwise a hidden prompt.
fn secret(prompt: &str, env: &str) -> anyhow::Result<String> {
    if let Ok(v) = std::env::var(env) {
        return Ok(v);
    }
    Ok(rpassword::prompt_password(prompt)?)
}

fn new_passphrase() -> anyhow::Result<String> {
    if let Ok(v) = std::env::var("OSHELF_NEW_PASSPHRASE") {
        return Ok(v);
    }
    let a = rpassword::prompt_password("New passphrase: ")?;
    if a.chars().count() < 8 {
        bail!("use at least 8 characters");
    }
    let b = rpassword::prompt_password("Again: ")?;
    if a != b {
        bail!("passphrases don't match");
    }
    Ok(a)
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("oshelf: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let home = Home::open(Home::default_dir()?);

    if let Command::Pair { url, code, name } = &cli.command {
        let c = shelf::pair(&home, url, code, name)?;
        println!("Paired as {} ({})", c.device_name, c.device_id);
        return Ok(());
    }

    let (config, client) = shelf::connect(&home)?;
    let needs_unlock = !matches!(
        cli.command,
        Command::Init | Command::Usage | Command::Devices | Command::PairCode | Command::Revoke { .. }
    );
    let secret_value = if !needs_unlock {
        String::new()
    } else if cli.recovery {
        secret("Recovery words: ", "OSHELF_RECOVERY_WORDS")?
    } else {
        secret("Passphrase: ", "OSHELF_PASSPHRASE")?
    };
    let unlock = || {
        if cli.recovery {
            Unlock::Recovery(&secret_value)
        } else {
            Unlock::Passphrase(&secret_value)
        }
    };
    let open = || Shelf::open(&home, &config, &client, unlock());

    match cli.command {
        Command::Pair { .. } => unreachable!("handled above"),
        Command::Init => {
            let p = new_passphrase()?;
            let words = shelf::init(&client, &p, Kdf::new_default())?;
            println!("Shelf created.\n\nRecovery words (shown once, write them down):\n");
            for (i, w) in words.split(' ').enumerate() {
                print!("{:>2}. {w:<10}", i + 1);
                if i % 4 == 3 {
                    println!();
                }
            }
        }
        Command::Status => {
            let u = client.get("/v1/usage")?.ok()?.json()?;
            println!("Pi       {}", config.server_url);
            println!("Device   {} ({})", config.device_name, config.device_id);
            let s = open()?;
            let files = s.tree.walk(&ROOT).iter().filter(|n| n.kind == Kind::File).count();
            println!(
                "Verified revision {} ({}…)",
                s.chain.revision,
                &hex::encode(s.chain.hash)[..12]
            );
            println!("Files    {files}");
            println!("Stored   {}", human(u["stored_bytes"].as_u64().unwrap_or(0)));
        }
        Command::Usage => {
            let u = client.get("/v1/usage")?.ok()?.json()?;
            println!(
                "{} in {} chunks, {} file versions, revision {}",
                human(u["stored_bytes"].as_u64().unwrap_or(0)),
                u["chunks"],
                u["objects"],
                u["revision"]
            );
        }
        Command::Devices => {
            let d = client.get("/v1/devices")?.ok()?.json()?;
            for dev in d.as_array().context("bad device list")? {
                let id = dev["id"].as_str().unwrap_or_default();
                let me = if id == config.device_id { "  (this device)" } else { "" };
                println!("{id}  {}{me}", dev["name"].as_str().unwrap_or_default());
            }
        }
        Command::PairCode => {
            let c = client.post("/v1/pairing-codes", &[], &[])?.ok()?.json()?;
            println!("{}  (valid 10 minutes)", c["code"].as_str().unwrap_or_default());
        }
        Command::Revoke { device_id } => {
            if device_id == config.device_id {
                bail!("that's this device; revoke it from another one");
            }
            client.delete(&format!("/v1/devices/{device_id}"))?.ok()?;
            println!("Revoked {device_id}");
        }
        Command::Passwd => {
            let old = unlock();
            let new = new_passphrase()?;
            shelf::change_passphrase(&client, old, &new)?;
            println!("Passphrase changed.");
        }
        Command::Ls { path } => {
            let s = open()?;
            let dir = s.tree.resolve(&path).with_context(|| format!("{path}: not found"))?;
            for n in s.tree.list(&dir) {
                match n.kind {
                    Kind::Dir => println!("{:>10}  {}/", "", n.name),
                    _ => println!("{:>10}  {}", human(n.size), n.name),
                }
            }
        }
        Command::Put { local, to } => {
            let mut s = open()?;
            for l in local {
                for u in s.put(&l, &to)? {
                    println!("{:>10}  {}", human(u.size), u.path);
                }
            }
        }
        Command::Get { remote, local_dir } => {
            let n = open()?.get(&remote, &local_dir)?;
            println!("{n} file(s) written to {}", local_dir.display());
        }
        Command::Cat { remote } => {
            let s = open()?;
            let node = s.node(&remote)?.clone();
            s.read_file(&node, &mut std::io::stdout().lock())?;
        }
        Command::Mkdir { path } => open()?.mkdir(&path)?,
        Command::Rm { path } => {
            open()?.rm(&path)?;
            println!("Deleted {path}");
        }
        Command::Mv { from, to } => open()?.mv(&from, &to)?,
        Command::Export { local_dir } => {
            let n = open()?.export(&local_dir)?;
            println!("{n} file(s) exported to {}", local_dir.display());
        }
        Command::Compact => {
            let r = open()?.compact()?;
            println!("Snapshot stored at revision {r}");
        }
    }
    Ok(())
}
