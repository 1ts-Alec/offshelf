use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use oshelfd::{config, AppState};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "oshelfd", version, about = "Offshelf server")]
struct Cli {
    /// Where chunks and the metadata database live (the SSD mount).
    #[arg(long, env = "OSHELF_DATA_DIR", default_value = "/var/lib/offshelf")]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Serve {
        /// LAN address to listen on. Public addresses are refused.
        #[arg(long, env = "OSHELF_BIND", default_value_t = SocketAddr::from(([0, 0, 0, 0], config::DEFAULT_PORT)))]
        bind: SocketAddr,
        /// Serve the web app from this folder instead of the built-in copy.
        #[arg(long, env = "OSHELF_WEB_DIR")]
        web_dir: Option<PathBuf>,
    },
    /// Make a one-time code for pairing a new device (valid 10 minutes).
    Pair,
    /// List paired devices.
    Devices,
    /// Revoke a paired device by id.
    Revoke { device_id: String },
    /// Delete chunks that no file version references.
    Gc {
        /// Keep unreferenced chunks younger than this, so uploads in flight survive.
        #[arg(long, default_value_t = 24)]
        grace_hours: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let cli = Cli::parse();
    let socket = oshelfd::control::socket_path(&cli.data_dir);

    // Pairing codes and the device list come from the running server when
    // there is one, so these work for any user, without sudo.
    let ask = match cli.command {
        Command::Pair => Some("pair"),
        Command::Devices => Some("devices"),
        _ => None,
    };
    if let Some(cmd) = ask {
        if let Some(reply) = oshelfd::control::ask(&socket, cmd).await? {
            print!("{reply}");
            return Ok(());
        }
    }

    let mut state = AppState::open(&cli.data_dir).map_err(|e| {
        if ask.is_some() {
            e.context(format!(
                "no oshelfd running (nothing at {}), and the data folder isn't readable as this user",
                socket.display()
            ))
        } else {
            e
        }
    })?;

    match cli.command {
        Command::Serve { bind, web_dir } => {
            config::check_bind(bind)?;
            if let Some(dir) = web_dir {
                anyhow::ensure!(dir.join("index.html").exists(), "{} has no index.html", dir.display());
                state.web = Some(std::sync::Arc::new(oshelfd::web::WebApp::Dir(dir)));
            }
            let control = state.clone();
            let socket_path = socket.clone();
            tokio::spawn(async move {
                if let Err(e) = oshelfd::control::serve(control, socket_path.clone()).await {
                    tracing::warn!(socket = %socket_path.display(), "control socket unavailable: {e}");
                }
            });
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!(%bind, data_dir = %cli.data_dir.display(), "oshelfd listening");
            axum::serve(listener, oshelfd::router(state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Command::Pair => print!("{}", oshelfd::control::run(&state, "pair").await?),
        Command::Devices => print!("{}", oshelfd::control::run(&state, "devices").await?),
        Command::Revoke { device_id } => {
            let mut id = [0u8; 16];
            hex::decode_to_slice(&device_id, &mut id)?;
            anyhow::ensure!(state.db.call(move |db| db.revoke_device(&id)).await?, "no such device");
            println!("revoked {device_id}");
        }
        Command::Gc { grace_hours } => {
            let removed = oshelfd::gc(&state, grace_hours * 3600).await?;
            println!("removed {removed} chunks");
        }
    }
    Ok(())
}
