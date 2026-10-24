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
    },
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
    let state = AppState::open(&cli.data_dir)?;

    match cli.command {
        Command::Serve { bind } => {
            config::check_bind(bind)?;
            let listener = tokio::net::TcpListener::bind(bind).await?;
            tracing::info!(%bind, data_dir = %cli.data_dir.display(), "oshelfd listening");
            axum::serve(listener, oshelfd::router(state))
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Command::Gc { grace_hours } => {
            let removed = oshelfd::gc(&state, grace_hours * 3600).await?;
            println!("removed {removed} chunks");
        }
    }
    Ok(())
}
