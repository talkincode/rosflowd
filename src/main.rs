use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use rosflowd::pipeline::{listen_udp, replay_file};
use rosflowd::store::Store;

#[derive(Debug, Parser)]
#[command(name = "rosflowd", about = "Headless RouterOS flow collector")]
struct Cli {
    /// UDP listen address for NetFlow/IPFIX
    #[arg(long, default_value = "0.0.0.0:2055")]
    listen: String,
    /// Dataset directory
    #[arg(long, default_value = "./data")]
    data: PathBuf,
    /// Calendar days to keep
    #[arg(long, default_value_t = 7)]
    retain_days: u32,
    /// Replay a single datagram file and exit (no UDP)
    #[arg(long)]
    replay: Option<PathBuf>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!(
            "{}",
            serde_json::json!({
                "error": err.to_string(),
            })
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(cli: Cli) -> rosflowd::Result<()> {
    let listen_label = if cli.replay.is_some() {
        "replay".to_string()
    } else {
        cli.listen.clone()
    };
    let mut store = Store::new(&cli.data, cli.retain_days, listen_label);
    if let Some(path) = cli.replay {
        replay_file(&mut store, &path)?;
        return Ok(());
    }
    listen_udp(&mut store, &cli.listen, 5)
}
