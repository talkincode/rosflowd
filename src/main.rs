use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use rosflowd::hints::Hints;
use rosflowd::pipeline::{listen_udp, replay_file, replay_tzsp_file, serve_udp};
use rosflowd::sidecar;
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
    /// Optional TZSP listen address (MikroTik packet-sniffer streaming). Off if omitted.
    #[arg(long)]
    tzsp: Option<String>,
    /// Replay a TZSP datagram file (no UDP). Can combine with --replay.
    #[arg(long)]
    replay_tzsp: Option<PathBuf>,
    /// JSONL sidecar: {"ip","mac?","hostname?","ssid?"} from wireless/DHCP dumps.
    #[arg(long)]
    identity: Option<PathBuf>,
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
    let mut hints = Hints::default();
    if let Some(path) = &cli.identity {
        sidecar::load_identity_jsonl(path, &mut store, &mut hints)?;
    }
    if let Some(path) = &cli.replay_tzsp {
        replay_tzsp_file(&mut store, &mut hints, path)?;
    }
    if let Some(path) = &cli.replay {
        replay_file(&mut store, path, &hints)?;
        return Ok(());
    }
    if cli.replay_tzsp.is_some() {
        store.flush()?;
        return Ok(());
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    if let Some(tzsp) = cli.tzsp {
        store.set_tzsp(&tzsp);
        let nf = UdpSocket::bind(&cli.listen)?;
        let tz = UdpSocket::bind(&tzsp)?;
        return serve_udp(&mut store, nf, Some(tz), 5, shutdown, &mut hints);
    }
    listen_udp(&mut store, &cli.listen, 5, shutdown, &mut hints)
}
