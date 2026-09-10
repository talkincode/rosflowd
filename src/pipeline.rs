use std::fs;
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::classify::classify;
use crate::error::{Error, Result};
use crate::netflow::Decoder;
use crate::store::Store;

pub fn process_datagram(store: &mut Store, decoder: &mut Decoder, datagram: &[u8]) {
    store.note_datagram();
    match decoder.decode(datagram) {
        Ok(flows) => {
            for flow in flows {
                let class = classify(&flow);
                store.ingest_flow(&flow, &class);
            }
        }
        Err(Error::UnsupportedVersion(_)) => store.note_unsupported(),
        Err(_) => store.note_decode_error(),
    }
}

pub fn replay_file(store: &mut Store, path: &Path) -> Result<()> {
    let mut decoder = Decoder::default();
    let bytes = fs::read(path)?;
    process_datagram(store, &mut decoder, &bytes);
    store.flush()
}

pub fn listen_udp(
    store: &mut Store,
    addr: &str,
    flush_secs: u64,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let sock = UdpSocket::bind(addr)?;
    serve_udp(store, sock, flush_secs, shutdown)
}

pub fn serve_udp(
    store: &mut Store,
    sock: UdpSocket,
    flush_secs: u64,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    let mut decoder = Decoder::default();
    let mut buf = [0u8; 65535];
    let mut idle_ticks = 0u64;
    let flush_ticks = flush_secs.saturating_mul(20).max(1);
    loop {
        if shutdown.load(Ordering::SeqCst) {
            store.flush()?;
            let now = Utc::now().timestamp() as u32;
            store.prune_now(now)?;
            return Ok(());
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                process_datagram(store, &mut decoder, &buf[..n]);
                if flush_secs == 0 {
                    store.flush()?;
                }
                idle_ticks = 0;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err.into()),
        }
        idle_ticks += 1;
        if flush_secs > 0 && idle_ticks >= flush_ticks {
            store.flush()?;
            let now = Utc::now().timestamp() as u32;
            store.prune_now(now)?;
            idle_ticks = 0;
        }
    }
}
