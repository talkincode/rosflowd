use std::fs;
use std::net::UdpSocket;
use std::path::Path;
use std::time::Duration;

use chrono::Utc;

use crate::classify::classify;
use crate::error::{Error, Result};
use crate::netflow;
use crate::store::Store;

pub fn process_datagram(store: &mut Store, datagram: &[u8]) {
    store.note_datagram();
    match netflow::decode(datagram) {
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
    let bytes = fs::read(path)?;
    process_datagram(store, &bytes);
    store.flush()
}

pub fn listen_udp(store: &mut Store, addr: &str, flush_secs: u64) -> Result<()> {
    let sock = UdpSocket::bind(addr)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut buf = [0u8; 65535];
    let mut since_flush = 0u64;
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => process_datagram(store, &buf[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err.into()),
        }
        since_flush += 1;
        if since_flush >= flush_secs.saturating_mul(2) {
            store.flush()?;
            let now = Utc::now().timestamp() as u32;
            store.prune_now(now)?;
            since_flush = 0;
        }
    }
}
