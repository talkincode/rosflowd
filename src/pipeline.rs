use std::fs;
use std::net::UdpSocket;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;

use crate::dhcp;
use crate::dns;
use crate::error::{Error, Result};
use crate::hints::Hints;
use crate::identity::client_ip;
use crate::netflow::Decoder;
use crate::packet;
use crate::quic;
use crate::sni;
use crate::store::Store;
use crate::tzsp;

pub fn process_datagram(store: &mut Store, decoder: &mut Decoder, hints: &Hints, datagram: &[u8]) {
    store.note_datagram();
    match decoder.decode(datagram) {
        Ok(flows) => {
            for flow in flows {
                let class = hints.classify_flow(&flow);
                store.ingest_flow(&flow, &class, hints.identity_for_flow(&flow));
            }
        }
        Err(Error::UnsupportedVersion(_)) => store.note_unsupported(),
        Err(_) => store.note_decode_error(),
    }
}

/// TZSP samples never add or subtract NetFlow byte counts.
pub fn process_tzsp(store: &mut Store, hints: &mut Hints, datagram: &[u8]) {
    store.note_tzsp();
    let frame = match tzsp::ethernet_payload(datagram) {
        Ok(frame) => frame,
        Err(_) => {
            store.note_dpi_dropped();
            return;
        }
    };
    let Some(l4) = packet::parse_ipv4_l4(frame) else {
        store.note_dpi_dropped();
        return;
    };
    if l4.proto == 17 && (l4.dst_port == 67 || l4.src_port == 67 || l4.dst_port == 68) {
        if let Some((ip, ident)) = dhcp::parse_ack(&l4.payload) {
            store.apply_identity(ip, &ident);
            hints.remember_identity(ip, ident);
        }
    }
    if l4.proto == 17 && (l4.dst_port == 53 || l4.src_port == 53) {
        if let Some(records) = dns::a_records(&l4.payload) {
            if let Some(client) = client_ip(l4.src, l4.dst) {
                for (ip, name) in records {
                    store.note_dns();
                    hints.remember_dns(client, ip, name);
                }
            }
        }
    }
    let sni_name = sni::client_hello_sni(&l4.payload).or_else(|| {
        if l4.proto == 17 {
            quic::client_initial_sni(&l4.payload)
        } else {
            None
        }
    });
    if let Some(name) = sni_name {
        store.note_sni();
        if let Some(client) = client_ip(l4.src, l4.dst) {
            let server = if l4.src == client { l4.dst } else { l4.src };
            let port = if l4.src == client {
                l4.dst_port
            } else {
                l4.src_port
            };
            hints.remember_sni(client, server, port, name);
        }
    }
}

pub fn replay_file(store: &mut Store, path: &Path, hints: &Hints) -> Result<()> {
    let mut decoder = Decoder::default();
    let bytes = fs::read(path)?;
    process_datagram(store, &mut decoder, hints, &bytes);
    store.flush()
}

pub fn replay_tzsp_file(store: &mut Store, hints: &mut Hints, path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    process_tzsp(store, hints, &bytes);
    Ok(())
}

pub fn listen_udp(
    store: &mut Store,
    addr: &str,
    flush_secs: u64,
    shutdown: Arc<AtomicBool>,
    hints: &mut Hints,
) -> Result<()> {
    let sock = UdpSocket::bind(addr)?;
    serve_udp(store, sock, None, flush_secs, shutdown, hints)
}

pub fn serve_udp(
    store: &mut Store,
    sock: UdpSocket,
    tzsp: Option<UdpSocket>,
    flush_secs: u64,
    shutdown: Arc<AtomicBool>,
    hints: &mut Hints,
) -> Result<()> {
    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    if let Some(ref tz) = tzsp {
        tz.set_nonblocking(true)?;
    }
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
                process_datagram(store, &mut decoder, hints, &buf[..n]);
                if flush_secs == 0 {
                    store.flush()?;
                }
                idle_ticks = 0;
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::TimedOut => {}
            Err(err) => return Err(err.into()),
        }
        if let Some(ref tz) = tzsp {
            loop {
                match tz.recv_from(&mut buf) {
                    Ok((n, _)) => process_tzsp(store, hints, &buf[..n]),
                    Err(err)
                        if err.kind() == std::io::ErrorKind::WouldBlock
                            || err.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break;
                    }
                    Err(err) => return Err(err.into()),
                }
            }
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
