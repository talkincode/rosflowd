use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rosflowd::clock::day_utc;

use rosflowd::flow::Flow;
use rosflowd::hints::Hints;
use rosflowd::netflow::{ipfix, v5, v9, Decoder};
use rosflowd::pipeline::{process_datagram, process_tzsp, replay_file, serve_udp};
use rosflowd::store::Store;

fn lan_https() -> Flow {
    Flow {
        src: Ipv4Addr::new(10, 0, 0, 95),
        dst: Ipv4Addr::new(1, 1, 1, 1),
        src_port: 50000,
        dst_port: 443,
        proto: 6,
        packets: 8,
        bytes: 4096,
        tcp_flags: 0x18,
        unix_secs: 1_704_067_200, // 2024-01-01 00:00:00 UTC
    }
}

fn wan_only() -> Flow {
    Flow {
        src: Ipv4Addr::new(203, 0, 113, 10),
        dst: Ipv4Addr::new(198, 51, 100, 20),
        src_port: 443,
        dst_port: 50000,
        proto: 6,
        packets: 4,
        bytes: 1024,
        tcp_flags: 0,
        unix_secs: 1_704_067_200,
    }
}

#[test]
fn e2e_replay_lan_https() {
    let tmp = tempfile::tempdir().unwrap();
    let pkt_path = tmp.path().join("lan.nfv5");
    fs::write(&pkt_path, v5::encode(lan_https().unix_secs, &[lan_https()])).unwrap();
    let data = tmp.path().join("data");
    let mut store = Store::new(&data, 7, "replay");
    replay_file(&mut store, &pkt_path).unwrap();

    let day = "2024-01-01";
    let clients = fs::read_to_string(data.join(day).join("clients.jsonl")).unwrap();
    assert!(clients.contains("10.0.0.95"));
    assert!(clients.contains("4096"));
    let apps = fs::read_to_string(data.join(day).join("apps.jsonl")).unwrap();
    assert!(apps.contains("\"app\":\"tls\""));
    assert!(apps.contains("\"confidence\":\"port\""));
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(data.join("metadata.json")).unwrap()).unwrap();
    assert_eq!(meta["schema_version"], "rosflowd.dataset.v1");
    assert_eq!(meta["dpi"]["engine"], "port");
    assert_eq!(meta["dpi"]["status"], "l2");
    assert!(data.join("README.md").exists());
}

#[test]
fn e2e_wan_only_has_no_client() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::new(tmp.path(), 7, "replay");
    let pkt = v5::encode(wan_only().unix_secs, &[wan_only()]);
    let mut decoder = Decoder::default();
    let hints = Hints::default();
    process_datagram(&mut store, &mut decoder, &hints, &pkt);
    store.flush().unwrap();
    assert_eq!(store.stats().no_client, 1);
    assert_eq!(store.stats().flows, 1);
    let day_dir = tmp.path().join("2024-01-01");
    if day_dir.join("clients.jsonl").exists() {
        let clients = fs::read_to_string(day_dir.join("clients.jsonl")).unwrap();
        assert!(
            clients.trim().is_empty(),
            "WAN-only must not create LAN clients, got {clients}"
        );
    }
}

#[test]
fn e2e_replay_cli_writes_data() {
    let tmp = tempfile::tempdir().unwrap();
    let pkt = tmp.path().join("p.bin");
    fs::write(&pkt, v5::encode(lan_https().unix_secs, &[lan_https()])).unwrap();
    let data = tmp.path().join("out");
    let exe = env!("CARGO_BIN_EXE_rosflowd");
    let status = std::process::Command::new(exe)
        .args([
            "--replay",
            pkt.to_str().unwrap(),
            "--data",
            data.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(data.join("metadata.json").exists());
    let _ = PathBuf::from(exe);
}

#[test]
fn e2e_listen_invalid_addr_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::new(tmp.path(), 7, "bad");
    let err = rosflowd::pipeline::listen_udp(
        &mut store,
        "not-a-socket",
        1,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not-a-socket")
            || msg.contains("invalid")
            || msg.contains("failed to lookup")
            || msg.contains("No such file")
            || msg.to_lowercase().contains("name or service"),
        "unexpected bind error: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn e2e_unwritable_data_dir_fails_cleanly() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("ro");
    fs::create_dir(&data).unwrap();
    let mut store = Store::new(&data, 7, "replay");
    let pkt = v5::encode(lan_https().unix_secs, &[lan_https()]);
    let mut decoder = Decoder::default();
    let hints = Hints::default();
    process_datagram(&mut store, &mut decoder, &hints, &pkt);
    let mut perms = fs::metadata(&data).unwrap().permissions();
    perms.set_mode(0o555);
    fs::set_permissions(&data, perms).unwrap();
    let result = store.flush();
    let mut perms = fs::metadata(&data).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&data, perms).unwrap();
    assert!(result.is_err(), "flush should fail on read-only dir");
}

#[test]
fn e2e_replay_v9_lan_https() {
    let tmp = tempfile::tempdir().unwrap();
    let pkt_path = tmp.path().join("lan.nfv9");
    fs::write(
        &pkt_path,
        v9::encode(lan_https().unix_secs, 1, &[lan_https()]),
    )
    .unwrap();
    let data = tmp.path().join("data");
    let mut store = Store::new(&data, 7, "replay");
    replay_file(&mut store, &pkt_path).unwrap();
    let clients = fs::read_to_string(data.join("2024-01-01").join("clients.jsonl")).unwrap();
    assert!(clients.contains("10.0.0.95"));
    let apps = fs::read_to_string(data.join("2024-01-01").join("apps.jsonl")).unwrap();
    assert!(apps.contains("\"app\":\"tls\""));
}

#[test]
fn e2e_replay_ipfix_lan_https() {
    let tmp = tempfile::tempdir().unwrap();
    let pkt_path = tmp.path().join("lan.ipfix");
    fs::write(
        &pkt_path,
        ipfix::encode(lan_https().unix_secs, 1, &[lan_https()]),
    )
    .unwrap();
    let data = tmp.path().join("data");
    let mut store = Store::new(&data, 7, "replay");
    replay_file(&mut store, &pkt_path).unwrap();
    let clients = fs::read_to_string(data.join("2024-01-01").join("clients.jsonl")).unwrap();
    assert!(clients.contains("10.0.0.95"));
}

#[test]
fn e2e_udp_v5_happy_path() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    fs::create_dir(&data).unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let local = sock.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    let data_thread = data.clone();
    let handle = thread::spawn(move || {
        let mut store = Store::new(&data_thread, 7, local.to_string());
        serve_udp(&mut store, sock, None, 0, sd)
    });
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut flow = lan_https();
    flow.unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let day = day_utc(flow.unix_secs);
    let pkt = v5::encode(flow.unix_secs, std::slice::from_ref(&flow));
    client.send_to(&pkt, local).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let clients_path = data.join(&day).join("clients.jsonl");
    while Instant::now() < deadline {
        if clients_path.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    shutdown.store(true, Ordering::SeqCst);
    handle.join().unwrap().unwrap();
    let clients = fs::read_to_string(&clients_path).unwrap();
    assert!(clients.contains("10.0.0.95"), "got {clients}");
}

#[test]
fn e2e_tzsp_drop_does_not_change_netflow_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::new(tmp.path(), 7, "replay");
    let mut decoder = Decoder::default();
    let mut hints = Hints::default();
    let pkt = v5::encode(lan_https().unix_secs, &[lan_https()]);
    process_datagram(&mut store, &mut decoder, &hints, &pkt);
    assert_eq!(store.stats().flows, 1);
    process_tzsp(&mut store, &mut hints, &[0, 1, 2]);
    assert_eq!(store.stats().dpi_dropped, 1);
    assert_eq!(store.stats().tzsp_datagrams, 1);
    assert_eq!(store.stats().flows, 1);
    store.flush().unwrap();
    let clients = fs::read_to_string(tmp.path().join("2024-01-01").join("clients.jsonl")).unwrap();
    assert!(clients.contains("4096"), "got {clients}");
}

#[test]
fn e2e_tzsp_sni_classifies_later_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::new(tmp.path(), 7, "replay");
    let mut decoder = Decoder::default();
    let mut hints = Hints::default();
    let hello = rosflowd::sni::encode_client_hello("example.com");
    let frame = rosflowd::packet::ethernet_ipv4(
        [0x02, 0, 0, 0, 0, 1],
        6,
        Ipv4Addr::new(10, 0, 0, 95),
        Ipv4Addr::new(1, 1, 1, 1),
        50000,
        443,
        &hello,
    );
    process_tzsp(
        &mut store,
        &mut hints,
        &rosflowd::tzsp::encode_ethernet(&frame),
    );
    let pkt = v5::encode(lan_https().unix_secs, &[lan_https()]);
    process_datagram(&mut store, &mut decoder, &hints, &pkt);
    store.flush().unwrap();
    let apps = fs::read_to_string(tmp.path().join("2024-01-01").join("apps.jsonl")).unwrap();
    assert!(apps.contains("\"app\":\"example.com\""), "got {apps}");
    assert!(apps.contains("\"confidence\":\"sni\""), "got {apps}");
    let clients = fs::read_to_string(tmp.path().join("2024-01-01").join("clients.jsonl")).unwrap();
    assert!(clients.contains("4096"), "got {clients}");
    let meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(tmp.path().join("metadata.json")).unwrap())
            .unwrap();
    assert_eq!(meta["dpi"]["engine"], "port");
    assert_eq!(meta["dpi"]["sni"], true);
}

#[test]
fn e2e_dhcp_ack_attaches_hostname() {
    let tmp = tempfile::tempdir().unwrap();
    let mut store = Store::new(tmp.path(), 7, "replay");
    let mut decoder = Decoder::default();
    let mut hints = Hints::default();
    let ack =
        rosflowd::dhcp::encode_ack(Ipv4Addr::new(10, 0, 0, 95), [0x02, 0, 0, 0, 0, 1], "phone");
    let frame = rosflowd::packet::ethernet_ipv4(
        [0x02, 0, 0, 0, 0, 1],
        17,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 95),
        67,
        68,
        &ack,
    );
    process_tzsp(
        &mut store,
        &mut hints,
        &rosflowd::tzsp::encode_ethernet(&frame),
    );
    let pkt = v5::encode(lan_https().unix_secs, &[lan_https()]);
    process_datagram(&mut store, &mut decoder, &hints, &pkt);
    store.flush().unwrap();
    let clients = fs::read_to_string(tmp.path().join("2024-01-01").join("clients.jsonl")).unwrap();
    assert!(clients.contains("phone"), "got {clients}");
    assert!(clients.contains("02:00:00:00:00:01"), "got {clients}");
}
