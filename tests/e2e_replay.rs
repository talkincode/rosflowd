use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use rosflowd::flow::Flow;
use rosflowd::netflow::v5;
use rosflowd::pipeline::{process_datagram, replay_file};
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
    process_datagram(&mut store, &pkt);
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
    let err = rosflowd::pipeline::listen_udp(&mut store, "not-a-socket", 1).unwrap_err();
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
    process_datagram(&mut store, &pkt);
    let mut perms = fs::metadata(&data).unwrap().permissions();
    perms.set_mode(0o555);
    fs::set_permissions(&data, perms).unwrap();
    let result = store.flush();
    let mut perms = fs::metadata(&data).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&data, perms).unwrap();
    assert!(result.is_err(), "flush should fail on read-only dir");
}
