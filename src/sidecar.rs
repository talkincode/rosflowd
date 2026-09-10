use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use serde::Deserialize;

use crate::error::Result;
use crate::hints::Hints;
use crate::identity::ClientIdentity;
use crate::store::Store;

#[derive(Debug, Deserialize)]
struct Row {
    ip: String,
    #[serde(default)]
    mac: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    ssid: Option<String>,
}

pub fn load_identity_jsonl(path: &Path, store: &mut Store, hints: &mut Hints) -> Result<u64> {
    let text = fs::read_to_string(path)?;
    let mut n = 0u64;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let row: Row = serde_json::from_str(line).map_err(|err| {
            crate::error::Error::Store(format!("identity jsonl line {}: {err}", i + 1))
        })?;
        let ip = Ipv4Addr::from_str(&row.ip)
            .map_err(|_| crate::error::Error::Store(format!("bad ip on line {}", i + 1)))?;
        let ident = ClientIdentity {
            mac: row.mac.filter(|s| !s.is_empty()),
            hostname: row.hostname.filter(|s| !s.is_empty()),
            ssid: row.ssid.filter(|s| !s.is_empty()),
        };
        store.apply_identity(ip, &ident);
        hints.remember_identity(ip, ident);
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify;
    use crate::flow::Flow;
    use crate::store::Store;
    use std::net::Ipv4Addr;

    #[test]
    fn sidecar_fills_ssid() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("id.jsonl");
        fs::write(
            &path,
            r#"{"ip":"10.0.0.95","mac":"02:00:00:00:00:01","hostname":"phone","ssid":"a2"}
"#,
        )
        .unwrap();
        let mut store = Store::new(tmp.path().join("data"), 7, "replay");
        let mut hints = Hints::default();
        load_identity_jsonl(&path, &mut store, &mut hints).unwrap();
        let flow = Flow {
            src: Ipv4Addr::new(10, 0, 0, 95),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 50000,
            dst_port: 443,
            proto: 6,
            packets: 1,
            bytes: 10,
            tcp_flags: 0,
            unix_secs: 1_704_067_200,
        };
        store.ingest_flow(&flow, &classify(&flow), hints.identity_for_flow(&flow));
        store.flush().unwrap();
        let clients = fs::read_to_string(
            tmp.path()
                .join("data")
                .join("2024-01-01")
                .join("clients.jsonl"),
        )
        .unwrap();
        assert!(clients.contains("\"ssid\":\"a2\""), "got {clients}");
        assert!(clients.contains("phone"), "got {clients}");
    }

    #[test]
    fn bad_json_is_store_error() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.jsonl");
        fs::write(&path, "{nope}\n").unwrap();
        let mut store = Store::new(tmp.path().join("data"), 7, "replay");
        let mut hints = Hints::default();
        assert!(load_identity_jsonl(&path, &mut store, &mut hints).is_err());
    }
}
