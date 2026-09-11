use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use chrono::{Duration, TimeZone, Utc};
use serde::Serialize;

use crate::classify::Classification;
use crate::clock::{day_utc, hour_utc};
use crate::error::{Error, Result};
use crate::flow::Flow;
use crate::identity::{client_ip_for_flow, ClientIdentity};

const SCHEMA_VERSION: &str = "rosflowd.dataset.v1";
const DATASET_README: &str = r#"# rosflowd data

Local rolling stats. Not a database. Default retention is 7 UTC calendar days.

| File | Meaning |
|------|---------|
| `metadata.json` | Schema, retain_days, classifier engine |
| `YYYY-MM-DD/clients.jsonl` | One JSON object per LAN client that day |
| `YYYY-MM-DD/apps.jsonl` | client × app totals |
| `YYYY-MM-DD/hourly.json` | Unix-hour → bytes |
| `YYYY-MM-DD/ingest.json` | Decode/drop counters |

`confidence=port` is not DPI. `confidence=sni`/`dns` come from TZSP samples. `confidence=ndpi` is nDPI on those samples, not on NetFlow records. WAN-only flows are counted in ingest but omitted from clients.jsonl. TZSP decode failures increment `dpi_dropped` and never subtract NetFlow bytes.
"#;

#[derive(Debug, Default)]
pub struct IngestStats {
    pub datagrams: u64,
    pub flows: u64,
    pub decode_errors: u64,
    pub unsupported_version: u64,
    pub no_client: u64,
    pub tzsp_datagrams: u64,
    pub dpi_dropped: u64,
}

#[derive(Debug, Default)]
struct ClientAgg {
    bytes: u64,
    packets: u64,
    flows: u64,
    mac: Option<String>,
    hostname: Option<String>,
    ssid: Option<String>,
}

#[derive(Debug, Default)]
struct AppAgg {
    bytes: u64,
    packets: u64,
    flows: u64,
    category: String,
    confidence: String,
}

#[derive(Debug)]
pub struct Store {
    root: PathBuf,
    retain_days: u32,
    listen: String,
    clients: BTreeMap<(String, Ipv4Addr), ClientAgg>,
    apps: BTreeMap<(String, Ipv4Addr, String), AppAgg>,
    hourly: BTreeMap<(String, u32), u64>,
    stats: IngestStats,
    tzsp: String,
    sni_enabled: bool,
    dns_enabled: bool,
    ndpi_enabled: bool,
}

impl Store {
    pub fn new(root: impl Into<PathBuf>, retain_days: u32, listen: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            retain_days,
            listen: listen.into(),
            clients: BTreeMap::new(),
            apps: BTreeMap::new(),
            hourly: BTreeMap::new(),
            stats: IngestStats::default(),
            tzsp: String::new(),
            sni_enabled: false,
            dns_enabled: false,
            ndpi_enabled: false,
        }
    }

    pub fn set_tzsp(&mut self, addr: impl Into<String>) {
        self.tzsp = addr.into();
    }

    pub fn stats(&self) -> &IngestStats {
        &self.stats
    }

    pub fn note_datagram(&mut self) {
        self.stats.datagrams += 1;
    }

    pub fn note_decode_error(&mut self) {
        self.stats.decode_errors += 1;
    }

    pub fn note_unsupported(&mut self) {
        self.stats.unsupported_version += 1;
    }

    pub fn note_tzsp(&mut self) {
        self.stats.tzsp_datagrams += 1;
    }

    pub fn note_dpi_dropped(&mut self) {
        self.stats.dpi_dropped += 1;
    }

    pub fn note_sni(&mut self) {
        self.sni_enabled = true;
    }

    pub fn note_dns(&mut self) {
        self.dns_enabled = true;
    }

    pub fn note_ndpi(&mut self) {
        self.ndpi_enabled = true;
    }

    pub fn apply_identity(&mut self, ip: Ipv4Addr, ident: &ClientIdentity) {
        for ((_, cip), agg) in self.clients.iter_mut() {
            if *cip == ip {
                if ident.mac.is_some() {
                    agg.mac.clone_from(&ident.mac);
                }
                if ident.hostname.is_some() {
                    agg.hostname.clone_from(&ident.hostname);
                }
                if ident.ssid.is_some() {
                    agg.ssid.clone_from(&ident.ssid);
                }
            }
        }
    }

    pub fn ingest_flow(
        &mut self,
        flow: &Flow,
        class: &Classification,
        ident: Option<&ClientIdentity>,
    ) {
        self.stats.flows += 1;
        let day = day_utc(flow.unix_secs);
        *self
            .hourly
            .entry((day.clone(), hour_utc(flow.unix_secs)))
            .or_insert(0) += flow.bytes;
        let Some(client) = client_ip_for_flow(flow) else {
            self.stats.no_client += 1;
            return;
        };
        let c = self.clients.entry((day.clone(), client)).or_default();
        c.bytes += flow.bytes;
        c.packets += flow.packets;
        c.flows += 1;
        if let Some(ident) = ident {
            if ident.mac.is_some() {
                c.mac.clone_from(&ident.mac);
            }
            if ident.hostname.is_some() {
                c.hostname.clone_from(&ident.hostname);
            }
            if ident.ssid.is_some() {
                c.ssid.clone_from(&ident.ssid);
            }
        }
        let a = self
            .apps
            .entry((day, client, class.app.to_string()))
            .or_default();
        a.bytes += flow.bytes;
        a.packets += flow.packets;
        a.flows += 1;
        a.category = class.category.to_string();
        a.confidence = class.confidence.to_string();
    }

    pub fn flush(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        write_atomic(self.root.join("README.md"), DATASET_README.as_bytes())?;
        let tzsp = if self.tzsp.is_empty() {
            None
        } else {
            Some(self.tzsp.as_str())
        };
        let meta = MetadataFile {
            schema_version: SCHEMA_VERSION,
            retain_days: self.retain_days,
            listen: &self.listen,
            tzsp,
            dpi: DpiMeta {
                engine: if self.ndpi_enabled { "ndpi" } else { "port" },
                status: if self.ndpi_enabled { "dpi" } else { "l2" },
                sni: self.sni_enabled,
                dns: self.dns_enabled,
            },
            time_zone: "UTC",
        };
        write_atomic(
            self.root.join("metadata.json"),
            serde_json::to_vec_pretty(&meta)?.as_slice(),
        )?;

        let mut days: BTreeMap<String, ()> = BTreeMap::new();
        for (day, _) in self.clients.keys() {
            days.insert(day.clone(), ());
        }
        for (day, _) in self.hourly.keys() {
            days.insert(day.clone(), ());
        }
        for day in days.keys() {
            let dir = self.root.join(day);
            fs::create_dir_all(&dir)?;
            self.write_day(day, &dir)?;
        }
        Ok(())
    }

    pub fn prune_now(&self, now_unix: u32) -> Result<Vec<String>> {
        prune_older_than(&self.root, self.retain_days, now_unix)
    }

    fn write_day(&self, day: &str, dir: &Path) -> Result<()> {
        let mut clients = Vec::new();
        for ((d, ip), agg) in &self.clients {
            if d != day {
                continue;
            }
            clients.push(ClientRow {
                client_ip: ip.to_string(),
                mac: agg.mac.clone(),
                hostname: agg.hostname.clone(),
                ssid: agg.ssid.clone(),
                bytes: agg.bytes,
                packets: agg.packets,
                flows: agg.flows,
            });
        }
        write_jsonl(dir.join("clients.jsonl"), &clients)?;

        let mut apps = Vec::new();
        for ((d, ip, app), agg) in &self.apps {
            if d != day {
                continue;
            }
            apps.push(AppRow {
                client_ip: ip.to_string(),
                app: app.clone(),
                category: agg.category.clone(),
                confidence: agg.confidence.clone(),
                bytes: agg.bytes,
                packets: agg.packets,
                flows: agg.flows,
            });
        }
        write_jsonl(dir.join("apps.jsonl"), &apps)?;

        let mut hourly = BTreeMap::new();
        for ((d, hour), bytes) in &self.hourly {
            if d == day {
                hourly.insert(hour.to_string(), *bytes);
            }
        }
        write_atomic(
            dir.join("hourly.json"),
            serde_json::to_vec_pretty(&hourly)?.as_slice(),
        )?;
        write_atomic(
            dir.join("ingest.json"),
            serde_json::to_vec_pretty(&IngestFile::from(&self.stats))?.as_slice(),
        )?;
        Ok(())
    }
}

/// Delete day directories older than retain_days relative to `now_unix`.
pub fn prune_older_than(root: &Path, retain_days: u32, now_unix: u32) -> Result<Vec<String>> {
    let now = Utc
        .timestamp_opt(i64::from(now_unix), 0)
        .single()
        .ok_or_else(|| Error::Store("invalid now".into()))?;
    let cutoff = now - Duration::days(i64::from(retain_days));
    let cutoff_s = cutoff.format("%Y-%m-%d").to_string();
    let mut removed = Vec::new();
    if !root.exists() {
        return Ok(removed);
    }
    for ent in fs::read_dir(root)? {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let name = ent.file_name().to_string_lossy().into_owned();
        if !is_day_dir(&name) {
            continue;
        }
        if name < cutoff_s {
            fs::remove_dir_all(ent.path())?;
            removed.push(name);
        }
    }
    Ok(removed)
}

fn is_day_dir(name: &str) -> bool {
    name.len() == 10
        && name.as_bytes()[4] == b'-'
        && name.as_bytes()[7] == b'-'
        && name.bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

fn write_jsonl<T: Serialize>(path: PathBuf, rows: &[T]) -> Result<()> {
    let mut buf = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut buf, row)?;
        buf.push(b'\n');
    }
    write_atomic(path, &buf)
}

fn write_atomic(path: PathBuf, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

#[derive(Serialize)]
struct MetadataFile<'a> {
    schema_version: &'a str,
    retain_days: u32,
    listen: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tzsp: Option<&'a str>,
    dpi: DpiMeta,
    time_zone: &'a str,
}

#[derive(Serialize)]
struct DpiMeta {
    engine: &'static str,
    status: &'static str,
    sni: bool,
    dns: bool,
}

#[derive(Serialize)]
struct ClientRow {
    client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssid: Option<String>,
    bytes: u64,
    packets: u64,
    flows: u64,
}

#[derive(Serialize)]
struct AppRow {
    client_ip: String,
    app: String,
    category: String,
    confidence: String,
    bytes: u64,
    packets: u64,
    flows: u64,
}

#[derive(Serialize)]
struct IngestFile {
    datagrams: u64,
    flows: u64,
    decode_errors: u64,
    unsupported_version: u64,
    no_client: u64,
    tzsp_datagrams: u64,
    dpi_dropped: u64,
}

impl From<&IngestStats> for IngestFile {
    fn from(s: &IngestStats) -> Self {
        Self {
            datagrams: s.datagrams,
            flows: s.flows,
            decode_errors: s.decode_errors,
            unsupported_version: s.unsupported_version,
            no_client: s.no_client,
            tzsp_datagrams: s.tzsp_datagrams,
            dpi_dropped: s.dpi_dropped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::classify;
    use crate::flow::Flow;
    use std::net::Ipv4Addr;

    #[test]
    fn retention_keeps_last_n_days() {
        let tmp = tempfile::tempdir().unwrap();
        for d in ["2026-09-01", "2026-09-02", "2026-09-03", "2026-09-04"] {
            fs::create_dir_all(tmp.path().join(d)).unwrap();
        }
        fs::write(tmp.path().join("README.md"), "x").unwrap();
        let now = Utc
            .with_ymd_and_hms(2026, 9, 10, 12, 0, 0)
            .unwrap()
            .timestamp() as u32;
        let removed = prune_older_than(tmp.path(), 7, now).unwrap();
        assert!(removed.contains(&"2026-09-01".into()));
        assert!(removed.contains(&"2026-09-02".into()));
        assert!(tmp.path().join("2026-09-03").exists());
        assert!(tmp.path().join("2026-09-04").exists());
        assert!(tmp.path().join("README.md").exists());
    }

    #[test]
    fn flush_writes_dataset() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = Store::new(tmp.path(), 7, "replay");
        let flow = Flow {
            src: Ipv4Addr::new(10, 0, 0, 95),
            dst: Ipv4Addr::new(1, 1, 1, 1),
            src_port: 50000,
            dst_port: 443,
            proto: 6,
            packets: 3,
            bytes: 300,
            tcp_flags: 0,
            unix_secs: 1_700_000_000,
        };
        store.note_datagram();
        store.ingest_flow(&flow, &classify(&flow), None);
        store.flush().unwrap();
        assert!(tmp.path().join("metadata.json").exists());
        assert!(tmp.path().join("README.md").exists());
        let day = crate::clock::day_utc(flow.unix_secs);
        let clients = fs::read_to_string(tmp.path().join(day).join("clients.jsonl")).unwrap();
        assert!(clients.contains("10.0.0.95"));
        let meta: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(tmp.path().join("metadata.json")).unwrap())
                .unwrap();
        assert_eq!(meta["dpi"]["engine"], "port");
        assert_eq!(meta["schema_version"], SCHEMA_VERSION);
    }
}
