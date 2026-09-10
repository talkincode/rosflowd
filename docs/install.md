# Build and run

## Local

```bash
cargo build --release
./target/release/rosflowd --help
```

The release binary is a single file. It writes only under `--data` (default `./data`).

## Replay without UDP

```bash
rosflowd --replay flow.nfv5 --data ./data
rosflowd --replay flow.nfv5 --replay-tzsp sample.tzsp --data ./data
rosflowd --replay flow.nfv5 --identity clients.jsonl --data ./data
```

`clients.jsonl` sidecar lines:

```json
{"ip":"10.0.0.95","mac":"02:00:00:00:00:01","hostname":"phone","ssid":"a2"}
```

SSID is not sniffed from bridged Ethernet. Dump `/interface wireless registration-table` (or equivalent) into this file.

## Listen

```bash
rosflowd --listen 0.0.0.0:2055 --data ./data --retain-days 7
rosflowd --listen 0.0.0.0:2055 --tzsp 0.0.0.0:37008 --data ./data
```

Point RouterOS `/ip traffic-flow` at the collector from a **LAN bridge**. Optional `/tool sniffer streaming` TZSP is sampled only.

## Linux release (manual)

```bash
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

CI does not publish artifacts yet.
