# Build and run

## Local

Needs **nDPI 6.x** + pkg-config (`brew install ndpi` or `scripts/ci-ndpi.sh`). Default builds **dynamically** link `libndpi`.

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

## Linux release

Tag `v*` on `main` runs `.github/workflows/release.yml` and attaches:

- `rosflowd-linux-amd64.tar.gz`
- `rosflowd-linux-arm64.tar.gz`

plus `.sha256` sidecars. Builds are **gnu libc + nDPI 6.0** (not musl). The host needs `libndpi.so.6` at runtime (`scripts/ci-ndpi.sh` or distro package).

Manual:

```bash
bash scripts/ci-ndpi.sh
cargo build --release --locked
```
