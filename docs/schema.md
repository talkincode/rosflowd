# Dataset schema

`metadata.json.schema_version` is currently `rosflowd.dataset.v1`.

Additive optional fields do **not** bump the version. A breaking rename/type change must bump to `rosflowd.dataset.v2` and record the mapping here.

## v1 fields

`metadata.json`: `schema_version`, `retain_days`, `listen`, `time_zone`, `dpi.engine`, `dpi.status`, `dpi.sni`. Optional: `tzsp`.

Day files:

- `clients.jsonl`: `client_ip`, `bytes`, `packets`, `flows`. Optional: `mac`, `hostname`, `ssid`.
- `apps.jsonl`: `client_ip`, `app`, `category`, `confidence`, `bytes`, `packets`, `flows`.
- `hourly.json`: unix-hour string → bytes.
- `ingest.json`: `datagrams`, `flows`, `decode_errors`, `unsupported_version`, `no_client`, `tzsp_datagrams`, `dpi_dropped`.

`dpi.engine` is `port` until nDPI is wired. SNI uses `dpi.sni=true` and `confidence=sni`.
