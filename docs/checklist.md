# rosflowd 清单

对照画像 [`docs/roadmap.md`](roadmap.md)。完成一项须有测试或明确「不适用」理由。这是边界核对表，不是排期。

## 契约

- [x] 无 UI，单二进制
- [x] 数据目录含 `metadata.json` 与 `README.md`
- [x] 按日历日分目录，默认保留 7 天
- [x] WAN-only 流不得写入 LAN 客户端主键
- [x] 不把 NetFlow 结果标成 DPI
- [ ] `schema_version` 变更有升级说明

## 采集

- [x] NetFlow v5 解码 + 回放
- [x] UDP 无效地址绑定失败
- [x] `--replay` 不打开 UDP
- [x] UDP 真实收包 Happy Path
- [x] NetFlow v9
- [x] IPFIX
- [ ] TZSP 采样 ingest（默关）
- [ ] 采样丢包不影响 NetFlow 字节计数

## 身份与分类

- [x] RFC1918 客户端主键
- [x] 端口分类 `confidence=port`
- [ ] DHCP lease 关联 MAC/hostname
- [ ] wireless registration 关联 SSID
- [ ] TLS/QUIC SNI（纯 Rust）
- [ ] nDPI 可选引擎，`metadata.json.dpi.engine` 如实声明

## 发布

- [ ] `cargo build --release` 产物说明
- [ ] Linux amd64/arm64 发布（若做 CI 发布）
- [ ] 覆盖率门禁（需要时再加，不阻塞 v5 回放闭环）
