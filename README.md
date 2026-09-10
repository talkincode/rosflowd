# rosflowd

无界面 RouterOS 流量采集守护进程。监听 NetFlow/IPFIX，按 LAN 客户端汇总行为，写成最多 7 天的本地统计文件。单二进制，没有 UI。

项目画像、非目标与验收矩阵：[`docs/roadmap.md`](docs/roadmap.md)。实现核对表：[`docs/checklist.md`](docs/checklist.md)。Agent 规范：[`AGENTS.md`](AGENTS.md)。

## 质量与验收

新增一级业务功能时，必须补 Happy Path E2E，并更新 `docs/roadmap.md` 验收矩阵。覆盖底线见该文档，不在 README 重复矩阵内容。

## 运行

```bash
# 回放（无 UDP，适合测试）
rosflowd --replay testdata/example.nfv5 --data ./data

# 监听（RouterOS /ip traffic-flow 指向此地址）
rosflowd --listen 0.0.0.0:2055 --data ./data --retain-days 7

# 可选：同机再听 TZSP（MikroTik /tool sniffer streaming），默关
rosflowd --listen 0.0.0.0:2055 --tzsp 0.0.0.0:37008 --data ./data
```

采集必须来自 **LAN 桥**。WAN 口导出的流在 NAT 之后，无法对应到家里的客户端。

当前分类是知名端口（L2）；TZSP 样本可补 TLS SNI（`confidence=sni`），**不是** DPI。nDPI 未实现。已解码 NetFlow v5/v9 与 IPFIX。

## 数据目录

```text
data/
  README.md
  metadata.json
  YYYY-MM-DD/
    clients.jsonl
    apps.jsonl
    hourly.json
    ingest.json
```

## 开发

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

License: MIT
