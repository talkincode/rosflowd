# AGENTS.md — rosflowd

给在本仓库工作的 Agent 与人类开发者。先读 [`docs/roadmap.md`](docs/roadmap.md) 的画像与非目标，再改代码。实现核对 [`docs/checklist.md`](docs/checklist.md)。

## 这是什么

无界面守护进程：接收 RouterOS 导出的流量记录，按客户端汇总行为，写成最多保留 7 天的本地统计文件。单二进制发布。

## 品质优先级

1. **客户端身份正确** 高于应用识别精度。NAT/WAN-only 流不得冒充 LAN 客户端。
2. **字节量可加总** 高于 DPI 覆盖率。分类失败记 `unknown`，不得丢 IPFIX/NetFlow 计数。
3. **文件契约稳定** 高于新字段。改 `metadata.json` schema 必须升 `schema_version`。
4. **机器可验证** 高于真机演示。没有回放夹具就不要声称某种 ingest 已完成。

## 硬边界

- 不做 UI、不做长期数据库、不做 TeamsACS 子系统。
- 不在 CPE 上开全量镜像；**只有 TZSP 采样包**进 nDPI。
- 不把 NetFlow/IPFIX 称为 DPI。`confidence=ndpi` 只来自采样。
- 不解密 TLS。加密流量最多用 SNI/QUIC/DNS/JA3 类侧信道。
- 仓库与产物不写明文凭据、内网管理地址、客户流量原文。
- 不把 `100.64/10`（CGNAT/管理隧道）默认当家庭 LAN 客户端。

## 工作方式

默认 TDD：先写失败测试，再写最小实现。副作用（UDP、文件系统、时钟）必须可注入。

建议命令：

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## 验收矩阵（硬性规定）

完整矩阵只维护在 [`docs/roadmap.md`](docs/roadmap.md)「验收矩阵」。MUST：

1. 每个一级功能至少有一条 Happy Path 的 E2E 验证。
2. 每个高风险功能至少覆盖一条失败路径。
3. 每个涉及权限的功能至少验证两种角色（本项目无多角色时，在矩阵写「不适用」并说明原因）。
4. 每个会修改系统状态的操作至少验证一次失败后的恢复或回滚。
5. 每次新增一级业务功能，必须同步新增对应的 E2E 并更新 `docs/roadmap.md` 的验收矩阵，否则变更不完整。

## 数据目录契约

默认输出：

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

保留天数由配置决定，默认 7 个日历日，过期删除整个日目录。`metadata.json` 是 schema 真值。
