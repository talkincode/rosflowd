# rosflowd 项目画像与方向

## 项目概述

`rosflowd` 是给 RouterOS 设备用的**无界面流量采集守护进程**。它监听端口，接收设备主动导出的流量记录，按「设备后面的客户端」汇总行为，写成可过期的本地统计文件。没有 Web、没有账号、没有长期库；文件就是对外接口。

第一服务对象是单台家用/实验室 CPE 的运维者（或 Agent）：需要回答「谁在上网、用成什么样」，并且统计在 7 天后自动消失。

- 架构图

```text
  RouterOS
   |  Traffic Flow (NetFlow/IPFIX)     [主通道：字节量]
   |  TZSP / packet sample             [辅通道：才允许 DPI]
   v
  rosflowd (单进程)
   |-- ingest decode
   |-- client identity (RFC1918, 禁止 WAN-only 冒充)
   |-- classify (port → 日后 SNI/nDPI)
   |-- aggregate
   v
  data/YYYY-MM-DD/*.jsonl + metadata.json + README.md
   (retain 7 calendar days)
```

## 项目画像（目标状态）

做好之后：一次启动、一个二进制、一个数据目录。Agent 或人打开当日 `clients.jsonl` 就能看到每个 LAN 客户端的字节量、应用占比和活跃小时，并且知道每条分类的依据（port / sni / ndpi / unknown）。

品质冲突时的优先级：

1. 客户端身份正确（宁可 `unknown_client` 也不把 NAT 后的 WAN 流安到某台手机上）。
2. 计数可加总、可回放。
3. 应用识别尽量准，但失败必须显式降级，不得假装 DPI。
4. 实现简单、可单文件分发。

## 当前能力清单

- NetFlow v5 UDP/回放解码并规范化为 flow 记录。证据：`src/netflow/v5.rs`，`tests/e2e_replay.rs`。
- NetFlow v9 / IPFIX（模板缓存，缺模板的 data set 不计流）。证据：`src/netflow/v9.rs`、`src/netflow/ipfix.rs`，`e2e_replay_v9_lan_https` / `e2e_replay_ipfix_lan_https`。
- UDP 监听收包（可 shutdown）。证据：`e2e_udp_v5_happy_path`。
- 基于知名端口的 L2 分类（`confidence=port`）。证据：`src/classify.rs`。
- RFC1918 客户端主键；WAN-only 流不进入 `clients.jsonl`。证据：`src/identity.rs`，`tests/e2e_replay.rs`。
- 按日写入 `clients.jsonl` / `apps.jsonl` / `hourly.json` / `ingest.json`，根目录 `metadata.json` 与 `README.md`。证据：`src/store.rs`。
- 保留最近 N 个日历日（默认 7），删除更旧日目录。证据：`src/store.rs` 保留测试。
- TZSP 采样、nDPI、DHCP/Wi-Fi 关联：**未实现**。

## 非目标（铁律）

- 不做任何图形界面、仪表盘或用户账号。
- 不做长期数据库或超过保留窗口的历史查询。
- 不并入 TeamsACS / 本仓库以外的控制面。
- 不在 CPE 上要求全量抓包或全量 TZSP。
- 不把 NetFlow/IPFIX 标注为 DPI 结果。
- 不解密 TLS/QUIC 内容。
- 不把 CGNAT/管理隧道地址段（`100.64.0.0/10`）默认当家庭 LAN 客户端。
- 产物与仓库不保存原始包或明文凭据。

## 方向与意图

- **LAN 侧精确计数**：Traffic Flow 从 LAN 桥导出，字节量成为主真值。服务于「这个客户端今天用了多少」。
- **采样后的应用识别**：同一二进制可开 TZSP/包采样，用 SNI 或 nDPI 填 `app`，并在 `metadata.json.dpi.engine` 如实声明。服务于「HTTPS 里大概是谁」，不服务于内容审计。
- **客户端身份增强**：用 DHCP lease / wireless registration 把 IP 升成 MAC/hostname/SSID。服务于人读，不改变「WAN-only 不得冒充」铁律。
- **文件契约给 Agent**：schema 稳定、字段可 jq，保留策略可测。服务于无 UI 的消费方式。

## 完成的样子

当下列结果同时成立，才算这个阶段的 rosflowd 可用：

- 回放一段 LAN NetFlow v5，能得到稳定的 `clients.jsonl` / `apps.jsonl`，WAN-only 夹具不会产生 LAN 客户端主键。
- 数据目录始终能用 `metadata.json` 解释；超过保留窗口的日目录不存在。
- 分类依据可机读；未实现 DPI 时 `dpi.engine` 不是 `ndpi`。
- CI 能挡住解码、身份、落盘、保留的回归。

具体手段建议：单元测试解码/分类/身份；E2E 回放写盘；不强制真机，真机只作人工抽查。

## 验收矩阵（业务能力覆盖矩阵）

> 覆盖底线（硬性规定）：
>
> 1. 每个一级功能至少有一条 Happy Path E2E。
> 2. 每个高风险功能至少覆盖一条失败路径。
> 3. 每个涉及权限的功能至少验证两种角色。
> 4. 每个会修改系统状态的操作至少验证一次失败后的恢复或回滚。
> 5. 每次新增一级业务功能，必须同步新增对应的 E2E 并更新本矩阵。

| 一级功能 | 风险级别 | Happy Path E2E | 失败路径 | 权限角色覆盖 | 失败恢复/回滚 | 证据（测试路径/用例） |
| --- | --- | --- | --- | --- | --- | --- |
| NetFlow v5 解码 | 中 | ✅ | ✅ 短包/错版本 | 不适用（无账号） | 不适用（纯解码） | `netflow::v5` 单测；`e2e_replay_lan_https` |
| 客户端身份 | 高 | ✅ | ✅ WAN-only 无客户端 | 不适用（无账号） | 不适用（不写错主键即恢复） | `identity` 单测；`e2e_wan_only_has_no_client` |
| 端口分类 | 低 | ✅ | ✅ 未知端口 → unknown | 不适用 | 不适用 | `classify` 单测 |
| 日文件落盘 | 中 | ✅ | ✅ 目录不可写 | 不适用 | ✅ 原子替换失败不留半截真文件 | `store` 单测；`e2e_replay_lan_https` |
| 7 日保留 | 中 | ✅ | ✅ 8 日后只剩 7 天 | 不适用 | ✅ 只删过期日目录 | `store::retention_keeps_last_n_days` |
| UDP 监听 | 中 | ✅ | ✅ 无效地址绑定失败 | 不适用 | 不适用（失败则不进入收包循环） | `e2e_udp_v5_happy_path`；`e2e_listen_invalid_addr_fails` |
| TZSP / DPI | 高 | ❌ 缺口 | ❌ 缺口 | 不适用 | 不适用 | 未实现；启用前必须有 golden pcap E2E |
| IPFIX / NetFlow v9 | 中 | ✅ | ✅ 缺模板不计流；IPFIX 长度不符 | 不适用 | 不适用 | `e2e_replay_v9_lan_https`；`e2e_replay_ipfix_lan_https`；`v9::data_without_template_yields_no_flows` |

DPI 在有 golden 包之前不得打开默认引擎。
