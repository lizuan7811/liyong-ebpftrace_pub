# 資料結構與 BPF Maps

## 核心資料結構（`types.h`）

所有結構雙端共用（Kernel Space + User Space）：

| 結構體 | 用途 |
|---|---|
| `flow_key` | 五元組 (saddr, daddr, sport, dport, proto)，Map Key |
| `flow_state` | 每條 Flow 的令牌桶狀態、速率、時間戳 |
| `connection_state` | Conntrack 條目，含 DPI 狀態 (0=Pending / 1=Passed / 2=Blocked) |
| `packet_meta` | 解析後的封包元資料，存入 per-CPU scratch map（繞過 BPF stack 512B 限制） |
| `packet_ctx` | 封包指標上下文，放 stack（含 ip/tcp/udp 指標，不放 Map） |
| `policy_ctx` | 策略執行上下文（綁定 pctx + flow_state） |
| `rule_key / rule_value` | 白名單規則鍵值對，`rule_key.src_ip` 實際語意為「連外目標 IP（remote_ip）」 |
| `blacklist_val` | 黑名單條目，含絕對時間戳封鎖區間（`start_absolute_ns` / `end_absolute_ns`） |
| `event` | 上報事件，含 BASIC / L7 DPI union，`__attribute__((packed))` |
| `global_bucket / fuse_bucket / pps_bucket` | 各層令牌桶 |

---

## BPF Maps（`maps.h`）

| Map 名稱 | 類型 | 用途 |
|---|---|---|
| `flow_table` | LRU_HASH | 每條 Flow 的速率狀態（令牌桶） |
| `established_connections_map` | LRU_HASH | Conntrack 快路徑（TC 寫、XDP 讀，共享 FD） |
| `whitelist_rules_map` | LRU_HASH + **PIN_BY_NAME** | 動態白名單規則，釘選 bpffs，跨程式共享且跨重啟保留 |
| `permanent_blocklist_map` | HASH | 永久黑名單 |
| `temp_blocklist_map` | LRU_HASH | 動態封鎖（含絕對時間到期自動解封） |
| `global_bucket_map` | PERCPU_ARRAY | 全域位元組令牌桶 |
| `global_pps_map` | ARRAY | 全域 PPS 令牌桶 |
| `fuse_ratelimit_map` | PERCPU_ARRAY | 熔斷保險絲令牌桶 |
| `allowed_ports` | HASH | Port 白名單門禁（TCP/UDP 目標埠） |
| `global_stats_map` | PERCPU_ARRAY | 全域吞吐量計數（Lock-Free，PPS + BPS） |
| `stats_map` | ARRAY | 協議層計數（TCP_OK / TCP_DROP / UDP_PASS / ...） |
| `report_to_user_map` | HASH (10001格) | 普通事件批次上報，按 saddr % 10000 分桶聚合降噪 |
| `l7_dpi_ringbuf` | RINGBUF | L7 DPI 事件即時推送（event-driven） |
| `pctx_scratch_map` | PERCPU_ARRAY | `packet_meta` 的 Per-CPU 暫存區 |
| `event_scratch_map` | PERCPU_ARRAY | `event` 的 Per-CPU 暫存區 |
| `attack_status_map` | ARRAY | 最後一次攻擊的時間戳（ns） |
| `attack_score_map` | ARRAY | 攻擊評分累積 |

`whitelist_rules_map` 透過 `LIBBPF_PIN_BY_NAME` 釘選到 `/sys/fs/bpf/whitelist_rules_map`，libbpf 載入時若路徑已存在則自動 reuse，Map 內容跨重啟保留，無需額外序列化。

> `attack_score_map` 目前存在清零競態問題，詳見 [`roadmap.md`](roadmap.md#現有問題與技術債)。
