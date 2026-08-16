# 現有問題與優化路線圖

## 現有問題與技術債

### `report_to_user_map` 全量輪詢開銷

用戶態每秒對 HASH map 做全量 `bpf_map_get_next_key` + `bpf_map_lookup_elem` + `bpf_map_delete_elem` 三次系統呼叫，在事件密集時 CPU 開銷線性增長。這是兩條路徑各司其職的設計代價，可接受但需注意上限。

### `attack_score_map` 清零競態

```c
*score = 0;  // ❌ 直接指標寫入，SMP 下有競態
```

應改為 `bpf_map_update_elem()` 確保原子性。

---

## 優化方向

### 6.1 短期（穩定性）

- 修正 `attack_score_map` 清零競態問題（改用 `bpf_map_update_elem()`）
- 相關即時黑名單操作，詳見 [`userspace.md`](userspace.md#sigusr1-外部管控通道)

### 6.2 中期（功能增強）

**DPI 事件處理 Producer-Consumer + Thread Pool**

當 `handle_l7event` 的 DPI 邏輯日趨複雜，處理時間拉長會阻塞 `ring_poll_thread` 的消費迴圈，導致 Ring Buffer overflow 丟事件。解法是 `ring_poll_thread` 只做 enqueue，另開 worker thread pool 消費：

```
ring_poll_thread（1 個）
    │
    │  handle_l7event → 只做 enqueue
    ▼
[ bounded ring queue ]
    │
    ├── worker thread 1 → DPI 解析 → 回寫 conn_state
    ├── worker thread 2 → DPI 解析 → 回寫 conn_state
    └── worker thread N → DPI 解析 → 回寫 conn_state
```

注意：多 worker 並發回寫同一 flow 的 `conn_state` 時，`bpf_map_update_elem` 是 last-write-wins，需確認對 DPI 狀態機的可接受性。worker 數量建議對齊實體 CPU 核心數。現階段 DPI 邏輯尚輕可暫緩，但 queue 抽象層建議提前預留。

**動態速率注入 API**

增加 Unix Domain Socket 控制通道，允許執行期動態調整 BPF `.data` 中的速率參數，不需重啟即可調整防禦規格。

**規則檔（`rules.txt`）動態載入**

設定檔中已有 `rule_file_path` 欄位但尚未實作對應解析邏輯，應補上完整規則解析器，支援 CIDR 格式黑白名單。

**Conntrack GC**

`established_connections_map` 和 `flow_table` 依賴 LRU 自動淘汰，在連線量暴增時可能淘汰合法連線。可新增 userspace 週期性掃描，主動刪除 `last_seen` 過舊的條目。

**IPv6 支援**

`flow_key` 的 `saddr / daddr` 目前為 `__u32`（IPv4 only），支援 IPv6 需擴展為 `__u8[16]` 並調整所有相關 Map 定義（詳見 [`maps.md`](maps.md)）。

### 6.3 進階（架構演進）

**SYN Cookie 驗證回路**

目前只有發送挑戰（`bpf_tcp_raw_gen_tsc_cookie`），缺少對後續 ACK 封包的驗證（`bpf_tcp_raw_check_tsc_cookie`），完整的 SYN Cookie 機制需補上入方向的驗證邏輯（見 [`dataplane.md`](dataplane.md#syn-cookie-挑戰)）。

**其餘 Map 的跨重啟保留**

`whitelist_rules_map` 已透過 PIN_BY_NAME 實現跨重啟保留。若 `temp_blocklist_map`（動態黑名單）也需要保留，可同樣加上 PIN，重啟後 libbpf 自動 reuse，黑名單封鎖不因重啟失效。

**可觀測性增強**

- `attack_score_map` 分數變化透過 Ring Buffer 推送，外接 Prometheus metrics
- status_code 三段解碼接入 ELK / Loki 結構化日誌

詳見 [`monitoring.md`](monitoring.md)。
