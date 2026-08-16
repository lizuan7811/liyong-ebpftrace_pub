# 架構總覽

## 一、專案整體定位

本專案是一個基於 Linux eBPF / XDP 技術棧的高效能網路防火牆，核心目標是在封包進入核心網路棧之前，於驅動層（XDP hook）完成流量過濾、限速、DPI 辨識與事件上報，兼具極低延遲與高吞吐的特性。

整體系統定位接近 Cloudflare-style eBPF dataplane，整合了：

- L3/L4 Flow Tracking（五元組有狀態追蹤）
- L7 DPI（TLS ClientHello 辨識）
- Stateful Firewall Engine（Conntrack 快路徑）
- Token Bucket Rate Limiting（三層令牌桶）
- Event Telemetry Pipeline（雙通道事件上報）

系統分為兩個 BPF 程式與一個 Userspace 管理程式：

- `xdp_fw.c`：XDP 入方向（Ingress）主防火牆
- `trace_connect.c`：TC Egress 出方向連線追蹤 + Tracepoint 白名單同步
- `main.c`：Userspace 管控程式（載入、Map 共享、動態策略下發、儀表板）

詳細的封包處理管線請見 [`dataplane.md`](dataplane.md)；BPF 資料結構與 Map 定義請見 [`maps.md`](maps.md)；DPI 與 Conntrack 分工請見 [`dpi.md`](dpi.md)；Userspace 管控程式請見 [`userspace.md`](userspace.md)。

---

## 模組職責概覽

| 模組 | 主要職責 |
|---|---|
| `types.h` | 所有核心 struct（Kernel + Userspace 雙端共用） |
| `maps.h` | 所有 BPF Map 定義 |
| `policy.h` | 限速、Conntrack、DPI、熔斷、SYN Cookie 邏輯 |
| `events.h` | 事件上報邏輯（`process_event` / `emit_event` / `emit_l7_event`） |
| `xdp_fw.c` | XDP 主程式入口 |
| `trace_connect.c` | TC Egress + Tracepoint 程式 |
| `main.c` | Userspace 管控（依賴 `types.h` + skeleton headers） |

---

## 架構亮點

| 亮點 | 說明 |
|---|---|
| XDP + TC 雙向分工 | 入向過濾（XDP）+ 出向學習（TC）實現完整 Conntrack，避免誤殺 |
| TLS DPI 在出方向 | TC 看到 ClientHello 才判斷，XDP 不對入向做 TLS 內容分析 |
| 三層令牌桶限速 | PPS → 全域位元組 → Per-Flow，層層遞進，超限自動升黑名單 |
| per-CPU scratch map | 繞過 BPF stack 512B 限制，`packet_meta` 和 `event` 放入 PERCPU_ARRAY |
| status_code 三段編碼 | 行動 / 階段 / 原因一次打包，便於 Grafana / ELK 大數據分析 |
| PERCPU ARRAY 全域統計 | 完全 Lock-Free 的 PPS + BPS 計數，不影響封包處理路徑 |
| bpffs PIN 跨重啟保留 | `whitelist_rules_map` PIN_BY_NAME，重啟後 libbpf 自動 reuse，規則不遺失 |
| 雙通道事件分離 | ringbuf 負責即時 DPI 決策，hash map 負責批次儀表板，各司其職不混用 |
| 熔斷 + SYN Cookie | 攻擊評分觸發熔斷，UDP/ICMP 全封，TCP 進入 Cookie 挑戰模式 |
| 絕對時間戳封鎖 | `blacklist_val` 使用 TAI 絕對時間戳，支援定時解封和預約封鎖 |

---

## 檔案依賴關係

```
types.h              ← 所有核心 struct（Kernel + Userspace 雙端共用）
  └── maps.h         ← 所有 BPF Map 定義
        ├── policy.h ← 限速、Conntrack、DPI、熔斷、SYN Cookie 邏輯
        │     └── xdp_fw.c        ← XDP 主程式入口
        ├── events.h ← 事件上報邏輯（process_event / emit_event / emit_l7_event）
        │     └── xdp_fw.c（共用）
        └── trace_connect.c       ← TC Egress + Tracepoint 程式

main.c               ← Userspace 管控（依賴 types.h + skel headers）
```
