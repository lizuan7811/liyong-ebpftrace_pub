# Conntrack + DPI 分工

## 雙向分工原則

| 方向 | 程式 | 負責事項 |
|---|---|---|
| 出方向（Client→Server） | TC Egress (`trace_connect.c`) | 建立 Conntrack 條目，解析 TLS ClientHello，設定 `dpi_state` |
| 入方向（Server→Client） | XDP (`xdp_fw.c`) | 反向查 Conntrack，依 `dpi_state` 決定快路徑或繼續 policy |

「XDP 讀、TC 寫」的分工是本系統最核心的架構決策。TLS ClientHello 只出現在出方向，XDP 入方向看到的是 ServerHello / Certificate，若在 XDP 做 TLS 內容判斷必然誤判。

## `dpi_state` 狀態轉換

```
0 (Pending)  ← TC 建立條目初始狀態
     ↓ TC 看到 TLS ClientHello 或系統服務
1 (Passed)   → XDP Conntrack 快路徑放行
2 (Blocked)  → XDP DROP
```

`dpi_state=0` 時 XDP 一律 pending 放行，等 TC 在後續出方向封包完成判斷。`conn_state == NULL`（TC 條目尚未建立）時同樣 pending 放行，避免 SYN-ACK 被誤殺。

---

## TC Egress 出方向（`trace_connect.c`）

### TC Egress `tc_egress_record`

- 監聽所有出方向 IPv4 TCP/UDP 封包
- 新連線寫入 `established_connections_map`，初始 `dpi_state=0`
- 目標埠 443/80 且 TCP：解析 TLS ClientHello（magic bytes `0x16 0x03 xx 0x01`）
- 目標 IP 在永久黑名單 → `dpi_state=2`
- DNS(53) / NTP(123) / DHCP(67/68) → `dpi_state=1`（直通，不做 TLS 判斷）
- 合法 TLS ClientHello → `dpi_state=1`

### Tracepoint `trace_connect_tp`

- 掛載 `sys_enter_connect` syscall
- 每次用戶程式發起 `connect()` → 自動將目標 IP:Port 寫入 `whitelist_rules_map`
- 速率規格：800MB/s rate / 200MB/s burst（為高信任的自主連外流量）
- 本地迴圈（`127.0.0.0/8`）直接跳過，非 AF_INET 靜音返回

相關的 Map 定義請見 [`maps.md`](maps.md)；DPI 決策後如何回寫 `conn_state` 並產生即時事件，請見 [`userspace.md`](userspace.md#事件系統-eventsh)。
