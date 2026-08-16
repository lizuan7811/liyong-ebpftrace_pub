# Userspace 管控程式（`main.c`）

## 事件系統（`events.h`）

兩條上報路徑職責明確，邊界嚴格分離：

| 路徑 | 觸發時機 | Kernel 開銷 | Userspace 消費 | 用途 |
|---|---|---|---|---|
| `l7_dpi_ringbuf` | `dpi_state=0` 的 pending 封包 | 較高（wakeup） | event-driven，幾乎零 CPU | 即時 DPI 決策，回寫 conn_state |
| `report_to_user_map` | 所有普通事件（DROP / 採樣） | 低（就地覆蓋） | 定時全掃，固定開銷 | 批次儀表板展示，天然聚合降噪 |

`process_event` 核心流程：SSH（Port 22）純 ACK 降噪 → metadata 填寫 → flow key 拷貝 → status_code 附加 → payload 安全複製（`data_end` 邊界守衛 + clamp）。

### `status_code` 32-bit 分層編碼

```
[31:24] ACT（行動）    0x01=PASS  0x02=DROP  0x03=CHALLENGE
[23:16] STG（階段）    PARSE / FUSE / ESTABLISHED / PERM_BLK / TEMP_BLK / PORT_WHT / GLOBAL_LMT / FLOW_LMT / L4_CHAL
[15: 0] RSN（原因）    BAD_PKT / PORT_MISS / CONN_TRACK / DPI_PASSED / DPI_VIOLATION / LIMIT_BYTES / CHAL_SEND / ...
```

該編碼便於後續接入 Grafana / ELK 做結構化分析，詳見 [`monitoring.md`](monitoring.md)。

---

## 啟動流程（14 步驟）

1. 載入設定檔 `xdp_fw.conf`
2. 開啟 + 載入 XDP skeleton
3. 開啟 trace_connect skeleton，`reuse_fd` 共享 `established_connections_map` + `whitelist_rules_map`
4. 載入並 attach trace_connect（Tracepoint + TC Egress）
5. 全網卡自動部署 TC Egress 鉤子（去重 ifindex）
6. 注入速率參數到 BPF `.data` section（除以 CPU 核心數做 per-CPU 分配）
7. 偵測本機子網路，注入 `LOCAL_SUBNET_NET` / `LOCAL_SUBNET_MASK`
8. 建立控制環境 `/run/xdp_fw/block_cmd`（權限 700/600）
9. 全網卡自動部署 XDP（優先 DRV 模式，退回 SKB 模式）
10. 取得黑名單 Map FD
11. 初始化熔斷保險絲（初始 0 token）
12. 掛載 SIGUSR1（讀取 block_cmd 動態封鎖）
13. 注入測試黑名單
14. 初始化 Ring Buffer pthread + Port 白名單 + 儀表板主迴圈

---

## 即時儀表板

每秒刷新，ANSI escape code 原地覆蓋，顯示 PPS、Mbps、協議計數、最新 5 筆事件（按核心時間戳排序）。

## SIGUSR1 外部管控通道

讀取 `/run/xdp_fw/block_cmd`，支援：

- `<IP> <秒數>`：封鎖指定秒數
- `<IP> 0`：永久封鎖
- `<IP> YYYY-MM-DD_HH:MM:SS`：預約封鎖

實際操作範例請見 [`deployment.md`](deployment.md#動態封鎖-ip)。

這段程式碼的商業邏輯作用是：「**即時防火牆黑名單更新**」。

用法：當網管人員或自動化腳本發現某個 IP 在進行 DDoS 攻擊時，不需要重啟防火牆，只需執行：

```bash
echo "192.168.1.50 3600" > /run/xdp_fw/block_cmd
kill -USR1 <pid_of_xdp_fw>
```
