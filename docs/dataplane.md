# 封包處理管線（Data Pipeline）

## 整體資料流

```
        TC Egress（出方向）          XDP Ingress（入方向）
        trace_connect.c              xdp_fw.c
               ↓                           ↓
       established_connections_map ←→ Conntrack 查表
       whitelist_rules_map（PIN）   ←→ 白名單規則比對
               ↓                           ↓
                        ↓
                  packet_ctx (stack)
                        ↓
                  flow_table (stateful)
                        ↓
                  policy_ctx (decision)
                        ↓
          ┌─────────────┴─────────────┐
          ↓                           ↓
   l7_dpi_ringbuf              report_to_user_map
   (即時 DPI 通知)              (批次儀表板聚合)
          ↓                           ↓
  handle_l7event()           poll_clean_and_print()
  → 回寫 conn_state           → 儀表板展示 + 降噪
```

事件系統的雙通道職責分工細節，請見 [`userspace.md`](userspace.md#事件系統-eventsh)。

## 封包解析鏈

所有封包解析從 `ethhdr` 開始，嚴格按層次推進：

```
Ethernet (ethhdr)
    ↓ h_proto
VLAN Stack（可選，0x8100）
    ↓ proto
IPv4 (iphdr)
    ↓ protocol
TCP / UDP / ICMP
    ↓
Payload
```

IPv4 分片包（`frag_off & 0x3FFF`）直接放行，不污染 Flow Map。

## XDP 入方向處理流程

```
XDP 入口
  → [Stage 1]   解析封包 + 全域統計 + 攻擊狀態偵測
  → [Stage 1-2] 全域 PPS 限速
  → [Stage 1.5] 廣播 / 多播快速過濾
  → [Stage 2]   建立 Flow Key
  → [Stage 3]   查詢或建立 Flow State
  → [Stage 4]   apply_policy
                  永久黑名單
                  → 臨時黑名單（含自動到期）
                  → Port 白名單門禁
                  → 動態白名單規則（whitelist_rules_map）
                  → 全域位元組限速
                  → Per-Flow 位元組限速
  → [Stage 5]   更新流量統計
  → [Stage 6]   採樣事件上報
```

---

## 限速體系（三層令牌桶）

```
[Layer 1] PPS 令牌桶（全域封包數/秒）
               ↓ 超限 → DROP
[Layer 2] Global 位元組令牌桶（全域頻寬）
               ↓ 超限 → DROP
[Layer 3] Per-Flow 位元組令牌桶（單一連線頻寬）
               ↓ 超限 → DROP + 自動升級 temp_blocklist（封鎖 300 秒）
```

Per-Flow 令牌桶使用 `__sync_fetch_and_add` / `__sync_bool_compare_and_swap` 實作無鎖原子操作，避免 SMP 多核競態。命中 `whitelist_rules_map` 的連線可套用規則指定的獨立速率（`custom_rate` / `custom_burst`），跳過全域限速。

---

## 熔斷保險絲（`trigger_fuse_ratelimit`）

- 令牌桶式保險絲，初始 2500 token，每毫秒補充 5 token
- 觸發熔斷 → UDP / ICMP 全部丟棄，TCP 進入 SYN Cookie 挑戰模式
- 攻擊評分（`attack_score_map`）累積，`attack_status_map` 記錄最後攻擊時間戳，動態調整 cooldown（基礎 5 秒，評分加乘，上限 60 秒）

---

## SYN Cookie 挑戰

- 使用核心 kfunc `bpf_tcp_raw_gen_tsc_cookie`（弱符號，核心不支援時降級 DROP）
- 攻擊模式下對所有新 SYN 包進行挑戰，不入 Flow Table
- 挑戰成功回傳 777，封包以 XDP_TX 反向送出

> 目前僅實作發送挑戰，尚缺後續 ACK 驗證回路，相關規劃請見 [`roadmap.md`](roadmap.md#63-進階架構演進)。
