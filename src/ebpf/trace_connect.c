#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "log.h"
#include "types.h"
#include "maps.h"

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

/* =========================================================
 * 🎯 dpi_state 編碼修正
 *
 *   原本 dpi_state 是「一次性」標記：只要不是 0，這條 flow
 *   就永遠不會再把封包送進 ring buffer，導致 TLS ClientHello
 *   被 TCP 分段時，userspace 永遠拿不到第二片資料、永遠卡在
 *   「還沒解析出 SNI」。
 *
 *   這裡把原本的 __u8 dpi_state 拆成兩個 nibble，不需要更動
 *   struct connection_state 的大小：
 *     - 低 4 bits：分類狀態 (DPI_xxx)
 *     - 高 4 bits：已經送出過幾次續傳封包 (attempts)
 *
 *   只要狀態還是 DPI_TLS_PENDING 且 attempts 沒超過上限，
 *   就持續把後續封包的 payload 送給 userspace 拼接 SNI；
 *   超過上限就標記成 DPI_TLS_DONE，停止繼續送，避免無限灌爆
 *   ring buffer。
 * ========================================================= */
#define DPI_ST_MASK        0x0F
#define DPI_ST(x)          ((x) & DPI_ST_MASK)
#define DPI_ATTEMPTS(x)    ((x) >> 4)
#define DPI_MAKE(state, attempts) \
((__u8)((((attempts) & 0x0F) << 4) | ((state) & DPI_ST_MASK)))

#define DPI_UNKNOWN        0   // 尚未分類（新連線）
#define DPI_IGNORE         1   // 非 TLS / 不需要 DPI 的流量
#define DPI_BLOCKLIST      2   // 命中黑名單
#define DPI_TLS_PENDING    3   // TLS，SNI 尚未組裝完成，等待續傳
#define DPI_TLS_DONE       4   // TLS 處理結束（解析完成或已放棄重試）

#define MAX_DPI_ATTEMPTS   5    // 最多續傳幾次封包給 userspace 拼 SNI

#define MAX_L7_PAYLOAD     DPI_PAYLOAD_SNAP_LEN

#define L3_OFFSET     14

/*
 * 🔧 編譯器屏障 (compiler barrier)
 *
 * 用途：強迫 clang「忘記」它在編譯期已經對某個變數推導出的數值
 * range，避免它把後面看似「多餘」的檢查當成死代碼直接刪掉。
 *
 * 這裡踩到的坑是：函式最前面已經有
 *     if (copy_len == 0) return TC_ACT_OK;
 * clang 在 -O2 下會靜態證明，後面任何 `len = copy_len; if (len==0)`
 * 這種重複檢查永遠不可能成立，於是直接把這條分支整個刪除（dead
 * code elimination）。結果產生出來的 BPF bytecode 跟完全沒加這個
 * 檢查時一模一樣，verifier 當然還是看到同樣的 [0, MAX] range，
 * 跟我們有沒有寫這段「就近檢查」完全無關。
 *
 * 解法：在賦值之後、檢查之前插入 barrier_var()。它是一個
 * `asm volatile` block，對 clang 來說是不透明的（opaque），會讓
 * 編譯器在這個時間點「重新開始」追蹤這個變數的值，不能再假設它
 * 跟之前推導出的 range 相同。這樣後面的 `if (len == 0)` 就不會被
 * 證明成死代碼，會真的被編譯成一條 compare + jump 指令，BPF
 * verifier 才能在這個呼叫點看到精確、收斂過的 range（smin >= 1）。
 */
#define barrier_var(var) asm volatile("" : "+r"(var))

SEC("tc/egress")
int tc_egress_record(struct __sk_buff *skb) {
    if (skb->len < 34) return TC_ACT_OK;

    struct iphdr iph;
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, L3_OFFSET, &iph, sizeof(iph)) < 0)
        return TC_ACT_OK;

    // 🎯 強制檢查 IP 版本是否為 4 (0x45 為標準 IPv4 Header 起始)
    // 如果不是 4，直接丟棄，徹底解決 0.0.0.0 問題
    if ((iph.version != 4) || (iph.ihl < 5) || (iph.protocol != IPPROTO_TCP && iph.protocol != IPPROTO_UDP))
    {
        return TC_ACT_OK;
    }

    struct flow_key key = {};
    __builtin_memset(&key, 0, sizeof(key));
    key.saddr = iph.addrs.saddr;
    key.daddr = iph.addrs.daddr;
    key.proto = iph.protocol;

    int l4_offset = 14 + (iph.ihl * 4);
    __be16 ports[2] = {0, 0};
    if (bpf_skb_load_bytes(skb, l4_offset, &ports, 4) != 0)
        return TC_ACT_OK;

    key.sport = ports[0];
    key.dport = ports[1];

    __u64 now = bpf_ktime_get_ns();

    struct connection_state* existing = bpf_map_lookup_elem(&established_connections_map, &key);

    if (existing)
    {
        __u8 st = DPI_ST(existing->dpi_state);
        __u8 attempts = DPI_ATTEMPTS(existing->dpi_state);

        // 已經分類完成（非 TLS / 黑名單 / TLS 已解析或已放棄）→ 真正不需要再處理
        if (st == DPI_IGNORE || st == DPI_BLOCKLIST || st == DPI_TLS_DONE)
        {
            existing->last_seen = now;
            return TC_ACT_OK;
        }

        // 🎯 還在等 SNI 組裝完成：這是同一條 TCP 連線的續傳封包，
        //    不需要（也不應該）重新檢查 0x16 ClientHello 開頭，
        //    直接把這個封包的 payload 也送一份給 userspace 拼接。
        if (st == DPI_TLS_PENDING)
        {
            existing->last_seen = now;

            if (attempts >= MAX_DPI_ATTEMPTS)
            {
                // 已經續傳太多次仍未解析出來，放棄並標記完成，
                // 避免這條 flow 無限期灌爆 ring buffer。
                existing->dpi_state = DPI_MAKE(DPI_TLS_DONE, attempts);
                return TC_ACT_OK;
            }

            __u8 tcp_data_offset;
            if (bpf_skb_load_bytes(skb, l4_offset + 12, &tcp_data_offset, 1) != 0)
                return TC_ACT_OK;

            int payload_offset = l4_offset + ((tcp_data_offset >> 4) * 4);
            __u32 total_len = skb->len;
            if (total_len <= payload_offset)
                return TC_ACT_OK; // 這個續傳封包沒有 L7 payload，跳過但不計入 attempts

            struct l7_dpi_event* l7_event = bpf_ringbuf_reserve(
                &l7_dpi_ringbuf, sizeof(struct l7_dpi_event), 0);
            if (!l7_event)
                return TC_ACT_OK;

            l7_event->src_ip = iph.addrs.saddr;
            l7_event->dst_ip = iph.addrs.daddr;
            l7_event->src_port = ports[0];
            l7_event->dst_port = ports[1];
            l7_event->ip_proto = iph.protocol;
            l7_event->timestamp_ns = now;

            // __u32 copy_len = total_len - payload_offset;
            __u32 copy_len = total_len - L3_OFFSET;
            barrier_var(copy_len);
            if (copy_len > MAX_L7_PAYLOAD)
                copy_len = MAX_L7_PAYLOAD; // 真正的上限 clamp，不是取餘數
            if (copy_len <= 0)
                copy_len = 1;
            l7_event->l3_packet_len = copy_len;
            barrier_var(copy_len);

            if (bpf_skb_load_bytes(skb, L3_OFFSET, l7_event->l3_packet, copy_len) < 0)
            {
                bpf_ringbuf_discard(l7_event, 0);
                return TC_ACT_OK;
            }
            l7_event->direction = DIR_OUT;
            bpf_ringbuf_submit(l7_event, 0);

            existing->dpi_state = DPI_MAKE(DPI_TLS_PENDING, attempts + 1);
            return TC_ACT_OK;
        }
    }

    __u8 dpi_state = 0; // 預設 pending
    __u8 tls_version = 0; // 預設 pending
    __u16 dport_hs = bpf_ntohs(ports[1]);
    __u16 sport_hs = bpf_ntohs(ports[0]);
    __u32 dst_ip = iph.addrs.daddr;
    __u32 src_ip = iph.addrs.saddr;

    struct blacklist_val* bv = bpf_map_lookup_elem(&permanent_blocklist_map, &dst_ip);
    if (bv)
    {
        dpi_state = DPI_BLOCKLIST;
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[TC_EGRESS] dst IP in blocklist -> dpi_state=2\n");
    }
    else
    {
        if (dport_hs == 53 || dport_hs == 123 || dport_hs == 67 || dport_hs == 68)
        {
            dpi_state = DPI_IGNORE;
        }
        else if (dport_hs == 443 || dport_hs == 80)
        {
            if (iph.protocol == IPPROTO_TCP)
            {
                __u8 tcp_data_offset;
                if (bpf_skb_load_bytes(skb, l4_offset + 12, &tcp_data_offset, 1) == 0)
                {
                    int payload_offset = l4_offset + ((tcp_data_offset >> 4) * 4);
                    // SLF_LOG_ACTION(LOG_LVL_DEBUG, ">>>>>> [DEBUG] TCP Offset Byte: 0x%02x, Calculated: %d\n",
                    //                tcp_data_offset, (tcp_data_offset >> 4) * 4);
                    __u8 tls_hdr[6] = {};
                    if (bpf_skb_load_bytes(skb, payload_offset, tls_hdr, 6) == 0)
                    {
                        // 🎯 命中 TLS ClientHello
                        // 【除錯日誌】直接印出前 6 個 bytes
                        SLF_LOG_ACTION(LOG_LVL_DEBUG,
                                       "[TC_EGRESS] TLS_HDR: %02x %02x %02x %02x %02x %02x\n",
                                       tls_hdr[0], tls_hdr[1], tls_hdr[2], tls_hdr[3], tls_hdr[4], tls_hdr[5]);

                        if (tls_hdr[0] == 0x16)
                        {
                            if (tls_hdr[1] == 0x03 && tls_hdr[5] == 0x01)
                            {
                                SLF_LOG_ACTION(LOG_LVL_DEBUG, "[TC_EGRESS] TLS ClientHello detected! Type: 0x%02x\n",
                                               tls_hdr[5]);
                                dpi_state = DPI_TLS_PENDING; // 需要深度 DPI 審查，等待後續封包組裝 SNI
                                tls_version = 1; // is TLS

                                // 🚀 【XDP 頂級神技導入】直接在全域 Ring Buffer 預留記憶體空間
                                struct l7_dpi_event* l7_event = bpf_ringbuf_reserve(
                                    &l7_dpi_ringbuf, sizeof(struct l7_dpi_event), 0);

                                // ... 前面保持不變 ...
                                if (l7_event)
                                {
                                    l7_event->src_ip = iph.addrs.saddr;
                                    l7_event->dst_ip = iph.addrs.daddr;
                                    l7_event->src_port = ports[0];
                                    l7_event->dst_port = ports[1];
                                    l7_event->ip_proto = iph.protocol;
                                    l7_event->timestamp_ns = now;

                                    // 🎯 【進階建議】在計算 copy_len 前加強邊界檢查
                                    __u32 total_len = skb->len;
                                    if (total_len <= payload_offset)
                                    {
                                        // 封包長度異常，丟棄此次處理
                                        bpf_ringbuf_discard(l7_event, 0);
                                        return TC_ACT_OK;
                                    }

                                    // 1. 計算原始長度
                                    __u32 copy_len = skb->len - L3_OFFSET;
                                    barrier_var(copy_len);

                                    // 2. 🎯 修正：原本用 `copy_len &= 0x3FF` 是取餘數，不是
                                    //    「限制在 0~1023」，封包較大時會截斷到錯誤的長度
                                    //    （例如 1460 & 0x3FF = 436，而不是 1023）。
                                    //    這裡改成真正的上限 clamp。
                                    if (copy_len > MAX_L7_PAYLOAD)
                                    {
                                        copy_len = MAX_L7_PAYLOAD;
                                    }

                                    // 3. 處理可能為 0 的極端情況：強行變成 1，避免 zero-sized read
                                    if (copy_len <= 0)
                                    {
                                        copy_len = 1;
                                    }

                                    // 4. 此時驗證器追蹤到的 copy_len 範圍是明確的 [1, MAX_L7_PAYLOAD]
                                    l7_event->l3_packet_len = copy_len;
                                    barrier_var(copy_len);

                                    // 🔧 關鍵修正：跟 PENDING 續傳分支同樣的道理，
                                    // 這裡也必須檢查 bpf_skb_load_bytes() 的回傳值，
                                    // 失敗就 discard，不要把 ring buffer 裡的舊垃圾
                                    // 資料當成這條全新連線的第一發封包送出去。
                                    if (bpf_skb_load_bytes(skb, L3_OFFSET, l7_event->l3_packet, copy_len) < 0)
                                    {
                                        bpf_ringbuf_discard(l7_event, 0);
                                    }
                                    else
                                    {
                                        bpf_ringbuf_submit(l7_event, 0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                dpi_state = DPI_IGNORE;
            }
        }
        else
        {
            dpi_state = DPI_IGNORE;
        }
    };


    SLF_LOG_ACTION(LOG_LVL_DEBUG,
                   ">>> [TC_EGRESS] src_ip=%pI4, dst_ip: %pI4 \n",
                   &src_ip, &dst_ip);
    // 🎯 強制轉型為 void*，這是 printk 最喜歡的指標形式
    SLF_LOG_ACTION(LOG_LVL_DEBUG,
                   ">>> [TC_EGRESS] sport: %u, dport: %u, dpi_state: %d\n", // 強制轉為 void* 指標
                   sport_hs,
                   dport_hs,
                   dpi_state);

    struct connection_state new_state = {
        .last_seen = now,
        .dpi_state = DPI_MAKE(dpi_state, (dpi_state == DPI_TLS_PENDING) ? 1 : 0),
        .tls_version = tls_version
    };

    // 1. 先用簡單的區域變數複製出來（這保證了 4-byte 對齊）
    __u32 saddr_val = iph.addrs.saddr;
    __u32 daddr_val = iph.addrs.daddr;

    bpf_map_update_elem(&established_connections_map, &key, &new_state, BPF_ANY);
    return TC_ACT_OK;
}

// =========================================================================
// 🚀 修正後的 trace_connect_tp (完美適配 vmlinux.h)
// =========================================================================
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_tp(struct trace_event_raw_sys_enter* ctx)
{
    // 💡 核心魔法：從 vmlinux.h 的 args 陣列中提取 connect 的參數
    // connect(int fd, struct sockaddr *uservaddr, int addrlen)
    // args[0] = fd, args[1] = uservaddr, args[2] = addrlen
    void* user_addr_ptr = (void*)ctx->args[1];
    long addrlen = ctx->args[2];

    // 🧱 1. 基本邊界檢查：防止結構體越界引發核心崩潰
    if (addrlen < sizeof(struct sockaddr_in))
    {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[TP_CONNECT] Addrlen too small: %ld\n", addrlen);
        return 0;
    }

    // 🧬 2. 安全跨界讀取：將使用者空間記憶體複製到核心空間
    struct sockaddr_in sin = {};
    if (bpf_probe_read_user(&sin, sizeof(sin), user_addr_ptr) != 0)
    {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[TP_CONNECT] Failed to read user memory\n");
        return 0;
    }

    // 🎯 3. 本地迴圈與 DNS 屏蔽：如果是 127.0.0.0/8 (包含本地 DNS 127.0.0.53)，光速放行
    if ((sin.sin_addr.s_addr & bpf_htonl(0xff000000)) == bpf_htonl(0x7f000000))
    {
        return 0;
    }

    // 🤫 4. 非 IPv4 靜音早退：如果是 IPv6 或 Unix Socket
    if (sin.sin_family != AF_INET)
    {
        return 0;
    }

    int xdp_ck = xdp_config_key;
    struct global_config* global_conf = bpf_map_lookup_elem(&global_config_map, &xdp_ck);

    if (!global_conf)
    {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[TP_CONNECT]  global_conf is empty\n");
        return 1;
    }

    struct rule_key wl_key = {};
    wl_key.remote_ip = sin.sin_addr.s_addr; // 外部目標 IP
    wl_key.remote_mask = 32;
    wl_key.remote_port = sin.sin_port;
    wl_key.proto = IPPROTO_TCP;

    struct rule_value wl_rule = {
        .action = 2,
        .priority = 1,
        .custom_rate = global_conf->custom_rate,
        .custom_burst = global_conf->custom_burst,
    };

    if (bpf_map_update_elem(&whitelist_rules_map, &wl_key, &wl_rule, BPF_ANY) != 0)
    {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[TP_CONNECT] Failed to update whitelist map\n");
    }
    else
    {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[TP_CONNECT]  Whitelist added: IP %pI4 Port %u\n",
                       &wl_key.remote_ip, bpf_ntohs(wl_key.remote_port));
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
