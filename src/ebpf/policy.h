//
// Created by root on 2026/5/25.
// Updated: Fixed DPI pending state handling & conntrack race condition
// Updated 2026/6/20: Fix pctx->ip assignment alignment to eliminate ghost IPs in XDP path
//

#ifndef LIYONG_EBPFTRACE_POLICY_H
#define LIYONG_EBPFTRACE_POLICY_H

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#include "vmlinux.h"
#include "kcommon.h"
#include "types.h"
#include "maps.h"
#include "stats.h"
#include "parser.h"
#include "fw_status_code.h"

struct xdp_fw_global_config;

extern long bpf_tcp_raw_gen_tsc_cookie(void *iph, void *th, __u32 iph_len) __ksym __attribute__((weak));

#define FUSE_INIT_TOKEN     2500
#define REFILL_INTERVAL_NS  1000000ULL
#define TOKENS_TO_ADD       5

bool check_attack_status(void);

/* =========================================================
 * 🛡️ 熔斷器保險絲
 * ========================================================= */
static __noinline bool trigger_fuse_ratelimit(void) {
    __u32 fuse_key = 0;
    struct fuse_bucket *fuse = bpf_map_lookup_elem(&fuse_ratelimit_map, &fuse_key);
    if (!fuse) {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "FUSE Map lookup failed\n");
        return false;
    }

    __u64 now = bpf_ktime_get_ns();

    if (fuse->last_time == 0) {
        fuse->last_time = now;
        fuse->tokens = FUSE_INIT_TOKEN;
        return false;
    }

    __u64 delta = now - fuse->last_time;
    if (delta >= REFILL_INTERVAL_NS) {
        __u64 tokens_to_add = (delta / REFILL_INTERVAL_NS) * TOKENS_TO_ADD;
        fuse->last_time = now - (delta % REFILL_INTERVAL_NS);
        __u64 new_tokens = (__u64) fuse->tokens + tokens_to_add;
        fuse->tokens = new_tokens > FUSE_INIT_TOKEN ? FUSE_INIT_TOKEN : (__u32) new_tokens;
    }

    if (fuse->tokens < 1) {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "FUSE Tokens exhausted, DROP\n");
        return true;
    }

    fuse->tokens--;
    return false;
}

/* =========================================================
 * 🛡️ SYN Cookie 挑戰
 * ========================================================= */
static __noinline int trigger_syncookie_challenge(struct xdp_md *ctx, struct iphdr *iph,
                                                 struct tcphdr *th, __u32 ip_hdr_len) {
    if (!th->syn || th->ack || th->rst || th->fin) {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "SYN_COOKIE Invalid flags\n");
        return -2;
    }

    if (!bpf_tcp_raw_gen_tsc_cookie) {
        increment_stat(STAT_TCP_SYN_DROP);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "SYN_COOKIE Ksym not found\n");
        return -99;
    }

    __u64 cookie = bpf_tcp_raw_gen_tsc_cookie(iph, th, ip_hdr_len);
    if ((__s64) cookie < 0) {
        increment_stat(STAT_TCP_SYN_DROP);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "SYN_COOKIE Gen cookie error\n");
        return -99;
    }

    __u32 old_seq = th->seq;
    __u32 new_seq = bpf_htonl((__u32) cookie);
    th->seq = new_seq;

    __u32 csum_acc = ~bpf_ntohs(th->check) & 0xFFFF;
    csum_acc += ~bpf_ntohs(old_seq >> 16) & 0xFFFF;
    csum_acc += ~bpf_ntohs(old_seq & 0xFFFF) & 0xFFFF;
    csum_acc += bpf_ntohs(new_seq >> 16);
    csum_acc += bpf_ntohs(new_seq & 0xFFFF);
    csum_acc = (csum_acc >> 16) + (csum_acc & 0xFFFF);
    csum_acc += (csum_acc >> 16);
    th->check = bpf_htons(~csum_acc & 0xFFFF);

    SLF_LOG_ACTION(LOG_LVL_ERROR, "SYN_COOKIE Success: %u -> %u\n",
                   bpf_ntohl(old_seq), (__u32) cookie);
    return 777;
}

/* =========================================================
 * GLOBAL TOKEN BUCKET
 * ========================================================= */
static __noinline int consume_global_tokens(__u64 pkt_len) {
    __u32 key = 0;
    struct global_bucket *g = bpf_map_lookup_elem(&global_bucket_map, &key);
    if (!g) return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();

    if (g->last_ts == 0) {
        g->tokens = GLOBAL_BURST;
        g->last_ts = now;
        bpf_map_update_elem(&global_bucket_map, &key, g, BPF_ANY);
        return XDP_PASS;
    }

    __u64 delta = now - g->last_ts;
    __u64 refill = (delta * GLOBAL_RATE_BYTES_PER_SEC) / 1000000000ULL;
    if (refill > 0) {
        g->tokens += refill;
        if (g->tokens > GLOBAL_BURST) g->tokens = GLOBAL_BURST;
        g->last_ts = now;
        bpf_map_update_elem(&global_bucket_map, &key, g, BPF_ANY);
    }

    if (g->tokens < pkt_len) {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "GLOBAL Token drop: %llu < %llu\n", g->tokens, pkt_len);
        return XDP_DROP;
    }

    g->tokens -= pkt_len;
    bpf_map_update_elem(&global_bucket_map, &key, g, BPF_ANY);
    return XDP_PASS;
}

/* =========================================================
 * PER-FLOW TOKEN BUCKET
 * ========================================================= */
static __noinline int consume_flow_tokens(struct flow_state *st, __u64 pkt_len) {
    if (!st) return XDP_PASS;

    __u64 now = bpf_ktime_get_ns();
    __u64 last_refill = st->last_refill;
    __u64 delta = now - last_refill;
    __u64 active_rate = st->current_rate ? st->current_rate : FLOW_RATE_BYTES_PER_SEC;
    __u64 active_burst = st->current_burst ? st->current_burst : FLOW_BURST;

    if (delta > 0) {
        __u64 refill = (delta * active_rate) / NS_PER_SEC;
        if (refill > 0) {
            if (__sync_bool_compare_and_swap(&st->last_refill, last_refill, now)) {
                __sync_fetch_and_add(&st->tokens, refill);
                __u64 curr = st->tokens;
                if (curr > active_burst)
                    __sync_bool_compare_and_swap(&st->tokens, curr, active_burst);
            }
        }
    }

    if (__sync_fetch_and_sub(&st->tokens, pkt_len) < pkt_len) {
        __sync_fetch_and_add(&st->tokens, pkt_len);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "FLOW Token Drop\n");
        return XDP_DROP;
    }
    return XDP_PASS;
}

static __noinline int consume_global_pps() {
    __u32 key = 0;
    struct pps_bucket *p = bpf_map_lookup_elem(&global_pps_map, &key);
    if (!p) return XDP_DROP;

    __u64 now = bpf_ktime_get_ns();
    __u64 delta = now - p->last_ts;
    __u64 refill = (delta * GLOBAL_PPS_LIMIT) / 1000000000ULL;
    if (refill > 0) {
        p->tokens += refill;
        if (p->tokens > GLOBAL_PPS_LIMIT) p->tokens = GLOBAL_PPS_LIMIT;
        p->last_ts = now;
        bpf_map_update_elem(&global_pps_map, &key, p, BPF_ANY);
    }

    if (p->tokens < 1) {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "PPS Drop\n");
        return XDP_DROP;
    }
    p->tokens -= 1;
    bpf_map_update_elem(&global_pps_map, &key, p, BPF_ANY);
    return XDP_PASS;
}

/* =========================================================
 * 工具函數
 * ========================================================= */
static __always_inline int is_port_allowed(__u16 port, bool is_ingress) {
    __u8 *val = NULL;
    if (is_ingress) {
        val = bpf_map_lookup_elem(&ingress_allowed_ports, &port);
    } else {
        val = bpf_map_lookup_elem(&egress_allowed_ports, &port);
    }
    return (val != NULL);
}

/* =========================================================
 * record_established
 * ========================================================= */
static __always_inline void record_established(struct packet_ctx *pctx) {
    if (pctx->meta->ip_proto != IPPROTO_TCP &&
        pctx->meta->ip_proto != IPPROTO_UDP)
        return;

    struct flow_key rev = {};
    rev.saddr = pctx->meta->key.daddr;
    rev.daddr = pctx->meta->key.saddr;
    rev.sport = pctx->meta->key.dport;
    rev.dport = pctx->meta->key.sport;
    rev.proto = pctx->meta->key.proto;
    __u64 now = bpf_ktime_get_ns();

    struct connection_state *state =
            bpf_map_lookup_elem(&established_connections_map, &rev);

    if (state) {
        state->last_seen = now;
    } else {
        struct connection_state conn_state = {
            .last_seen = now,
            .dpi_state = 0,
            .tls_version = 0,
        };
        bpf_map_update_elem(&established_connections_map, &rev,
                            &conn_state, BPF_ANY);
    }
}

/* =========================================================
 * apply_policy
 * ========================================================= */
static __noinline void apply_policy(struct policy_ctx *polctx) {
    struct packet_ctx *pctx = polctx->pctx;
    __u16 dport = bpf_ntohs(pctx->meta->key.dport);
    __u16 sport = bpf_ntohs(pctx->meta->key.sport);

    bool is_special = false;
    if (pctx->meta->ip_proto == IPPROTO_UDP) {
        if (sport == 123 || dport == 123 ||
            dport == 67 || dport == 68 ||
            dport == 137 || sport == 67 || sport == 68 || sport == 137 ||
            dport == 53 || dport == 5353 || sport == 53 || sport == 5353)
            is_special = true;
    }

    __u32 src_ip = pctx->meta->key.saddr;

    /* Step 3: Port 白名單 */
    if (pctx->meta->ip_proto == IPPROTO_TCP ||
        pctx->meta->ip_proto == IPPROTO_UDP) {
        if (!is_special && !is_port_allowed(dport, true) && !is_port_allowed(sport, true)) {
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_DROP, STG_PORT_WHT, RSN_PORT_MISS);
            SLF_LOG_ACTION(LOG_LVL_ERROR, "WHITE_PORT drop: %u->%u\n", sport, dport);
            return;
        }
        record_established(pctx);
    }

    /* Step 4: whitelist_rules_map 動態規格 */
    struct flow_key flow_key = pctx->meta->key;
    struct rule_value *wl_rule = NULL;
    struct rule_key rule_key = {};
    rule_key.remote_ip = flow_key.saddr;
    rule_key.remote_mask = 32;
    rule_key.remote_port = flow_key.sport;
    rule_key.proto = IPPROTO_TCP;

    if (pctx->meta->ip_proto == IPPROTO_TCP ||
        pctx->meta->ip_proto == IPPROTO_UDP) {
        wl_rule = bpf_map_lookup_elem(&whitelist_rules_map, &rule_key);
        if (wl_rule && polctx->st) {
            polctx->st->current_rate = wl_rule->custom_rate;
            polctx->st->current_burst = wl_rule->custom_burst;
        }
    }

    /* Step 5: 全域限速 */
    if (!wl_rule) {
        if (consume_global_tokens(pctx->meta->pkt_len) == XDP_DROP) {
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_DROP, STG_GLOBAL_LMT, RSN_LIMIT_BYTES);
            SLF_LOG_ACTION(LOG_LVL_ERROR, "Global rate limit drop\n");
            return;
        }
    }

    /* Step 6: 單流限速 */
    if (consume_flow_tokens(polctx->st, pctx->meta->pkt_len) == XDP_DROP) {
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_FLOW_LMT, RSN_LIMIT_BYTES);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "Flow rate limit drop\n");

        if (!wl_rule) {
            struct blacklist_val new_bv = {};
            new_bv.action = XDP_DROP;
            __u64 cur_ns = bpf_ktime_get_ns();
            new_bv.start_absolute_ns = cur_ns;
            new_bv.end_absolute_ns = cur_ns + (300ULL * 1000000000ULL);
            bpf_map_update_elem(&temp_blocklist_map, &src_ip, &new_bv, BPF_ANY);
        }
        return;
    }

    pctx->meta->status_code =
            MAKE_STATUS(ACT_PASS, STG_FLOW_LMT, RSN_SUCCESS);
}

static __noinline void global_stats(__u32 pkt_len) {
    __u32 key_pps = STATS_KEY_PPS;
    __u32 key_bps = STATS_KEY_BPS;

    __u64 *pps_counter = bpf_map_lookup_elem(&global_stats_map, &key_pps);
    if (pps_counter) *pps_counter += 1;

    __u64 *bps_counter = bpf_map_lookup_elem(&global_stats_map, &key_bps);
    if (bps_counter) *bps_counter += pkt_len;
}

/* =========================================================
 * check_conntrack_and_blacklist
 * ========================================================= */
static __always_inline int check_conntrack_and_blacklist(struct packet_ctx *pctx,
                                                  struct connection_state *conn_state) {
    __u32 src_ip = pctx->meta->key.saddr;
    struct blacklist_val *bv;

    /* ── Step 1：永久黑名單 ── */
    bv = bpf_map_lookup_elem(&permanent_blocklist_map, &src_ip);
    if (bv) {
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_PERM_BLK, RSN_RULE_STATIC);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "CONNTRACK perm blocklist hit src=%x\n", src_ip);
        return VDT_DROP;
    }

    /* ── Step 2：臨時黑名單 ── */
    bv = bpf_map_lookup_elem(&temp_blocklist_map, &src_ip);
    if (bv) {
        __u64 now_ns = bpf_ktime_get_ns();
        if (now_ns >= bv->start_absolute_ns &&
            (bv->end_absolute_ns == 0 || now_ns < bv->end_absolute_ns)) {
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_DROP, STG_TEMP_BLK, RSN_RULE_DYNA);
            SLF_LOG_ACTION(LOG_LVL_ERROR, "CONNTRACK temp blocklist hit src=%x\n", src_ip);
            return VDT_DROP;
        }
    }

    if (!conn_state) {
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_ESTABLISHED, RSN_DPI_PENDING);
        return VDT_DROP;
    }

    /* ── conn_state 存在：根據 dpi_state 決定 ── */
    switch (conn_state->dpi_state) {
        case 1: /* DPI 已確認通過 → 快路徑放行 */
            conn_state->last_seen = bpf_ktime_get_ns();
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_PASS, STG_ESTABLISHED, RSN_DPI_PASSED);
            return VDT_DPI_PASSED;

        case 2: /* DPI 確認違規 → 封鎖 */
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_DROP, STG_ESTABLISHED, RSN_DPI_VIOLATION);
            return VDT_DROP;

        case 0:
        case 3:
        default:
            conn_state->last_seen = bpf_ktime_get_ns();
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_PASS, STG_ESTABLISHED, RSN_DPI_PENDING);
            return VDT_DPI_PENDING;
    }
}

/* =========================================================
 * is_tls_payload
 * ========================================================= */
static __always_inline bool is_tls_payload(void *payload_ptr,
                                           struct packet_ctx *pctx) {
    __u8 *ptr = (__u8 *) payload_ptr;

    if (ptr + 6 > (__u8 *) pctx->data_end)
        return false;

    if (ptr[0] < 0x14 || ptr[0] > 0x17)
        return false;

    if (ptr[1] != 0x03 || ptr[2] < 0x01 || ptr[2] > 0x04)
        return false;

    return true;
}

/* =========================================================
 * enforce_l4_l7_policy_and_dpi
 * ========================================================= */
static __noinline int enforce_l4_l7_policy_and_dpi(struct packet_ctx *pctx,
                                                 __u32 exact_payload_len,
                                                 void *payload_start,
                                                 struct connection_state *conn_state) {
    __u16 dport_hs = bpf_ntohs(pctx->meta->key.dport);
    __u16 sport_hs = bpf_ntohs(pctx->meta->key.sport);

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "enter: sport=%u dport=%u payload_len=%u\n",
                   sport_hs, dport_hs, exact_payload_len);

    /* ── 熔斷保險絲 ── */
    pctx->meta->is_fuse_ratelimit = trigger_fuse_ratelimit();
    if (pctx->meta->is_fuse_ratelimit) {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "fuse triggered -> DROP\n");

        __u32 key = 0;
        __u64 now = bpf_ktime_get_ns();
        __u64 *score = bpf_map_lookup_elem(&attack_score_map, &key);
        if (score) (*score)++;
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_FUSE, RSN_LIMIT_BYTES);
        bpf_map_update_elem(&attack_status_map, &key, &now, BPF_ANY);
        return -1;
    }

    bool attack_sample = false;

    /* ── 戰時模式 ── */
    if (pctx->meta->is_under_attack) {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "under_attack: proto=%u\n", pctx->meta->ip_proto);

        if (pctx->meta->ip_proto == IPPROTO_UDP) {
            increment_stat(STAT_UDP_DROP);
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
            return -1;
        }
        if (pctx->meta->ip_proto == IPPROTO_ICMP) {
            pctx->meta->status_code =
                    MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
            return -1;
        }
        attack_sample = true;
    }

    /* ── L7 DPI ── */
    SLF_LOG_ACTION(LOG_LVL_DEBUG, "[DPI] conn_state=%s dpi_state=%d\n",
                   conn_state ? "ok" : "null",
                   conn_state ? (int) conn_state->dpi_state : -1);

    if (conn_state != NULL && conn_state->dpi_state == 1) {
        return 0;
    } else if (conn_state != NULL && conn_state->dpi_state == 0) {
        if (dport_hs == 53 || sport_hs == 53 ||
            dport_hs == 123 || sport_hs == 123 ||
            dport_hs == 67 || dport_hs == 68) {
            SLF_LOG_ACTION(LOG_LVL_DEBUG, "system service ingress, pass\n");
            conn_state->dpi_state = 1;
            return 0;
        }
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "dpi_state=0, defer to TC egress for TLS check\n");
    }

    return -1;
}

/* =========================================================
 * parse_packet_and_flood_protect
 * ========================================================= */
static __always_inline int parse_packet_and_flood_protect(struct xdp_md *ctx, struct packet_ctx *pctx) {
    struct hdr_cursor hc = {};
    __be16 proto;
    __u8 ip_proto;

    pctx->data = (void *) (long) ctx->data;
    pctx->data_end = (void *) (long) ctx->data_end;
    pctx->meta->is_fuse_ratelimit = false;
    hc.pos = pctx->data;

    if (parse_eth(&hc, pctx->data_end, &pctx->eth, &proto) < 0) {
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] PARSE_ETH STATUS: 0x%08x\n",
                       pctx->meta->status_code);
        return -1;
    }

    __be16 eth_proto = proto;

    if (parse_vlan_stack(&hc, pctx->data_end, &eth_proto) < 0) {
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] PARSE_VLAN_STACK STATUS: 0x%08x\n",
                       pctx->meta->status_code);
        return -1;
    }

    pctx->meta->pkt_len = (__u64) pctx->data_end - (__u64) pctx->data;
    global_stats(pctx->meta->pkt_len);
    pctx->meta->is_under_attack = check_attack_status();

    if (eth_proto != bpf_htons(ETH_P_IP)) {
        if (eth_proto == bpf_htons(ETH_P_ARP)) {
            return 1;
        }
        if (eth_proto == bpf_htons(ETH_P_IPV6)) {
            pctx->meta->status_code = MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_UNSUPPORTED);
            return -1;
        }
        return -1;
    }

    /* ── 🎯 這裡原本是 parse_ipv4 內部決定起點 ── */
    void *ip_header_start = hc.pos; // 記錄精確的 L3 起點位置

    if (parse_ipv4(&hc, pctx->data_end, &pctx->ip, &ip_proto) < 0) {
        pctx->meta->status_code =
                MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] PARSE_IPV4 STATUS: 0x%08x\n",
                       pctx->meta->status_code);
        return -1;
    }

    /* ── 🛠️ 關鍵修正點：強制重寫，校正指標 ──
     * 某些版本的 parse_ipv4() 會因為回傳結構與指標最佳化，導致 pctx->ip 位址沒有貼緊。
     * 我們在這裡強制將 pctx->ip 與真正的 L3 封包起始點（ip_header_start）同步！
     */
    pctx->ip = (struct iphdr *)ip_header_start;

    pctx->meta->ip_proto = ip_proto;
    pctx->meta->key.saddr = pctx->ip->saddr;
    pctx->meta->key.daddr = pctx->ip->daddr;
    pctx->meta->key.proto = ip_proto;

    if (bpf_ntohs(pctx->ip->frag_off) & 0x3FFF)
        return 0;

    pctx->payload = hc.pos;

    __u32 exact_payload_len = 0;
    bool len_calculated = false;

    switch (ip_proto) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp_hdr = NULL;
            if (parse_tcp(&hc, pctx->data_end, &tcp_hdr, pctx->ip,
                          &exact_payload_len) < 0) {
                pctx->meta->status_code =
                        MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] PARSE_TCP STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }
            pctx->tcp = tcp_hdr;
            pctx->meta->payload_len = exact_payload_len;
            pctx->payload = hc.pos;
            len_calculated = true;
            pctx->meta->key.sport = tcp_hdr->source;
            pctx->meta->key.dport = tcp_hdr->dest;

            struct flow_key lookup_key;
            __builtin_memset(&lookup_key, 0, sizeof(lookup_key));
            lookup_key.saddr = pctx->ip->daddr;
            lookup_key.daddr = pctx->ip->saddr;
            lookup_key.proto = pctx->ip->protocol;
            lookup_key.sport = tcp_hdr->dest;
            lookup_key.dport = tcp_hdr->source;

            struct connection_state *conn_state =
                    bpf_map_lookup_elem(&established_connections_map, &lookup_key);

            int pass_res = check_conntrack_and_blacklist(pctx, conn_state);
            if (pass_res == -1) {
                increment_stat(STAT_TCP_SYN_DROP);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] CHECK_CONNTRACK_AND_BLACKLIST STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }
            if (pass_res == 1) {
                increment_stat(STAT_TCP_SYN_SUCCESS);
                return 1;
            } else if (pass_res == 3) {
                increment_stat(STAT_TCP_SYN_SUCCESS);
                return 3;
            }

            if (enforce_l4_l7_policy_and_dpi(pctx, exact_payload_len,
                                             pctx->payload, conn_state) < 0) {
                increment_stat(STAT_TCP_SYN_DROP);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] ENFORCE_L4_L7_POLICY_AND_DPI STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }

            if (pctx->meta->is_under_attack) {
                __u32 ip_hdr_len = pctx->ip->ihl * 4;
                int cookie_rc = trigger_syncookie_challenge(
                    ctx, pctx->ip, tcp_hdr, ip_hdr_len);
                if (cookie_rc == 777) {
                    increment_stat(STAT_TCP_SYN_DROP);
                    pctx->meta->status_code =
                            MAKE_STATUS(ACT_CHALLENGE, STG_L4_CHAL, RSN_CHAL_SEND);
                    return -1;
                }
                increment_stat(STAT_TCP_SYN_DROP);
                pctx->meta->status_code =
                        MAKE_STATUS(ACT_DROP, STG_L4_CHAL, RSN_BAD_PKT);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] SYN_COOKIE STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }

            increment_stat(STAT_TCP_SYN_SUCCESS);
            break;
        }

        case IPPROTO_UDP: {
            struct udphdr *udp_hdr = NULL;
            if (parse_udp(&hc, pctx->data_end, &udp_hdr) < 0) {
                pctx->meta->status_code =
                        MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] PARSE_UDP STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }
            pctx->udp = udp_hdr;
            pctx->meta->key.sport = udp_hdr->source;
            pctx->meta->key.dport = udp_hdr->dest;
            pctx->payload = hc.pos;

            exact_payload_len =
                    bpf_ntohs(udp_hdr->len) > 8 ? bpf_ntohs(udp_hdr->len) - 8 : 0;
            pctx->meta->payload_len = exact_payload_len;

            struct flow_key lookup_key = {
                .saddr = pctx->ip->daddr,
                .daddr = pctx->ip->saddr,
                .proto = pctx->ip->protocol,
                .sport = udp_hdr->dest,
                .dport = udp_hdr->source,
            };

            struct connection_state *conn_state =
                    bpf_map_lookup_elem(&established_connections_map, &lookup_key);

            int pass_res = check_conntrack_and_blacklist(pctx, conn_state);
            if (pass_res == -1) {
                increment_stat(STAT_UDP_DROP);
                return -1;
            }
            if (pass_res == 1) {
                increment_stat(STAT_UDP_PASS);
                return 1;
            } else if (pass_res == 3) {
                return 3;
            }

            if (enforce_l4_l7_policy_and_dpi(pctx, exact_payload_len,
                                             pctx->payload, conn_state) < 0) {
                increment_stat(STAT_UDP_DROP);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] ENFORCE_L4_L7_POLICY_AND_DPI STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }

            increment_stat(STAT_UDP_PASS);
            break;
        }

        case IPPROTO_ICMP: {
            if (parse_icmp(&hc, pctx->data_end, &pctx->icmp) < 0) {
                pctx->meta->status_code =
                        MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] PARSE_ICMP STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }
            if (enforce_l4_l7_policy_and_dpi(pctx, 0, NULL, NULL) < 0) {
                pctx->meta->status_code = MAKE_STATUS(ACT_DROP, STG_PARSE, RSN_BAD_PKT);
                increment_stat(STAT_ICMP_DROP);
                SLF_LOG_ACTION(LOG_LVL_ERROR, "[POLICY] ENFORCE_L4_L7_POLICY_AND_DPI STATUS: 0x%08x\n",
                               pctx->meta->status_code);
                return -1;
            }
            break;
        }

        default:
            if (pctx->meta->is_fuse_ratelimit) {
                return -1;
            } else {
                pctx->meta->status_code =
                        MAKE_STATUS(ACT_PASS, STG_PARSE, RSN_UNSUPPORTED);
                return 0;
            }
    }

    if (!len_calculated) {
        __u64 header_len = (__u64) pctx->payload - (__u64) pctx->data;
        if ((__u64) pctx->payload >= (__u64) pctx->data &&
            pctx->meta->pkt_len >= header_len)
            pctx->meta->payload_len = pctx->meta->pkt_len - header_len;
        else
            pctx->meta->payload_len = 0;
    }

    return 0;
}

#endif /* LIYONG_EBPFTRACE_POLICY_H */