//
// xdp_fw.bpf.c
// Updated:
//   - LOCAL_SUBNET_NET / LOCAL_SUBNET_MASK 實體定義在這裡
//   - verify_broadcast_and_policy 移至此處，不污染共用 policy.h
//

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "types.h"
#include "policy.h"
#include "flow.h"
#include "stats.h"
#include "events.h"
#include "fw_status_code.h"

// =================================================================
// ⚡ 全域速率參數（補上 = 0，強迫編譯器將其分發至 .data 區段，與 Userspace 的 skel->data 對齊）
// =================================================================
volatile bool isInitialed = false; // 使用 const 或 volatile const
const volatile __u64 NUM_CPUS; // 使用 const 或 volatile const
// ⚡ 真正定義這些變數的實體
volatile __u64 GLOBAL_RATE_BYTES_PER_SEC = 0;
volatile __u64 GLOBAL_BURST = 0;
volatile __u64 FLOW_RATE_BYTES_PER_SEC = 0;
volatile __u64 FLOW_BURST = 0;
volatile __u64 GLOBAL_PPS_LIMIT = 0;
/* =========================================================
 * 🌐 本機子網路參數（User-space 啟動時透過 skel->data 注入）
 *
 *   💡 這兩個變數只有 xdp_fw 需要，放在這裡而不放在
 *      policy.h，避免 trace_connect.bpf.c 編譯時找不到
 *      實體而報錯。
 * ========================================================= */
SEC(".data") __u32 LOCAL_SUBNET_NET = 0;
SEC(".data") __u32 LOCAL_SUBNET_MASK = 0;

/* =========================================================
 * 廣播 / 多播定義（只在本檔用到）
 * ========================================================= */
#define IP_BROADCAST        0xFFFFFFFFU
#define IP_MULTICAST_MASK   0xF0000000U
#define IP_MULTICAST_START  0xE0000000U
// 建議定義在檔案頂部，確保使用網路序定義
#define IP_BROADCAST_NET        bpf_htonl(0xFFFFFFFFU)
#define IP_MULTICAST_MASK_NET   bpf_htonl(0xF0000000U)
#define IP_MULTICAST_START_NET  bpf_htonl(0xE0000000U)
/* =========================================================
 * verify_broadcast_and_policy
 *
 *   在進入完整 apply_policy 之前，快速過濾廣播/多播封包。
 *   傳回 XDP_DROP 代表應丟棄，XDP_PASS 代表可繼續處理。
 *
 *   💡 放在 xdp_fw.bpf.c 而非 policy.h，原因：
 *      此函數依賴 LOCAL_SUBNET_NET / LOCAL_SUBNET_MASK，
 *      而那兩個變數只在本程式有實體，trace_connect.bpf.c
 *      不需要也不應該引用它們。
 * ========================================================= */
static __always_inline
long verify_broadcast_and_policy(__u32 saddr, __u32 daddr, __u16 dport)
{
    SLF_LOG_ACTION(LOG_LVL_DEBUG, "VBP_DEBUG saddr=%x, daddr=%x, dport=%u\n", saddr, daddr, bpf_ntohs(dport));

    // 來源是廣播/多播
    if (saddr == IP_BROADCAST_NET) return XDP_DROP;

    if ((saddr & IP_MULTICAST_MASK_NET) == IP_MULTICAST_START_NET)
    {
#ifdef DEBUG
        bpf_printk("[VBP_DEBUG] Drop: saddr is MULTICAST, saddr=%x\n", saddr);
#endif
        return XDP_DROP;
    }

    // 目的是有限廣播
    if (daddr == IP_BROADCAST_NET)
    {
        return (dport == bpf_htons(67)) ? XDP_PASS : XDP_DROP;
    }

    // 目的是多播
    if ((daddr & IP_MULTICAST_MASK_NET) == IP_MULTICAST_START_NET)
    {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "VBP_DEBUG Drop: daddr is MULTICAST, daddr=%x\n", daddr);
        return XDP_DROP;
    }

    // 子網路廣播
    if (LOCAL_SUBNET_MASK != 0)
    {
        __u32 subnet_broadcast = LOCAL_SUBNET_NET | ~LOCAL_SUBNET_MASK;
        if (daddr == subnet_broadcast) return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline __u32 resolve_action(struct policy_ctx* polctx)
{
    struct packet_ctx* pctx = polctx->pctx;

    __u32 policy_action = pctx->meta->status_code & 0xFF000000;

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "[RESOLVE_ACTION] STATUSCODE : 0x%08x\n", pctx->meta->status_code);

    if (policy_action == ACT_DROP)
    {
        return XDP_DROP;
    }
    if (policy_action == ACT_CHALLENGE)
    {
        return XDP_TX;
    }
    return XDP_PASS;
}

__always_inline void init_gconfig_and_gmap(void)
{
    /* =========================================================
     * ⚡ 全域速率參數（User-space 啟動時透過 skel->data 注入）
     * ========================================================= */
    if (isInitialed)
    {
        return;
    }
    int xdp_ck = xdp_config_key;
    struct global_config* global_conf = bpf_map_lookup_elem(&global_config_map, &xdp_ck);
    GLOBAL_RATE_BYTES_PER_SEC = global_conf->global_rate;
    GLOBAL_BURST = global_conf->global_burst;
    FLOW_RATE_BYTES_PER_SEC = global_conf->flow_rate;
    FLOW_BURST = global_conf->flow_burst;
    GLOBAL_PPS_LIMIT = global_conf->global_pps_limit;
    isInitialed = true;
}

/* =========================================================
 * XDP 主程式入口
 * ========================================================= */
SEC("xdp")
int xdp_fw(struct xdp_md* ctx)
{
    init_gconfig_and_gmap();

    __u32 zero = 0;

    struct packet_meta* meta = bpf_map_lookup_elem(&pctx_scratch_map, &zero);
    if (!meta) return XDP_PASS;
    __builtin_memset(meta, 0, sizeof(*meta));

    // packet_ctx 放 stack，56 bytes 沒問題
    struct packet_ctx pctx = {};
    pctx.meta = meta;
    // polctx 改回 stack（只有 24 bytes，完全沒問題）
    struct policy_ctx polctx = {};

    /* ---------------------------------------------------
     * Stage 1: 解析封包 + 熔斷保險絲 + SYN Cookie 前線
     * --------------------------------------------------- */
    int parse_rc = parse_packet_and_flood_protect(ctx, &pctx);

    polctx.pctx = &pctx; // ← 這樣 verifier 能追蹤到 &pctx 是合法的 map_value

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "PARSE_RC: %d\n", parse_rc);

    __u32 xdp_action = resolve_action(&polctx);
    if (parse_rc < 0)
    {
        return xdp_action;
    }
    else if (parse_rc == 1)
    {
        return XDP_PASS;
    }
    else if (parse_rc == 3)
    {
        emit_l7_event(xdp_action, &polctx,EVENT_TYPE_L7_DPI);
        return XDP_PASS;
    }

    /* ---------------------------------------------------
     * Stage 1-2: 🛡️ 強制限流 - 頻率 (PPS)
     * ---------------------------------------------------
     * 只有「正常流量 (0)」與「TCP 續航包 (-2)」等需要繼續往下走的封包，
     * 才會來到這裡接受全域限流排隊。
     * --------------------------------------------------- */
    int pps_rc = consume_global_pps();
    if (pps_rc == XDP_DROP)
    {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[PPS] limit exceeded. Flow PPS blocked\n");
        return XDP_DROP;
    }

    /* ---------------------------------------------------
     * Stage 1.5: 廣播 / 多播快速過濾
     * --------------------------------------------------- */
    if (pctx.ip)
    {
        long bcast_rc = verify_broadcast_and_policy(
            pctx.ip->saddr,
            pctx.ip->daddr,
            pctx.meta->key.dport);
        if (bcast_rc == XDP_DROP)
            return XDP_DROP;
    }

    /* ---------------------------------------------------
     * Stage 2: 建立 Flow Key
     * --------------------------------------------------- */
    build_flow_key(&polctx);

    /* ---------------------------------------------------
     * Stage 3: 查詢或建立 Flow State
     * --------------------------------------------------- */
    struct flow_state* st = lookup_or_create_flow(&polctx);
    if (!st)
        return XDP_PASS;

    /* ---------------------------------------------------
     * Stage 4: 執法策略
     * --------------------------------------------------- */
    polctx.pctx = &pctx;
    polctx.st = st;

    apply_policy(&polctx);
    __u32 xdp_action_af_policy = resolve_action(&polctx);

    // 命中黑名單或 Port 封鎖 → 立刻送出事件，不走採樣
    __u32 sc = polctx.pctx->meta->status_code;
    __u32 policy_stage = sc & 0x00FF0000;
    __u32 policy_reason = sc & 0x0000FFFF;

    if (xdp_action_af_policy == XDP_DROP &&
        (policy_stage == STG_PERM_BLK ||
            policy_stage == STG_TEMP_BLK ||
            policy_reason == RSN_PORT_MISS))
    {
        if (should_emit_event(&polctx, st, xdp_action_af_policy) == 2)
            emit_event(xdp_action_af_policy, &polctx,EVENT_TYPE_BASIC);
        return XDP_DROP;
    }

    /* ---------------------------------------------------
     * Stage 5: 更新統計
     * --------------------------------------------------- */
    update_flow_stats(&pctx, st);

    /* ---------------------------------------------------
     * Stage 6: 採樣事件上報
     * --------------------------------------------------- */
    if (should_emit_event(&polctx, st, xdp_action) == 1)
        emit_event(xdp_action, &polctx,EVENT_TYPE_BASIC);

    return xdp_action;
}

char LICENSE[] SEC("license") = "GPL";
