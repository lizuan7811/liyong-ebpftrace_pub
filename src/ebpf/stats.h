//
// Created by root on 2026/5/25.
//

#ifndef LIYONG_EBPFTRACE_STATS_H
#define LIYONG_EBPFTRACE_STATS_H

#include <stdbool.h>

#include "maps.h"
#include "types.h"
#include <bpf/bpf_endian.h> // 這是必須的

#include "log.h"


static __always_inline

void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    }
}

static __always_inline bool check_attack_status() {
    __u32 key = 0;

    // 1. 取得最後攻擊時間
    __u64 *last_attack_ns = bpf_map_lookup_elem(&attack_status_map, &key);
    if (!last_attack_ns || *last_attack_ns == 0) {
        return false;
    }

    // 🎯 修正：改成正確的 attack_score_map，並在取值時加上 * 號解引用
    __u64 *score = bpf_map_lookup_elem(&attack_score_map, &key);
    __u64 current_score = score ? *score : 0; // 👈 關鍵修正：score -> *score

    __u64 now = bpf_ktime_get_ns();

    // 基礎冷卻 5 秒，每多 1000 次攻擊，冷卻時間就多加 1 秒
    __u64 dynamic_cooldown = 5000000000ULL + (current_score / 1000) * 1000000000ULL;

    if (dynamic_cooldown > 60000000000ULL) {
        dynamic_cooldown = 60000000000ULL;
    }

    if ((now - *last_attack_ns) < dynamic_cooldown) {
        return true;
    }

    // 🎯 修正：這裡也要用 *score = 0
    if (score && *score > 0) {
        *score = 0;
        bpf_map_update_elem(&attack_score_map, &key, score, BPF_ANY);
    }
    return false;
}

static __always_inline

struct flow_state *lookup_or_create_flow(struct policy_ctx *polctx) {
    struct packet_ctx *pctx = polctx->pctx;
    // 1. 嘗試尋找既有的 Flow 狀態
    struct flow_state *st = bpf_map_lookup_elem(&flow_table, &pctx->meta->key);
    if (st) {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[STATS] pkts=%llu bytes=%llu \n", st->packets, st->bytes);
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[STATS] saddr=%pI4, daddr=%pI4 \n", &(pctx->meta->key.saddr), &(pctx->meta->key.daddr));
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[STATS] sport=%d dport=%d \n",
                       bpf_ntohs(pctx->meta->key.sport), bpf_ntohs(pctx->meta->key.dport));
        return st;
    }

    // 💡 關鍵修正：原本 st 為 NULL 時直接 return 了，導致永遠無法建立新項目。
    // 現在如果找不到，就開始進行初始化（Create 邏輯）。

    __u64 now = bpf_ktime_get_ns();
    struct flow_state init = {
        .packets = 0,
        .bytes = 0,

        .tokens = FLOW_BURST,
        .last_refill = now,

        .first_seen = now,
        .last_seen = now,

        .flags = 0,
    };

    // 2. 將初始化的結構寫入 Map
    long ret = bpf_map_update_elem(
        &flow_table,
        &pctx->meta->key,
        &init,
        BPF_ANY);

    if (ret < 0) {
        SLF_LOG_ACTION(LOG_LVL_ERROR, "[STATS] Failed to update flow_table map, err=%ld\n", ret);
        return NULL;
    }

    // 3. 再次查詢以獲取持久的 Map 元素指標給 Verifier 追蹤
    st = bpf_map_lookup_elem(&flow_table, &pctx->meta->key);

    if (st) {
        SLF_LOG_ACTION(LOG_LVL_DEBUG,
                       "[STATS] New flow entry successfully created and retrieved, saddr=%x daddr=%pI4, sport=%d dport=%d\n",
                       &pctx->meta->key.saddr, &pctx->meta->key.daddr, bpf_ntohs(pctx->meta->key.sport),
                       bpf_ntohs(pctx->meta->key.dport));
    } else {
        SLF_LOG_ACTION(LOG_LVL_DEBUG, "[STATS] Critical: Flow entry lost after map update!\n");
    }

    return st;
}

static __always_inline

void update_flow_stats(struct packet_ctx *pctx,
                       struct flow_state *st) {
    // 使用原子操作防止多核心併發（Concurrency）時的資料競爭
    __sync_fetch_and_add(&st->packets, 1);
    __sync_fetch_and_add(&st->bytes, pctx->meta->pkt_len);
    st->last_seen = bpf_ktime_get_ns();

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "[STATS] Stats updated: total_pkts=%llu, total_bytes=%llu\n",
                   st->packets, st->bytes);
}

static __always_inline

int should_emit_event(struct policy_ctx *polctx,
                      struct flow_state *st,
                      int xdp_action) {
    // 只要封包被 DROP，就必定觸發事件印 Log

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "[STATS] ip: %pI4, sport: %u,should_emit_event  Action is %d\n",
                   &polctx->pctx->ip, bpf_ntohs(polctx->pctx->meta->key.sport), xdp_action);
    if (xdp_action != XDP_PASS) {
        return 1;
    }

    if (polctx->pctx->meta->is_under_attack && ((st->packets & LOG_ATTACK_MASK) == 0)) {
        return 2;
    } else if (!polctx->pctx->meta->is_under_attack || ((st->packets & LOG_SAMPLE_MASK) == 0)) {
        return 1;
    }

    return 0;
}
#endif //LIYONG_EBPFTRACE_STATS_H
