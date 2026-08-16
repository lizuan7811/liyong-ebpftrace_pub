//
// Created by root on 2026/5/25.
//

#ifndef LIYONG_EBPFTRACE_FLOW_H
#define LIYONG_EBPFTRACE_FLOW_H
#include "log.h"
#include "types.h"
#include "vmlinux.h"


#ifdef __bpf__
#include "vmlinux.h"
#include "types.h"
#else

#endif

/* ================================
 * FLOW ENGINE (Stage 3) - 完美瘦身版
 * ================================ */
static __always_inline

void build_flow_key(struct policy_ctx* polctx)
{
    struct packet_ctx *pctx = polctx->pctx;

    if (!pctx->ip)
    {
        return;
    }

    // L3 資訊填寫
    pctx->meta->key.saddr = pctx->ip->addrs.saddr;
    pctx->meta->key.daddr = pctx->ip->addrs.daddr;
    pctx->meta->key.proto = pctx->meta->ip_proto;

    // 💡 提示：L4 的 sport 和 dport 已經在 Stage 1 解析時
    // 直接由 parser 安全注入 pctx->key 了，這裡不需要再重複處理！
}
#endif //LIYONG_EBPFTRACE_FLOW_H
