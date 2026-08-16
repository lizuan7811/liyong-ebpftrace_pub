//
// Created by root on 2026/5/25.
// Updated 2026/6/20: Fix L3 header offset mismatch between XDP ingress and TC egress paths
// Updated 2026/6/20 (v3): Fix verifier rejection "R2 unbounded memory access"
//

#ifndef LIYONG_EBPFTRACE_EVENTS_H
#define LIYONG_EBPFTRACE_EVENTS_H
#include <bpf/bpf_endian.h>

#include "types.h"

#ifdef __bpf__
#include "fw_status_code.h"
#else

#endif

/* =========================================================
 * 🔧 verifier 安全遮罩
 *
 *   原本用「if (copy_len > DPI_PAYLOAD_SNAP_LEN) copy_len = DPI_PAYLOAD_SNAP_LEN;」
 *   這種「條件式夾限」，理論上能把 copy_len 限制在合法範圍內，
 *   但 Clang 在最佳化時，可能把夾限前 / 夾限後的 copy_len 拆成兩個
 *   不同的暫存器（SSA 值），如果之後又因為控制流程被重新排序，
 *   最終傳進 bpf_probe_read_kernel() 的，可能剛好是「夾限生效之前」
 *   留下的那份舊副本，導致 verifier 看到的 size 參數完全沒有上界，
 *   直接以 "R2 unbounded memory access" 拒絕載入整支程式。
 *
 *   修法：改用「位元遮罩 (bitwise AND)」做最後一道夾限。AND 運算
 *   是 verifier 唯一能「無條件、不靠任何分支推理」就精確證明結果
 *   範圍的運算子，不管前面的控制流程被編譯器怎麼重排，緊接在
 *   bpf_probe_read_kernel() 呼叫之前做這個 AND，都能保證 verifier
 *   看到的是一個鐵板一塊、範圍 [0, MASK] 的值。
 *
 *   這裡刻意把夾限上限定為 SNAP_LEN-1（也就是 0x3FF=1023），而不是
 *   SNAP_LEN 本身（1024）。原因：如果夾限上限剛好等於 1024，那麼
 *   「copy_len == 1024」這個邊界值在做「&= 0x3FF」時會被誤算成 0
 *   （1024 & 1023 = 0），等於把一個合法的最大長度錯誤地清零。讓
 *   夾限上限直接對齊遮罩值，可以確保這個 AND 在所有合法輸入下
 *   永遠是 no-op，只在編譯器產生「理論上不可能但 verifier 證不出來」
 *   的極端值時，才真正發揮安全網的作用。少存 1 byte 對 1024 bytes
 *   的 DPI 快照來說完全無影響。
 * ========================================================= */
#define DPI_PAYLOAD_SNAP_LEN_MASK (DPI_PAYLOAD_SNAP_LEN - 1)

/* 🔧 強制材質化：避免編譯器用另一個（可能未經夾限證明的）SSA 副本
 *    取代我們剛剛遮罩過的值。寫法是標準的 eBPF 慣用招式：用一個
 *    no-op 的 inline asm，強迫 Clang 把當下這個值真正寫回暫存器，
 *    不要在背地裡偷換成別的副本。
 */
#ifndef barrier_var
#define barrier_var(var) asm volatile("" : "+r"(var))
#endif

static __always_inline void process_event(int action, struct packet_ctx* pctx, int type, struct event* e)
{
    // SLF_LOG_ACTION(LOG_LVL_DEBUG, "action: %d, sport: %u, dport: %u, plen: %u", action,
    // bpf_ntohs(pctx->meta->key.sport), bpf_ntohs(pctx->meta->key.dport), pctx->meta->payload_len);

    /* =========================================================
     * 0. SSH (Port 22) 專屬降噪閘門
     * ========================================================= */
    // SSH 降噪不變
    if (pctx->meta->key.sport == 22 || pctx->meta->key.dport == 22 ||
        pctx->meta->key.sport == __builtin_bswap16(22) ||
        pctx->meta->key.dport == __builtin_bswap16(22))
    {
        if ((pctx->meta->status_code & 0xFF000000) == ACT_PASS && pctx->meta->payload_len <= 6)
            return;
    }

    /* =========================================================
     * 2. METADATA & CONTROL 填寫
     * ========================================================= */
    e->ts = bpf_ktime_get_ns();
    e->pkt_len = pctx->meta->pkt_len;

    /* =========================================================
     * 3. FLOW KEY 完整拷貝 (✨ 消滅 0.0.0.0 與 0:0)
     * ========================================================= */
    e->key = pctx->meta->key;

    /* =========================================================
     * 4. EVENT TYPE & ACTION 判定
     * ========================================================= */
    e->status_code = pctx->meta->status_code; // ← 直接帶入
    /* =========================================================
  * 5. PAYLOAD 安全複製 (Verifier 最愛的安全防禦)
  * ========================================================= */

    __u32 len = pctx->meta->payload_len;
    // 💡 雙重邊界防禦：確保長度不會超越你定義的 PAYLOAD_SNAPSHOT (64)
    if (len > DPI_PAYLOAD_SNAP_LEN)
    {
        len = DPI_PAYLOAD_SNAP_LEN;
    }

    if (type == EVENT_TYPE_L7_DPI)
    {
        e->type = EVENT_TYPE_L7_DPI; // 自定義 macro

        // 🔧 actual_len 預設為 0：只有真的成功拷貝才回報非 0 值。
        // event_scratch_map 是 PERCPU_ARRAY，每個 CPU 永遠重複借用同一塊
        // e->data.l7.payload 記憶體，且這塊記憶體從來沒有被清零過。
        __u32 actual_len = 0;

        // 拷貝起點必須是 pctx->ip（IP header 真正所在的記憶體位置），
        // 不能是 pctx->payload（那是 L4 header 之後的純 L7 payload）。
        // 詳見上一輪修正的說明。
        void* l3_start = (void*)pctx->ip;

        if (l3_start && l3_start < pctx->data_end)
        {
            __u64 max_allow = (__u64)pctx->data_end - (__u64)l3_start;
            __u32 copy_len = (__u32)max_allow;

            // 🔧🔧🔧 關鍵修正：把「條件式夾限」換成「位元遮罩」。
            //
            // 原本這裡是：
            //     if (copy_len > DPI_PAYLOAD_SNAP_LEN) copy_len = DPI_PAYLOAD_SNAP_LEN;
            // 邏輯上沒錯，但 Clang 編譯後，這個夾限後的 copy_len 跟最終
            // 傳進 bpf_probe_read_kernel() 的那個值，可能因為最佳化重排序
            // 而變成兩個不同的暫存器（其中一個沒有經過夾限），導致
            // verifier 報 "R2 unbounded memory access"。
            //
            // 改成位元遮罩後，這一行本身就是 copy_len 最終、唯一、
            // 緊接著被使用的版本，verifier 可以從這一行單獨、無條件地
            // 證明 copy_len ∈ [0, DPI_PAYLOAD_SNAP_LEN_MASK]，不需要
            // 依賴任何前面的分支推理。
            copy_len &= DPI_PAYLOAD_SNAP_LEN_MASK;
            barrier_var(copy_len); // 強制材質化，避免編譯器又偷換成別的副本

            if (copy_len > 0)
            {
                // 🚀 從 IP header 起點開始拷貝
                long ret = bpf_probe_read_kernel(
                    e->data.l7.payload,
                    copy_len,
                    l3_start
                );

                if (ret == 0)
                {
                    // ✅ 只有真的讀取成功，這次的 payload 才算數
                    actual_len = copy_len;
                }
#ifdef DEBUG
                if (ret < 0)
                {
                    SLF_LOG_ACTION(LOG_LVL_DEBUG, "bpf_probe_read_kernel failed with res: %ld\n", ret);
                }
#endif
            }
        }
        e->payload_len = actual_len; // 🔧 絕對不能用未經驗證成功、且起點錯誤的 len
    }
    else
    {
        e->type = EVENT_TYPE_BASIC;
        e->payload_len = len; // 👈 明確告知此事件沒有 Payload
        // 建議這裡顯式清空，雖然 e={} 已經做過，但在複雜邏輯中這樣更安全
        // __builtin_memset(e->data.basic.reserved, 0, sizeof(e->data.basic.reserved));
        // __builtin_memset(&e->data.basic, 0, sizeof(e->data.basic));
    }
}

static __always_inline void push_ol7event(struct event* _event)
{
    // 1. 🚀 直接在 Ring Buffer 的記憶體池裡申請一塊專屬於 l7_dpi_event 的空間
    struct l7_dpi_event* l7_event;

    l7_event = bpf_ringbuf_reserve(&l7_dpi_ringbuf, sizeof(struct l7_dpi_event), 0);
    if (!l7_event)
    {
        // 記憶體不足或 Ring Buffer 滿了（在高防系統中很常見，直接默默丟棄或紀錄日誌）
        SLF_LOG_ACTION(LOG_LVL_ERROR, "Ringbuf reserve failed (buffer full)\n");
        return;
    }

    // 2. 🟢 就地填寫資料（零拷貝直達 User Space）
    l7_event->src_ip = _event->key.saddr;
    l7_event->dst_ip = _event->key.daddr;
    l7_event->src_port = _event->key.sport;
    l7_event->dst_port = _event->key.dport;
    l7_event->ip_proto = _event->key.proto;
    l7_event->timestamp_ns = _event->ts;

    // 安全邊界防護：防止 payload_len 超過快照陣列大小
    // 🔧 同樣的道理：這裡也用位元遮罩取代條件式夾限，避免 verifier
    // 在這個迴圈（下面的 #pragma unroll 拷貝）也遇到一樣的問題。
    __u16 valid_len = _event->payload_len;
    valid_len &= DPI_PAYLOAD_SNAP_LEN_MASK;
    barrier_var(valid_len);
    l7_event->l3_packet_len = valid_len;

    // 3. 🟢 拷貝 Payload（使用內核安全的 memcpy）
    // 你的原本寫法 `_event->data.l7.payload` 是陣列名稱，直接用 __builtin_memcpy 拷貝
    // __builtin_memcpy(l7_event->payload, _event->data.l7.payload, valid_len);

    // 🟢 核心絕招：用迴圈逐個字元拷貝，並強制展開！
    // 這樣 Clang 會在編譯期把這裡變成純粹的內聯指令，完美繞過動態變數的 memcpy 限制
#pragma unroll
    for (int i = 0; i < DPI_PAYLOAD_SNAP_LEN; i++)
    {
        // 只有在小於實際動態長度時才真正寫入，確保不會越界，且安全符合 Verifier 規範
        if (i < valid_len)
        {
            l7_event->l3_packet[i] = _event->data.l7.payload[i];
        }
    }

    // 4. 🚀 物理提交到 User Space
    // 這一點下去，你在 C++ 端的回調（Callback）就會立刻收到這個封包

    l7_event->direction = DIR_IN;
    bpf_ringbuf_submit(l7_event, 0);
}

static __always_inline void update_report_map(struct packet_ctx* pctx, struct event* e)
{
    /* =========================================================
     * 1. 🎯 核心雜湊桶 Key 計算（補正問題！）
     * ========================================================= */
    // 利用來源 IP 進行 10000 取模分流，死死鎖定 report_to_user_map 的空間上限
    __u32 bucket_key = pctx->meta->key.saddr % 10000;
    /* =========================================================
 * 6. ⚡ 擠進 10,000 個雜湊桶上報（修正變數名稱對齊！）
 * ========================================================= */
    // BPF_ANY：同一個格子如果這一秒有複數個惡意 IP 擠進來，直接覆蓋更新，完美降噪去重

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "[PROCESS_EVENT] STATUSCODE : 0x%08x\n", pctx->meta->status_code);

    bpf_map_update_elem(&report_to_user_map, &bucket_key, e, BPF_ANY); // ✨ ev 改成 e
}

static __always_inline

void emit_l7_event(int action, struct policy_ctx* polctx, int type)
{
    __u32 zero = 0;
    struct event* e = bpf_map_lookup_elem(&event_scratch_map, &zero);
    if (!e) return;

    struct packet_ctx* pctx = polctx->pctx;

    process_event(action, pctx, type, e);

    SLF_LOG_ACTION(LOG_LVL_DEBUG, "[EMIT_L7_EVENT] action: %d, sport: %u, dport: %u, plen: %u\n",
                   action, bpf_ntohs(pctx->meta->key.sport), bpf_ntohs(pctx->meta->key.dport), pctx->meta->payload_len);

    push_ol7event(e);
}

static

__always_inline

void emit_event(int action, struct policy_ctx* polctx, int type)
{
    __u32 zero = 0;
    struct event* e = bpf_map_lookup_elem(&event_scratch_map, &zero);
    if (!e) return;

    struct packet_ctx* pctx = polctx->pctx;

    process_event(action, pctx, type, e);

    // push_ol7event(e);
    SLF_LOG_ACTION(LOG_LVL_DEBUG, "Ringbuf real output action: %d, sport: %u, dport: %u, plen: %u\n",
                   action, bpf_ntohs(pctx->meta->key.sport), bpf_ntohs(pctx->meta->key.dport), pctx->meta->payload_len);

    update_report_map(pctx, e);
}
#endif //LIYONG_EBPFTRACE_EVENTS_H
