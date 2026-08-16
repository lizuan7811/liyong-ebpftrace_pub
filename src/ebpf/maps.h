//
// Created by root on 2026/5/23.
// Updated: whitelist_rules_map 加上 BPF_PIN_BY_NAME，移除 __attribute__((weak))
//
#ifndef LIYONG_EBPFTRACE_MAPS_H
#define LIYONG_EBPFTRACE_MAPS_H

// 1. 先引入型態基礎防線（它會幫我們搞定核心/用戶態的基礎定義）
#include "types.h"

// 2. 處理 libbpf 釘選常數相容性
#ifndef BPF_PIN_BY_NAME
#define BPF_PIN_BY_NAME 1  // 核心對應 LIBBPF_PIN_BY_NAME，用戶態當作標記常數
#endif

/* =========================================================
 * 🛡️ 標頭檔隔離防線：只有在核心編譯階段才引入 helpers
 * ========================================================= */
#ifdef __KERNEL__
#include <bpf/bpf_helpers.h>
#else
// 用戶態模擬 BPF 語法巨集，防止 g++ 看不懂 SEC(".maps")
#ifndef SEC
#define SEC(name)
#endif
#ifndef __uint
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]
#endif
#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif
#endif

// /* ================================
//  * Ring Buffer (事件上報通道)
//  * ================================ */
// struct
// {
//     __uint(type, BPF_MAP_TYPE_RINGBUF);
//     __uint(max_entries, 1 << 24); // 16MB
// } rb SEC(".maps");


struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value,struct global_config);
    __uint(max_entries, 1);
} global_config_map SEC(".maps");


/* ================================
 * Flow Table (連線狀態追蹤)
 * ================================ */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
} flow_table SEC(".maps");

/* ================================
 * Whitelist Rules Map
 * 💡 核心改動：
 *   1. 加上 BPF_PIN_BY_NAME → libbpf 載入時自動釘選到
 *      /sys/fs/bpf/xdp_fw/maps/whitelist_rules_map
 *   2. 移除 __attribute__((weak)) → Pinning 後兩個 BPF
 *      程式透過 bpffs 自動複用同一個 Map 實體，不再需要
 *      弱符號技巧。
 * ================================ */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct rule_key);
    __type(value, struct rule_value);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} whitelist_rules_map SEC(".maps");

/* ================================
 * Blacklists
 * ================================ */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2048);
    __type(key, __u32);
    __type(value, struct blacklist_val);
} permanent_blocklist_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 20480);
    __type(key, __u32);
    __type(value, struct blacklist_val);
} temp_blocklist_map SEC(".maps");

/* ================================
 * Token Buckets
 * ================================ */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_bucket);
} global_bucket_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fuse_bucket);
} fuse_ratelimit_map SEC(".maps");

/* ================================
 * Port Allowlist (門禁白名單)
 * ================================ */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 512);
} ingress_allowed_ports SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 512);
} egress_allowed_ports SEC(".maps");

/* ================================
 * Established Connections (回程快速通道)
 * 💡 只有 xdp_fw 使用，不需要 Pinning
 * ================================ */
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct flow_key);
    __type(value, struct connection_state);
} established_connections_map SEC(".maps");

// 定義 Map：key 是 __u32 (固定為 0)，value 是 pps_bucket
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pps_bucket);
} global_pps_map SEC(".maps");

// 統計用的 Map
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);
} stats_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64); // 儲存最後一次攻擊的時間戳 (ns)
    __uint(max_entries, 1);
} attack_status_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32); // 這裡 key 可以是 0 (全域) 或 src_ip
    __type(value, __u64); // 儲存分數
    __uint(max_entries, 1);
} attack_score_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10001); // 🚀 關鍵：多開一個格子當全域防空洞
    __type(key, __u32); // Key: 0~9999 是桶子 ID，10000 是全域 ID
    __type(value, struct event); // Value: 儲存分數、事件、快照
} report_to_user_map SEC(".maps");

/* =========================================================
 * 📊 大廠級全域流量統計 Map (PERCPU ARRAY)
 * ========================================================= */
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // 🚀 關鍵：每個 CPU 核心獨立格子，完全 Lock-Free
    __uint(max_entries, 2); // 0: 總封包數, 1: 總位元組數
    __type(key, __u32);
    __type(value, __u64); // 累積計數器（開機到現在的總量）
} global_stats_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // 👈 讓多個 BPF 程式共享同一個 Ringbuf，防止第二個加載時變 -1
} l7_dpi_ringbuf SEC(".maps");

// maps.h
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct packet_meta); // ← 改成 meta
} pctx_scratch_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event);
} event_scratch_map SEC(".maps");
#endif //LIYONG_EBPFTRACE_MAPS_H
