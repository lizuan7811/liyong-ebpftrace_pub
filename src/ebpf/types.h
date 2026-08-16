#ifndef LIYONG_EBPFTRACE_TYPES_H
#define LIYONG_EBPFTRACE_TYPES_H

#ifdef __bpf__
    /* =========================================================
     * 🌀 核心態編譯環境 (Kernel Space / Clang BPF)
     * ========================================================= */
    #include "vmlinux.h"

#else
    /* =========================================================
     * 🖥️ 用戶態編譯環境 (User Space / g++ C++20)
     * ========================================================= */
    // 1. 引入標準用戶態與網路標頭檔
    #include <stdint.h>
    #include <arpa/inet.h>

    // 2. 💡 關鍵：直接引入 Linux 系統自帶的基礎型態定義，防止 typedef 衝突
    #include <asm/types.h>
    #include <linux/types.h>

    // 3. 補上網路位元組序 (Big-Endian) 型態（以防萬一有些環境沒帶到）
    #ifndef __be32
    typedef uint32_t __be32;
#endif
#ifndef __be16
typedef uint16_t __be16;
#endif

// 4. 補上核心內建的強迫 Inline 關鍵字
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#endif

// 確保 C++ 包含此 C 標頭檔時不會發生 Name Mangling
#ifdef __cplusplus
extern "C" {
#endif

#define DPI_PAYLOAD_SNAP_LEN 2000

/* =========================================================
 * 📅 2026 雙端架構最穩定的單調時間適配
 * ========================================================= */
static __always_inline __u64 get_absolute_now_ns(void) {
#ifdef __bpf__
    return bpf_ktime_get_tai_ns();
#else
    // Userspace 不走這裡，返回 0 避免編譯器阻擋
    return 0;
#endif
}

#define ETH_P_IP 0x0800

#define NS_PER_SEC 1000000000ULL

#define LOG_SAMPLE_MASK 0x3FF   // 1024 packets sample once
#define LOG_ATTACK_MASK 0x3FFF   // 1024 packets sample once

#define WL_KEY_SRC_MASK 32

// 定義 Key 索引
#define STAT_TCP_SYN_SUCCESS 0
#define STAT_TCP_SYN_DROP    1
#define STAT_UDP_PASS        2
#define STAT_UDP_DROP        3
#define STAT_ICMP_PASS       4
#define STAT_ICMP_DROP       5

#define STATE_CLEAN     0
#define STATE_SUSPICIOUS 1
#define STATE_ATTACKING  2

// 定義統計格子的 Index
#define STATS_KEY_PPS 0
#define STATS_KEY_BPS 1

// 定義事件類型 for event struct
#define EVENT_TYPE_BASIC 0
#define EVENT_TYPE_L7_DPI 1

#define DROP_REASON_MAX (sizeof(drop_reason_names) / sizeof(char *))
// 📝 留在 types.h 裡的最正確寫法：

#define MAX_PORTS 512

__attribute__((weak)) const volatile int xdp_config_key = 0;

// 1. 核心端變數的宣告（加上 extern，不給數值）
extern volatile __u64 GLOBAL_RATE_BYTES_PER_SEC;
extern volatile __u64 GLOBAL_BURST;
extern volatile __u64 FLOW_RATE_BYTES_PER_SEC;
extern volatile __u64 FLOW_BURST;
extern volatile __u64 GLOBAL_PPS_LIMIT;

// 2. 用戶端 Config 結構體定義（只留結構藍圖，不要在這邊實例化 g_cfg）
struct config {
    char log_path[256];
    char rule_file_path[256];
    unsigned long long global_rate;
    unsigned long long global_burst;
    unsigned long long flow_rate;
    unsigned long long flow_burst;
};

// enum event_type {
//     EVENT_PASS = 1,      // 封包順利放行
//     EVENT_DROP,          // 封包被丟棄（限速、黑名單、畸形等通通屬於此事件）
//     EVENT_CHALLENGE,     // 封包觸發了防禦挑戰（SYN Cookie）
//     EVENT_SAMPLE,        // 封包被採樣上送
// };
//
// enum drop_reason {
//     REASON_NONE = 0,
//
//     /* 🚨 丟棄原因 */
//     REASON_GLOBAL_RATE_LIMIT,
//     REASON_FLOW_RATE_LIMIT,
//     REASON_RULE_MATCH,
//     REASON_TCP_INVALID,
//
//     /* 🟢 新增：放行原因（讓維護者一眼看穿為什麼放行） */
//     REASON_PASS_ESTABLISHED,  // 憑什麼放行：命中 Established 老客戶信任表
//     REASON_PASS_UNSUPPORTED,  // 憑什麼放行：不支援的協議（如 ARP、IPv6）安全降級
//     REASON_PASS_CLEAN,        // 憑什麼放行：完全健康的全新連線，通過所有常規檢測
// };

struct mpls_hdr {
    __be32 label_stack_entry; // 包含 20-bit Label, 3-bit TC, 1-bit S, 8-bit TTL
};

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 proto;
    __u8 pad1;
    __u16 pad2;
} __attribute__((packed));

// 只存純資料，放 map（無指標）
struct packet_meta {
    __u8 ip_proto;
    __u8 is_under_attack;
    __u8 is_fuse_ratelimit;
    __u8 pad;
    struct flow_key key;
    __u32 pkt_len;
    __u32 payload_len;
    __u32 status_code;
};

// 存指標，放 stack（夠小）
struct packet_ctx {
    void *data;
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;

    union {
        struct tcphdr *tcp;
        struct udphdr *udp;
        struct icmphdr *icmp;
    };

    void *payload;
    struct packet_meta *meta; // ← 指向 map 裡的資料
};

struct connection_state {
    __u64 last_seen; // 用於 LRU 淘汰機制
    __u8 dpi_state; // 核心重點！(0: Pending, 1: DPI_Passed, 2: Blocked)
    __u8 tls_version; // 記錄該連線的 TLS 版本
    __u16 reserved; // 記憶體對齊
};

struct event {
    __u64 ts;
    __u32 action;
    __u32 status_code; // ← 取代原本的 type + action + reason
    struct flow_key key;
    __u32 pkt_len;
    __u32 type; // 標記這是哪種事件 (BASIC 還是 DPI)
    __u32 payload_len;

    union {
        // 基本事件不需要額外資料
        struct {
            __u8 reserved[DPI_PAYLOAD_SNAP_LEN];
        } basic;

        // DPI 事件專用結構
        struct {
            __u8 payload[DPI_PAYLOAD_SNAP_LEN]; // 這裡就是你原本的 e.payload
        } l7;
    } data;
}__attribute__((__packed__));

struct flow_state {
    // struct bpf_spin_lock lock;
    __u64 packets;
    __u64 bytes;

    __u64 tokens;
    __u64 last_refill;

    __u64 first_seen;
    __u64 last_seen;

    __u32 flags;

    // 💡 核心改動：這個連線目前正在套用的水門規格
    __u64 current_rate;
    __u64 current_burst;
};

struct policy_ctx {
    struct packet_ctx *pctx;
    struct flow_state *st;

    __u32 action;
};

// struct l4_info {
//     __u8 proto;
//     __u16 sport;
//     __u16 dport;
//
//     union {
//         struct {
//             __u8 syn;
//             __u8 ack;
//             __u8 fin;
//             __u8 rst;
//         } tcp_flags;
//
//         struct {
//             __u16 len;
//         } udp_flags;
//
//         struct {
//             __u8 type;
//             __u8 code;
//         } icmp_flags;
//     };
// };

struct global_bucket {
    __u64 tokens;
    __u64 last_ts;
};

struct fuse_bucket {
    __u64 last_time;
    __u32 tokens;
};

struct rule_key {
    __u32 remote_ip;
    __u32 remote_mask;
    __u16 remote_port;
    __u8 proto;
    __u8 pad[1]; // 💡 手動對齊 1 byte，確保結構體在不同平台編譯時長度皆為 12 bytes
}__attribute__((packed));

struct rule_value {
    __u32 action;
    __u32 priority;

    // 💡 讓規則檔案或網管指令可以動態賦予這條規則專屬的速限
    __u64 custom_rate;
    __u64 custom_burst;
};

struct blacklist_val {
    __u32 action;
    __u32 reason;

    /* =========================================================
     * 📅 絕對日期時間控制（單位：從 1970 年起算的奈秒數）
     * ========================================================= */
    __u64 start_absolute_ns; // 💡 封鎖開始的絕對時間 (0 代表不設起點，立刻生效)
    __u64 end_absolute_ns; // 💡 封鎖結束的絕對時間 (0 代表永久封鎖)
};

struct pps_bucket {
    __u64 tokens; // 剩餘的封包額度
    __u64 last_ts; // 最後一次更新時間
};

enum l7_direction {
    DIR_IN  = 0,
    DIR_OUT = 1
};

struct l7_dpi_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 ip_proto;
    __u64 timestamp_ns;   // bpf_ktime_get_ns() 拿到的時間戳
    __u16 l3_packet_len; // 實際抓到的 Payload 長度
    __u8 l3_packet[DPI_PAYLOAD_SNAP_LEN]; // 封包的二進位 Payload 快照
    __u8 direction;   // 0 = IN, 1 = OUT
};


struct global_config {
    __u32 log_level; // Log 等級 (0: None, 1: INFO, 2: WARN, 3: DEBUG)
    __u32 drop_threshold; // 防火牆攔截閾值
    __u32 enable_dpi; // 是否啟用 DPI 功能
    __u32 global_rate;
    __u32 global_burst;
    __u32 custom_rate;
    __u32 custom_burst;
    __u32 flow_rate;
    __u32 flow_burst;
    __u64 global_pps_limit;
    __u16 src_ports[MAX_PORTS];
    __u16 dst_ports[MAX_PORTS];
    __u32 reserved[5]; // 預留空間，未來擴充參數不需破壞記憶體結構
}__attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif //LIYONG_EBPFTRACE_TYPES_H
