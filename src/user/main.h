// -*- mode: c++ -*-
#ifndef LIYONG_EBPFTRACE_NEW_MAIN_H
#define LIYONG_EBPFTRACE_NEW_MAIN_H

#include <array>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <vector>
#include <cstring> // C++ 標準寫法 (推薦)
#include "time.h"
// #include "../ebpf/fw_status_code.h" // C++ 標準寫法 (推薦)

constexpr long long global_key = 0;
constexpr int MAX_LOG_LINES = 5;
constexpr int MAX_IFINDEX = 256; // 或者是原本的數值
inline int g_temp_map_fd = -1;
inline int g_perm_map_fd = -1;

// 💡 1. 取出高位元組：解析最終動作 (0xFF000000)
constexpr uint32_t GET_ACTION(uint32_t code) {
    return (code & 0xFF000000) >> 24;
}

// 💡 1. 取出高位元組：解析最終動作 (0xFF000000)
constexpr uint32_t GET_STAGE(uint32_t code) {
    return (code & 0x00FF0000) >> 16;
}

// 💡 1. 取出高位元組：解析最終動作 (0xFF000000)
constexpr uint32_t GET_REASON(uint32_t code) {
    return (code & 0x0000FFFF);
}

// ==========================================
// 💡 終極防禦：強行解除可能在上游被惡意定義的巨集
// ==========================================
#undef string
#undef std
#undef inline

const std::array<std::string_view, 5> action_names = {
    "XDP_ABORTED",
    "XDP_DROP",
    "XDP_PASS",
    "XDP_TX",
    "XDP_REDIRECT"
};

const std::array<std::string_view, 7> event_type_names = {
    "UNKNOWN",
    "EVENT_NEW_FLOW",
    "EVENT_DROP",
    "EVENT_BLOCK",
    "EVENT_SAMPLE",
    "EVENT_TCP_SYN",
    "EVENT_TCP_RST"
};

const std::array<std::string_view, 5> drop_reason_names = {
    "REASON_NONE",
    "REASON_GLOBAL_RATE_LIMIT",
    "REASON_FLOW_RATE_LIMIT",
    "REASON_RULE_MATCH",
    "REASON_TCP_INVALID"
};

const std::array<std::string_view, 6> stat_names = {
    "TCP_OK",
    "TCP_DROP",
    "UDP_PASS",
    "UDP_DROP",
    "ICMP_PASS",
    "ICMP_DROP"
};

size_t max_actions = action_names.size();
size_t max_event_type = event_type_names.size();
size_t max_drop_reason = drop_reason_names.size();

inline std::string_view action_icon(uint32_t sc) {
    switch (GET_ACTION(sc)) {
        case 0x01: return "🟢 PASS";
        case 0x02: return "🚨 DROP";
        case 0x03: return "⚔️  CHAL";
        default: return "❓ UNK";
    }
}


inline std::string_view stage_str(uint32_t sc) {
    switch (GET_STAGE(sc)) {
        case 0x01: return "PARSE";
        case 0x02: return "FUSE";
        case 0x03: return "ESTABLISHED";
        case 0x04: return "PERM_BLK";
        case 0x05: return "TEMP_BLK";
        case 0x06: return "PORT_WHT";
        case 0x07: return "GLOBAL_LMT";
        case 0x08: return "FLOW_LMT";
        case 0x09: return "L4_CHAL";
        default: return "?";
    }
}

inline std::string_view reason_str(uint32_t sc) {
    switch (GET_REASON(sc)) {
        case 0x0000: return "SUCCESS";
        case 0x0001: return "BAD_PKT";
        case 0x0002: return "UNSUPPORTED";
        case 0x0005: return "FRAG_PKT";
        case 0x0010: return "CONN_TRACK";
        case 0x0011: return "CONN_NEW";
        case 0x0020: return "RULE_STATIC";
        case 0x0021: return "RULE_DYNA";
        case 0x0030: return "PORT_MISS";
        case 0x0040: return "LIMIT_BYTES";
        case 0x0041: return "LIMIT_PPS";
        case 0x0050: return "CHAL_SEND";
        case 0x0051: return "CHAL_VERIFY";
        case 0x0060: return "DPI_PENDING";
        case 0x0061: return "DPI_PASSED";
        case 0x0062: return "DPI_VIOLATION";
        case 0x0064: return "DPI_INCOMPLETE";
        default: return "?";
    }
}

#endif
