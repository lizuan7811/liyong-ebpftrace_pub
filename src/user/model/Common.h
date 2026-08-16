//
// Created by root on 2026/7/3.
//

#ifndef LIYONG_EBPFTRACE_COMMON_H
#define LIYONG_EBPFTRACE_COMMON_H
#include <cstring>

struct __attribute__((packed)) CommMsgHeader {
    uint32_t type;
    uint32_t count; // 告訴 Go 這次要送幾筆
};

struct __attribute__((packed)) BPFTraceBody {
    char label[32];   // 限制長度為 32
    char domain[32];
    char srcIp[16];   // IPv4 最長 15 字元 + null
    char dstIp[16];
    uint64_t count;
};

// 封包本體：必須與 Go 端的 model.FileEventData 記憶體佈局與順序完全一致
struct __attribute__((packed)) KsmFEExportBody {
    uint32_t pid;
    char comm[16];
    char filepath[256];
    int32_t is_write;
    uint64_t count;
};
#endif //LIYONG_EBPFTRACE_COMMON_H
