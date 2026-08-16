//
// Created by root on 2026/6/8.
//

#ifndef LIYONG_EBPFTRACE_LOG_H
#define LIYONG_EBPFTRACE_LOG_H

#include "maps.h"

#define LOG_LVL_NONE 0
#define LOG_LVL_INFO 1
#define LOG_LVL_WARN 2
#define LOG_LVL_DEBUG 3
#define LOG_LVL_ERROR 4

static __always_inline __u32 get_debug_level(void)
{
    __u32 log_key = 0;
    struct global_config* g_config = bpf_map_lookup_elem(&global_config_map, &log_key);
    __u32 val = g_config->log_level;
    return val ? val : 0;
}


#define SLF_LOG_ACTION(level,fmt, ...) \
do{ \
    if(get_debug_level()>=level){ \
        bpf_printk(fmt,##__VA_ARGS__); \
    }\
}while (0)

#endif //LIYONG_EBPFTRACE_LOG_H
