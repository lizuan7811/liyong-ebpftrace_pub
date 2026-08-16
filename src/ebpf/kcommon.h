#ifndef LIYONG_EBPFTRACE_COMMON_H
#define LIYONG_EBPFTRACE_COMMON_H

#include "maps.h"
/* safer macro for eBPF verifier */

#define BPF_PTR_CHECK(ptr, end)              \
do {                                     \
if ((void *)(ptr) > (end))           \
return -1;                       \
} while (0)

struct hdr_cursor
{
    void* pos;
};

static __always_inline struct global_config* get_config(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&global_config_map, &key);
}

enum verdict {
    VDT_DROP = -1,
    VDT_PASS = 0,
    VDT_PASS_DPI = 3,
    VDT_DPI_PASSED = 1,
    VDT_DPI_PENDING = 3
};

#endif /* LIYONG_EBPFTRACE_COMMON_H */
