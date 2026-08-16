//
// Created by root on 2026/7/29.
//

#ifndef LIYONG_EBPFTRACE_KSM_FILEEVENT_H
#define LIYONG_EBPFTRACE_KSM_FILEEVENT_H

#define DEV_PATH "/dev/ksm_dev"

// 必須與核心中的 struct file_event_data 完全一致
struct ksm_file_event {
    uint32_t pid;
    char comm[16];
    char filepath[256];
    int is_write;
};
#endif //LIYONG_EBPFTRACE_KSM_FILEEVENT_H
