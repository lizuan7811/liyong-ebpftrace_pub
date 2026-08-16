//
// Created by root on 2026/6/21.
//

#ifndef LIYONG_EBPFTRACE_USER_LOG_H
#define LIYONG_EBPFTRACE_USER_LOG_H

#include <iostream>
#include <string>

#include "xdp_fw_config.h"

// 1. 定義日誌級別
/**
 * 高
 |
ERROR     最高
WARN
INFO
DEBUG
TRACE     最詳細
 |
 低
 */
#define LOG_LVL_TRACE 4
#define LOG_LVL_DEBUG 3
#define LOG_LVL_INFO  2
#define LOG_LVL_WARN  1
#define LOG_LVL_ERROR 0

// 假設全域變數，實際專案中可以跟你的 Engine 設定連動
static inline  uint32_t get_user_debug_level() {
   return xdp_fw_config::instance().get_log_level();
}

// 2. 核心魔法：仿照 eBPF 的格式化日誌巨集
#define USER_LOG(level, fmt, ...) \
do { \
if (get_user_debug_level() >= level) { \
/* 1. 先打印時間與前綴標籤 */ \
std::string prefix = "[" #level "] "; \
if (level == LOG_LVL_INFO)  std::cout << "\033[32m[INFO]\033[0m ";  /* 綠色 */ \
if (level == LOG_LVL_WARN)  std::cout << "\033[33m[WARN]\033[0m ";  /* 黃色 */ \
if (level == LOG_LVL_DEBUG) std::cout << "\033[36m[DEBUG]\033[0m "; /* 青色 */ \
if (level == LOG_LVL_ERROR) std::cout << "\033[31m[ERROR]\033[0m "; /* 紅色 */ \
\
/* 2. 使用 C 風格的 printf 安全格式化輸出 */ \
/* 這樣就能跟你的 eBPF bpf_printk 寫法完全對齊 */ \
printf(fmt "\n", ##__VA_ARGS__); \
} \
} while (0)

#endif //LIYONG_EBPFTRACE_USER_LOG_H
