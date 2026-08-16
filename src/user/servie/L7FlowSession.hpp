//
// Created by root on 2026/6/16.
//

#ifndef LIYONG_EBPFTRACE_FLOWSESSION_HPP
#define LIYONG_EBPFTRACE_FLOWSESSION_HPP

#include <cstdlib>
#include <cstring>  // 為了使用 std::memset 清零記憶體
#include <chrono>   // 🎯 修正：必須引入時間庫

// 根據你的環境引入正確的 nDPI 標頭檔，確保 ndpi_flow_struct 的宣告存在
extern "C" {
#include <../third_party/ndpi/include/ndpi_api.h>
}
// 如果你在其他地方引過，這裡可以維持前向宣告
struct ndpi_flow_struct;

class L7FlowSession {
private:
    struct ndpi_flow_struct *ndpi_flow_; // 🎯 修正：拼字從小寫 npdi 改回 ndpi
    std::chrono::steady_clock::time_point last_seen_;

public:
    L7FlowSession() {
        // 🎯 修正：移除了錯誤的 sizeof(1, ...) 語法
        // 並加上 memset 清零，徹底杜絕 0xffffffffffffffff 的髒資料
        size_t size = ndpi_detection_get_sizeof_ndpi_flow_struct();
        ndpi_flow_ = (struct ndpi_flow_struct *) std::malloc(size);
        if (ndpi_flow_) {
            std::memset(ndpi_flow_, 0, size);
        }
        last_seen_ = std::chrono::steady_clock::now();
    }

    ~L7FlowSession() {
        if (ndpi_flow_) {
            std::free(ndpi_flow_);
        }
    }

    void update_activity() {
        last_seen_ = std::chrono::steady_clock::now();
    }

    bool isExpired(std::chrono::steady_clock::time_point now, std::chrono::seconds timeoutLimit) const {
        return (now - last_seen_) >= timeoutLimit;
    }

    struct ndpi_flow_struct *get_ndpi_flow() {
        return ndpi_flow_;
    }
};

#endif //LIYONG_EBPFTRACE_FLOWSESSION_HPP