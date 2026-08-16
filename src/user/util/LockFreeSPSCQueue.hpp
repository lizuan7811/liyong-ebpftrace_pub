//
// Created by root on 2026/6/15.
//

#ifndef LIYONG_EBPFTRACE_LOCKFREESPSCQUEUE_H
#define LIYONG_EBPFTRACE_LOCKFREESPSCQUEUE_H
#include <atomic>
#include <optional>
#include <vector>


template<typename T>
class LockFreeSPSCQueue {
private:
    std::vector<T> buffer_;
    const size_t capacity_;

    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};

public:
    LockFreeSPSCQueue(size_t capacity) : capacity_(capacity), buffer_(capacity) {
    }

    bool push(const T &val) {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_relaxed);

        if ((current_head + 1) % capacity_ == current_tail) {
            return false;
        }
        buffer_[current_head] = val;
        head_.store((current_head + 1) % capacity_, std::memory_order_relaxed);
        return true;
    }

    std::optional<T> pop() {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_relaxed);
        if (current_tail == current_head) {
            return std::nullopt;
        }
        T val = buffer_[current_tail];
        tail_.store((current_tail + 1) % capacity_, std::memory_order_relaxed);
        return val;
    }
};

#endif //LIYONG_EBPFTRACE_LOCKFREESPSCQUEUE_H
