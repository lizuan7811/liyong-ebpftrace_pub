#ifndef LIYONG_EBPFTRACE_L7FLOWMANAGER_HPP
#define LIYONG_EBPFTRACE_L7FLOWMANAGER_HPP

#include <unordered_map>
#include <string>
#include <mutex>
#include <chrono>
#include "L7FlowSession.hpp"

/**
 * L7FlowManager 負責管理系統中所有「活動中」的網路會話（Flow）。
 * 它確保不會因為遺漏釋放記憶體而導致 OOM (OutOfMemoryError)，
 * 同時透過 Mutex 保證在多執行緒環境下的存取安全。
 */
class L7FlowManager {
private:
    // 使用 std::unordered_map 進行 O(1) 平均時間複雜度的快速連線查找
    std::unordered_map<std::string, L7FlowSession *> flow_table_;
    
    // Mutex：網路流量封包處理通常是多執行緒的，必須確保 Map 讀寫不發生競態條件 (Race Condition)
    std::mutex mtx_;
    
    // 設定連線閒置存活時間，防止死掉的連線永久佔用系統記憶體
    std::chrono::seconds timeout_limit_;

public:
    L7FlowManager(int timeout_seconds = 30) : timeout_limit_(timeout_seconds) {}

    // 析構子：當 Manager 被銷毀時，確保所有 Session 記憶體被一併回收
    ~L7FlowManager() {
        std::lock_guard<std::mutex> lock(mtx_);

        // 明確遍歷 Map，釋放每一個 L7FlowSession 物件
        // 當 delete session 時，會觸發 L7FlowSession 的解構子，進而 free 掉 nDPI 的指標
        for (std::unordered_map<std::string, L7FlowSession *>::iterator it = flow_table_.begin();
             it != flow_table_.end(); ++it) {
            delete it->second; 
        }
        flow_table_.clear();
    }

    /**
     * 核心邏輯：根據五元組 Key 取得現有連線，若不存在則建立新連線。
     */
    struct ndpi_flow_struct *getOrCreateFlow(const std::string &flowKey) {
        std::lock_guard<std::mutex> lock(mtx_);

        // 嘗試查找是否已經存在該連線
        std::unordered_map<std::string, L7FlowSession *>::iterator it = flow_table_.find(flowKey);

        if (it != flow_table_.end()) {
            // 找到舊連線：重置該連線的最後活動時間，延長其壽命
            it->second->update_activity();
            return it->second->get_ndpi_flow();
        }

        // 沒找到：建立一個新的會話物件 (L7FlowSession 會在建構子進行記憶體清零)
        L7FlowSession *newSession = new L7FlowSession();
        if (!newSession) {
            return nullptr; // 若記憶體分配失敗，回傳 NULL，避免後續非法操作
        }

        // 放入 Map 並回傳底層 nDPI 需要的指標
        flow_table_[flowKey] = newSession;
        return newSession->get_ndpi_flow();
    }

    /**
     * GC (垃圾回收) 機制：定期呼叫以清理超時連線
     */
    void perform_gc() {
        std::lock_guard<std::mutex> lock(mtx_);
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();

        std::unordered_map<std::string, L7FlowSession *>::iterator it = flow_table_.begin();

        while (it != flow_table_.end()) {
            L7FlowSession *session = it->second;

            // 如果閒置時間超過 timeout_limit_，則釋放該連線
            if (session->isExpired(now, timeout_limit_)) {
                delete session; // 釋放物件本身，觸發 Session 解構子自動 free 指標
                it = flow_table_.erase(it); // 將節點從 Map 移除並取得下一個迭代器
            } else {
                ++it; // 繼續檢查下一個
            }
        }
    }

    // 監控介面：返回當前在記憶體中的連線總數
    size_t get_active_flow_count() {
        std::lock_guard<std::mutex> lock(mtx_);
        return flow_table_.size();
    }
};

#endif