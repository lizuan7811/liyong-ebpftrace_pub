//
// Created by root on 2026/7/29.
//

#include <string>
#include <cstdint>
#include <atomic>
#include <ctime>
#include <vector>
#include <algorithm>
#include <iostream>
#include <cstring>
#include <tbb/concurrent_hash_map.h>

class KsmFEMetricInfo {
public:
    class KsmFEKey {
    private:
        uint32_t pid;
        std::string comm;
        std::string filepath;
        int32_t is_write;

    public:
        KsmFEKey(uint32_t pid, std::string comm, std::string filepath, int32_t is_write)
            : pid(pid), comm(std::move(comm)), filepath(std::move(filepath)), is_write(is_write) {
        }

        uint32_t get_pid() const { return pid; }
        const std::string& get_comm() const { return comm; }
        const std::string& get_filepath() const { return filepath; }
        int32_t get_is_write() const { return is_write; }

        bool operator==(const KsmFEKey &other) const {
            return (pid == other.pid) &&
                   (comm == other.comm) &&
                   (filepath == other.filepath) &&
                   (is_write == other.is_write);
        }
    };

    struct KsmFEKeyHashCompare {
        static size_t hash(const KsmFEKey &k) {
            size_t seed = 0;
            auto hash_combine = [&](size_t v) {
                seed ^= v + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            };

            hash_combine(std::hash<uint32_t>{}(k.get_pid()));
            hash_combine(std::hash<std::string>{}(k.get_comm()));
            hash_combine(std::hash<std::string>{}(k.get_filepath()));
            hash_combine(std::hash<int32_t>{}(k.get_is_write()));
            return seed;
        }

        static bool equal(const KsmFEKey &x, const KsmFEKey &y) {
            return x == y;
        }
    };

    class KsmFEMetricData {
    public:
        mutable std::atomic<uint64_t> count{0};
        mutable std::atomic<time_t> last_updated{0};
        mutable std::atomic<bool> _isRisk{false};

        KsmFEMetricData() : last_updated(time(nullptr)) {
        }

        void touch(bool isRisk) const {
            last_updated.store(time(nullptr), std::memory_order_relaxed);
            _isRisk.store(isRisk, std::memory_order_relaxed);
        }

        KsmFEMetricData(const KsmFEMetricData &other) {
            count.store(other.count.load());
            last_updated.store(other.last_updated.load());
            _isRisk.store(other._isRisk.load());
        }

        KsmFEMetricData &operator=(const KsmFEMetricData &other) {
            count.store(other.count.load());
            last_updated.store(other.last_updated.load());
            _isRisk.store(other._isRisk.load());
            return *this;
        }
    };

    using KsmFEMap = tbb::concurrent_hash_map<KsmFEKey, KsmFEMetricData, KsmFEKeyHashCompare>;
    using Iterator = KsmFEMap::iterator;
    using ConstIterator = KsmFEMap::const_iterator;

private:
    KsmFEMap ksmFEMap;

    KsmFEMetricInfo() = default;

public:
    static KsmFEMetricInfo &instance() {
        static KsmFEMetricInfo inst;
        return inst;
    }

    // 更新指標時帶入 pid 與 is_write
    void update_metrics(uint32_t pid, const std::string &comm, const std::string &filepath, int32_t is_write, bool risk) {
        // 清洗 comm 字串（過濾掉控制字元與結尾的 \0）
        std::string clean_comm = comm;
        clean_comm.erase(std::remove_if(clean_comm.begin(), clean_comm.end(),
                                          [](unsigned char c) {
                                              return c == '\0' || c < 32 || c > 126;
                                          }), clean_comm.end());

        // 清洗 filepath 字串（過濾掉控制字元與結尾的 \0）
        std::string clean_path = filepath;
        clean_path.erase(std::remove_if(clean_path.begin(), clean_path.end(),
                                          [](unsigned char c) {
                                              return c == '\0' || c < 32 || c > 126;
                                          }), clean_path.end());

        KsmFEKey safe_key(pid, clean_comm, clean_path, is_write);

        KsmFEMap::accessor acc;
        if (ksmFEMap.insert(acc, safe_key)) {
            acc->second.count = 1;
            if (get_user_debug_level() >= LOG_LVL_TRACE) {
                // 🔍 Debug：印出當前成功新增的 Key 資訊與 Map 總大小，用以驗證是否持續增長
                std::cout << "[MAP_DEBUG] NEW Key Inserted! Map Size: " << ksmFEMap.size()
                          << " | PID: " << pid
                          << " | Comm: " << clean_comm
                          << " | Path: " << clean_path << std::endl;
            }
        } else {
            acc->second.count.fetch_add(1, std::memory_order_relaxed);
        }
        acc->second.touch(risk);
    }

    void clean_old_metrics() {
        time_t threshold = time(nullptr) - (7 * 24 * 3600);
        std::vector<KsmFEKey> to_delete;
        for (auto it = ksmFEMap.begin(); it != ksmFEMap.end(); ++it) {
            if (it->second.last_updated.load() < threshold) {
                to_delete.push_back(it->first);
            }
        }
        for (const auto &key: to_delete) {
            ksmFEMap.erase(key);
        }
    }

    KsmFEMap &get_map() { return ksmFEMap; }
};
