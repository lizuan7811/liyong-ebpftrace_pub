#include <algorithm>
#include <cstdint>
#include <tbb/concurrent_hash_map.h>
#include <string>
#include <atomic>
#include <ctime>
#include <vector>
#include <iostream>

class RiskMetricInfos {
public:
    class TrafficKey {
    private:
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        std::string domain;

    public:
        TrafficKey(uint32_t s_ip, uint32_t d_ip, uint16_t s_port, uint16_t d_port, std::string dom)
            : src_ip(s_ip), dst_ip(d_ip), src_port(s_port), dst_port(d_port), domain(std::move(dom)) {}

        uint32_t get_src_ip() const { return src_ip; }
        uint32_t get_dst_ip() const { return dst_ip; }
        uint16_t get_src_port() const { return src_port; }
        uint16_t get_dst_port() const { return dst_port; }
        const std::string &get_domain() const { return domain; }

        // // 修正你的 operator==
        // bool operator==(const TrafficKey &other) const {
        //     if (src_ip != other.src_ip || dst_ip != other.dst_ip ||
        //         src_port != other.src_port || dst_port != other.dst_port) return false;
        //
        //     // 確保這裡比對的是內容，而非指標
        //     return domain.compare(other.domain) == 0;
        // }

        bool operator==(const TrafficKey &other) const {
            // 基礎欄位比對
            if (src_ip != other.src_ip || dst_ip != other.dst_ip ||
                src_port != other.src_port || dst_port != other.dst_port) return false;

            // 關鍵：如果 domain 看起來一樣但匹配失敗，一定是這裡搞鬼
            if (domain != other.domain) {
                // 強制列印出它們的真實長度與十六進位碼
                std::cerr << ">>>>>> [MATCH FAIL] A: " << domain << " (len " << domain.length() << ")" << std::endl;
                for (unsigned char c : domain) std::cerr << (int)c << " ";
                std::cerr << std::endl;
                std::cerr << ">>>>>> [MATCH FAIL] B: " << other.domain << " (len " << other.domain.length() << ")" << std::endl;
                for (unsigned char c : other.domain) std::cerr << (int)c << " ";
                std::cerr << std::endl;
                return false;
            }
            return true;
        }


    };

    struct TrafficKeyHashCompare {
        static size_t hash(const TrafficKey &k) {
            size_t seed = 0;
            auto hash_combine = [&](size_t v) {
                seed ^= std::hash<size_t>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
            };
            hash_combine(k.get_src_ip());
            hash_combine(k.get_dst_ip());
            hash_combine(k.get_src_port());
            hash_combine(k.get_dst_port());
            hash_combine(std::hash<std::string>{}(k.get_domain()));
            return seed;
        }

        static bool equal(const TrafficKey &x, const TrafficKey &y) {
            return x == y;
        }
    };

    class MetricData {
    public:
        mutable std::atomic<uint64_t> count{0};
        mutable std::atomic<time_t> last_updated{0};
        mutable std::atomic<bool> _isRisk{false};

        MetricData() : last_updated(time(nullptr)) {}

        void touch(bool isRisk) const {
            last_updated.store(time(nullptr), std::memory_order_relaxed);
            _isRisk.store(isRisk, std::memory_order_relaxed);
        }

        MetricData(const MetricData &other) {
            count.store(other.count.load());
            last_updated.store(other.last_updated.load());
            _isRisk.store(other._isRisk.load());
        }

        MetricData &operator=(const MetricData &other) {
            count.store(other.count.load());
            last_updated.store(other.last_updated.load());
            _isRisk.store(other._isRisk.load());
            return *this;
        }
    };

    using TrafficMap = tbb::concurrent_hash_map<TrafficKey, MetricData, TrafficKeyHashCompare>;
    using Iterator = TrafficMap::iterator;
    using ConstIterator = TrafficMap::const_iterator;

private:
    TrafficMap trafficMap;
    RiskMetricInfos() = default;

public:
    static RiskMetricInfos &instance() {
        static RiskMetricInfos inst;
        return inst;
    }

    void update_metrics(const TrafficKey &key, bool risk) {
        // 【清洗步驟】確保 Key 是乾淨的
        // 這裡我們在 update_metrics 內部對 domain 做處理，
        // 如果你發現某些 domain 根本不需要，可以在這裡直接 return
        std::string clean_domain = key.get_domain();
        clean_domain.erase(std::remove_if(clean_domain.begin(), clean_domain.end(),
            [](unsigned char c) {
                // 只保留可見字元 (ASCII 32-126)，過濾掉所有隱形雜訊
                return c < 32 || c > 126;
            }), clean_domain.end());

        // 重新建構一個乾淨的 Key 用於查找
        TrafficKey safe_key(key.get_src_ip(), key.get_dst_ip(),
                            key.get_src_port(), key.get_dst_port(),
                            clean_domain);

        TrafficMap::accessor acc;
        if (trafficMap.insert(acc, safe_key)) {
            acc->second.count = 1;
        } else {
            acc->second.count.fetch_add(1, std::memory_order_relaxed);
        }
        acc->second.touch(risk);
    }

    void clean_old_metrics() {
        time_t threshold = time(nullptr) - (7 * 24 * 3600);
        std::vector<TrafficKey> to_delete;
        for (auto it = trafficMap.begin(); it != trafficMap.end(); ++it) {
            if (it->second.last_updated.load() < threshold) {
                to_delete.push_back(it->first);
            }
        }
        for (const auto &key : to_delete) {
            trafficMap.erase(key);
        }
    }

    TrafficMap &get_map() { return trafficMap; }
};