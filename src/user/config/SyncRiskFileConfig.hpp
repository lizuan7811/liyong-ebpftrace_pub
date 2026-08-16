#ifndef LIYONG_EBPFTRACE_SYNCRISKFILECONFIG_HPP
#define LIYONG_EBPFTRACE_SYNCRISKFILECONFIG_HPP

#include <vector>
#include <string>
#include <cstdint>

class SyncRiskFileConfig {
public:
    static SyncRiskFileConfig& instance();

    struct SyncRiskProperty {
        uint64_t id;
        std::string indicator;
        std::string type;
        std::string created;
        uint8_t isActive;
    };

#pragma pack(push, 1)
    struct BinaryRiskProperty {
        uint64_t id;
        char indicator[64];
        char type[32];
        char created[32];
        uint8_t isActive;
    };

    struct BinaryHeader {
        char syncNextUrl[256];
        char updateTime[64];
        uint64_t count;
        uint64_t reserved[4];
    };
#pragma pack(pop)

private:
    SyncRiskFileConfig() : riskCount(0) {}
    ~SyncRiskFileConfig() = default;

    SyncRiskFileConfig(const SyncRiskFileConfig&) = delete;
    SyncRiskFileConfig& operator=(const SyncRiskFileConfig&) = delete;

    std::string syncNextUrl;
    std::string updateTime;
    uint64_t riskCount; // 讓這個變數成為 Header 的鏡像
    std::vector<SyncRiskProperty> collected_risks;

public:
    // Getter / Setter
    std::string getSyncNextUrl() const { return syncNextUrl; }
    void setSyncNextUrl(const std::string& url) { syncNextUrl = url; }

    std::string getUpdateTime() const { return updateTime; }
    void setUpdateTime(const std::string& time) { updateTime = time; }

    uint64_t getRiskCount() const { return riskCount; }
    void setRiskCount(uint64_t count) { riskCount = count; }

    const std::vector<SyncRiskProperty>& getCollectedRisks() const { return collected_risks; }
    void setCollectedRisks(const std::vector<SyncRiskProperty>& risks) { collected_risks = risks; }
};

#endif