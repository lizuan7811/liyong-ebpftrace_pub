#ifndef LIYONG_EBPFTRACE_RISKFILEUPDATER_HPP
#define LIYONG_EBPFTRACE_RISKFILEUPDATER_HPP

#include "SyncRiskFileConfig.hpp"
#include "simdjson.h"
#include <curl/curl.h>
#include <string>
#include <vector>
#include <optional>

class RiskFileUpdater {
private:
    RiskFileUpdater();
    ~RiskFileUpdater();

    // 禁止拷貝建構與賦值，確保單例模式唯一性
    RiskFileUpdater(const RiskFileUpdater &) = delete;
    RiskFileUpdater &operator=(const RiskFileUpdater &) = delete;

    std::string syncNextUrl;
    std::vector<SyncRiskFileConfig::SyncRiskProperty> collected_risks;

public:
    [[nodiscard]] std::vector<SyncRiskFileConfig::SyncRiskProperty> collected_risks1() const
    {
        return collected_risks;
    }

    void set_collected_risks(const std::vector<SyncRiskFileConfig::SyncRiskProperty>& collected_risks)
    {
        this->collected_risks = collected_risks;
    }

private:
    // 連線復用 handle
    CURL* curl_handle = nullptr;

    void initCurl();

public:
    static RiskFileUpdater &instance();

    // 核心邏輯
    std::string fetchOtxData(const std::string &apiKey, const std::string &remoteUrl);

    void performRiskSync();

    std::optional<std::string> processOtxResponseAndCollect(const std::string &jsonData);

    static void binaryToRiskConfig();

    static void fileToRiskConfig();

    void riskConfigToFile();

    static void riskConfigToBinary();

    void parseAndStoreIndicator(simdjson::ondemand::object indicator);
};

#endif // LIYONG_EBPFTRACE_RISKFILEUPDATER_HPP