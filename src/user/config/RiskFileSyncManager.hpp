//
// Created by root on 2026/6/22.
//
#ifndef LIYONG_EBPFTRACE_RISKFILESYNCMANAGER_HPP
#define LIYONG_EBPFTRACE_RISKFILESYNCMANAGER_HPP
#include <atomic>
#include <thread>
#include <unordered_map>
#include <vector>

#include "simdjson.h"
#include "SyncRiskFileConfig.hpp"
#include "../util/CommonUtil.hpp"

// Implementing a background routine for the periodic batch synchronization of risk data into in-memory configuration

class RiskFileSyncManager {
private:
    RiskFileSyncManager();

    ~RiskFileSyncManager();

    // 禁止拷貝建構與賦值，確保單例模式唯一性
    RiskFileSyncManager(const RiskFileSyncManager &) = delete;

    RiskFileSyncManager &operator=(const RiskFileSyncManager &) = delete;

    std::atomic<bool> running;

    std::thread workerThread;

    void syncTask();

    std::unordered_map<std::string, std::string> get_category_map() {
        return {
            {"domain", "network"}, {"hostname", "network"}, {"uri", "network"}, {"url", "network"},

            {"ipv4", "ips"}, {"ipv6", "ips"},

            {"cidr", "cidr"},

            // --- 應用層特徵類 (Application) ---
            {"ja3", "application"},
            {"sslcertfingerprint", "application"},

            {"filehash-sha256", "file"}, {"filehash-sha1", "file"},
            {"filehash-md5", "file"}, {"filehash-pehash", "file"},
            {"filehash-imphash", "file"}, {"filepath", "file"}, {"yara", "file"},

            {"mutex", "host"},

            {"bitcoinaddress", "identity"}, {"email", "identity"},

            {"cve", "vulnerability"}
        };
    }

public:
    static RiskFileSyncManager &instance();

    void startSyncService();

    void stopSyncService();

    void initCronJobToSyncFileFromRemote();

    // std::vector<SyncRiskFileConfig::SyncRiskProperty> configToRiskProps();

    void riskConfigToFile();

    void fileToRiskConfig();

    void riskConfigToBinary();

    void binaryToRiskConfig();

    void riskPropsToConfig(std::vector<SyncRiskFileConfig::SyncRiskProperty> &riskData);

    void riskPropsToFile(std::vector<SyncRiskFileConfig::SyncRiskProperty> &riskData);

    void processRiskConfig();

    std::string getCategory(std::string type) {
        static const auto category_map = get_category_map();

        // 關鍵動作：搜尋前先轉小寫
        std::string key = CommonUtil::toLower(type);

        auto it = category_map.find(key);
        if (it != category_map.end()) {
            return it->second;
        }
        return "Others";
    }
};


#endif //LIYONG_EBPFTRACE_SYNCRISKFILECONFIG_HPP
