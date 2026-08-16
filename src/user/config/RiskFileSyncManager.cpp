//
// Created by root on 2026/6/22.
//
#include "RiskFileSyncManager.hpp"

#include <iostream>

#include "RiskFileUpdater.hpp"
#include "xdp_fw_config.h"
#include "../../third_party/nlohmann/json.hpp"

using namespace std::chrono_literals;

RiskFileSyncManager::RiskFileSyncManager() {}

RiskFileSyncManager::~RiskFileSyncManager()
{
    stopSyncService();
}

RiskFileSyncManager& RiskFileSyncManager::instance()
{
    static RiskFileSyncManager inst;
    return inst;
}


void RiskFileSyncManager::syncTask()
{
    while (running)
    {
        std::cout << "Starting batch sync..." << std::endl;
        std::cout << "Sync completed Sleeping..." << std::endl;
        RiskFileUpdater::instance().performRiskSync();

        std::this_thread::sleep_for(24h);
    }
}

void RiskFileSyncManager::startSyncService()
{
    if (!running)
    {
        running = true;
        workerThread = std::thread(&RiskFileSyncManager::syncTask, this);
    }
}

void RiskFileSyncManager::stopSyncService()
{
    running = false;
    if (workerThread.joinable())
    {
        workerThread.join();
    }
}

void RiskFileSyncManager::riskPropsToFile(std::vector<SyncRiskFileConfig::SyncRiskProperty>& riskData)
{
    RiskFileUpdater::instance().riskConfigToFile();
}

void RiskFileSyncManager::riskConfigToFile()
{
    RiskFileUpdater::instance().riskConfigToFile();
}

void RiskFileSyncManager::fileToRiskConfig()
{
    RiskFileUpdater::instance().fileToRiskConfig();
}

void RiskFileSyncManager::binaryToRiskConfig()
{
    RiskFileUpdater::instance().binaryToRiskConfig();
}

void RiskFileSyncManager::riskConfigToBinary()
{
    RiskFileUpdater::instance().riskConfigToBinary();
}

void RiskFileSyncManager::riskPropsToConfig(std::vector<SyncRiskFileConfig::SyncRiskProperty>& riskData)
{
    SyncRiskFileConfig& syncRiskFileConfig = SyncRiskFileConfig::instance();
    syncRiskFileConfig.setCollectedRisks(riskData);


    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    struct std::tm buf;
    // localtime_r 是執行緒安全版本
    localtime_r(&now_c, &buf);

    std::stringstream ss;
    ss << std::put_time(&buf, "%Y-%m-%d %H:%M:%S");

    syncRiskFileConfig.setUpdateTime(ss.str());
}

void RiskFileSyncManager::processRiskConfig()
{
   // parse riskconfig

    

}

