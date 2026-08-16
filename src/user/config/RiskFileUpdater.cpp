#include "RiskFileUpdater.hpp"
#include "xdp_fw_config.h"
#include "../util/CommonUtil.hpp"
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <../../../third_party/nlohmann/json.hpp>

// 處理 Curl 返回資料的 Callback
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

RiskFileUpdater::RiskFileUpdater() { initCurl(); }

RiskFileUpdater::~RiskFileUpdater()
{
    if (curl_handle) curl_easy_cleanup(curl_handle);
}

RiskFileUpdater& RiskFileUpdater::instance()
{
    static RiskFileUpdater inst;
    return inst;
}

void RiskFileUpdater::initCurl()
{
    if (curl_handle) curl_easy_cleanup(curl_handle);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 30L);
}

std::string RiskFileUpdater::fetchOtxData(const std::string& apiKey, const std::string& remoteUrl)
{
    if (!curl_handle) initCurl();

    const int MAX_RETRIES = 600;
    int retryCount = 0;

    while (retryCount < MAX_RETRIES)
    {
        std::string readBuffer;
        struct curl_slist* headers = nullptr;
        std::string authHeader = "X-OTX-API-KEY: " + apiKey;
        headers = curl_slist_append(headers, authHeader.c_str());

        curl_easy_reset(curl_handle);
        curl_easy_setopt(curl_handle, CURLOPT_URL, remoteUrl.c_str());
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &readBuffer);

        CURLcode res = curl_easy_perform(curl_handle);
        curl_slist_free_all(headers);
        // --- 新增：獲取 HTTP Status Code ---
        long response_code = 0;
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);

        std::cout << "Curl retryCount: " << retryCount << ", remoteUrl: " << remoteUrl << std::endl;

        if (res == CURLE_OK)
        {
            if (response_code == 200)
            {
                return readBuffer; // 成功
            }
            else
            {
                std::cerr << "HTTP Error: " << response_code << " for URL: " << remoteUrl << std::endl;
                retryCount++;
                std::this_thread::sleep_for(std::chrono::seconds(retryCount % 5));
            }
        }
        else
        {
            retryCount++;
            std::cerr << "Curl attempt " << retryCount << " failed: " << curl_easy_strerror(res) << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(retryCount % 5));
        }
    }
    return "";
}

void RiskFileUpdater::performRiskSync()
{
    std::string currentUrl = xdp_fw_config::instance().get_risk_config_info().remote_source_url();
    std::string apiKey = xdp_fw_config::instance().get_risk_config_info().api_key();
    syncNextUrl = currentUrl;
    collected_risks.clear();

    // 只有當 currentUrl 為空時，迴圈才會結束
    do
    {
        try
        {
            std::string rawData = fetchOtxData(apiKey, currentUrl);
            if (rawData.empty()) continue; // 觸發下一次迴圈 (do-while)

            std::optional<std::string> nextUrl = processOtxResponseAndCollect(rawData);

            // 關鍵：如果 process 回傳 nullopt，強制丟出錯誤進 catch 重試
            if (!nextUrl.has_value()) throw std::runtime_error("Parsing error");

            // 成功邏輯：若沒 next 則設為 ""，準備結束
            currentUrl = nextUrl.value();

            // 只有確實有新 URL 時才更新檢查點
            if (!currentUrl.empty()) syncNextUrl = currentUrl;
        }
        catch (std::exception& e)
        {
            std::cerr << "Sync error: " << e.what() << ". Retrying..." << std::endl;
            currentUrl = syncNextUrl; // 丟回上次成功的檢查點，觸發重試
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    // 你的終止條件：當 currentUrl 變為 "" 時，條件為假，跳出迴圈
    while (!currentUrl.empty());

    // 迴圈結束後，這裡代表同步完成
    std::cout << "Sync finished." << std::endl;
}

void RiskFileUpdater::parseAndStoreIndicator(simdjson::ondemand::object indicator)
{
    SyncRiskFileConfig::SyncRiskProperty prop;

    // 將 auto 改為 std::function<void(simdjson::error_code)>
    std::function<void(simdjson::error_code)> check = [](simdjson::error_code err)
    {
        if (err != simdjson::SUCCESS)
        {
            throw std::runtime_error("JSON field extraction failed: " + std::string(simdjson::error_message(err)));
        }
    };

    // 處理欄位讀取
    check(indicator["id"].get(prop.id));

    std::string_view ind, typ, crt;
    check(indicator["indicator"].get_string().get(ind));
    prop.indicator = std::string(ind);

    check(indicator["type"].get_string().get(typ));
    prop.type = std::string(typ);

    check(indicator["created"].get_string().get(crt));
    prop.created = std::string(crt);

    uint64_t active = 0;
    check(indicator["is_active"].get(active));
    prop.isActive = static_cast<uint8_t>(active);

    collected_risks.push_back(prop);
}

std::optional<std::string> RiskFileUpdater::processOtxResponseAndCollect(const std::string& jsonData)
{
    simdjson::ondemand::parser parser;
    simdjson::padded_string json_data = simdjson::padded_string(jsonData);
    simdjson::ondemand::document doc;

    if (parser.iterate(json_data).get(doc) != simdjson::SUCCESS) return std::nullopt;

    // 1. 先處理 "next" (因為它的位置通常在 JSON 的最前面或固定位置)
    std::string next_url;
    simdjson::ondemand::value next_val;
    if (doc.find_field("next").get(next_val) == simdjson::SUCCESS && !next_val.is_null())
    {
        next_url = std::string(next_val.get_string().value());
    }

    // 2. 再處理 "results" (這會把 doc 的指標往後移)
    simdjson::ondemand::array results;
    if (doc["results"].get(results) == simdjson::SUCCESS)
    {
        for (auto item : results)
        {
            simdjson::ondemand::array indicators;
            if (item["indicators"].get(indicators) == simdjson::SUCCESS)
            {
                for (auto element : indicators)
                {
                    parseAndStoreIndicator(element.get_object());
                }
            }
        }
    }
    else
    {
        std::cerr << "Warning: 'results' field missing or empty." << std::endl;
        // 即使 results 為空，只要有 next 還是應該要回傳 next_url
    }

    return next_url; // 沒下一頁就回傳空字串
}

void RiskFileUpdater::riskConfigToFile()
{
    std::cout << "Persist Risk File" << std::endl;
    if (collected_risks.empty()) return;
    std::string path = xdp_fw_config::instance().get_risk_config_info().file_source_path();

    nlohmann::json root;
    nlohmann::json jsonArr = nlohmann::json::array();
    for (const auto& item : collected_risks)
    {
        nlohmann::json entry;
        entry["id"] = item.id;
        entry["indicator"] = item.indicator;
        entry["type"] = item.type;
        entry["created"] = item.created;
        entry["is_active"] = (int)item.isActive;
        jsonArr.push_back(entry);
    }
    root["indicators"] = jsonArr;
    root["syncNextUrl"] = syncNextUrl;
    root["updateTime"] = CommonUtil::getLocalTime("%Y-%m-%d %H:%M:%S");
    // ----------------------

    std::string tmpPath = path + ".tmp";
    std::ofstream file(tmpPath, std::ios::trunc);
    if (file.is_open())
    {
        file << root.dump(4);
        file.close();
        std::rename(tmpPath.c_str(), path.c_str());
    }
    else
    {
        std::cerr << "Failed to open tmp file for writing: " << tmpPath << std::endl;
    }
}

// 讀取 Binary 檔並更新單例
void RiskFileUpdater::binaryToRiskConfig()
{
    auto& srfc = SyncRiskFileConfig::instance();
    std::ifstream ifs(xdp_fw_config::instance().get_risk_config_info().file_source_binary_path(), std::ios::binary);

    if (!ifs) return;

    SyncRiskFileConfig::BinaryHeader bh{};
    ifs.read(reinterpret_cast<char*>(&bh), sizeof(SyncRiskFileConfig::BinaryHeader));

    // 自動同步 Header 資訊到單例
    srfc.setSyncNextUrl(std::string(bh.syncNextUrl));
    srfc.setUpdateTime(std::string(bh.updateTime));
    srfc.setRiskCount(bh.count);

    std::vector<SyncRiskFileConfig::SyncRiskProperty> loadedRisks;
    loadedRisks.reserve(bh.count);

    for (uint64_t i = 0; i < bh.count; ++i)
    {
        SyncRiskFileConfig::BinaryRiskProperty brp{};
        ifs.read(reinterpret_cast<char*>(&brp), sizeof(SyncRiskFileConfig::BinaryRiskProperty));
        loadedRisks.push_back({brp.id, brp.indicator, brp.type, brp.created, brp.isActive});
    }
    srfc.setCollectedRisks(loadedRisks);
    std::cout << "Loaded " << srfc.getRiskCount() << " records." << std::endl;
}

// 寫入 Binary 檔
void RiskFileUpdater::riskConfigToBinary()
{
    auto& srfc = SyncRiskFileConfig::instance();
    std::ofstream ofs(xdp_fw_config::instance().get_risk_config_info().file_source_binary_path(), std::ios::binary);

    SyncRiskFileConfig::BinaryHeader bh = {};
    std::strncpy(bh.syncNextUrl, srfc.getSyncNextUrl().c_str(), sizeof(bh.syncNextUrl)-1);
    std::strncpy(bh.updateTime, srfc.getUpdateTime().c_str(), sizeof(bh.updateTime)-1);
    bh.count = srfc.getCollectedRisks().size(); // 確保 count 正確

    ofs.write(reinterpret_cast<const char*>(&bh), sizeof(SyncRiskFileConfig::BinaryHeader));

    for (const auto& srp : srfc.getCollectedRisks())
    {
        SyncRiskFileConfig::BinaryRiskProperty brp = {};
        brp.id = srp.id;
        std::strncpy(brp.indicator, srp.indicator.c_str(), sizeof(brp.indicator)-1);
        std::strncpy(brp.type, srp.type.c_str(), sizeof(brp.type)-1);
        std::strncpy(brp.created, srp.created.c_str(), sizeof(brp.created)-1);
        brp.isActive = srp.isActive;
        ofs.write(reinterpret_cast<const char*>(&brp), sizeof(SyncRiskFileConfig::BinaryRiskProperty));
    }
}

void RiskFileUpdater::fileToRiskConfig()
{
    SyncRiskFileConfig& syncRiskFileConfig = SyncRiskFileConfig::instance();

    std::string fileSourcePath = xdp_fw_config::instance().get_risk_config_info().file_source_path();

    std::ifstream readIn(fileSourcePath, std::ios::in | std::ios::binary);
    if (!readIn.is_open()) return;

    std::string content((std::istreambuf_iterator<char>(readIn)), std::istreambuf_iterator<char>());
    readIn.close();

    simdjson::ondemand::parser parser;
    simdjson::padded_string json_data = simdjson::padded_string(content);
    simdjson::ondemand::document doc;

    // 如果解析失敗，直接回傳
    if (parser.iterate(json_data).get(doc) != simdjson::SUCCESS) return;

    // 1. 處理 indicators 陣列
    simdjson::ondemand::array indicators;
    if (doc["indicators"].get(indicators) == simdjson::SUCCESS)
    {
        for (auto element : indicators)
        {
            // 必須傳遞 object 物件，且 parseAndStoreIndicator 內部必須做深拷貝
            RiskFileUpdater::instance().parseAndStoreIndicator(element.get_object());
        }
        syncRiskFileConfig.setCollectedRisks(RiskFileUpdater::instance().collected_risks1());
    }

    // 2. 處理字串 (建議轉換為 string 避免 string_view 指標溢出)
    std::string_view sv;
    if (doc["syncNextUrl"].get_string().get(sv) == simdjson::SUCCESS)
    {
        syncRiskFileConfig.setSyncNextUrl(std::string(sv));
    }

    if (doc["updateTime"].get_string().get(sv) == simdjson::SUCCESS)
    {
        // 這裡如果你存的是字串，直接設定進去即可
        syncRiskFileConfig.setUpdateTime(std::string(sv));
    }
}