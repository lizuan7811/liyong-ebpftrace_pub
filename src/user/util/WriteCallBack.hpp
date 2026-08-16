#ifndef LIYONG_EBPFTRACE_WRITECALLBACK_HPP
#define LIYONG_EBPFTRACE_WRITECALLBACK_HPP

#include <string>
#include <iostream>
#include "../config/simdjson.h"

// 假設這兩個函數在你的 .cpp 中實作
// 使用 const std::string& 避免不必要的複製
std::string getAuthToken(const std::string &path, const std::string &username, const std::string &password);
std::string fetchOtxData(const std::string &apiKey, const std::string &remoteUrl);

// 自動解析模板
template<typename T>
void deserializeConfig(const std::string &jsonData, T &target) {
    simdjson::ondemand::parser parser;
    simdjson::padded_string json = simdjson::padded_string(jsonData);
    
    try {
        auto doc = parser.iterate(json);
        auto obj = doc.get_object();
        target.from_json(obj);
    } catch (const simdjson::simdjson_error &e) {
        throw std::runtime_error("JSON 解析失敗: " + std::string(e.what()));
    }
}

#endif