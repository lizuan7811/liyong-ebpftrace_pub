//
// Created by root on 2026/6/25.
//

#include "CommonUtil.hpp"

#include <format>
#include <iostream>
#include <string>
#include <filesystem>

bool CommonUtil::processDirectory(const std::string& absolutePath)
{
    try
    {
        std::filesystem::path pathObj(absolutePath);
        std::filesystem::path dirPath = pathObj.parent_path();

        if (dirPath.empty())
        {
            return true;
        }
        if (std::filesystem::create_directories(dirPath))
        {
            std::cout << "[COMMONTOOL] 📂 成功動態建立目錄: " << dirPath << "\n";
        }
        return true;
    }
    catch (std::exception& e)
    {
        std::cerr << "[COMMONTOOL] ❌ 建立目錄失敗: " << e.what() << "\n";
        return false;
    }
}

std::string CommonUtil::getLocalTime(const std::string& timeFormat)
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    struct std::tm buf;
    localtime_r(&now_c, &buf);

    std::stringstream ss;
    // 修正：必須使用 timeFormat.c_str() 轉為 const char*
    ss << std::put_time(&buf, timeFormat.c_str());
    return ss.str();
}

// 在讀取設定檔時，順便轉換成絕對路徑
std::string CommonUtil::getAbsolute(const std::string& relative_path) {
    return std::filesystem::absolute(relative_path).string();
}