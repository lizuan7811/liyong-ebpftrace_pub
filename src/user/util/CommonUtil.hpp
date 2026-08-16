#ifndef COMMON_UTIL_HPP
#define COMMON_UTIL_HPP

#include <iostream>
#include <string>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <vector>

class CommonUtil {
public:
    // --- 原有的功能 ---
    static bool processDirectory(const std::string &absolutePath);

    static std::string getLocalTime(const std::string &timeFormat);

    // 在讀取設定檔時，順便轉換成絕對路徑
    static std::string getAbsolute(const std::string& relative_path);

    // --- 新增的通用模板工具 (整合在這裡) ---
    template<typename Container>
    static void printContainer(const Container &container, const std::string &prefix = "") {
        if (!prefix.empty()) {
            std::cout << "[" << getLocalTime("%Y-%m-%d %H:%M:%S") << "] "
                    << prefix << ": ";
        }

        std::cout << "{ ";
        auto it = container.begin();
        while (it != container.end()) {
            std::cout << *it;
            if (++it != container.end()) std::cout << ", ";
        }
        std::cout << " }" << std::endl;
    }

    // 將 Helper 函式放入類別或工具庫中
    static std::string toLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return s;
    }
};
#endif
