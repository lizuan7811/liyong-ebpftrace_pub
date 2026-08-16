//
// Created by root on 2026/6/14.
//

#ifndef LIYONG_EBPFTRACE_RULEPARSER_HPP
#define LIYONG_EBPFTRACE_RULEPARSER_HPP
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

// using ACMap = std::map<std::string, std::string>;
using ACMap = std::map<std::string, std::string>;
using ACMapVector = std::vector<ACMap>;

class AtomicCtlFactory
{
public:
    using ACPtr = std::shared_ptr<const ACMapVector>;

    void reload(ACMapVector nVec)
    {
        c_ptr.store(std::make_shared<const ACMapVector>(std::move(nVec)));
    }

    std::shared_ptr<const std::vector<std::map<std::string, std::string>>> reloadAndGet(ACMapVector nVec)
    {
        c_ptr.store(std::make_shared<const ACMapVector>(std::move(nVec)));
        return c_ptr.load();
    }

    ACPtr get() const
    {
        return c_ptr.load();
    }

private:
    std::atomic<ACPtr> c_ptr{std::make_shared<const ACMapVector>()};
};

class RuleParser
{
public:
    static ACMapVector parse_file(std::string path)
    {
        ACMapVector rules_vec;
        std::ifstream file(path);
        std::string line;
        while (std::getline(file, line))
        {
            if (line.empty() || line[0] == '#') continue;
            rules_vec.push_back(parse_line(line));
        }
        return rules_vec;
    }

private:
    // 改用 std::map<...>& 引用傳遞
    static ACMap parse_line(std::string_view line)
    {
        ACMap current_line_map;
        size_t start = 0, end;
        // 這裡也要修復你的 find 邏輯，原本的 while 寫法有誤
        while ((end = line.find(',', start)) != std::string_view::npos)
        {
            process_pair(line.substr(start, end - start), current_line_map);
            start = end + 1;
        }
        process_pair(line.substr(start), current_line_map);
        return current_line_map;
    }

    static void process_pair(std::string_view pair, ACMap& rules)
    {
        size_t pos = pair.find('=');
        if (pos != std::string_view::npos)
        {
            // 直接使用引用存取，乾淨俐落
            rules[std::string(pair.substr(0, pos))] = std::string(pair.substr(pos + 1));
        }
    }
};


#endif //LIYONG_EBPFTRACE_RULEPARSER_HPP
