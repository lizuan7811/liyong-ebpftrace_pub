#ifndef LIYONG_EBPFTRACE_RISKINDICATORS_HPP
#define LIYONG_EBPFTRACE_RISKINDICATORS_HPP

#include <array>
#include <cstdint>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <arpa/inet.h>

class RiskIndicators {
private:
    RiskIndicators() = default;

    ~RiskIndicators() = default;

    // 禁止拷貝建構與賦值，確保單例模式唯一性
    RiskIndicators(const RiskIndicators &) = delete;

    RiskIndicators &operator=(const RiskIndicators &) = delete;

    // 將成員變數設為 public，或透過 getter 方法存取
    std::unordered_set<std::string> identity;
    std::unordered_set<std::string> application;
    std::unordered_set<std::string> network;
    std::unordered_set<std::string> vulnerability;
    std::unordered_set<std::string> file;
    std::unordered_set<std::string> host;
    std::unordered_set<__uint64_t> ipv4s;
    std::set<std::array<uint8_t, 16>> ipv6s;

    // std::unordered_set<CidrRange> cidrs;
    std::unordered_map<uint32_t, std::unordered_set<uint32_t> > cidrsMap;

public:
    static RiskIndicators &instance() {
        static RiskIndicators inst;
        return inst;
    }

    class CidrRange {
    public:
        [[nodiscard]] uint32_t ip_address() const {
            return ipAddress;
        }

        void set_ip_address(uint32_t ip_address) {
            ipAddress = ip_address;
        }

        [[nodiscard]] uint32_t mask1() const {
            return mask;
        }

        void set_mask(uint32_t mask) {
            this->mask = mask;
        }

        CidrRange() = default;

        // 修正：提供公開的建構函式以支援 { ... } 初始化
        CidrRange(uint32_t ip, uint32_t m) : ipAddress(ip), mask(m) {
        }

    private:
        uint32_t ipAddress = 0;
        uint32_t mask = 0;
    };

    // 您可以加入一個簡單的 helper 函數來處理數據載入
    void analysIndicator(const std::string &type, const std::string &category, const std::string &value) {
        if (category == "identity") identity.insert(value);
        else if (category == "application") application.insert(value);
        else if (category == "network") network.insert(value);
        else if (category == "vulnerability") vulnerability.insert(value);
        else if (category == "file") file.insert(value);
        else if (category == "host") host.insert(value);
        else if (type == "ipv4") addIPs(value);
        else if (type == "ipv6") addIPv6(value);
        else if (category == "cidrs") addCidrRange(value);
    }

    static CidrRange parseCidr(const std::string &cidr_str) {
        CidrRange cidrRange;

        size_t pos = cidr_str.find("/");
        if (pos == std::string::npos) {
            struct in_addr addr;
            if (inet_pton(AF_INET, cidr_str.c_str(), &addr) != 1) {
                throw std::invalid_argument("invalid IP address");
            }
            return CidrRange{ntohl(addr.s_addr), 0xFFFFFFFF};
        }

        std::string ip_part = cidr_str.substr(0, pos);
        int prefix = std::stoi(cidr_str.substr(pos + 1));
        if (prefix < 0 || prefix > 32) {
            throw std::out_of_range("Prefix must between 0 and 32");
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, ip_part.c_str(), &addr) != 1) {
            throw std::invalid_argument("invalid IP address");
        }
        uint32_t network = ntohl(addr.s_addr);
        uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
        return CidrRange{network & mask, mask};
    }

    void addIPs(const std::string &cidr_str) {
        struct in_addr addr;
        if (inet_pton(AF_INET, cidr_str.c_str(), &addr) != 1) {
            throw std::invalid_argument("invalid IP address");
        }
        ipv4s.insert(ntohl(addr.s_addr));
    }

    void addIPv6(const std::string &ip_str) {
        struct in6_addr addr;

        // 使用 AF_INET6 處理 IPv6
        if (inet_pton(AF_INET6, ip_str.c_str(), &addr) != 1) {
            throw std::invalid_argument("invalid IPv6 address");
        }

        // 將結構轉換為 std::array 以便存入 std::set
        std::array<uint8_t, 16> arr;
        std::copy(std::begin(addr.s6_addr), std::end(addr.s6_addr), arr.begin());
        ipv6s.insert(arr);
    }

    void addCidrRange(const std::string &cidr_str) {
        CidrRange cidrRange = parseCidr(cidr_str);
        cidrsMap[cidrRange.mask1()].insert(cidrRange.ip_address());
    }

    bool isMatchIdentity(const std::string &value) {
        return identity.find(value) != identity.end();
    }

    bool isMatchApplication(const std::string &value) {
        return application.find(value) != application.end();
    }

    bool isMatchNetwork(const std::string &value) {
        return network.find(value) != network.end();
    }

    bool isMatchVulnerability(const std::string &value) {
        return vulnerability.find(value) != vulnerability.end();
    }

    bool isMatchFile(const std::string &value) {
        return file.find(value) != file.end();
    }

    bool isMatchHost(const std::string &value) {
        return host.find(value) != host.end();
    }

    bool isMatchIPs(uint64_t value) {
        return ipv4s.find(value) != ipv4s.end();
    }

    bool isMatchCidr(const uint32_t value) const {
        for (const auto &[mask, networks]: cidrsMap) {
            if (networks.contains(value & mask)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] std::unordered_set<std::string> identity1() const {
        return identity;
    }

    [[nodiscard]] std::unordered_set<std::string> application1() const {
        return application;
    }

    [[nodiscard]] std::unordered_set<std::string> network1() const {
        return network;
    }

    [[nodiscard]] std::unordered_set<std::string> vulnerability1() const {
        return vulnerability;
    }

    [[nodiscard]] std::unordered_set<std::string> file1() const {
        return file;
    }

    [[nodiscard]] std::unordered_set<std::string> host1() const {
        return host;
    }

    [[nodiscard]] std::unordered_set<__uint64_t> ipv4s1() const {
        return ipv4s;
    }

    [[nodiscard]] std::set<std::array<uint8_t, 16>> ipv6s1() const {
        return ipv6s;
    }

    [[nodiscard]] std::unordered_map<uint32_t, std::unordered_set<uint32_t> > cidrs_map() const {
        return cidrsMap;
    }

    // 輔助函式：將 std::array 轉為字串
    std::string ipv6ToString(const std::array<uint8_t, 16>& ip_arr) {
        char str[INET6_ADDRSTRLEN];
        // inet_ntop 需要將 array 的指標轉為 void* 或 in6_addr 指標
        if (inet_ntop(AF_INET6, ip_arr.data(), str, INET6_ADDRSTRLEN)) {
            return std::string(str);
        }
        return "invalid_ip";
    }
};

#endif //LIYONG_EBPFTRACE_RISKINDICATORS_HPP
