#ifndef LIYONG_EBPFTRACE_XDP_FW_CONFIG_H
#define LIYONG_EBPFTRACE_XDP_FW_CONFIG_H

#include "../../ebpf/types.h"
#include <string>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <map>
#include <filesystem>
#include <cstdint>
#include <cstring>
#include "simdjson.h"
#include "../util/RuleParser.hpp"
#include "../util/CommonUtil.hpp"

inline const std::string default_config_path = "resource/config.json";

inline const std::map<std::string, uint32_t> log_level_map = {
    {"TRACE", 4},
    {"DEBUG", 3},
    {"INFO", 2},
    {"WARN", 1},
    {"ERROR", 0}
};


// 使用雙冒號 ::std::string 迫使編譯器從最頂層全域尋找，無視任何局部命名空間污染
inline std::uint64_t parse_size(const ::std::string &str) {
    double value;
    char unit[16] = {0};

    if (sscanf(str.c_str(), "%lf%15s", &value, unit) != 2) {
        ::std::string msg = "invalid size: ";
        msg.append(str);
        throw ::std::runtime_error(msg);
    }

    if (!strcmp(unit, "KB") || !strcmp(unit, "KB/s")) {
        return static_cast<uint64_t>(value * 1024ULL);
    }
    if (!strcmp(unit, "MB") || !strcmp(unit, "MB/s")) {
        return static_cast<uint64_t>(value * 1024ULL * 1024ULL);
    }
    if (!strcmp(unit, "GB") || !strcmp(unit, "GB/s")) {
        return static_cast<uint64_t>(value * 1024ULL * 1024ULL * 1024ULL);
    }
    return static_cast<std::uint64_t>(value);
}

class xdp_fw_config {
public:
    class RateLimitConfig {
        friend class xdp_fw_config;

    private:
        uint64_t global_pps_limit = 0;
        std::string global_rate;
        std::string global_burst;
        std::string custom_rate;
        std::string custom_burst;
        std::string flow_rate;
        std::string flow_burst;

    public:
        uint64_t get_global_pps_limit() const { return global_pps_limit; }
        const std::string &get_global_rate() const { return global_rate; }
        const std::string &get_global_burst() const { return global_burst; }
        const std::string &get_custom_rate() const { return custom_rate; }
        const std::string &get_custom_burst() const { return custom_burst; }
        const std::string &get_flow_rate() const { return flow_rate; }
        const std::string &get_flow_burst() const { return flow_burst; }
    };

    class WhiteListConfig {
        friend class xdp_fw_config;

    private:
        std::string path;

    public:
        const std::string &get_path() const { return path; }
    };

    class BlackListConfig {
        friend class xdp_fw_config;

    public:
        class TempList {
            friend class xdp_fw_config;

        private:
            std::string path;

        public:
            const std::string &get_path() const { return path; }
        };

        class PermList {
            friend class xdp_fw_config;

        private:
            std::string path;

        public:
            const std::string &get_path() const { return path; }
        };

    private:
        TempList temp_list;
        PermList perm_list;

    public:
        const TempList &get_temp_list() const { return temp_list; }
        const PermList &get_perm_list() const { return perm_list; }
    };

    class AllowPortsConfig {
        friend class xdp_fw_config;

    private:
        std::vector<std::string> src_port;
        std::vector<std::string> dst_port;

    public:
        const std::vector<std::string> &get_src_port() const { return src_port; }
        const std::vector<std::string> &get_dst_port() const { return dst_port; }
    };

    class RiskConfigInfo {
        friend class xdp_fw_config;

    private:
        std::string remoteSourceUrl;
        std::string fileSourcePath;
        std::string fileSourceBinaryPath;
        std::string authTokenPath;
        std::string checksumStoragePath;
        std::string apiKey;
        uint64_t syncIntervalSeconds;
        uint64_t retryLimit;
        uint64_t timeoutSeconds;
        bool forceReload;

    public:
        [[nodiscard]] std::string remote_source_url() const { return remoteSourceUrl; }
        [[nodiscard]] std::string file_source_path() const { return fileSourcePath; }
        [[nodiscard]] std::string file_source_binary_path() const { return fileSourceBinaryPath; }
        [[nodiscard]] std::string auth_token_path() const { return authTokenPath; }
        [[nodiscard]] std::string checksum_storage_path() const { return checksumStoragePath; }
        [[nodiscard]] uint64_t sync_interval_seconds() const { return syncIntervalSeconds; }
        [[nodiscard]] uint64_t retry_limit() const { return retryLimit; }
        [[nodiscard]] uint64_t timeout_seconds() const { return timeoutSeconds; }
        [[nodiscard]] const std::string &api_key() const { return apiKey; }
        [[nodiscard]] bool force_reload() const { return forceReload; }
    };

    class SSLConf {
        friend class xdp_fw_config;

    private:
        std::string caPath;
        std::string keyPath;
        std::string certPath;
        std::string certPasswd;
        std::string tlsVersion;
        std::string ciphers;
        bool isActive;
        bool enableMtls;

    public:
        const std::string &ca_path() const {
            return caPath;
        }

        const std::string &key_path() const {
            return keyPath;
        }

        const std::string &cert_path() const {
            return certPath;
        }

        const std::string &cert_passwd() const {
            return certPasswd;
        }

        const std::string &tls_version() const {
            return tlsVersion;
        }

        const std::string &ciphers1() const {
            return ciphers;
        }

        const bool is_active() const {
            return isActive;
        }

        const bool enable_mtls() const {
            return enableMtls;
        }
    };

    class ExporterConfig {
        friend class xdp_fw_config;

    private:
        bool enableExporter; // 是否啟用 Prometheus Exporter 模式
        bool enableSocket; // 是否啟用 Prometheus Exporter 模式
        std::string socketPath; // Socket 通訊路徑 (預設: /tmp/xdp_metrics.sock)
        int metricsPort; // 若未來想讓 C++ 直接提供簡單資訊時的 Port
        int updateIntervalMs; // 數據刷新間隔 (與 Go 輪詢頻率配合)

    public:
        [[nodiscard]] bool enable_exporter() const {
            return enableExporter;
        }

        [[nodiscard]] bool enable_socket() const {
            return enableSocket;
        }

        [[nodiscard]] std::string socket_path() const {
            return socketPath;
        }

        [[nodiscard]] int metrics_port() const {
            return metricsPort;
        }

        [[nodiscard]] int update_interval_ms() const {
            return updateIntervalMs;
        }
    };

private:
    uint16_t port = 9443;
    std::string log_level;
    std::string log_path;
    std::string rule_file_path;
    std::string time_format;
    bool enable_dpi = false;

    RateLimitConfig rate_limit;
    WhiteListConfig white_list;
    BlackListConfig black_list;
    AllowPortsConfig allow_ports;
    RiskConfigInfo riskConfigInfo;
    SSLConf sslConf;
    ExporterConfig exporterConfig;

    uint64_t *cpu_values = nullptr;
    int cpu_values_nr_cpus = 0;

    xdp_fw_config() = default;

    void clear_resources() {
        if (cpu_values) {
            free(cpu_values);
            cpu_values = nullptr;
        }
        allow_ports.src_port.clear();
        allow_ports.dst_port.clear();
    }

public:
    xdp_fw_config(const xdp_fw_config &) = delete;

    xdp_fw_config &operator=(const xdp_fw_config &) = delete;

    ~xdp_fw_config() {
        if (cpu_values) free(cpu_values);
    }

    static xdp_fw_config &instance() {
        static xdp_fw_config inst;
        return inst;
    }

    static void sync_xdp_config_map(global_config *out_global_config);

    static void sync_xdp_block_map(uint32_t map_fd,
                                   std::shared_ptr<const std::vector<std::map<std::string, std::string> >> &sharedMap,
                                   const std::string &type);

    static void destroy_skeleton();

    void load(const std::string &file_path = default_config_path) {
        std::string absolutePath = CommonUtil::getAbsolute(file_path);

        if (!std::filesystem::exists(absolutePath)) {
            throw std::runtime_error("找不到設定檔: " + absolutePath);
        }

        clear_resources();

        simdjson::ondemand::parser parser;
        auto json_data = simdjson::padded_string::load(absolutePath).value();
        simdjson::ondemand::document doc = parser.iterate(json_data).value();

        simdjson::ondemand::object obj_g = doc["global"].get_object().value();
        port = static_cast<uint16_t>(obj_g["port"].get_uint64().value());
        log_level = std::string(obj_g["log_level"].get_string().value());
        log_path = std::string(obj_g["log_path"].get_string().value());
        rule_file_path = std::string(obj_g["rule_file_path"].get_string().value());
        time_format = std::string(obj_g["time_format"].get_string().value());

        simdjson::ondemand::object rate_obj = obj_g["rate_limit"].get_object().value();
        rate_limit.global_pps_limit = rate_obj["global_pps_limit"].get_uint64().value();
        rate_limit.global_rate = std::string(rate_obj["global_rate"].get_string().value());
        rate_limit.global_burst = std::string(rate_obj["global_burst"].get_string().value());
        rate_limit.custom_rate = std::string(rate_obj["custom_rate"].get_string().value());
        rate_limit.custom_burst = std::string(rate_obj["custom_burst"].get_string().value());
        rate_limit.flow_rate = std::string(rate_obj["flow_rate"].get_string().value());
        rate_limit.flow_burst = std::string(rate_obj["flow_burst"].get_string().value());

        white_list.path = std::string(doc["white_list"].get_object()["path"].get_string().value());
        black_list.temp_list.path = std::string(
            doc["black_list"].get_object()["temp_list"].get_object()["path"].get_string().value());
        black_list.perm_list.path = std::string(
            doc["black_list"].get_object()["perm_list"].get_object()["path"].get_string().value());

        for (auto val: doc["allow_ports"].get_object()["src_port"].get_array().value())
            allow_ports.src_port.emplace_back(val.get_string().value());
        for (auto val: doc["allow_ports"].get_object()["dest_port"].get_array().value())
            allow_ports.dst_port.emplace_back(val.get_string().value());

        enable_dpi = doc["enable_dpi"].get_bool().value();

        simdjson::ondemand::object risk = doc["risk_config_info"].get_object().value();
        riskConfigInfo.remoteSourceUrl = std::string(risk["remote_source_url"].get_string().value());
        riskConfigInfo.fileSourcePath = std::string(risk["file_source_path"].get_string().value());
        riskConfigInfo.fileSourceBinaryPath = std::string(risk["file_source_binary_path"].get_string().value());
        riskConfigInfo.authTokenPath = std::string(risk["auth_token_path"].get_string().value());
        riskConfigInfo.checksumStoragePath = std::string(risk["checksum_storage_path"].get_string().value());
        riskConfigInfo.syncIntervalSeconds = risk["sync_interval_seconds"].get_int64().value();
        riskConfigInfo.retryLimit = risk["retry_limit"].get_int64().value();
        riskConfigInfo.timeoutSeconds = risk["timeout_seconds"].get_int64().value();
        riskConfigInfo.apiKey = risk["api_key"].get_string().value();
        riskConfigInfo.forceReload = risk["force_reload"].get_bool().value();

        simdjson::ondemand::object sslConfig = doc["ssl_conf"].get_object().value();
        sslConf.isActive = sslConfig["is_active"].get_bool().value();
        sslConf.enableMtls = sslConfig["enable_mtls"].get_bool().value();
        sslConf.caPath = std::string(sslConfig["ca_path"].get_string().value());
        sslConf.keyPath = std::string(sslConfig["key_path"].get_string().value());
        sslConf.certPath = std::string(sslConfig["cert_path"].get_string().value());
        sslConf.certPasswd = std::string(sslConfig["cert_passwd"].get_string().value());
        sslConf.tlsVersion = std::string(sslConfig["tls_version"].get_string().value());
        sslConf.ciphers = std::string(sslConfig["ciphers"].get_string().value());

        simdjson::ondemand::object exporterConf = doc["exporter_config"].get_object().value();
        exporterConfig.enableExporter = exporterConf["enable_exporter"].get_bool().value();
        exporterConfig.enableSocket = exporterConf["enable_socket"].get_bool().value();
        exporterConfig.socketPath = std::string(exporterConf["socket_path"].get_string().value());
        exporterConfig.metricsPort = exporterConf["metrics_port"].get_uint64().value();
        exporterConfig.updateIntervalMs = exporterConf["update_interval_ms"].get_uint64().value();
    }

    uint16_t get_port() const { return port; }

    uint32_t get_log_level() const {
        auto it = log_level_map.find(log_level);
        return (it != log_level_map.end()) ? it->second : 1;
    }

    const RateLimitConfig &get_rate_limit() const { return rate_limit; }
    const BlackListConfig &get_black_list() const { return black_list; }
    const WhiteListConfig &get_white_list() const { return white_list; }
    const AllowPortsConfig &get_allow_ports() const { return allow_ports; }
    const RiskConfigInfo &get_risk_config_info() const { return riskConfigInfo; }

    const SSLConf &ssl_conf() const {
        return sslConf;
    }

    const std::string &get_time_format() const { return time_format; }

    const std::string &get_log_path() const { return log_path; }

    const std::string &get_rule_file_path() const { return rule_file_path; }

    // 💡 修正 4：布林值極小，直接傳值（bool），不要用 const bool &

    bool get_enable_dpi() const { return enable_dpi; } // 在 class xdp_fw_config 的 public 區段：

    [[nodiscard]] SSLConf ssl_conf1() const {
        return sslConf;
    }

    [[nodiscard]] ExporterConfig exporter_config() const {
        return exporterConfig;
    }

    uint64_t *&get_cpu_values() { return cpu_values; }
    int &get_cpu_values_nr_cpus() { return cpu_values_nr_cpus; }
};

#endif
