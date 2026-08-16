//
// Created by root on 2026/6/16.
//

#include "../L7DpiEngine.hpp"
#include <iomanip>
#include "../../user/config/RiskIndicators.hpp"
#include <openssl/evp.h>

#include "../../model/RiskMetricInfos.hpp"

// ================================================================
// JA3 輔助函式實作
// ================================================================

inline bool L7DpiEngine::is_grease_value(uint16_t val) const {
    return ((val & 0x0F0F) == 0x0A0A) && ((val >> 8) == (val & 0xFF));
}

std::string L7DpiEngine::md5_hex(const std::string &input) const {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, digest, &digest_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < digest_len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int) digest[i];
    return oss.str();
}

std::string L7DpiEngine::compute_ja3_client(const uint8_t *payload, size_t len) const {
    if (!payload || len < 5 || payload[0] != 0x16) return "";
    size_t offset = 5;

    if (len < offset + 4 || payload[offset] != 0x01) return "";
    offset += 4;

    if (len < offset + 2) return "";
    uint16_t tls_version = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    if (len < offset + 32) return "";
    offset += 32;

    if (len < offset + 1) return "";
    offset += 1 + payload[offset];

    if (len < offset + 2) return "";
    uint16_t cipher_suites_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;
    if (len < offset + cipher_suites_len) return "";

    std::vector<std::string> ciphers;
    for (size_t i = 0; i < cipher_suites_len; i += 2) {
        uint16_t cs = (payload[offset + i] << 8) | payload[offset + i + 1];
        if (!is_grease_value(cs)) ciphers.push_back(std::to_string(cs));
    }
    offset += cipher_suites_len;

    if (len < offset + 1) return "";
    offset += 1 + payload[offset];

    std::vector<std::string> extensions, elliptic_curves, ec_point_formats;

    if (len >= offset + 2) {
        uint16_t ext_total_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;
        size_t ext_end = std::min(offset + ext_total_len, len);

        while (offset + 4 <= ext_end) {
            uint16_t ext_type = (payload[offset] << 8) | payload[offset + 1];
            uint16_t ext_len = (payload[offset + 2] << 8) | payload[offset + 3];
            size_t ext_data_start = offset + 4;
            if (ext_data_start + ext_len > ext_end) break;

            if (!is_grease_value(ext_type))
                extensions.push_back(std::to_string(ext_type));

            if (ext_type == 0x000a && ext_len >= 2) {
                uint16_t curves_len = (payload[ext_data_start] << 8) | payload[ext_data_start + 1];
                size_t curve_off = ext_data_start + 2;
                for (size_t i = 0; i + 2 <= curves_len && curve_off + i + 2 <= ext_data_start + ext_len; i += 2) {
                    uint16_t curve = (payload[curve_off + i] << 8) | payload[curve_off + i + 1];
                    if (!is_grease_value(curve)) elliptic_curves.push_back(std::to_string(curve));
                }
            }

            if (ext_type == 0x000b && ext_len >= 1) {
                uint8_t fmt_len = payload[ext_data_start];
                size_t fmt_off = ext_data_start + 1;
                for (size_t i = 0; i < fmt_len && fmt_off + i < ext_data_start + ext_len; ++i)
                    ec_point_formats.push_back(std::to_string(payload[fmt_off + i]));
            }

            offset = ext_data_start + ext_len;
        }
    }

    auto join = [](const std::vector<std::string> &v) {
        std::string s;
        for (size_t i = 0; i < v.size(); ++i) {
            if (i) s += "-";
            s += v[i];
        }
        return s;
    };

    std::ostringstream ja3_str;
    ja3_str << tls_version << "," << join(ciphers) << ","
            << join(extensions) << "," << join(elliptic_curves) << ","
            << join(ec_point_formats);

    return md5_hex(ja3_str.str());
}

// ================================================================
// 風險判斷函式實作
// ================================================================

bool L7DpiEngine::checkJA3Fingerprint(const struct l7_dpi_event *event,
                                      const struct ndpi_flow_struct *ndpi_flow,
                                      const uint8_t *tls_payload,
                                      size_t tls_len) {
    if (!ndpi_flow) return false;
    bool is_risky = false;

    // --- 1. 自算 JA3 Client，比對 OTX application 黑名單 ---
    std::string ja3_client = compute_ja3_client(tls_payload, tls_len);
    if (!ja3_client.empty()) {
        USER_LOG(LOG_LVL_DEBUG, "🧬 自算 JA3 Client: %s", ja3_client.c_str());
        if (RiskIndicators::instance().isMatchApplication(ja3_client)) {
            USER_LOG(LOG_LVL_WARN, "🚨 命中惡意 JA3 Client 指紋（OTX）: %s", ja3_client.c_str());
            is_risky = true;
        }
    }

    // --- 2. nDPI 內建 JA4C，同樣查 application 集合 ---
    const char *ja4c_raw = ndpi_flow->protos.tls_quic.ja4_client;
    if (ja4c_raw[0] != '\0') {
        USER_LOG(LOG_LVL_DEBUG, "🧬 JA4C: %s", ja4c_raw);
        if (RiskIndicators::instance().isMatchApplication(std::string(ja4c_raw))) {
            USER_LOG(LOG_LVL_WARN, "🚨 命中惡意 JA4C 指紋: %s", ja4c_raw);
            is_risky = true;
        }
    }

    return is_risky;
}

bool L7DpiEngine::riskDomainCheck(const std::string &sni) {
    (void) sni;
    return false;
}

bool L7DpiEngine::checkIPReputation(const uint32_t &ip) {
    return RiskIndicators::instance().isMatchIPs(ip);
}

bool L7DpiEngine::checkFileReputation(const std::string &file) {
    return RiskIndicators::instance().isMatchFile(file);
}

bool L7DpiEngine::checkHostReputation(const __u32 &dst_ip, char *str) {
    (void) dst_ip;
    return RiskIndicators::instance().isMatchHost(std::string(str));
}

void L7DpiEngine::renderInfoToJson() {
    // TODO: serialize DPI result
}

void L7DpiEngine::sendToDataCollector() {
    // TODO: send to kafka / grpc / socket
}

void L7DpiEngine::riskChainFilter(bool has_sni,
                                  const struct l7_dpi_event *event,
                                  struct ndpi_flow_struct *ndpi_flow,
                                  const uint8_t *tls_payload,
                                  size_t tls_len) {
    if (!has_sni) return;

    bool is_risky = false;

    if (event->direction == DIR_IN) {
        if (checkIPReputation(event->src_ip)) {
            USER_LOG(LOG_LVL_WARN, "🚨 來源 IP 命中黑名單");
            is_risky = true;
        }
        // ✅ 在成員函式內呼叫 compute_ja3_client 完全合法
        if (checkJA3Fingerprint(event, ndpi_flow, tls_payload, tls_len)) {
            USER_LOG(LOG_LVL_WARN, "🚨 JA3/JA4 指紋命中黑名單");
            is_risky = true;
        }
    } else {
        if (checkIPReputation(event->dst_ip)) {
            USER_LOG(LOG_LVL_WARN, "🚨 目的 IP 命中黑名單");
            is_risky = true;
        }
        if (checkFileReputation(ndpi_flow->host_server_name)) {
            USER_LOG(LOG_LVL_WARN, "🚨 FILE 命中黑名單");
            is_risky = true;
        }
        if (checkHostReputation(event->dst_ip, ndpi_flow->host_server_name)) {
            USER_LOG(LOG_LVL_WARN, "🚨 HOST 命中黑名單");
            is_risky = true;
        }
    }

    if (is_risky) {
        // TODO: 觸發阻斷或告警動作, need to update bpf map
    }

    std::string clean_domain = ndpi_flow->host_server_name;
    // 移除所有非可見字元或結尾的 \0
    clean_domain.erase(std::remove_if(clean_domain.begin(), clean_domain.end(),
                       [](char c) { return !isprint(c); }), clean_domain.end());

    // 建立 Key
    RiskMetricInfos::TrafficKey key(event->src_ip, event->dst_ip, event->src_port, event->dst_port,
                                    clean_domain);

    // 存入 Map (instance() 會回傳你的 Singleton)
    RiskMetricInfos::instance().update_metrics(key, is_risky);

    renderInfoToJson();

    sendToDataCollector();
}
