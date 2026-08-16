//
// Created by root on 2026/6/16.
// Updated with Deep Comments on 2026/6/16.
//

#ifndef LIYONG_EBPFTRACE_FWDPIENGINE_H
#define LIYONG_EBPFTRACE_FWDPIENGINE_H

#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <iostream>
#include <cstring>
#include <utility>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "../../ebpf/types.h"
#include "../config/user_log.h"

extern "C" {
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <ndpi_main.h>
#include <ndpi_api.h>
#include <ndpi_typedefs.h>
}

class L7DpiEngine {
private:
    struct ndpi_global_context *ndpi_g_ctx_ = nullptr;
    struct ndpi_detection_module_struct *ndpi_ctx_ = nullptr;
    std::unordered_map<std::string, struct ndpi_flow_struct *> flow_table_;

    // JA3 輔助函式宣告
    inline bool is_grease_value(uint16_t val) const;

    std::string md5_hex(const std::string &input) const;

    std::string compute_ja3_client(const uint8_t *payload, size_t len) const;

    inline std::string get_birectional_key(const struct l7_dpi_event *event) const {
        uint32_t min_ip = std::min(event->src_ip, event->dst_ip);
        uint32_t max_ip = std::max(event->src_ip, event->dst_ip);
        uint16_t min_port = std::min(event->src_port, event->dst_port);
        uint16_t max_port = std::max(event->src_port, event->dst_port);
        return std::to_string(min_ip) + "_" + std::to_string(max_ip) + "_" +
               std::to_string(min_port) + "_" + std::to_string(max_port) + "_" +
               std::to_string(event->ip_proto);
    }

    struct ndpi_flow_struct *get_or_create_ndpi_flow(const std::string &key) {
        auto it = flow_table_.find(key);
        if (it != flow_table_.end()) return it->second;

        size_t size = ndpi_detection_get_sizeof_ndpi_flow_struct();
        struct ndpi_flow_struct *new_flow = (struct ndpi_flow_struct *) ndpi_malloc(size);
        if (new_flow) {
            std::memset(new_flow, 0, size);
            flow_table_[key] = new_flow;
        }
        return new_flow;
    }

public:
    L7DpiEngine() {
        ndpi_g_ctx_ = ndpi_global_init();
        if (!ndpi_g_ctx_) {
            USER_LOG(LOG_LVL_ERROR, "Fatal: nDPI Global context initialization failed!");
            exit(1);
        }

        ndpi_ctx_ = ndpi_init_detection_module(ndpi_g_ctx_);
        if (!ndpi_ctx_) {
            USER_LOG(LOG_LVL_ERROR, "Fatal: nDPI Module initialization failed!");
            exit(1);
        }

        ndpi_dump_config(ndpi_ctx_, stdout);

        if (get_user_debug_level() >= LOG_LVL_DEBUG) {
            ndpi_load_protocols_file(ndpi_ctx_, NULL);
        }

        ndpi_finalize_initialization(ndpi_ctx_);
        USER_LOG(LOG_LVL_INFO, "🎯 [nDPI] 防火牆 L7 DPI 辨識引擎初始化成功！");
    }

    ~L7DpiEngine() {
        for (auto &[key, flow]: flow_table_) ndpi_free(flow);
        flow_table_.clear();
        if (ndpi_ctx_) ndpi_exit_detection_module(ndpi_ctx_);
        if (ndpi_g_ctx_) ndpi_global_deinit(ndpi_g_ctx_);
    }

    // ✅ 簽名統一：帶 tls_payload / tls_len
    bool checkJA3Fingerprint(const struct l7_dpi_event *event,
                             const struct ndpi_flow_struct *ndpi_flow,
                             const uint8_t *tls_payload,
                             size_t tls_len);

    bool riskDomainCheck(const std::string &sni);

    bool checkIPReputation(const uint32_t &ip);

    void renderInfoToJson();

    void sendToDataCollector();

    bool checkFileReputation(const std::string &file);

    bool checkHostReputation(const __u32 &dst_ip, char *str);

    // ✅ riskChainFilter 也補上 payload 參數
    void riskChainFilter(bool has_sni,
                         const struct l7_dpi_event *event,
                         struct ndpi_flow_struct *ndpi_flow,
                         const uint8_t *tls_payload,
                         size_t tls_len);

    std::pair<std::string, bool> analyze_packet(const struct l7_dpi_event *event) {
        if (!event || event->l3_packet_len < sizeof(struct iphdr))
            return {"BAD_PACKET", false};

        uint16_t safe_len = event->l3_packet_len;
        if (safe_len > sizeof(event->l3_packet))
            safe_len = sizeof(event->l3_packet);

        std::vector<uint8_t> local_packet(event->l3_packet, event->l3_packet + safe_len);

        struct iphdr iph;
        std::memcpy(&iph, local_packet.data(), sizeof(struct iphdr));

        size_t ip_hdr_len = iph.ihl * 4;
        if (local_packet.size() < ip_hdr_len) return {"BAD_IP_LEN", false};

        char src_ip_str[INET_ADDRSTRLEN] = {0};
        char dst_ip_str[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &(iph.saddr), src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph.daddr), dst_ip_str, INET_ADDRSTRLEN);

        uint16_t src_port = 0, dst_port = 0;
        size_t l4_hdr_len = 0;

        if (iph.protocol == IPPROTO_TCP) {
            if (local_packet.size() < ip_hdr_len + sizeof(struct tcphdr))
                return {"BAD_TCP_LEN", false};
            struct tcphdr tcph;
            std::memcpy(&tcph, local_packet.data() + ip_hdr_len, sizeof(struct tcphdr));
            src_port = ntohs(tcph.source);
            dst_port = ntohs(tcph.dest);
            l4_hdr_len = tcph.doff * 4;
        } else if (iph.protocol == IPPROTO_UDP) {
            if (local_packet.size() < ip_hdr_len + 8) return {"BAD_UDP_LEN", false};
            src_port = ntohs(*(uint16_t *) (local_packet.data() + ip_hdr_len));
            dst_port = ntohs(*(uint16_t *) (local_packet.data() + ip_hdr_len + 2));
            l4_hdr_len = 8;
        } else {
            return {"UNSUPPORTED_L4", false};
        }

        size_t total_hdr_len = ip_hdr_len + l4_hdr_len;
        if (local_packet.size() <= total_hdr_len) return {"NO_PAYLOAD", false};

        size_t payload_len = local_packet.size() - total_hdr_len;
        const uint8_t *payload_ptr = local_packet.data() + total_hdr_len;

        std::string flow_key = get_birectional_key(event);
        struct ndpi_flow_struct *ndpi_flow = get_or_create_ndpi_flow(flow_key);
        if (!ndpi_flow) return {"INTERNAL_ERROR(OOM)", false};

        uint64_t time_ms = 0;
        ndpi_protocol detected_proto = ndpi_detection_process_packet(
            ndpi_ctx_, ndpi_flow, local_packet.data(), local_packet.size(), time_ms, nullptr
        );

        bool n_finished = (ndpi_flow->init_finished == 1) || (detected_proto.proto.app_protocol != 0);

        u_int16_t proto_id = 0;
        if (detected_proto.proto.app_protocol != 0)
            proto_id = detected_proto.proto.app_protocol;
        else if (detected_proto.proto.master_protocol != 0)
            proto_id = detected_proto.proto.master_protocol;
        else
            proto_id = ndpi_get_master_proto(ndpi_ctx_, ndpi_flow);

        const char *proto_name_ptr = ndpi_get_proto_by_id(ndpi_ctx_, proto_id);
        std::string proto_name = proto_name_ptr ? proto_name_ptr : "UNKNOWN";

        bool has_sni = (ndpi_flow->host_server_name != nullptr &&
                        ndpi_flow->host_server_name[0] != '\0');

        if (proto_id != 0 && has_sni) {
            char ev_src_ip[INET_ADDRSTRLEN] = {0};
            char ev_dst_ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &(event->src_ip), ev_src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(event->dst_ip), ev_dst_ip, INET_ADDRSTRLEN);
            if (get_user_debug_level() >= LOG_LVL_DEBUG) {
                USER_LOG(LOG_LVL_INFO, "\n================= 🎯 nDPI L7 深度辨識報告 =================");
                USER_LOG(LOG_LVL_INFO, " 基本五元組   | %s %s:%d -> %s:%d",
                         (iph.protocol == IPPROTO_TCP ? "TCP" : "UDP"),
                         ev_src_ip, ntohs(event->src_port),
                         ev_dst_ip, ntohs(event->dst_port));
                USER_LOG(LOG_LVL_INFO, " 識別應用協議 | %s (ID: %d)", proto_name.c_str(), proto_id);
                USER_LOG(LOG_LVL_INFO, " 狀態機階段   | %s", n_finished ? "【辨識完成】" : "【持續追蹤中】");
                USER_LOG(LOG_LVL_INFO, " 網域名稱(Host)| %s", ndpi_flow->host_server_name);
                USER_LOG(LOG_LVL_INFO, "===========================================================\n");
            }
            // ✅ 把 payload_ptr / payload_len 一路傳下去
            riskChainFilter(has_sni, event, ndpi_flow, payload_ptr, payload_len);

            if (n_finished || has_sni) {
                ndpi_free(ndpi_flow);
                flow_table_.erase(flow_key);
                return {proto_name, true};
            }
        }

        return {proto_name, false};
    }
};

#endif //LIYONG_EBPFTRACE_FWDPIENGINE_H
