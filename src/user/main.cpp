// main.cpp 最頂部，所有 include 之前
#define _LINUX_STAT_H   // 阻止 linux/stat.h 被載入
#include "./config/RiskFileSyncManager.hpp"
#include "./config/RiskIndicators.hpp"
#include "../user/config/RiskFileUpdater.hpp"
#include "servie/L7DpiEngine.hpp"
#include "servie/L7FlowSession.hpp"
#include "servie/ExporterService.hpp"
#include "util/CommonUtil.hpp"
#include "util/LockFreeSPSCQueue.hpp"
#include "util/RuleParser.hpp"

// =================================================================
// 🛡️ 幹掉 Linux 核心層與 Userspace 的 struct stat 衝突
// =================================================================
#ifndef _LINUX_STAT_H
#define _LINUX_STAT_H
#endif
#define _I386_STAT_H
#define _X86_64_STAT_H

// 🟢 搶先載入 Userspace 檔案控制與狀態庫，搶先卡位標準定義
#include <sys/stat.h>
#include <fcntl.h>
// =================================================================

#include "main.h"
#include <format>
#include "config/xdp_fw_config.h"
#include <iostream>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>
#include <signal.h>
#include <ifaddrs.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <thread>
#include <mutex>
#include <cstring>
#include <atomic>       // ← 新增：std::atomic<bool>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "../third_party/crow/crow.h"

#include "config/Firewall.hpp"
#include "config/xdp_fw_config.hpp"

// =========================================================
// 全域變數
// =========================================================

// 注意：g_temp_map_fd / g_perm_map_fd 統一由 FirewallController 管理。
// 這裡保留 extern 宣告僅供仍在使用老 C 介面的其他翻譯單元連結；
// main.cpp 內部一律透過 firewallController.get_*_map_fd() 存取。
extern uint32_t g_local_subnet_mask;
extern uint32_t g_local_subnet_net;
extern int g_temp_map_fd;
extern int g_perm_map_fd;

// Per-CPU 統計緩衝
static uint64_t *cpu_values = nullptr;
static int cpu_values_nr_cpus = 0;

// 使用 std::atomic<bool> 取代 volatile sig_atomic_t，
// 確保多執行緒（ring_poll_thread）的讀取可見性符合 C++ 記憶體模型。
static std::atomic<bool> g_running{true};

static bool tc_attached_map[MAX_IFINDEX] = {false};
static xdp_fw_bpf *skel = nullptr;
static trace_connect_bpf *trace_skel = nullptr;
static ring_buffer *rb = nullptr;
static FirewallController &firewallController = FirewallController::instance();
static global_config g_cfg;
// static pthread_t dpi_thread_id = 0;

volatile __u64 NUM_CPUS;

static std::jthread g_poll_thread;
static std::jthread g_ui_dashboard_thread;
static std::jthread g_netlink_thread; // 🟢 新增：網卡熱插拔監聽執行緒

// 保護熱插拔重掛載流程，避免同一張網卡的多個 netlink 事件並發觸發重複掛載
static std::mutex g_hotplug_mutex;

// 🟢 正確寫法：直接宣告，容量必須是 2 的冪次方（例如 65536）
// 這樣會直接在記憶體中配置好空間，不使用 new，效能最高！
static LockFreeSPSCQueue<struct l7_dpi_event> g_lockFreeQueue(65536);

// 2. 🟢 加上這行！初始化 Userspace 丟包計數器為 0
static std::atomic<uint64_t> g_dropped_userspace_logs{0};

static L7DpiEngine fwDpiEngine;

// =========================================================
// 設定解析輔助
// =========================================================

void convert_to_struct(const std::vector<std::string> &src_ports,
                       const std::vector<std::string> &dst_ports,
                       global_config *out_global_config) {
    memset(out_global_config->src_ports, 0, sizeof(out_global_config->src_ports));
    memset(out_global_config->dst_ports, 0, sizeof(out_global_config->dst_ports));

    for (size_t i = 0; i < src_ports.size() && i < MAX_PORTS; ++i)
        out_global_config->src_ports[i] = static_cast<uint16_t>(std::stoi(src_ports[i]));

    for (size_t i = 0; i < dst_ports.size() && i < MAX_PORTS; ++i)
        out_global_config->dst_ports[i] = static_cast<uint16_t>(std::stoi(dst_ports[i]));
}

void parse_list_to_block(const std::string * /*temp_path*/,
                         const std::string * /*perm_path*/,
                         global_config * /*out_global_config*/) {
    // 預留實作
}

void load_allow_ports_to_map(const std::vector<std::string> &src_ports,
                             const std::vector<std::string> &dst_ports,
                             global_config *out_global_config) {
    if (!skel || !skel->maps.ingress_allowed_ports) return;

    convert_to_struct(src_ports, dst_ports, out_global_config);

    int i_map_fd = bpf_map__fd(skel->maps.ingress_allowed_ports);
    int e_map_fd = bpf_map__fd(skel->maps.egress_allowed_ports);
    __u8 value = 1;

    for (size_t i = 0; i < src_ports.size() && i < MAX_PORTS; i++) {
        uint16_t port = static_cast<uint16_t>(std::stoi(src_ports[i]));
        if (port != 0)
            bpf_map_update_elem(i_map_fd, &port, &value, BPF_ANY);
    }
    for (size_t i = 0; i < dst_ports.size() && i < MAX_PORTS; i++) {
        uint16_t port = static_cast<uint16_t>(std::stoi(dst_ports[i]));
        if (port != 0)
            bpf_map_update_elem(e_map_fd, &port, &value, BPF_ANY);
    }
}

inline void load_blocklist_to_map(const std::string *temp_list, const std::string *perm_list) {
    // 使用 static 確保這些管理器在函式結束後不會被銷毀
    static AtomicCtlFactory temp_blocklist_ctl;
    static AtomicCtlFactory perm_blocklist_ctl;

    if (!skel || !skel->maps.temp_blocklist_map || !skel->maps.permanent_blocklist_map) {
        std::cerr << "[ERROR] BPF maps not found!\n";
        return;
    }
    if (!assure_control_file_exists("/etc/xdp_fw", *temp_list) || !
        assure_control_file_exists("/etc/xdp_fw", *perm_list)) {
        std::cerr << "[FATAL] ❌ 初始化/etc/xdp_fw，防火牆中止啟動。\n";
        throw std::runtime_error("初始化/etc/xdp_fw，防火牆中止啟動.");
    }

    // 1. 載入並解析 Temp 規則
    std::cout << "[INFO] Loading temp blocklist from: " << *temp_list << "...\n";
    ACMapVector tempMap = RuleParser::parse_file(*temp_list);
    std::shared_ptr<const std::vector<std::map<std::string, std::string> >> nTempMap = temp_blocklist_ctl.
            reloadAndGet(tempMap);
    // 這裡不用 move，因為下面 sync 還要用

    // 2. 載入並解析 Perm 規則
    std::cout << "[INFO] Loading permanent blocklist from: " << *perm_list << "...\n";
    ACMapVector permMap = RuleParser::parse_file(*perm_list);
    std::shared_ptr<const std::vector<std::map<std::string, std::string> >> nPermMap = perm_blocklist_ctl.
            reloadAndGet(permMap);

    // 4. 同步至 BPF Map
    std::cout << "[SYNC] Starting XDP map synchronization...\n";

    xdp_fw_config::sync_xdp_block_map(g_temp_map_fd, nTempMap, "TEMP");
    xdp_fw_config::sync_xdp_block_map(g_perm_map_fd, nPermMap, "PERM");

    std::cout << "[SUCCESS] All blocklist rules synchronized to Kernel Space.\n";
}

// =========================================================
// 配置轉換與 Map 同步
// =========================================================

void fill_xfg_and_update_xdpmap(const xdp_fw_config *config, global_config *out_global_config) {
    if (!out_global_config) return;

    long num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_cpus <= 0) num_cpus = 1;

    out_global_config->log_level = config->get_log_level();
    out_global_config->flow_burst = parse_size(config->get_rate_limit().get_flow_burst());
    out_global_config->flow_rate = parse_size(config->get_rate_limit().get_flow_rate()) / num_cpus;
    out_global_config->global_burst = parse_size(config->get_rate_limit().get_global_burst());
    out_global_config->global_rate = parse_size(config->get_rate_limit().get_global_rate()) / num_cpus;
    out_global_config->custom_rate = parse_size(config->get_rate_limit().get_custom_rate()) / num_cpus;
    out_global_config->custom_burst = parse_size(config->get_rate_limit().get_custom_burst());
    out_global_config->global_pps_limit = config->get_rate_limit().get_global_pps_limit();
    out_global_config->enable_dpi = config->get_enable_dpi();

    load_allow_ports_to_map(config->get_allow_ports().get_src_port(),
                            config->get_allow_ports().get_dst_port(),
                            out_global_config);

    load_blocklist_to_map(&config->get_black_list().get_temp_list().get_path(),
                          &config->get_black_list().get_perm_list().get_path());

    g_cfg = *out_global_config;
}

// =========================================================
// 設定內容列印
// =========================================================

inline void look_config(const xdp_fw_config &config) {
    std::cout << "✅ 【解析成功！】目前讀取到的設定內容如下：\n";
    std::cout << "--------------------------------------------------\n";
    std::cout << " 🔹 [Global 基礎設定]\n";
    std::cout << "    - 監聽連接埠 (port)       : " << config.get_port() << "\n";
    std::cout << "    - 日誌層級 (log_level)    : " << config.get_log_level() << "\n";
    std::cout << "    - 日誌路徑 (log_path)     : " << config.get_log_path() << "\n";
    std::cout << "    - 規則檔案路徑 (rule_path): " << config.get_rule_file_path() << "\n";
    std::cout << "    - 時間格式 (time_format)  : " << config.get_time_format() << "\n";
    std::cout << "    - OPEN DPI PROCESS        : " << config.get_enable_dpi() << "\n";

    std::cout << " 🔹 [RateLimit 限速監控]\n";
    auto &rl = config.get_rate_limit();
    std::cout << "    - 全域 PPS 上限 (global_pps)  : " << rl.get_global_pps_limit() << "\n";
    std::cout << "    - 全域速率 (global_rate)       : " << rl.get_global_rate() << "\n";
    std::cout << "    - 全域突發流量 (global_burst)  : " << rl.get_global_burst() << "\n";
    std::cout << "    - Custom 速率 (custom_rate)    : " << rl.get_custom_rate() << "\n";
    std::cout << "    - Custom 突發流量 (custom_burst): " << rl.get_custom_burst() << "\n";
    std::cout << "    - 單一流量速率 (flow_rate)     : " << rl.get_flow_rate() << "\n";
    std::cout << "    - 單一流量突發 (flow_burst)    : " << rl.get_flow_burst() << "\n";

    std::cout << " 🔹 [WhiteList 白名單]\n";
    std::cout << "    - 白名單檔案路徑 (path)   : " << config.get_white_list().get_path() << "\n";

    std::cout << " 🔹 [BlackList 黑名單]\n";
    auto &bl = config.get_black_list();
    std::cout << "    - 臨時黑名單路徑 (temp)   : " << bl.get_temp_list().get_path() << "\n";
    std::cout << "    - 永久黑名單路徑 (perm)   : " << bl.get_perm_list().get_path() << "\n";

    std::cout << " 🔹 [RISK CONFIG INFO]\n";
    const xdp_fw_config::RiskConfigInfo &riskConfigInfo = config.get_risk_config_info();
    std::cout << "    - REMOTE SOURCE URL: " << riskConfigInfo.remote_source_url() << "\n";
    std::cout << "    - file source path : " << riskConfigInfo.file_source_path() << "\n";
    std::cout << "    - Authorization Token Path : " << riskConfigInfo.auth_token_path() << "\n";
    std::cout << "    - CHECKSUM STORAGE PATH : " << riskConfigInfo.checksum_storage_path() << "\n";
    std::cout << "    - SYNC INTERVAL SECONDS : " << riskConfigInfo.sync_interval_seconds() << "\n";
    std::cout << "    - RETRY LIMIT : " << riskConfigInfo.retry_limit() << "\n";
    std::cout << "    - TIMEOUT SECONDS : " << riskConfigInfo.timeout_seconds() << "\n";
    std::cout << "    - FORCE RELOAD : " << riskConfigInfo.force_reload() << "\n";


    std::cout << " 🔹 [SSL CONFIG INFO]\n";

    const xdp_fw_config::SSLConf &sslConfig = config.ssl_conf();
    std::cout << "    - IS ACTIVE: " << sslConfig.is_active() << "\n";
    std::cout << "    - ENABLE MTLS : " << sslConfig.enable_mtls() << "\n";
    std::cout << "    - CA PATH : " << sslConfig.ca_path() << "\n";
    std::cout << "    - KEY PATH : " << sslConfig.key_path() << "\n";
    std::cout << "    - CERT PATH : " << sslConfig.cert_path() << "\n";
    std::cout << "    - CERT PASSWD : " << sslConfig.cert_passwd() << "\n";
    std::cout << "    - TLS VERSION : " << sslConfig.tls_version() << "\n";
    std::cout << "    - CIPHERS : " << sslConfig.ciphers1() << "\n";

    std::cout << "--------------------------------------------------\n";
}

// =========================================================
// 日誌排序比較函數
// =========================================================

int compare_by_time(const void *a, const void *b) {
    const struct event *ev_a = static_cast<const struct event *>(a);
    const struct event *ev_b = static_cast<const struct event *>(b);
    if (ev_a->ts < ev_b->ts) return -1;
    if (ev_a->ts > ev_b->ts) return 1;
    return 0;
}

// =========================================================
// 日誌輪詢與即時大盤列印
// =========================================================

void poll_clean_and_print_log_ordered(int report_map_fd) {
    uint32_t next_key;
    void *lookup_key = nullptr;

    static struct event sorted_buffer[10000];
    memset(sorted_buffer, 0, sizeof(sorted_buffer));
    int count = 0;

    while (bpf_map_get_next_key(report_map_fd, lookup_key, &next_key) == 0) {
        if (next_key == 10000) {
            static uint32_t temp_key;
            temp_key = next_key;
            lookup_key = &temp_key;
            continue;
        }

        if (count >= 10000) {
            bpf_map_delete_elem(report_map_fd, &next_key);
            static uint32_t temp_key;
            temp_key = next_key;
            lookup_key = &temp_key;
            continue;
        }

        if (bpf_map_lookup_elem(report_map_fd, &next_key, &sorted_buffer[count]) == 0) {
            if (sorted_buffer[count].ts > 0)
                count++;
        }

        bpf_map_delete_elem(report_map_fd, &next_key);

        static uint32_t base_key;
        base_key = next_key;
        lookup_key = &base_key;
    }

    if (count > 1)
        qsort(sorted_buffer, count, sizeof(struct event), compare_by_time);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];

    int start = (count > MAX_LOG_LINES) ? (count - MAX_LOG_LINES) : 0;
    int printed = 0;

    for (int i = start; i < count; i++) {
        if (!inet_ntop(AF_INET, &sorted_buffer[i].key.saddr, src_ip_str, sizeof(src_ip_str)))
            snprintf(src_ip_str, sizeof(src_ip_str), "ERR_%x", sorted_buffer[i].key.saddr);
        if (!inet_ntop(AF_INET, &sorted_buffer[i].key.daddr, dst_ip_str, sizeof(dst_ip_str)))
            snprintf(dst_ip_str, sizeof(dst_ip_str), "ERR_%x", sorted_buffer[i].key.daddr);

        int64_t offset = get_boot_to_real_offset_ns();
        uint64_t real_unix_ns = sorted_buffer[i].ts + static_cast<uint64_t>(offset);
        time_t seconds = static_cast<time_t>(real_unix_ns / 1000000000ULL);
        uint64_t milliseconds = (real_unix_ns % 1000000000ULL) / 1000000;

        struct tm *tm_info = localtime(&seconds);
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        std::cout << std::format("[{}.{:03d}] {} | STG={:<11} RSN={:<12} | {} -> {}\n",
                                 time_str,
                                 milliseconds,
                                 action_icon(sorted_buffer[i].status_code),
                                 stage_str(sorted_buffer[i].status_code),
                                 reason_str(sorted_buffer[i].status_code),
                                 src_ip_str,
                                 dst_ip_str);
        printed++;
    }

    // 清除游標以下殘留空間，防止洗版
    std::cout << "\033[J" << std::flush;
}

// =========================================================
// Per-CPU 統計加總
// =========================================================

uint64_t get_percpu_stats_total(int map_fd, uint32_t key) {
    uint64_t total_sum = 0;
    if (!cpu_values) {
        cpu_values_nr_cpus = libbpf_num_possible_cpus();
        if (cpu_values_nr_cpus <= 0) return 0;
        cpu_values = static_cast<uint64_t *>(calloc(cpu_values_nr_cpus, sizeof(*cpu_values)));
        if (!cpu_values) return 0;
    }

    if (bpf_map_lookup_elem(map_fd, &key, cpu_values) == 0) {
        for (int i = 0; i < cpu_values_nr_cpus; i++)
            total_sum += cpu_values[i];
    }
    return total_sum;
}

// =========================================================
// 全域儀表板主迴圈
// =========================================================

void start_global_dashboard(int global_stats_map_fd, int report_map_fd, int stats_map_fd) {
    std::fflush(stdout);
    std::cout << std::flush;
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    uint64_t last_packets = get_percpu_stats_total(global_stats_map_fd, STATS_KEY_PPS);
    uint64_t last_bytes = get_percpu_stats_total(global_stats_map_fd, STATS_KEY_BPS);

    struct pollfd fds[1];
    fds[0].fd = FirewallController::get_read_fd(); // ← 修正：使用 get_read_fd()
    fds[0].events = POLLIN;

    if (get_user_debug_level() >= LOG_LVL_DEBUG) {
        std::cout << "\033[2J\033[?25l" << std::flush;
    }
    while (g_running.load(std::memory_order_relaxed)) {
        handle_sigusr_event(fds);

        if (get_user_debug_level() >= LOG_LVL_DEBUG) {
            std::cout << "\033[H";
        }
        uint64_t current_packets = get_percpu_stats_total(global_stats_map_fd, STATS_KEY_PPS);
        uint64_t current_bytes = get_percpu_stats_total(global_stats_map_fd, STATS_KEY_BPS);

        uint64_t pps = current_packets - last_packets;
        uint64_t bps = current_bytes - last_bytes;
        double mbps = (static_cast<double>(bps) * 8.0) / 1000000.0;

        last_packets = current_packets;
        last_bytes = current_bytes;

        if (get_user_debug_level() >= LOG_LVL_DEBUG) {
            std::cout << "\033[K==================================================\n"
                    << "\033[K       XDP 高防防火牆即時流量大盤           \n"
                    << "\033[K==================================================\n"
                    << "\033[K 📈 全網實時吞吐量統計 (不受 1024 抽樣影響):\n";

            std::cout << std::format("\033[K    ➔  【 {:<11} 】 Packets/Sec (即時 PPS)\n", pps);
            std::cout << std::format("\033[K    ➔  【 {:<11.2f} 】 Mbps (即時網路頻寬)\n", mbps);
            std::cout << "\033[K--------------------------------------------------\n"
                    << "\033[K 🗂️  核心協議計數統計:\n"
                    << "\033[K    ";
        }

        for (int i = 0; i < 6; i++) {
            uint64_t val = 0;
            if (bpf_map_lookup_elem(stats_map_fd, &i, &val) == 0)
                std::cout << std::format("{}: {:<6} | ", stat_names[i], val);
        }

        if (get_user_debug_level() >= LOG_LVL_DEBUG) {
            std::cout << "\n"
                    << "\033[K--------------------------------------------------\n";

            std::cout << std::format("\033[K 🕵️ 最新現行犯與抽樣日誌 (時序對齊，最新 {} 筆):\n", MAX_LOG_LINES);
            std::cout << "\033[K==================================================\n";

            poll_clean_and_print_log_ordered(report_map_fd);

            std::cout << "\033[K==================================================\n" << std::flush;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// =========================================================
// TC Egress 掛載
// =========================================================

int attach_tc_egress(int ifindex, trace_connect_bpf *tskel) {
    if (!tskel || !tskel->progs.tc_egress_record) {
        std::cerr << "[TC] ❌ 找不到 tc_egress_record 程式\n";
        return -1;
    }

    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    };

    bpf_tc_hook_create(&hook);

    struct bpf_tc_opts detach_opts = {.sz = sizeof(detach_opts)};
    bpf_tc_detach(&hook, &detach_opts);

    struct bpf_tc_opts attach_opts = {
        .sz = sizeof(attach_opts),
        .prog_fd = bpf_program__fd(tskel->progs.tc_egress_record),
        .flags = BPF_TC_F_REPLACE
    };
    return bpf_tc_attach(&hook, &attach_opts);
}

int safe_attach_tc_egress(int ifindex, trace_connect_bpf *tskel) {
    if (ifindex <= 0 || ifindex >= MAX_IFINDEX) return -1;
    if (tc_attached_map[ifindex]) return 0;

    int err = attach_tc_egress(ifindex, tskel);
    if (err == 0) tc_attached_map[ifindex] = true;
    return err;
}

// =========================================================
// TC Egress 卸載（供熱插拔 down 事件 / 單張網卡場景使用）
// =========================================================

void detach_tc_egress(int ifindex) {
    if (ifindex <= 0 || ifindex >= MAX_IFINDEX) return;

    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS
    };
    struct bpf_tc_opts detach_opts = {.sz = sizeof(detach_opts)};
    bpf_tc_detach(&hook, &detach_opts);
    // 不呼叫 bpf_tc_hook_destroy，避免影響同介面上其他方向（ingress）可能存在的 clsact qdisc
    tc_attached_map[ifindex] = false;
}

// =========================================================
// 全域 PPS Token Bucket 初始化
// =========================================================

inline void init_global_pps_limit(const __u64 *pps_limit) {
    uint32_t key = 0;
    struct pps_bucket initial_pps = {
        .tokens = *pps_limit,
        .last_ts = 0
    };
    int gpmf = bpf_map__fd(skel->maps.global_pps_map);
    bpf_map_update_elem(gpmf, &key, &initial_pps, BPF_ANY);
    printf("[GLOBAL_PPS] GLOBAL_PPS INIT！\n");
}

// =========================================================
// Signal 遮罩設定：必須在 main() 一開始、任何其他 thread 產生之前呼叫！
// =========================================================
static sigset_t g_shutdown_sigset;

// 執行最底層的掃蕩，不依賴任何 API，直接從 Kernel 層砍掉所有 BPF 殘留
void force_clean_all_net_hooks() {
    std::cout << "[CLEANUP] 正在執行底層強制掃蕩，清除所有 BPF 殘留...\n";

    ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        // 跳過 loopback 與空介面
        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, "lo") == 0) continue;

        // 強制移除該介面的 clsact，這會瞬間抹除所有舊的 egress/ingress filter
        std::string cmd = "tc qdisc del dev " + std::string(ifa->ifa_name) + " clsact 2>/dev/null";
        system(cmd.c_str());

        // 同步移除 XDP 綁定
        std::string xdp_cmd = "ip link set dev " + std::string(ifa->ifa_name) + " xdp off 2>/dev/null";
        system(xdp_cmd.c_str());
    }
    freeifaddrs(ifaddr);
    std::cout << "[CLEANUP] ✅ 所有介面的 BPF/TC Hook 已強制清除。\n";
}

// =========================================================
// 全域 XDP / TC 卸載＋重掛（供熱插拔事件使用）
// 不 join g_poll_thread / g_ui_dashboard_thread，也不重建 ring buffer，
// 只重新處理「掛載」這一層，避免動到還在正常運作的執行緒與資料流。
// =========================================================
// =========================================================
// 全域 XDP / TC 卸載＋重掛（供熱插拔事件使用）
// 實作精確的清理與重新掛載邏輯，徹底解決重複掛載導致的 Kernel 衝突
// =========================================================
inline void full_reload_all_xdp_tc() {
    std::cout << "[HOTPLUG] 🔄 開始執行全域 XDP/TC 卸載與重新部署...\n";

    // 1. 【清理 XDP】：透過 FirewallController 卸載現有 XDP
    firewallController.detach_interfaces();
    std::cout << "[HOTPLUG]   ├── [XDP] 🧹 已卸載全機所有網卡的 XDP 掛載\n";

    // 2. 【清理 TC】：執行強制清理指令，確保每個介面都不留殘影
    ifaddrs *ifaddr_clean, *ifa_clean;
    if (getifaddrs(&ifaddr_clean) != -1) {
        for (ifa_clean = ifaddr_clean; ifa_clean != nullptr; ifa_clean = ifa_clean->ifa_next) {
            if (!ifa_clean->ifa_addr || strcmp(ifa_clean->ifa_name, "lo") == 0) continue;

            // 強制移除該介面的 clsact，這會瞬間抹除所有舊的 egress/ingress filter
            std::string cmd = "tc qdisc del dev " + std::string(ifa_clean->ifa_name) + " clsact 2>/dev/null";
            system(cmd.c_str());
        }
        freeifaddrs(ifaddr_clean);
    }

    // 重置內部的追蹤狀態
    for (int i = 0; i < MAX_IFINDEX; i++) tc_attached_map[i] = false;
    std::cout << "[HOTPLUG]   └── [TC]  🧹 已強制清除全機 TC Egress 鉤子\n";

    // 3. 【重新掛載檢查】：確保 skeleton 已就緒
    if (!skel || !skel->progs.xdp_fw) {
        std::cerr << "[HOTPLUG] ⚠️ skeleton 尚未就緒，跳過本次重掛\n";
        return;
    }

    // 4. 【重新掛載 XDP】：掃描並部署
    int prog_fd = bpf_program__fd(skel->progs.xdp_fw);
    int attached_count = firewallController.attach_xdp_to_all_interfaces(prog_fd);
    std::cout << std::format("[HOTPLUG]   ├── [XDP] ✅ 已重新覆蓋全機 {} 個網路通道\n", attached_count);

    // 5. 【重新掛載 TC】：先建立 clsact，再掛載規則
    ifaddrs *ifaddr_tc, *ifa_tc;
    if (getifaddrs(&ifaddr_tc) != -1) {
        int visited[256] = {0};
        for (ifa_tc = ifaddr_tc; ifa_tc != nullptr; ifa_tc = ifa_tc->ifa_next) {
            if (!ifa_tc->ifa_addr || strcmp(ifa_tc->ifa_name, "lo") == 0) continue;

            int ifindex = if_nametoindex(ifa_tc->ifa_name);
            if (ifindex <= 0 || ifindex >= 256 || visited[ifindex]) continue;
            visited[ifindex] = 1;

            // 必須先 add clsact 才能掛載 bpf 規則
            std::string cmd_add_qdisc = "tc qdisc add dev " + std::string(ifa_tc->ifa_name) + " clsact";
            system(cmd_add_qdisc.c_str());

            if (attach_tc_egress(ifindex, trace_skel) == 0) {
                tc_attached_map[ifindex] = true;
                std::cout << std::format("[HOTPLUG]   └── [TC]  ✅ {} (Index: {}) 掛載成功\n",
                                         ifa_tc->ifa_name, ifindex);
            } else {
                std::cerr << std::format("[HOTPLUG]   └── [TC]  ❌ {} (Index: {}) 掛載失敗\n",
                                         ifa_tc->ifa_name, ifindex);
            }
        }
        freeifaddrs(ifaddr_tc);
    }

    std::cout << "[HOTPLUG] 🔄 全域 XDP/TC 重掛完成\n";
}

// =========================================================
// 網卡熱插拔事件處理：偵測到任一網卡斷線重新連接時，
// 觸發「全部網卡」的 XDP/TC 卸載＋重掛（而不只是變化的那張）。
// =========================================================

// 記錄每張網卡「上一次已知的 up/down 狀態」，用來去抖動。
// 核心對同一次實體連線變化（插上網線/熱點重連）常常會連續發出多個
// RTM_NEWLINK 通知（carrier、位址指派、flags 變動各觸發一次），
// 若不去抖動，會在同一瞬間收到幾十個重複事件，導致狂打全域重掛。
static bool g_iface_last_up[MAX_IFINDEX] = {false};
static bool g_iface_state_known[MAX_IFINDEX] = {false};

void on_interface_changed(int ifindex, const std::string &interface_name, bool is_up) {
    if (ifindex <= 0 || ifindex >= MAX_IFINDEX) return;

    std::lock_guard<std::mutex> lock(g_hotplug_mutex);

    // 狀態沒有真的改變（例如同一次事件被核心重複通知），直接忽略
    if (g_iface_state_known[ifindex] && g_iface_last_up[ifindex] == is_up) {
        return;
    }
    g_iface_state_known[ifindex] = true;
    g_iface_last_up[ifindex] = is_up;

    if (is_up) {
        std::cout << std::format("[HOTPLUG] 🔌 介面 {} (ifindex={}) 已重新連線，觸發全域重掛...\n",
                                 interface_name, ifindex);
        full_reload_all_xdp_tc();
    } else {
        std::cout << std::format("[HOTPLUG] 🔌 介面 {} (ifindex={}) 已斷線\n", interface_name, ifindex);
        // 網卡消失後舊的 TC 掛載記錄已經無效，清掉避免 ifindex 被複用時誤判「已掛載」。
        // （XDP 部分交由下一次 full_reload_all_xdp_tc() 統一處理，不在此單獨動作。）
        tc_attached_map[ifindex] = false;
    }
}

// =========================================================
// Netlink 監聽執行緒：偵測網卡 up/down，觸發 on_interface_changed
// =========================================================

void netlink_monitor_thread(std::stop_token stoken) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0) {
        std::cerr << "[NETLINK] ❌ 建立 netlink socket 失敗\n";
        return;
    }

    struct sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK; // 監聽介面 up/down/新增/移除事件

    if (bind(fd, reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa)) < 0) {
        std::cerr << "[NETLINK] ❌ bind netlink socket 失敗\n";
        close(fd);
        return;
    }

    // 設定接收逾時，讓迴圈能定期檢查 stop_token / g_running，避免卡死在 recv()
    struct timeval tv{};
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // 放大接收緩衝，降低短時間內大量 NEWLINK 通知造成 ENOBUFS 溢出的機率
    int rcvbuf_size = 1 << 20; // 1MB
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf_size, sizeof(rcvbuf_size));

    std::cout << "[NETLINK] 🛰️  網卡熱插拔監聽執行緒已啟動\n";

    char buf[8192];
    while (g_running.load(std::memory_order_relaxed) && !stoken.stop_requested()) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            if (errno == ENOBUFS) {
                // 緩衝區溢出：核心可能丟棄了部分通知，但 socket 本身仍可用，
                // 不能直接 break，否則整個熱插拔監聽會永久停擺（這正是先前的問題）。
                std::cerr << "[NETLINK] ⚠️ 接收緩衝溢出，可能遺漏部分事件，持續監聽中...\n";
                continue;
            }
            std::cerr << std::format("[NETLINK] ❌ recv 錯誤 (errno={})，5 秒後嘗試恢復監聽...\n", errno);
            std::this_thread::sleep_for(std::chrono::seconds(5));
            continue;
        }
        if (len == 0) continue;

        for (struct nlmsghdr *nh = reinterpret_cast<struct nlmsghdr *>(buf);
             NLMSG_OK(nh, len) && nh->nlmsg_type != NLMSG_DONE;
             nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type != RTM_NEWLINK && nh->nlmsg_type != RTM_DELLINK)
                continue;

            auto *ifi = static_cast<struct ifinfomsg *>(NLMSG_DATA(nh));
            char name[IF_NAMESIZE] = {0};
            if (!if_indextoname(static_cast<unsigned int>(ifi->ifi_index), name))
                continue;
            if (std::strcmp(name, "lo") == 0)
                continue;

            bool is_up = (nh->nlmsg_type == RTM_NEWLINK) &&
                         (ifi->ifi_flags & IFF_UP) &&
                         (ifi->ifi_flags & IFF_RUNNING);

            on_interface_changed(ifi->ifi_index, name, is_up);
        }
    }

    close(fd);
    std::cout << "[NETLINK] 🛰️  網卡熱插拔監聽執行緒已結束\n";
}

// =========================================================
// 全系統卸載（供正常關閉流程使用）
// =========================================================
inline bool unload_tc() {
    bool result = g_poll_thread.joinable() || g_ui_dashboard_thread.joinable();
    // 1. 先安全停止執行緒
    if (g_poll_thread.joinable()) {
        g_poll_thread.detach();
        std::cout << "    ├── [Thread A] 核心 Poll 執行緒已安全關閉\n";
    }

    if (g_ui_dashboard_thread.joinable()) {
        g_ui_dashboard_thread.detach();
        std::cout << "    └── [Thread B] 大盤 UI 執行緒已安全關閉\n";
    }

    // 2. 透過現有的控制器卸載 (標準流程)
    firewallController.detach_interfaces();

    // 3. 【關鍵補強】：執行強制掃蕩，處理所有遺留的殭屍規則
    force_clean_all_net_hooks();

    // 4. 清理 eBPF 資源
    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }
    if (cpu_values) {
        free(cpu_values);
        cpu_values = nullptr;
    }
    return result || cpu_values != nullptr || cpu_values != nullptr;
}

// =========================================================
// Signal handler：cleanup_and_exit
// 注意：此函式現在只負責「安全清理資源」，不再呼叫 exit()。
// 真正的行程結束交回 main() 正常 return，避免與隱式的
// 全域/靜態物件析構（例如 MetricService 這個 Meyer's singleton）
// 發生跨執行緒競爭，造成 "pure virtual method called" 之類的崩潰。
// =========================================================
inline static void cleanup_and_exit(int sig) noexcept {
    // 還原游標顯示（async-signal-safe；忽略回傳值）
    g_running.store(false);

    if (write(STDOUT_FILENO, "\033[?25h", 6) < 0) {
        /* 終端不可寫：忽略 */
    }

    // 等待 g_running 變 false
    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // std::format 在 signal handler 內技術上並非 async-signal-safe，
    // 但實務上（glibc + C++23）通常不會出問題；若有嚴格要求可改用 write()。
    std::cout << std::format("\n[SIGNAL] 🚨 偵測到關閉訊號 ({})，正在進行原子級卸載...\n", sig);
    do {
        if (unload_tc()) {
            break;
        }
    } while (true);
}

// =========================================================
// Signal 註冊
// =========================================================
void register_signal_handler() {
    // 建立一個 sigaction 結構體
    struct sigaction sa;
    sa.sa_handler = cleanup_and_exit;
    sigemptyset(&sa.sa_mask);

    // SA_RESTART 很重要：當系統呼叫（如 read/write/poll）被訊號中斷時，
    // 它會嘗試自動重啟，這能避免程式在等待 I/O 時崩潰
    sa.sa_flags = SA_RESTART;

    sigaction(SIGINT, &sa, NULL); // Ctrl+C
    sigaction(SIGTERM, &sa, NULL); // 一般終止訊號
    sigaction(SIGHUP, &sa, NULL); // 終端中斷
    sigaction(SIGQUIT, &sa, NULL); // 鍵盤退出

    // SIGUSR1 保持你原本的處理邏輯
    struct sigaction sa_usr;
    sa_usr.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr.sa_mask);
    sa_usr.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa_usr, NULL);

    // SIGKILL 完全不需要也無法註冊
}

void block_shutdown_signals() {
    sigemptyset(&g_shutdown_sigset);
    sigaddset(&g_shutdown_sigset, SIGINT);
    sigaddset(&g_shutdown_sigset, SIGTERM);
    sigaddset(&g_shutdown_sigset, SIGHUP);
    sigaddset(&g_shutdown_sigset, SIGQUIT);

    // 注意：pthread_sigmask 只影響「呼叫的當下這個 thread」，
    // 但之後用 std::thread/std::jthread 建立的子執行緒會「繼承」這個遮罩，
    // 所以一定要在 main() 最開頭、任何 thread 產生之前呼叫。
    pthread_sigmask(SIG_BLOCK, &g_shutdown_sigset, nullptr);

    // SIGUSR1 維持原本 sigaction 方式即可（假設它原本的 handler 本身就很輕量/安全）
    struct sigaction sa_usr{};
    sa_usr.sa_handler = handle_sigusr1;
    sigemptyset(&sa_usr.sa_mask);
    sa_usr.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa_usr, nullptr);
    register_signal_handler();
}

// =========================================================
// 真正安全的關閉流程：這裡面呼叫什麼都合法（不是 signal handler）
// =========================================================
inline void do_graceful_shutdown() {
    std::cout << "\n[MAIN] 偵測到結束標記，開始安全清理..." << std::endl;

    if (g_netlink_thread.joinable()) {
        g_netlink_thread.request_stop();
        g_netlink_thread.detach();
    }

    cleanup_and_exit(0); // 只做 join/detach，不會提前終止行程

    ExporterService::instance().stop(); // 在主執行緒、行程仍完全存活的狀態下，顯式且同步地停掉 crow server
    xdp_fw_config::destroy_skeleton();

    std::cout << "[CLEANUP] 🧹 ✅ 所有 BPF 資源已歸還核心，程式安全退出。\n";
    std::cout << "\033[?25h" << std::flush; // 還原游標
}

// 在專屬 thread 裡「同步」等待訊號，收到後只設 flag，
// 真正清理留給主執行緒的迴圈結束後統一處理
inline void signal_wait_thread_func() {
    int sig = 0;
    sigwait(&g_shutdown_sigset, &sig); // 這裡是普通函式呼叫，安全
    std::cout << std::format("\n[SIGNAL] 🚨 收到關閉訊號 ({})，準備安全退出...\n", sig);
    g_running.store(false, std::memory_order_relaxed);
}

// =========================================================
// 設定檔解析與 pipe 初始化
// =========================================================

void registerRiskIndicators();

inline global_config register_config_and_pipe_handler(int *argc, char **argv) {
#ifdef CONFIG_PATH
    std::string config_path = CONFIG_PATH;
#else
    std::string config_path = "resource/config.json";
#endif

    if (*argc > 1)
        config_path = argv[1];

    std::cout << "==================================================\n";
    std::cout << "🛡️  [xdp_fw] 防火牆使用者空間主程式啟動...\n";
    std::cout << "==================================================\n";
    std::cout << "[Step 1] 正在讀取並解析現代 C++ JSON 設定檔: " << config_path << "\n";

    global_config out_global_config = {};
    try {
        xdp_fw_config &config = xdp_fw_config::instance();
        config.load(config_path);

        look_config(config);

        fill_xfg_and_update_xdpmap(&config, &out_global_config);

        registerRiskIndicators();
    } catch (const std::exception &e) {
        std::cerr << "\n❌ 設定檔解析過程中發生嚴重崩潰！\n";
        std::cerr << "原因: " << e.what() << "\n";
        throw std::runtime_error(std::string("[ERR_REASON]: 設定檔解析過程中發生嚴重崩潰 - ") + e.what());
    }

    if (skel->data) {
        std::cout << "[CORE] global_rate:  " << out_global_config.global_rate << "\n";
        std::cout << "[CORE] global_burst: " << out_global_config.global_burst << "\n";
        std::cout << "[CORE] flow_rate:    " << out_global_config.flow_rate << "\n";
        std::cout << "[CORE] flow_burst:   " << out_global_config.flow_burst << "\n";

        // 修正：std::format 使用 {}，不是 %llu
        std::cout << std::format("[CORE] 💧 核心動態水門參數同步成功！(共 {} 核 Per-CPU 調配)\n",
                                 static_cast<unsigned long long>(NUM_CPUS));

        unsigned long long temp_pps = out_global_config.global_pps_limit;
        init_global_pps_limit(&temp_pps);
    }

    if (!assure_control_file_exists("/run/xdp_fw", "/run/xdp_fw/block_cmd")) {
        std::cerr << "[FATAL] ❌ 初始化環境失敗，防火牆中止啟動。\n";
        throw std::runtime_error("初始化環境失敗，防火牆中止啟動.");
    }

    xdp_fw_config::sync_xdp_config_map(&out_global_config);

    return out_global_config;
}

// =========================================================
// Skeleton 載入
// =========================================================

inline int register_skeleton_handler() {
    xdp_fw_global_config &xfg_config = xdp_fw_global_config::instance();

    skel = xfg_config.get_skeleton();
    trace_skel = xfg_config.get_trace_skel();

    if (skel == nullptr || trace_skel == nullptr) {
        xfg_config.load_xdp_skeleton();
        skel = xfg_config.get_skeleton();
        if (skel == nullptr)
            throw std::runtime_error("skel is nullptr!");
    }
    return 0;
}

// =========================================================
// L7 DPI Ring Buffer callback
// =========================================================

static int push_l7event(void * /*ctx*/, void *data, size_t size) {
    if (size != sizeof(struct l7_dpi_event)) {
        std::cout << "[L7DPI] ❌ 大小不符\n";
        return 0;
    }
    if (!g_lockFreeQueue.push(*static_cast<struct l7_dpi_event *>(data))) {
        g_dropped_userspace_logs.fetch_add(1, std::memory_order_relaxed);
    }
    return 0;
}

// =========================================================
// L7 DPI Ring Buffer callback
// =========================================================

static void consume_and_print_userspace_logs() {
    while (std::optional<l7_dpi_event> msg = g_lockFreeQueue.pop()) {
        struct l7_dpi_event l7_event = msg.value();

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &l7_event.src_ip, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &l7_event.dst_ip, dst_ip, sizeof(dst_ip));

        // std::cout << std::format("[L7DPI] {}:{} -> {}:{} proto={} payload={} bytes hex: ",
        //                          src_ip,
        //                          ntohs(l7_event.src_port),
        //                          dst_ip,
        //                          ntohs(l7_event.dst_port),
        //                          l7_event.ip_proto,
        //                          static_cast<uint32_t>(l7_event.payload_len)) << std::flush;

        // for (int i = 0; i < 16 && i < l7_event.payload_len; i++)
        //     std::cout << std::format("{:02x} ", static_cast<unsigned int>(l7_event.payload[i]));
        //
        // std::cout << "\n";
        std::pair<std::string, bool> analyResult = fwDpiEngine.analyze_packet(&l7_event);
        // std::cout << analyResult.first << "; " << analyResult.second << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// =========================================================
// Ring Buffer 輪詢執行緒
// =========================================================

static void *ring_poll_thread(void *arg) {
    struct ring_buffer *p_rb = static_cast<struct ring_buffer *>(arg);
    while (g_running.load(std::memory_order_relaxed)) {
        int ret = ring_buffer__poll(p_rb, 100);
        if (ret < 0) {
            if (errno == EINTR) continue;
            if (g_running.load(std::memory_order_relaxed))
                std::cerr << std::format("[SYSTEM] ❌ Ring Buffer Poll 發生錯誤: {} (errno: {})\n", ret, errno);
            break;
        }
    }
    return nullptr;
}

// =========================================================
// XDP / TC 掛載與功能套件初始化
// =========================================================

void register_xdp_fw_plugins(global_config *global_config_ptr) {
    // TC Egress 部署
    ifaddrs *ifaddr_tc, *ifa_tc;
    if (getifaddrs(&ifaddr_tc) != -1) {
        printf("\n🌐 [AUTO-DEPLOY] 正在部署 TC Egress 流量統計鉤子...\n");
        int visited[256] = {0};

        for (ifa_tc = ifaddr_tc; ifa_tc != nullptr; ifa_tc = ifa_tc->ifa_next) {
            if (!ifa_tc->ifa_addr) continue;
            if (strcmp(ifa_tc->ifa_name, "lo") == 0) continue;

            int ifindex = if_nametoindex(ifa_tc->ifa_name);
            if (ifindex <= 0 || ifindex >= 256) continue;
            if (visited[ifindex]) continue;
            visited[ifindex] = 1;

            if (safe_attach_tc_egress(ifindex, trace_skel) == 0)
                printf("    └── [TC] ✅ 網卡 %s (Index: %d) 掛載成功\n", ifa_tc->ifa_name, ifindex);
        }
        freeifaddrs(ifaddr_tc);
    }

    // 全網卡 XDP 部署
    int prog_fd = bpf_program__fd(skel->progs.xdp_fw);
    int attached_count = firewallController.attach_xdp_to_all_interfaces(prog_fd);
    std::cout << std::format("\n[INIT] 🚀 防火牆已成功動態覆蓋全機 {} 個網路通道！\n", attached_count) << std::endl;

    // 修正：透過 FirewallController setter 統一管理 map fd，
    // 並同步回老介面的全域變數供其他翻譯單元使用。
    int temp_fd = bpf_map__fd(skel->maps.temp_blocklist_map);
    int perm_fd = bpf_map__fd(skel->maps.permanent_blocklist_map);
    firewallController.set_map_fds(temp_fd, perm_fd);
    g_temp_map_fd = temp_fd; // 同步老介面全域變數
    g_perm_map_fd = perm_fd;

    // 1. 初始化 eBPF 核心 Ring Buffer
    // 注意：第二個參數必須是負責將資料「推入無鎖佇列」的 Callback (例如 handle_l7event)
    rb = ring_buffer__new(bpf_map__fd(skel->maps.l7_dpi_ringbuf), push_l7event, nullptr, nullptr);

    if (!rb) {
        std::cerr << "❌ [ERROR] 建立 eBPF Ring Buffer 失敗！\n";
        return;
    }

    printf("\n🔥 [INIT] 正在啟動工業級無鎖雙執行緒日誌引擎...\n");

    // 2. 🟢 啟動執行緒 A：狂暴生產者 (專職從核心 poll 日誌)
    // 使用 std::jthread 傳入 lambda 函式，完全取代舊的 pthread_create
    g_poll_thread = std::jthread([]() {
        while (g_running.load(std::memory_order_relaxed)) {
            // 從核心撈取，超時設為 10 毫秒防止 CPU 飆高
            int ret = ring_buffer__poll(rb, 10);
            if (ret < 0 && errno != EINTR) {
                break;
            }
        }
    });
    std::cout << "    ├── [Thread A] ✅ 核心 Poll 執行緒已綁定就緒\n";

    // 3. 🔵 啟動執行緒 B：另開這個 Thread 作為大盤消費者
    // 負責從 Userspace 無鎖佇列 pop 資料、排序並繪製 UI
    g_ui_dashboard_thread = std::jthread([]() {
        while (g_running.load(std::memory_order_relaxed)) {
            // 呼叫我們上一輪寫好的：無鎖消費 -> 排序 -> std::format 刷洗大盤面
            consume_and_print_userspace_logs();

            // 大盤每 50 毫秒穩定更新一次即可（人眼最流暢節奏，且 CPU 佔用接近 0%）
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });
    std::cout << "    └── [Thread B] ✅ 大盤 UI 渲染執行緒已獨立啟動\n";
}

// =========================================================
// 全域儀表板啟動
// =========================================================

inline void register_global_dashboard() {
    int global_stats_fd = bpf_map__fd(skel->maps.global_stats_map);
    int report_user_fd = bpf_map__fd(skel->maps.report_to_user_map);
    int stats_map_fd = bpf_map__fd(skel->maps.stats_map);

    std::cout << "[INIT] 🚀 系統全面就緒！正在接管終端繪製...\n";
    start_global_dashboard(global_stats_fd, report_user_fd, stats_map_fd);
}

inline void _printTest() {
    // RiskFileSyncManager::instance().fileToRiskConfig();
    // RiskFileSyncManager::instance().riskConfigToBinary();
    RiskFileSyncManager::instance().binaryToRiskConfig();

    SyncRiskFileConfig &syncRiskFileConfig = SyncRiskFileConfig::instance();
    std::vector<SyncRiskFileConfig::SyncRiskProperty> collects = syncRiskFileConfig.getCollectedRisks();
    // 隨時隨地取得 Header 資訊範例
    std::set<std::string> typeCollect;
    RiskIndicators &riskIndicators = RiskIndicators::instance();
    for (SyncRiskFileConfig::SyncRiskProperty col: collects) {
        std::string category = RiskFileSyncManager::instance().getCategory(col.type);
        riskIndicators.analysIndicator(CommonUtil::toLower(col.type), category, col.indicator);
    }

    std::cout << "系統狀態報告：" << std::endl;
    std::cout << "URL: " << syncRiskFileConfig.getSyncNextUrl() << std::endl;
    std::cout << "最後更新: " << syncRiskFileConfig.getUpdateTime() << std::endl;
    std::cout << "記錄筆數: " << syncRiskFileConfig.getRiskCount() << std::endl;
    std::cout << "collect size: " << collects.size() << std::endl;

    CommonUtil::printContainer(riskIndicators.identity1(), "Detected identity1");
    CommonUtil::printContainer(riskIndicators.application1(), "Detected application1");
    CommonUtil::printContainer(riskIndicators.file1(), "Detected file1");
    CommonUtil::printContainer(riskIndicators.host1(), "Detected host1");
    CommonUtil::printContainer(riskIndicators.ipv4s1(), "Detected ips1");
    std::set<std::string> ipv6set;
    for (auto ipv6_s1: riskIndicators.ipv6s1()) {
        ipv6set.insert(riskIndicators.ipv6ToString(ipv6_s1));
    }
    CommonUtil::printContainer(ipv6set, "Detected ipv6s1");

    CommonUtil::printContainer(riskIndicators.vulnerability1(), "Detected vulnerability1");
    CommonUtil::printContainer(riskIndicators.network1(), "Detected network1");
}

void registerRiskIndicators() {
    RiskFileSyncManager::instance().binaryToRiskConfig();

    SyncRiskFileConfig &syncRiskFileConfig = SyncRiskFileConfig::instance();

    RiskIndicators &riskIndicators = RiskIndicators::instance();

    std::vector<SyncRiskFileConfig::SyncRiskProperty> collects = syncRiskFileConfig.getCollectedRisks();

    for (SyncRiskFileConfig::SyncRiskProperty col: collects) {
        std::string category = RiskFileSyncManager::instance().getCategory(col.type);
        riskIndicators.analysIndicator(CommonUtil::toLower(col.type), category, col.indicator);
    }
}

void run_exporter_server() {
    xdp_fw_config::ExporterConfig expConf = xdp_fw_config::instance().exporter_config();
    if (!expConf.enable_exporter()) {
        return;
    }
    // For bpf
    if (expConf.enable_socket()) {
        ExporterService::instance().startUDSService(expConf);
    } else {
        xdp_fw_config::SSLConf sslConf = xdp_fw_config::instance().ssl_conf();
        ExporterService::instance().startHttpService(sslConf);
    }

}

void start_exporter_server() {
    std::thread http_thread(run_exporter_server);
    http_thread.detach();
}

// =========================================================
// main 進入點
// =========================================================
int main(int argc, char **argv) {
    block_shutdown_signals(); // 一定要最先做
    std::jthread sig_thread(signal_wait_thread_func); // 建在其他 thread 之前也行，反正遮罩已生效

    try {
        register_skeleton_handler();

        global_config out_global_config = register_config_and_pipe_handler(&argc, argv);

        register_xdp_fw_plugins(&out_global_config);

        start_exporter_server();

        // 🟢 啟動網卡熱插拔監聽執行緒：Wi-Fi 熱點重開、網卡拔插時，
        // 會自動偵測並只重新掛載該張網卡的 XDP/TC，不需要手動關閉防火牆。
        g_netlink_thread = std::jthread(netlink_monitor_thread);

        register_global_dashboard(); // 內部迴圈檢查 g_running，訊號來時會自然跳出
    } catch (const std::exception &e) {
        std::cerr << "遭遇未捕獲異常: " << e.what() << "\n";
        do_graceful_shutdown(); // 統一在「正常執行緒context」做清理，不在 signal handler 裡
    }

    do_graceful_shutdown(); // 統一在「正常執行緒context」做清理，不在 signal handler 裡
    return 0;
}
