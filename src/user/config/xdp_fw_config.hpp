//
// Created by root on 2026/6/9.
//

#ifndef XDP_FW_GLOBAL_CONFIG_HPP
#define XDP_FW_GLOBAL_CONFIG_HPP

#include "xdp_fw_config.h"
#include "../../skel/trace_connect.skel.h"
#include "../../skel/xdp_fw.skel.h"
#include <iostream> // 確保引入標準輸出入流
// 🟢 確保引入 libbpf 核心操作函式
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <iomanip>
#include <sstream>

// 外部宣告宣告解析函式（根據你前面的程式碼，若在別的 cpp 請確保連結得到）
extern uint64_t parse_size(const std::string& str);

// =================================================================
// 🟢 Userspace 流量大盤專用的「 Per-CPU 核心快取緩衝區」
// 加上 static，限制它們只活在當前編譯單元中，安全且速度極快
// =================================================================
static uint64_t* g_cpu_values = nullptr;
static int g_cpu_values_nr_cpus = 0;

class xdp_fw_global_config
{
private:
    // 內部的 eBPF Skeleton 骨架指標與設定檔成員移至內部隱藏
    xdp_fw_bpf* skel = nullptr;
    trace_connect_bpf* trace_skel = nullptr;
    global_config global_config_m;

    xdp_fw_global_config()
    {
        init();
    };

    inline void init()
    {
        std::cout << "[INIT] 🔒 核心 eBPF 引擎正在進行唯一一次的初始化..." << std::endl;
        if (load_xdp_skeleton() != 0)
        {
            std::cout << "[INIT] 🔒 核心 eBPF Init Failed!..." << std::endl;
        }
    }

public:
    // 禁止拷貝與賦值
    xdp_fw_global_config(const xdp_fw_global_config&) = delete;
    xdp_fw_global_config& operator=(const xdp_fw_global_config&) = delete;

    static xdp_fw_global_config& instance()
    {
        static xdp_fw_global_config inst;
        return inst;
    }

    // 析構建構子：確保類別生命週期結束時，資源能被妥善釋放
    ~xdp_fw_global_config()
    {
        if (trace_skel)
        {
            std::cout << "[DESTROY] 🔒 核心 eBPF trace_skel 引擎 Destroy..." << std::endl;
            trace_connect_bpf__destroy(trace_skel);
        }
        if (skel)
        {
            std::cout << "[DESTROY] 🔒 核心 eBPF skel 引擎 Destroy..." << std::endl;
            xdp_fw_bpf__destroy(skel);
        }
        // 如果程式結束，釋放 Per-CPU 統計緩衝區
        if (g_cpu_values)
        {
            std::cout << "[DESTROY] 🔒 核心 eBPF free cpu buffer ..." << std::endl;
            free(g_cpu_values);
            g_cpu_values = nullptr;
        }
    }

    inline xdp_fw_bpf* get_skeleton()
    {
        return this->skel;
    }

    inline trace_connect_bpf* get_trace_skel()
    {
        return this->trace_skel;
    }

    // 取得內部保存的設定
    inline global_config get_xdp_fw_global_config() const
    {
        return this->global_config_m;
    }

    // ✅ 調整後的完美 cout 格式對齊
    static void verify_shared_map(int fd1, int fd2, const char* map_name)
    {
        struct bpf_map_info info1 = {};
        struct bpf_map_info info2 = {};

        uint32_t len1 = sizeof(info1);
        uint32_t len2 = sizeof(info2);

        int ret1 = bpf_obj_get_info_by_fd(fd1, &info1, &len1);
        int ret2 = bpf_obj_get_info_by_fd(fd2, &info2, &len2);

        std::cout << "\n========== MAP VERIFY : " << map_name << " ==========" << std::endl;

        if (ret1)
        {
            perror("bpf_obj_get_info_by_fd(fd1)");
            return;
        }

        if (ret2)
        {
            perror("bpf_obj_get_info_by_fd(fd2)");
            return;
        }

        std::cout << "FD1           : " << fd1 << std::endl;
        std::cout << "FD2           : " << fd2 << std::endl;

        std::cout << "Map ID1       : " << info1.id << std::endl;
        std::cout << "Map ID2       : " << info2.id << std::endl;

        std::cout << "Type1         : " << info1.type << std::endl;
        std::cout << "Type2         : " << info2.type << std::endl;

        std::cout << "Key Size1     : " << info1.key_size << std::endl;
        std::cout << "Key Size2     : " << info2.key_size << std::endl;

        std::cout << "Value Size1   : " << info1.value_size << std::endl;
        std::cout << "Value Size2   : " << info2.value_size << std::endl;

        std::cout << "Max Entries1  : " << info1.max_entries << std::endl;
        std::cout << "Max Entries2  : " << info2.max_entries << std::endl;

        if (info1.id == info2.id)
        {
            std::cout << "\n✅ SAME KERNEL MAP OBJECT" << std::endl;
        }
        else
        {
            std::cout << "\n❌ DIFFERENT MAP OBJECT" << std::endl;
        }

        std::cout << "=====================================" << std::endl;
    }

    int load_xdp_skeleton()
    {
        if (this->skel != nullptr && this->trace_skel != nullptr)
        {
            return 0;
        }
        // 🟢 修正：必須先呼叫 open 實例化 trace_skel，否則下方指標檢查必失敗
        trace_skel = trace_connect_bpf__open();

        skel = xdp_fw_bpf__open();
        if (!skel || xdp_fw_bpf__load(skel))
        {
            fprintf(stderr, "[INIT] ❌ 加載 XDP 防火牆骨架失敗\n");
            if (trace_skel) trace_connect_bpf__destroy(trace_skel);
            return 1;
        }
        int estab_map_fd = bpf_map__fd(skel->maps.established_connections_map);
        int whitelist_map_fd = bpf_map__fd(skel->maps.whitelist_rules_map);
        int global_config_fd = bpf_map__fd(skel->maps.global_config_map);

        std::cout << "\n[TRACE_CONNECT] 📡 正在加載 TRACE_CONNECT 連線追蹤引擎..." << std::endl;

        if (!trace_skel)
        {
            std::cerr << "[TRACE_CONNECT] ❌ 打開 TRACE_CONNECT 骨架失敗" << std::endl;
            xdp_fw_bpf__destroy(skel);
            return 1;
        }

        // 核心特技：將動態追蹤引擎內部的 Maps 導向 XDP 當前持有的實體，完成內核零拷貝共享
        bpf_map__reuse_fd(trace_skel->maps.established_connections_map, estab_map_fd);
        bpf_map__reuse_fd(trace_skel->maps.whitelist_rules_map, whitelist_map_fd);
        bpf_map__reuse_fd(trace_skel->maps.global_config_map, global_config_fd);

        int trace_err = trace_connect_bpf__load(trace_skel);
        if (trace_err)
        {
            fprintf(stderr, "[TRACE_CONNECT] ❌ Load TRACE_CONNECT 失敗: %d\n", trace_err);
            xdp_fw_bpf__destroy(skel);
            trace_connect_bpf__destroy(trace_skel);
            return 1;
        }
        int fd1 = bpf_map__fd(skel->maps.established_connections_map);
        int fd2 = bpf_map__fd(trace_skel->maps.established_connections_map);

        verify_shared_map(fd1, fd2, "established_connections_map");

        int fd3 = bpf_map__fd(skel->maps.whitelist_rules_map);
        int fd4 = bpf_map__fd(trace_skel->maps.whitelist_rules_map);

        verify_shared_map(fd3, fd4, "whitelist_rules_map");

        trace_err = trace_connect_bpf__attach(trace_skel);
        if (trace_err)
        {
            fprintf(stderr, "[TRACE_CONNECT] ❌ Attach TRACE_CONNECT 失敗: %d\n", trace_err);
            xdp_fw_bpf__destroy(skel);
            trace_connect_bpf__destroy(trace_skel);
            return 1;
        }

        return 0; // 🟢 補上：加載完全成功，回傳常規狀態碼 0
    }

    void fill_xfg_and_update_xdpmap(xdp_fw_config* config, global_config* out_global_config)
    {
        if (!config || !out_global_config) return;

        out_global_config->log_level = config->get_log_level();
        out_global_config->flow_burst = parse_size(config->get_rate_limit().get_flow_burst());
        out_global_config->flow_rate = parse_size(config->get_rate_limit().get_flow_rate());
        out_global_config->global_burst = parse_size(config->get_rate_limit().get_global_burst());
        out_global_config->global_rate = parse_size(config->get_rate_limit().get_global_rate());
        out_global_config->global_pps_limit = config->get_rate_limit().get_global_pps_limit();
        out_global_config->enable_dpi = config->get_enable_dpi();

        this->global_config_m = *out_global_config;
    }

    // 💡 加上 static：回應 Clang-Tidy 警告，優化 Local 函式連結效能
    // 💡 拿掉 xdp_fw_config 引數：統計快取完全獨立，不再和設定檔物件搞混
    static uint64_t get_percpu_stats_total(int map_fd, uint32_t key)
    {
        uint64_t total_sum = 0;

        // 1. 檢查全域快取指標是否尚未初始化
        if (g_cpu_values == nullptr)
        {
            g_cpu_values_nr_cpus = libbpf_num_possible_cpus();

            if (g_cpu_values_nr_cpus <= 0)
            {
                return 0; // 偵測核心數失敗
            }

            // 分配可以容納所有 CPU 核心數量的記憶體空間
            g_cpu_values = static_cast<uint64_t*>(calloc(g_cpu_values_nr_cpus, sizeof(uint64_t)));
            if (g_cpu_values == nullptr)
            {
                return 0; // 記憶體配置失敗
            }
        }

        // 2. 向 eBPF Map 索取各核心的實時統計數據，直接灌進全域快取陣列中
        if (bpf_map_lookup_elem(map_fd, &key, g_cpu_values) == 0)
        {
            // 3. 確確實實地將每個 CPU 的數據加總起來
            for (int i = 0; i < g_cpu_values_nr_cpus; i++)
            {
                total_sum += g_cpu_values[i];
            }
        }

        // 4. 成功回傳實際加總後的流量數據
        return total_sum;
    }
};

inline void xdp_fw_config::sync_xdp_config_map(global_config* out_global_config)
{
    xdp_fw_global_config& inst = xdp_fw_global_config::instance(); // ✅ 引用，不複製
    int map_fd = bpf_map__fd(inst.get_skeleton()->maps.global_config_map);

    // 1. 讀取 Kernel 當前的值
    int current_key = inst.get_trace_skel()->rodata->xdp_config_key;
    bpf_map_update_elem(map_fd, &current_key, out_global_config, BPF_ANY);

    std::cout << "[SYN_XDP_CONFIG_MAP] 🧠 同步user space config 至 xdp global config map..." << std::endl;
}

// 將格式 2026-06-15_09:00:00 轉為時間戳 (time_t)
inline time_t parse_wall_time(const std::string& time_str)
{
    struct tm tm = {};
    std::istringstream ss(time_str);
    ss >> std::get_time(&tm, "%Y-%m-%d_%H:%M:%S");
    return mktime(&tm); // 注意：mktime 預設使用系統時區
}

// 在 sync 函數中使用
inline uint64_t parse_time(const std::string& time_str)
{
    if (time_str == "0") return 0;

    time_t target_wall_time = parse_wall_time(time_str);
    time_t now_wall_time = time(NULL);

    // 計算距離現在還有多少秒
    long diff_seconds = (long)target_wall_time - (long)now_wall_time;

    // 取得當前 monotonic 時間 (Kernel 使用的基準)
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now_monotonic_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    // 回傳該目標時間點的 monotonic 奈秒數
    return now_monotonic_ns + (diff_seconds * 1000000000ULL);
}

#endif // XDP_FW_GLOBAL_CONFIG_HPP
