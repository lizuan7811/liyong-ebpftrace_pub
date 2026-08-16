//
// Created by root on 2026/6/9.
// Revised: fixed double-pipe init, added get_read_fd/get_write_fd,
//          fixed update_blacklist_map comment, fixed init_signal_pipe ordering.
//

#ifndef LIYONG_EBPFTRACE_FIREWALL_HPP
#define LIYONG_EBPFTRACE_FIREWALL_HPP

#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <format>
#include <poll.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdexcept>

#include "../../skel/trace_connect.skel.h"
#include "../../ebpf/types.h"

// =========================================================
// 🛡️ 1. 底層時間轉換小工具
// =========================================================
inline int64_t get_boot_to_real_offset_ns(void)
{
    struct timespec real_ts{}, mono_ts{};
    clock_gettime(CLOCK_REALTIME,  &real_ts);
    clock_gettime(CLOCK_MONOTONIC, &mono_ts);

    uint64_t real_ns = static_cast<uint64_t>(real_ts.tv_sec) * 1000000000ULL + real_ts.tv_nsec;
    uint64_t mono_ns = static_cast<uint64_t>(mono_ts.tv_sec) * 1000000000ULL + mono_ts.tv_nsec;

    return static_cast<int64_t>(real_ns) - static_cast<int64_t>(mono_ns);
}

// =========================================================
// 🛡️ 2. eBPF Map 黑名單更新邏輯
// =========================================================
inline void update_blacklist_map(int map_fd, uint32_t src_ip, uint32_t duration_sec, const std::string& table_tag)
{
    if (map_fd < 0) return;

    struct blacklist_val bv = {};

    // offset = real_ns - mono_ns
    // 因此 mono_ns = real_ns - offset
    // eBPF 端使用 bpf_ktime_get_ns()，回傳值與 CLOCK_MONOTONIC 相同（開機後奈秒數）
    // 所以 start/end 必須存 monotonic 時間，即 unix_ns - offset
    int64_t offset = get_boot_to_real_offset_ns();

    struct timespec now{};
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t now_unix_ns = static_cast<uint64_t>(now.tv_sec) * 1000000000ULL + now.tv_nsec;

    // now_unix_ns - offset = mono_ns（開機後奈秒），與 bpf_ktime_get_ns() 同域
    uint64_t now_mono_ns = static_cast<uint64_t>(static_cast<int64_t>(now_unix_ns) - offset);

    if (duration_sec == 0)
    {
        // 永久封鎖：end = 0 作為哨兵值，eBPF 端判斷 end == 0 → 永久
        bv.start_absolute_ns = now_mono_ns;
        bv.end_absolute_ns   = 0;
    }
    else if (duration_sec < 100000000ULL)
    {
        // 動態封鎖：從現在起封鎖 duration_sec 秒
        uint64_t end_unix_ns  = now_unix_ns + (static_cast<uint64_t>(duration_sec) * 1000000000ULL);
        uint64_t end_mono_ns  = static_cast<uint64_t>(static_cast<int64_t>(end_unix_ns) - offset);
        bv.start_absolute_ns  = now_mono_ns;
        bv.end_absolute_ns    = end_mono_ns;
    }
    else
    {
        // 預約封鎖：duration_sec 本身即為目標 Unix epoch 秒數
        uint64_t end_unix_ns  = static_cast<uint64_t>(duration_sec) * 1000000000ULL;
        uint64_t end_mono_ns  = static_cast<uint64_t>(static_cast<int64_t>(end_unix_ns) - offset);
        bv.start_absolute_ns  = now_mono_ns;
        bv.end_absolute_ns    = end_mono_ns;
    }

    bpf_map_update_elem(map_fd, &src_ip, &bv, BPF_ANY);

    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, ip_str, sizeof(ip_str));

    if (duration_sec == 0)
        std::cout << std::format("[MAP:{}] 🔒 黑名單更新: {} | 🛑 永久封鎖\n", table_tag, ip_str);
    else if (duration_sec < 100000000ULL)
        std::cout << std::format("[MAP:{}] 🔒 黑名單更新: {} | ⏳ 動態封鎖 {} 秒\n", table_tag, ip_str, duration_sec);
    else
        std::cout << std::format("[MAP:{}] 🔒 黑名單更新: {} | ⏰ 預約封鎖至 Unix 時間戳 {}\n", table_tag, ip_str, duration_sec);
}

// =========================================================
// 🛡️ 3. 環境初始化小工具
// =========================================================
inline bool assure_control_file_exists(const std::string& dirpath, const std::string& filepath)
{
    if (mkdir(dirpath.c_str(), 0700) < 0)
    {
        if (errno != EEXIST)
        {
            std::cerr << "[INIT] ❌ 無法建立 " << dirpath << " 資料夾\n";
            return false;
        }
    }
    else
    {
        std::cout << std::format("[INIT] 📂 成功動態建立防禦核心目錄: {} (權限: 700)\n", dirpath);
    }

    int init_fd = open(filepath.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
    if (init_fd < 0)
    {
        perror("[INIT] ❌ 無法建立或確保 block_cmd 檔案存在");
        return false;
    }
    close(init_fd);
    std::cout << "[INIT] 🔒 已成功確保控制環境與檔案存在 (權限: 600)\n";

    return true;
}

// =========================================================
// 🛡️ 4. 防火牆主要控制器類別
// =========================================================
class FirewallController
{
private:
    int g_temp_map_fd = -1;
    int g_perm_map_fd = -1;

    // pipe fd：[0] = read 端，[1] = write 端
    inline static int g_pipe_fd[2] = {-1, -1};

    bool tc_attached_map[MAX_IFINDEX] = {false};

    // -------------------------------------------------------
    // 建構子：只做一次 pipe 初始化，並將 read 端設為非阻塞
    // -------------------------------------------------------
    FirewallController()
    {
        if (pipe(g_pipe_fd) < 0)
        {
            perror("[Firewall] ❌ 無法建立控制 Pipe");
            throw std::runtime_error("[Firewall] ❌ 無法建立控制 Pipe");
        }
        // read 端設為非阻塞，確保 poll 迴圈不會卡死
        if (fcntl(g_pipe_fd[0], F_SETFL, O_NONBLOCK) < 0)
        {
            perror("[Firewall] ❌ 無法設定 Pipe 非阻塞");
            close(g_pipe_fd[0]);
            close(g_pipe_fd[1]);
            g_pipe_fd[0] = g_pipe_fd[1] = -1;
            throw std::runtime_error("[Firewall] ❌ 無法設定 Pipe 非阻塞");
        }
    }

    ~FirewallController()
    {
        if (g_pipe_fd[0] != -1) { close(g_pipe_fd[0]); g_pipe_fd[0] = -1; }
        if (g_pipe_fd[1] != -1) { close(g_pipe_fd[1]); g_pipe_fd[1] = -1; }
    }

public:
    // 禁止拷貝與賦值
    FirewallController(const FirewallController&)            = delete;
    FirewallController& operator=(const FirewallController&) = delete;

    static FirewallController& instance()
    {
        static FirewallController inst;
        return inst;
    }

    // -------------------------------------------------------
    // Pipe fd 存取介面
    // -------------------------------------------------------
    static int* get_g_pipe_fd()  { return g_pipe_fd; }
    static int  get_read_fd()    { return g_pipe_fd[0]; }   // ← 新增，供外部 poll 使用
    static int  get_write_fd()   { return g_pipe_fd[1]; }   // ← 新增，供 signal handler 使用

    // -------------------------------------------------------
    // Map fd setter（由 main 在 skel 載入後呼叫）
    // -------------------------------------------------------
    void set_map_fds(int temp_fd, int perm_fd)
    {
        g_temp_map_fd = temp_fd;
        g_perm_map_fd = perm_fd;
    }

    int get_temp_map_fd() const { return g_temp_map_fd; }
    int get_perm_map_fd() const { return g_perm_map_fd; }

    // -------------------------------------------------------
    // 公開介面宣告
    // -------------------------------------------------------
    bool init();
    void run();
    void detach_interfaces();
    void process_block_cmd_file(const std::string& filepath);
    void process_block_maps(const std::string& filepath);
    int  attach_xdp_to_all_interfaces(int prog_fd);
    void detach_xdp_from_all_interfaces();
    void detach_tc_from_all_interfaces();
    int  attach_tc_egress(int ifindex, struct bpf_object* obj);
};

// =========================================================
// inline 方法實作
// =========================================================

inline void FirewallController::detach_interfaces()
{
    detach_xdp_from_all_interfaces();
    detach_tc_from_all_interfaces();
}

inline void FirewallController::process_block_cmd_file(const std::string& filepath)
{
    printf("\n[SIGNAL] 🔔 收到網管外部指令！正在讀取控制通道...\n");
    FILE* f = fopen(filepath.c_str(), "r");
    if (!f)
    {
        std::cerr << "[SIGNAL] ❌ 開啟檔案失敗" << std::endl;
        return;
    }

    char ip_buf[64];
    char time_buf[64];

    while (fscanf(f, "%63s %63s", ip_buf, time_buf) == 2)
    {
        uint32_t target_ip;
        if (inet_pton(AF_INET, ip_buf, &target_ip) != 1)
        {
            std::cerr << std::format("[SIGNAL] ❌ 錯誤的 IP 格式 {}\n", ip_buf);
            continue;
        }

        uint32_t duration_param = 0;
        if (std::strchr(time_buf, '-') != nullptr)
        {
            struct tm tm_target = {};
            tm_target.tm_isdst  = -1;
            if (strptime(time_buf, "%Y-%m-%d_%H:%M:%S", &tm_target) != nullptr)
            {
                time_t target_epoch = mktime(&tm_target);
                if (target_epoch != -1)
                    duration_param = static_cast<uint32_t>(target_epoch);
            }
        }
        else
        {
            duration_param = static_cast<uint32_t>(strtoul(time_buf, nullptr, 10));
        }

        update_blacklist_map(g_perm_map_fd, target_ip, duration_param, "PERM");
    }
    fclose(f);

    // 指令讀完後清空檔案，避免重複執行
    f = fopen(filepath.c_str(), "w");
    if (f) fclose(f);
}

inline void FirewallController::process_block_maps(const std::string& filepath)
{
    printf("\n[SIGNAL] 🔔 收到網管外部指令！正在讀取控制通道...\n");
    FILE* f = fopen(filepath.c_str(), "r");
    if (!f)
    {
        std::cerr << "[SIGNAL] ❌ 開啟檔案失敗" << std::endl;
        return;
    }

    char ip_buf[64];
    char time_buf[64];

    while (fscanf(f, "%63s %63s", ip_buf, time_buf) == 2)
    {
        uint32_t target_ip;
        if (inet_pton(AF_INET, ip_buf, &target_ip) != 1)
        {
            std::cerr << std::format("[SIGNAL] ❌ 錯誤的 IP 格式 {}\n", ip_buf);
            continue;
        }

        uint32_t duration_param = 0;
        if (std::strchr(time_buf, '-') != nullptr)
        {
            struct tm tm_target = {};
            tm_target.tm_isdst  = -1;
            if (strptime(time_buf, "%Y-%m-%d_%H:%M:%S", &tm_target) != nullptr)
            {
                time_t target_epoch = mktime(&tm_target);
                if (target_epoch != -1)
                    duration_param = static_cast<uint32_t>(target_epoch);
            }
        }
        else
        {
            duration_param = static_cast<uint32_t>(strtoul(time_buf, nullptr, 10));
        }

        update_blacklist_map(g_perm_map_fd, target_ip, duration_param, "PERM");
    }
    fclose(f);

    // 指令讀完後清空檔案，避免重複執行
    f = fopen(filepath.c_str(), "w");
    if (f) fclose(f);
}

// =========================================================
// 靜態輔助函數（檔案內部使用）
// =========================================================

static int attach_xdp_auto(int ifindex, int prog_fd)
{
    int err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, nullptr);
    if (!err)
    {
        printf("  └── [XDP] ✨ 成功以 DRV (Native) 模式硬體加速綁定！\n");
        return 0;
    }

    printf("\n  ├── [XDP] ⚠️ 網卡驅動不支援 DRV 模式，嘗試切換至 SKB...\n");
    err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, nullptr);
    if (!err)
    {
        printf("  └── [XDP] 🔌 成功以 SKB (Generic) 通用模式完成綁定！\n");
        return 0;
    }
    return err;
}

static int get_default_iface(char* ifname, size_t len)
{
    FILE* f = fopen("/proc/net/route", "r");
    if (!f) return -1;

    char line[256];
    if (!fgets(line, sizeof(line), f))
    {
        fclose(f);
        return -1;
    }

    while (fgets(line, sizeof(line), f))
    {
        char iface[IF_NAMESIZE];
        unsigned long dest, gateway;

        if (sscanf(line, "%s %lx %lx", iface, &dest, &gateway) != 3)
            continue;

        if (dest == 0)
        {
            strncpy(ifname, iface, len - 1);
            ifname[len - 1] = '\0';
            fclose(f);
            return if_nametoindex(ifname);
        }
    }
    fclose(f);
    return -1;
}

// =========================================================
// XDP 掛載 / 卸載
// =========================================================

inline int FirewallController::attach_xdp_to_all_interfaces(int prog_fd)
{
    struct ifaddrs *ifaddr, *ifa;
    int success_count   = 0;
    int visited_indexes[128] = {0};
    int visited_count   = 0;

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("[AUTO-DISCOVER] ❌ 獲取系統網卡列表失敗");
        return -1;
    }
    printf("\n🌐 [AUTO-DISCOVER] 開始掃描全機活動網卡並動態部署...\n");

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr) continue;

        if ((ifa->ifa_flags & IFF_UP) &&
            (ifa->ifa_addr->sa_family == AF_INET ||
             ifa->ifa_addr->sa_family == AF_INET6))
        {
            const char* ifname  = ifa->ifa_name;
            int         ifindex = if_nametoindex(ifname);
            if (ifindex <= 0)                    continue;
            if (strcmp(ifname, "lo") == 0)       continue;

            bool already_visited = false;
            for (int i = 0; i < visited_count; i++)
            {
                if (visited_indexes[i] == ifindex) { already_visited = true; break; }
            }
            if (already_visited) continue;
            if (visited_count < 128) visited_indexes[visited_count++] = ifindex;

            printf("   🔍 發現活動中介面: %-12s (Index: %d)\n", ifname, ifindex);

            if (attach_xdp_auto(ifindex, prog_fd) == 0)
                success_count++;
        }
    }
    freeifaddrs(ifaddr);
    return success_count;
}

inline void FirewallController::detach_xdp_from_all_interfaces(void)
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET &&
            ifa->ifa_addr->sa_family != AF_INET6) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0)  continue;

        int ifindex = if_nametoindex(ifa->ifa_name);
        if (ifindex > 0)
        {
            bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, nullptr);
            bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, nullptr);
        }
    }
    freeifaddrs(ifaddr);
    std::cout << "[CLEANUP] 🧹 ✅ 已自動解除全機（已排除 lo）所有活動網卡的 XDP 綁定！\n" << std::endl;
}

inline void FirewallController::detach_tc_from_all_interfaces(void)
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr ||
            ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0)   continue;

        int ifindex = if_nametoindex(ifa->ifa_name);
        if (ifindex <= 0) continue;

        struct bpf_tc_hook hook = {
            .sz           = sizeof(struct bpf_tc_hook),
            .ifindex      = ifindex,
            .attach_point = BPF_TC_EGRESS
        };
        bpf_tc_hook_destroy(&hook);
    }
    freeifaddrs(ifaddr);
    std::cout << "[CLEANUP] 🧹 ✅ 已清理所有介面的 TC Egress 鉤子！\n" << std::endl;
}

// =========================================================
// TC Egress 掛載
// =========================================================
inline int FirewallController::attach_tc_egress(int ifindex, struct bpf_object* obj)
{
    struct bpf_program* prog = bpf_object__find_program_by_name(obj, "tc_egress_record");
    if (!prog)
    {
        std::cerr << "[TC] ❌ 找不到 tc_egress_record 程式\n" << std::endl;
        return -1;
    }

    struct bpf_tc_hook hook = {
        .sz           = sizeof(hook),
        .ifindex      = ifindex,
        .attach_point = BPF_TC_EGRESS
    };

    // 確保 hook 存在（如果已存在會回傳 -EEXIST，可忽略）
    bpf_tc_hook_create(&hook);

    // 先嘗試 detach 舊的，避免 Exclusivity flag 衝突
    struct bpf_tc_opts detach_opts = {.sz = sizeof(detach_opts)};
    bpf_tc_detach(&hook, &detach_opts);

    struct bpf_tc_opts attach_opts = {
        .sz      = sizeof(attach_opts),
        .prog_fd = bpf_program__fd(prog),
        .flags   = BPF_TC_F_REPLACE
    };
    return bpf_tc_attach(&hook, &attach_opts);
}

// =========================================================
// 🛡️ Signal 信號處理
// =========================================================

// handle_sigusr1：只做最簡單的 write，不使用任何非 async-signal-safe 的函數
inline void handle_sigusr1(int /*sig*/)
{
    char dummy = 1;
    int  wfd   = FirewallController::get_write_fd();
    if (wfd != -1)
    {
        // write 是 async-signal-safe；管線滿時 EAGAIN，直接丟棄即可。
        // 用 if 消耗回傳值，避免 -Wunused-result warning。
        if (write(wfd, &dummy, 1) < 0) { /* EAGAIN / EINTR：忽略 */ }
    }
}

// handle_sigusr_event：在主迴圈中呼叫，處理 pipe 觸發的封鎖指令
inline static void handle_sigusr_event(pollfd* fds)
{
    int ret = poll(fds, 1, 10);
    if (ret > 0 && (fds[0].revents & POLLIN))
    {
        char dummy;
        // 排空管線中所有位元組（可能有多個 signal 累積）
        while (read(FirewallController::get_read_fd(), &dummy, 1) > 0) {}

        FirewallController& fc = FirewallController::instance();
        fc.process_block_cmd_file("/run/xdp_fw/block_cmd");
    }
}

#endif // LIYONG_EBPFTRACE_FIREWALL_HPP