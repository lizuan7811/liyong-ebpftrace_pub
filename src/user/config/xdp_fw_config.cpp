//
// Created by root on 2026/6/24.
//

#include "xdp_fw_config.h"
#include "xdp_fw_config.hpp" // 包含所有骨架與定義

void xdp_fw_config::sync_xdp_block_map(uint32_t map_fd,
                                              std::shared_ptr<const std::vector<std::map<std::string, std::string>>>& sharedMap,
                                              const std::string& type)
{
    // 直接使用 sharedMap-> 存取 vector，不需要拷貝
    // 為了簡潔，給個參考名稱
    const ACMapVector& blockMVector = *sharedMap;
    for (int i = 0; i < blockMVector.size(); i++)
    {
        const std::string& ip_str = blockMVector[i].at("IP");
        const std::string& start = blockMVector[i].at("START");
        const std::string& end = blockMVector[i].at("END");
        uint32_t ip_network_order;
        // inet_pton 會自動處理轉換並存入網路位元組序 (大端)
        if (inet_pton(AF_INET, ip_str.c_str(), &ip_network_order) == 1)
        {
            struct blacklist_val new_bv = {};
            new_bv.action = XDP_DROP;

            struct timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            __u64 cur_ns = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
            if (strcmp("PERM", type.c_str()))
            {
                // --- 修改部分：在 User Space 取得 Monotonic Time (奈秒) ---
                // -----------------------------------------------------
                new_bv.start_absolute_ns = parse_time(start);
                new_bv.end_absolute_ns = parse_time(end); // 這裡也要轉！
            }
            else
            {
                // --- 修改部分：在 User Space 取得 Monotonic Time (奈秒) ---
                // -----------------------------------------------------
                new_bv.start_absolute_ns = cur_ns;
                // 假設 300 秒後結束
                new_bv.end_absolute_ns = cur_ns + (300ULL * 1000000000ULL);
            }
            bpf_map_update_elem(map_fd, &ip_network_order, &new_bv, BPF_ANY);
        }
    }

    std::cout << "[SYN_XDP_BLOCK_MAP] 🧠 同步user space config 至 xdp global config map..." << std::endl;
}


void xdp_fw_config::destroy_skeleton()
{
    // ❌ 不要依賴類別自然解構，因為 _exit 不會觸發它
    // 🟢 直接主動調用單例的銷毀邏輯，或者手動 delete
    // 如果想要常規解構，這裡改用 exit(0) 即可（但注意多執行緒安全）
    std::cout << "[CLEANUP] 🧠 正在排隊等待全域資源生命週期自然釋放..." << std::endl;
    exit(0);
}
