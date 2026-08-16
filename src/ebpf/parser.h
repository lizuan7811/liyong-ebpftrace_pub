//
// Created by root on 2026/5/23.
//

#ifndef LIYONG_EBPFTRACE_PARSER_H
#define LIYONG_EBPFTRACE_PARSER_H

#ifndef ETH_P_8021Q
#define ETH_P_8021Q  0x8100
#include "vmlinux.h"
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP   0x0806
#endif

#include "kcommon.h"
#include "types.h"
#include <bpf/bpf_endian.h>

/* =========================================================
 * Ethernet (乙太網路標頭解析)
 * ========================================================= */
static __always_inline

int parse_eth(struct hdr_cursor* nh,
              void* data_end,
              struct ethhdr** eth,
              __be16* proto)
{
    struct ethhdr* ethhdr = nh->pos;

    if ((void*)(ethhdr + 1) > data_end)
        return -1;
    *eth = ethhdr;
    *proto = ethhdr->h_proto;

    nh->pos = (void*)(ethhdr + 1);

    return 0;
}

/* =========================================================
 * VLAN (802.1Q / 802.1AD 虛擬區域網路標頭)
 * ========================================================= */
static __always_inline

int parse_vlan(struct hdr_cursor* nh,
               void* data_end,
               __be16* proto)
{
    struct vlan_hdr* vh = nh->pos;

    if ((void*)(vh + 1) > data_end)
        return -1;

    *proto = vh->h_vlan_encapsulated_proto;
    nh->pos = (void*)(vh + 1);

    return 0;
}

static __always_inline

int parse_vlan_stack(struct hdr_cursor* nh,
                     void* data_end,
                     __be16* proto)
{
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        if (*proto != bpf_htons(ETH_P_8021Q) &&
            *proto != bpf_htons(ETH_P_8021AD))
            return 0;

        struct vlan_hdr* vh = nh->pos;
        if ((void*)(vh + 1) > data_end)
            return -1;

        *proto = vh->h_vlan_encapsulated_proto;
        nh->pos = (void*)(vh + 1);
    }
    return 0;
}

/* =========================================================
 * MPLS (多協議標籤切換)
 * ========================================================= */
static __always_inline

int parse_mpls(struct hdr_cursor* nh,
               void* data_end,
               __be32* label)
{
    struct mpls_hdr* mh = nh->pos;

    if ((void*)(mh + 1) > data_end)
        return -1;

    *label = mh->label_stack_entry;
    nh->pos = (void*)(mh + 1);

    return 0;
}

/* =========================================================
 * IPv4 (網際網路網路協定標頭解析)
 * ========================================================= */
static __always_inline

int parse_ipv4(struct hdr_cursor* nh,
               void* data_end,
               struct iphdr** ip,
               __u8* proto)
{
    struct iphdr* iph = nh->pos;

    if ((void*)(iph + 1) > data_end)
        return -1;

    if (iph->ihl < 5)
        return -1;

    void* ip_end = (void*)iph + iph->ihl * 4;

    if (ip_end > data_end)
        return -1;

    *ip = iph;
    *proto = iph->protocol;

    nh->pos = ip_end;

    return 0;
}

/* =========================================================
 * TCP (傳輸控制協定標頭解析)
 * ========================================================= */
static __always_inline

int parse_tcp(struct hdr_cursor* nh,
              void* data_end,
              struct tcphdr** tcp,
              struct iphdr* ip,
              __u32* out_payload_len)
{
    struct tcphdr* tcph = nh->pos;

    // 1. 基礎邊界檢查：確保至少有標準的 20 字節 TCP Header
    if ((void*)(tcph + 1) > data_end)
        return -1;

    // 2. 取得並驗證 TCP 標頭實際總長度（包含 Options）
    __u32 tcp_hdr_len = tcph->doff * 4;
    if (tcp_hdr_len < 20)
    {
        return -1;
    }

    // 3. 安全邊界檢查：確保整塊 TCP 標頭都在封包範圍內
    void* tcp_end = (void*)tcph + tcp_hdr_len; // 🚀 優化：直接使用 tcp_hdr_len
    if (tcp_end > data_end)
        return -1;

    // 4. 解析成功，更新游標與外接指標
    *tcp = tcph;
    nh->pos = tcp_end;

    /* =========================================================
     * ✨ 核心去噪邏輯：利用 IP 總長度排除網卡 Padding
     * ========================================================= */
    __u32 ip_tot_len = bpf_ntohs(ip->tot_len);
    __u32 ip_hdr_len = ip->ihl * 4;

    if (ip_tot_len >= (ip_hdr_len + tcp_hdr_len))
    {
        *out_payload_len = ip_tot_len - ip_hdr_len - tcp_hdr_len;
    }
    else
    {
        *out_payload_len = 0;
    }

    return 0;
}

/* =========================================================
 * UDP
 * ========================================================= */
static __always_inline

int parse_udp(struct hdr_cursor* nh,
              void* data_end,
              struct udphdr** udp)
{
    struct udphdr* udph = nh->pos;

    if ((void*)(udph + 1) > data_end)
        return -1;

    *udp = udph;
    nh->pos = (void*)(udph + 1);

    return 0;
}

/* =========================================================
 * ICMP (🔥 修正型態與邊界錯誤)
 * ========================================================= */
static __always_inline

int parse_icmp(struct hdr_cursor* nh,
               void* data_end,
               struct icmphdr** icmp)
{
    struct icmphdr* icmph = nh->pos;

    // 💡 關鍵修正：原本寫成 (icmp + 1)，那是二級指標的加法，完全越界！改為 (icmph + 1)
    if ((void*)(icmph + 1) > data_end)
        return -1;

    *icmp = icmph;
    nh->pos = (void*)(icmph + 1);
    return 0;
}

/* =========================================================
 * IGMP GREC (🔥 修正型態與邊界錯誤)
 * ========================================================= */
static __always_inline

int grec(struct hdr_cursor* nh,
         void* data_end,
         struct igmpv3_grec** grec)
{
    struct igmpv3_grec* grech = nh->pos;

    // 💡 關鍵修正：同樣原本寫成 (grec + 1)，改為實體指標 (grech + 1) 才是正確的 4 核心邊界
    if ((void*)(grech + 1) > data_end)
    {
        return -1;
    }
    *grec = grech;
    nh->pos = (void*)(grech + 1);
    return 0;
}

#endif //LIYONG_EBPFTRACE_PARSER_H
