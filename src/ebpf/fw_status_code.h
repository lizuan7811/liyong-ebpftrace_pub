//
// Created by root on 2026/6/2.
//

#ifndef LIYONG_EBPFTRACE_FW_STATUS_CODE_H
#define LIYONG_EBPFTRACE_FW_STATUS_CODE_H

#ifdef __bpf__
    // 只有在編譯 eBPF 程式 (Kernel Space) 時才載入
    #include "vmlinux.h"
#else

#endif


/* ================================================================= *
 * 💥 動作遮罩 ACTION MASKS (Bits 24-31) - 決定封包最終去向          *
 * ================================================================= */
#define ACT_PASS          0x01000000  // 放行：封包合法，允許進入系統
#define ACT_DROP          0x02000000  // 阻擋：直接丟棄封包，不回應任何訊息
#define ACT_CHALLENGE     0x03000000  // 挑戰：觸發主動防禦機制（如 SYN Cookie 驗證）

/* ================================================================= *
 * 🛡️ 階段遮罩 STAGE MASKS (Bits 16-23) - 標記封包是在哪一個關卡被處理 *
 * ================================================================= */
#define STG_PARSE         0x00010000  // 協定解析：L2/L3/L4 標頭解析與邊界抽查
#define STG_FUSE          0x00020000  // 熔斷保護：全域保險絲機制，防止極端流量壓垮防禦核心
#define STG_ESTABLISHED   0x00030000  // 連線追蹤：反向信任表快速通道（歷史合法連線直接放行）
#define STG_PERM_BLK      0x00040000  // 永久黑名單：命中靜態封鎖 IP 規則
#define STG_TEMP_BLK      0x00050000  // 臨時黑名單：動態防禦機制（如超速被自動關入狗籠）
#define STG_PORT_WHT      0x00060000  // 門禁白名單：檢查目標/來源埠號（Port）是否為允許開放之服務
#define STG_GLOBAL_LMT    0x00070000  // 全域限速：觸發總體頻寬/速率 Token Bucket 限制
#define STG_FLOW_LMT      0x00080000  // 單流限速：觸發單一連線（Per-flow）速率限制
#define STG_L4_CHAL       0x00090000  // 傳輸層挑戰：正處於 SYN Cookie 等防禦出題現場

/* ================================================================= *
 * 🔍 原因遮罩 REASON MASKS (Bits 0-15) - 記錄觸發動作的底層核心原因  *
 * ================================================================= */
#define RSN_SUCCESS       0x00000000  // 正常無異常：順利通過檢測
#define RSN_BAD_PKT       0x00000001  // 畸形封包：欄位衝突、長度異常或核心指針越界
#define RSN_UNSUPPORTED   0x00000002  // 不支援協議：非系統維護與防禦之流量類型（如 IPv6, ARP, IGMP）
#define RSN_FRAG_PKT      0x00000005  // 💡 新增｜分片封包：非第一片的 IPv4 Fragmented 封包，安全放行降級

#define RSN_CONN_TRACK    0x00000010  // 追蹤命中：命中 Established 快速通道信任表（TCP/UDP 反向通關）
#define RSN_CONN_NEW      0x00000011  // 💡 新增｜合法新連線：非攻擊狀態下，首發通過白名單與防禦檢驗的全新連線

#define RSN_RULE_STATIC   0x00000020  // 靜態規則：命中管理者手動設定的安全策略（如永久黑名單）
#define RSN_RULE_DYNA     0x00000021  // 動態規則：命中系統自動生成的防禦策略（如臨時黑名單）
#define RSN_PORT_MISS     0x00000030  // 埠號未開放：埠號不在允許訪問的服務白名單內

#define RSN_LIMIT_BYTES   0x00000040  // 流量超速：超過每秒位元組數（Bytes/s）上限
#define RSN_LIMIT_PPS     0x00000041  // 封包超速：超過每秒封包數（PPS）上限

#define RSN_CHAL_SEND     0x00000050  // 發射挑戰：防禦機制生效，向客戶端發射加密 Seq 驗證碼 (SYN Cookie)
#define RSN_CHAL_VERIFY   0x00000051  // 💡 新增｜挑戰成功：客戶端帶回了正確的 ACK Cookie，驗證通過並放行

/* =========================================================
 * 🛡️ 新增：DPI 應用層驗證狀態碼
 * ========================================================= */
#define RSN_DPI_PENDING     0x00000060  // ⏳ DPI 檢查中：等待後續封包以完成握手驗證
#define RSN_DPI_PASSED      0x00000061  // ✅ DPI 驗證成功：TLS 握手與特徵比對皆通過
#define RSN_DPI_VIOLATION   0x00000062  // ❌ DPI 策略違規：偵測到非法 Host/SNI 或特徵碼
#define RSN_DPI_INCOMPLETE  0x00000063  // ⚠️ 封包不完整：無法執行 DPI (例如 Client Hello 被截斷)

/* ================================================================= *
 * 🛠️ 快速複合狀態碼構造工具 (eBPF 核心內部呼叫)                      *
 * ================================================================= */
// 將動作、階段、原因利用位元或（OR）運算，組合成單一個 __u32 狀態碼
#define MAKE_STATUS(act, stg, rsn) ((__u32)((act) | (stg) | (rsn)))

/* ================================================================= *
 * 🛠️ User Space 解包巨集 (用於 Go / C++ 控制主程式分析日誌)            *
 * ================================================================= */
#define GET_ACTION(code)    (((__u32)(code) & 0xFF000000) >> 24)  // 取出高位元組：解析最終動作
#define GET_STAGE(code)     (((__u32)(code) & 0x00FF0000) >> 16)  // 取出中位元組：解析攔截階段 (已修正遮罩)
#define GET_REASON(code)    ((__u32)(code) & 0x0000FFFF)          // 取出低 16 位：解析核心原因

#endif //LIYONG_EBPFTRACE_FW_STATUS_CODE_H
