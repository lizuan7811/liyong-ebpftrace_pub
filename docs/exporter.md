# Metric Exporter（Go）

本專案除了 XDP/TC 的 eBPF 資料面與 `main.c` 的 Userspace 管控程式之外，另有一個以 **Go** 撰寫的 Metric Exporter，負責：

1. 啟動並監管既有的 C++ 統計程式（子行程管理）
2. 透過 **Unix Domain Socket** 連線該 C++ 程式，持續讀取二進位格式的 BPF 追蹤資料
3. 將資料轉譯為 Prometheus 可抓取的 Metrics，並以 HTTPS 對外提供 `/metrics`（搭配 [`deployment.md`](deployment.md#建立自建-ca-自簽憑證) 中建立的自簽憑證）

整體監控串接關係：

```
xdp_fw.c / trace_connect.c（eBPF）
        ↓（BPF Maps）
C++ 統計程式（由 Go 啟動與監管，透過 Unix Socket 輸出）
        ↓ Unix Domain Socket（BPFTraceHeader + BPFTraceBody，二進位協議）
Go Metric Exporter（本文件）
        ↓ HTTPS /metrics
Prometheus → Grafana
```

Prometheus / Grafana 的部署方式請見 [`monitoring.md`](monitoring.md)；憑證建立請見 [`deployment.md`](deployment.md#建立自建-ca-自簽憑證)。

---

## 主程式（`main.go`）

負責整體生命週期管理：載入設定 → 啟動 C++ 子行程 → 建立 Unix Socket 連線（含重試）→ 啟動 HTTPS Metric Server → 持續讀取二進位資料流並轉換為 Metrics → 收到中止訊號時優雅關閉。

```go
package main

import (
	"context"
	"encoding/binary"
	"liyong-ebpftrace/cmd/model"
	"liyong-ebpftrace/cmd/svc" // 引入 svc 套件
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

func initLog() {
	log.SetOutput(&lumberjack.Logger{
		Filename:   "app.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	})
}

func main() {
	initLog()

	manager, err := NewExporterManager("resource/config.json")
	if err != nil {
		log.Fatalf("Init failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if err := manager.Start(ctx); err != nil {
		log.Fatalf("啟動 C++ 程式失敗: %v", err)
	}

	socketPath := manager.Config.ExporterConfig.SocketPath
	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if conn == nil {
		log.Fatal("無法連線至 Socket")
	}

	// 啟動 Prometheus Metric Server
	svc.StartMetricServer(manager.Config.SSLConf.CaPath, manager.Config.SSLConf.KeyPath, manager.Config.SSLConf.CertPath, strconv.Itoa(manager.Config.ExporterConfig.MetricsPort))

	go func() {
		<-sigCh
		log.Println("[main] 收到終止訊號...")
		conn.Close()
		manager.Stop()
		cancel()
		os.Exit(0)
	}()

	for {
		var head model.BPFTraceHeader
		if err := binary.Read(conn, binary.LittleEndian, &head); err != nil {
			log.Printf("Read header error: %v", err)
			break
		}

		// 【重要】每輪數據開始前，清空指標，確保顯示的是最新狀態
		svc.ResetMetrics()

		for i := uint32(0); i < head.Count; i++ {
			var body model.BPFTraceBody
			if err := binary.Read(conn, binary.LittleEndian, &body); err != nil {
				log.Printf("Read body error: %v", err)
				return
			}
			svc.ProcessSocketData(body)
		}
	}
	manager.Stop()
}
```

---

## 流程重點說明

| 階段 | 說明 |
|---|---|
| 日誌初始化 | 使用 `lumberjack` 做 log rotation（單檔 10MB、保留 5 份、最長 30 天、自動壓縮），輸出至 `app.log` |
| `NewExporterManager` | 讀取 `resource/config.json`，建立 C++ 子行程管理器（Socket 路徑、SSL 憑證路徑、Metrics Port 等設定皆來自此檔） |
| 訊號處理 | 監聽 `SIGINT` / `SIGTERM`，收到後關閉 Socket 連線、停止 C++ 子行程、取消 context 後結束程式，確保優雅關閉 |
| `manager.Start(ctx)` | 啟動並監管底層 C++ 統計程式（對應 [`deployment.md`](deployment.md) 中編譯出的可執行檔） |
| Socket 連線重試 | 因 C++ 子行程啟動需要時間，採 50 次 × 100ms 的輪詢重試建立 Unix Socket 連線，避免啟動時序競態 |
| `svc.StartMetricServer` | 啟動 HTTPS Metric Server，載入 CA / Key / Cert（見 [`deployment.md`](deployment.md#建立自建-ca-自簽憑證)），對外提供 `/metrics` 給 Prometheus 抓取 |
| 主迴圈讀取協議 | 先讀取固定格式的 `BPFTraceHeader`（含本輪資料筆數 `Count`），再依序讀取對應數量的 `BPFTraceBody`，兩者皆以 Little-Endian 二進位格式透過 `binary.Read` 解析 |
| `svc.ResetMetrics()` | 每輪資料讀取前重置指標，確保 Prometheus 抓取到的永遠是最新一輪的即時狀態，而非累積殘留舊值 |
| `svc.ProcessSocketData(body)` | 將單筆 `BPFTraceBody` 轉換並更新對應的 Prometheus Metric |

---

## 二進位協議（`model.BPFTraceHeader` / `model.BPFTraceBody`）

C++ 程式與 Go Exporter 之間透過 Unix Domain Socket 傳輸固定格式的二進位資料，分為：

- **`BPFTraceHeader`**：每輪資料的表頭，至少包含本輪資料筆數 `Count`
- **`BPFTraceBody`**：逐筆的追蹤資料本體，對應到防火牆內部的 `status_code` / 統計欄位（三段編碼定義請見 [`userspace.md`](userspace.md#status_code-32-bit-分層編碼)）

> 建議在 `liyong-ebpftrace/cmd/model` 套件中明確定義這兩個 struct 的欄位與位元組對齊方式，並在此文件補上對應的欄位表，避免日後修改 C++ 端結構時，Go 端解析出現位移錯誤。

---

## 設定檔（`resource/config.json`）

`NewExporterManager` 依賴此設定檔，主要包含：

| 區塊 | 欄位（推測） | 用途 |
|---|---|---|
| `ExporterConfig` | `SocketPath` | C++ 程式提供的 Unix Socket 路徑 |
| `ExporterConfig` | `MetricsPort` | Go Exporter 對外提供 `/metrics` 的埠號 |
| `SSLConf` | `CaPath` / `KeyPath` / `CertPath` | HTTPS Metric Server 使用的憑證路徑，對應 [`deployment.md`](deployment.md#建立自建-ca-自簽憑證) 產出的檔案 |

> 建議補上實際 `config.json` 範例內容，方便其他協作者依樣建立自己的環境設定。
