package svc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"liyong-ebpftrace/cmd/model"
	"liyong-ebpftrace/cmd/util"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	riskMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ebpf_risk_domain",
			Help: "Domain risk count tracked by XDP",
		},
		[]string{"label", "domain", "src_ip", "dst_ip"},
	)
	ksmEventCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kernel_file_events_total",
			Help: "Total number of file open/access events intercepted by kernel module",
		},
		[]string{"pid", "comm", "filepath", "is_write", "count"},
	)
)

func init() {
	// 在程式啟動時，自動將指標註冊到 Prometheus 系統中
	prometheus.MustRegister(riskMetrics)
	prometheus.MustRegister(ksmEventCounter)
}

// StartMetricServer 啟動 HTTPS 服務 (支援可選的 mTLS)
func StartMetricServer(caPath string, sslKey string, sslCert string, port string) {

	dir, _ := util.GetExeDir()
	mux := http.NewServeMux()

	// --- 修改這裡：使用自定義的 Middleware 包裝 metrics handler ---
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 在這裡加入你的日誌邏輯
		log.Printf("Metrics request received from: %s, User-Agent: %s", r.RemoteAddr, r.UserAgent())

		// 執行原始的 metrics 處理
		promhttp.Handler().ServeHTTP(w, r)
	})

	mux.Handle("/metrics", wrappedHandler)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// 關鍵：明確設定 SessionTicketsDisabled 以減少握手開銷 (針對伺服器壓力過大)
		SessionTicketsDisabled: true,
	}

	// 如果提供了 CA 路徑，則啟用雙向認證 (mTLS)
	if caPath != "" {
		realCaPath := filepath.Join(dir, caPath)
		caCert, err := os.ReadFile(realCaPath)
		if err != nil {
			log.Fatalf("無法讀取 CA 憑證: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	server := &http.Server{
		Addr:      ":" + port,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	go func() {
		log.Printf("Starting HTTPS Metrics server on port %s", port)
		// 使用 ListenAndServeTLS 啟動 HTTPS

		realSslKey := filepath.Join(dir, sslKey)
		realSslCert := filepath.Join(dir, sslCert)

		if err := server.ListenAndServeTLS(realSslCert, realSslKey); err != nil {
			log.Fatalf("HTTPS Metrics server failed: %v", err)
		}
	}()
}

// ResetMetrics 清除所有舊的指標，確保數據是「當前存活」的
func ResetMetrics() {
	riskMetrics.Reset()
	ksmEventCounter.Reset()
}

// ProcessSocketData 處理來自 Socket 的資料並更新指標
func ProcessSocketData(body model.BPFTraceBody) {
	label := string(bytes.Trim(body.Label[:], "\x00"))
	domain := string(bytes.Trim(body.Domain[:], "\x00"))
	srcIp := string(bytes.Trim(body.SrcIp[:], "\x00"))
	dstIp := string(bytes.Trim(body.DstIp[:], "\x00"))

	riskMetrics.WithLabelValues(label, domain, srcIp, dstIp).Set(float64(body.Count))
	// log.Printf("Metric Updated: [%s] %s -> %s, Count: %d", domain, srcIp, dstIp, body.Count)
}

// ProcessKSMEvent 處理來自 kernel module 的 KSM 檔案監控事件並更新指標
func ProcessKSMEvent(pid uint32, comm string, filepath string, is_write int32, count int64) {
	// 將 is_write 轉換成可讀的字串標籤 ("read" 或 "write")
	writeStr := "read"
	if is_write > 0 {
		writeStr = "write"
	}

	pidStr := strconv.FormatUint(uint64(pid), 10)
	countStr := strconv.FormatInt(count, 10)

	// 增加對應標籤的計數器
	ksmEventCounter.WithLabelValues(pidStr, comm, filepath, writeStr, countStr).Inc()

	// 若需要印出 Log 進行除錯，可以開啟這行
	// log.Printf("[KSM Event] PID: %s, Comm: %s, File: %s, Type: %s", pidStr, comm, filepath, writeStr)
}
