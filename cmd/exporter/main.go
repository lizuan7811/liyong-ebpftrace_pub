package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"liyong-ebpftrace/cmd/model"
	"liyong-ebpftrace/cmd/svc"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	socketDialTimeout = 100 * time.Millisecond
	socketDialRetries = 50
	readDeadline      = 10 * time.Second
	reconnectBackoff  = 500 * time.Millisecond
)

func initLog() {
	// 同時輸出到 stdout 和檔案,終端機上就能立刻看到錯誤
	multi := io.MultiWriter(os.Stdout, &lumberjack.Logger{
		Filename:   "app.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	})
	log.SetOutput(multi)
}

// dialSocket 嘗試連線到 unix socket,失敗會重試
func dialSocket(socketPath string) (net.Conn, error) {
	var conn net.Conn
	var err error
	for i := 0; i < socketDialRetries; i++ {
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			return conn, nil
		}
		time.Sleep(socketDialTimeout)
	}
	return nil, err
}

// readLoop 從 conn 讀資料直到出錯,回傳時代表連線已經不可用
// 回傳 true 代表是因為 ctx 被取消而正常結束,false 代表是連線錯誤,需要重連
// func readLoop(ctx context.Context, conn net.Conn) bool {
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			log.Println("[readLoop] Done ...")
// 			return true
// 		default:
// 		}

// 		conn.SetReadDeadline(time.Now().Add(readDeadline))

// 		var head model.BPFTraceHeader
// 		if err := binary.Read(conn, binary.LittleEndian, &head); err != nil {
// 			log.Printf("[readLoop] Read header error: %v", err)
// 			return false
// 		}

// 		// 【重要】每輪數據開始前,清空指標,確保顯示的是最新狀態
// 		svc.ResetMetrics()

// 		summaryBody := make(map[string]model.BPFTraceBody)
// 		bodyReadFailed := false
// 		for i := uint32(0); i < head.Count; i++ {
// 			conn.SetReadDeadline(time.Now().Add(readDeadline))

// 			var body model.BPFTraceBody
// 			if err := binary.Read(conn, binary.LittleEndian, &body); err != nil {
// 				log.Printf("[readLoop] Read body error: %v", err)
// 				bodyReadFailed = true
// 				break // 只跳出內層,不要讓整個程式結束
// 			}
// 			domain := string(bytes.Trim(body.Domain[:], "\x00"))

// 			if existing, ok := summaryBody[domain]; ok {
// 				body.Count += existing.Count
// 				// 如果 BPFTraceBody 裡還有其他要累加的統計欄位（例如 bytes、packets 之類），
// 				// 也要在這裡一起加，不能只處理 Count
// 				// body.Bytes += existing.Bytes
// 			}
// 			summaryBody[domain] = body
// 		}

// 		if bodyReadFailed {
// 			log.Println("[readLoop] body Read Failed ...")
// 			return false // body 讀取失敗,連線視為壞掉,交給外層重連
// 		}

// 		// log.Println("[readLoop] summaryBody len: " + strconv.Itoa(len(summaryBody)))
// 		for sbody := range summaryBody {
// 			svc.ProcessSocketData(summaryBody[sbody])
// 		}
// 	}
// }

// readLoop 從 conn 讀資料直到出錯,回傳時代表連線已經不可用
func readLoop(ctx context.Context, conn net.Conn) bool {
	for {
		select {
		case <-ctx.Done():
			log.Println("[readLoop] Done ...")
			return true
		default:
		}

		conn.SetReadDeadline(time.Now().Add(readDeadline))

		var head model.BPFTraceHeader
		if err := binary.Read(conn, binary.LittleEndian, &head); err != nil {
			log.Printf("[readLoop] Read header error: %v", err)
			return false
		}

		// 根據 C++ 傳過來的 Type 進行分流處理
		switch head.Type {
		case 1:
			if !readAndProcessBPFData(conn, head.RowsNum) {
				return false
			}
		case 2:
			if !readAndProcessKSMData(conn, head.RowsNum) {
				return false
			}
		default:
			log.Printf("[readLoop] Unknown message type received: %d", head.Type)
			return false
		}
	}
}

// 抽離出的函式 1：負責處理 BPF 統計資料
func readAndProcessBPFData(conn net.Conn, count uint32) bool {
	// 【重要】每輪數據開始前,清空指標,確保顯示的是最新狀態
	svc.ResetMetrics()

	summaryBody := make(map[string]model.BPFTraceBody)
	for i := uint32(0); i < count; i++ {
		conn.SetReadDeadline(time.Now().Add(readDeadline))

		var body model.BPFTraceBody
		if err := binary.Read(conn, binary.LittleEndian, &body); err != nil {
			log.Printf("[readLoop] Read BPF body error: %v", err)
			return false
		}
		domain := string(bytes.Trim(body.Domain[:], "\x00"))

		if existing, ok := summaryBody[domain]; ok {
			body.Count += existing.Count
		}
		summaryBody[domain] = body
	}

	for sbody := range summaryBody {
		svc.ProcessSocketData(summaryBody[sbody])
	}
	return true
}

// 抽離出的函式 2：負責處理 KSM 檔案監控事件
func readAndProcessKSMData(conn net.Conn, rowsNum uint32) bool {
	for i := uint32(0); i < rowsNum; i++ {

		// log.Printf("rowsNum - %d", rowsNum)

		conn.SetReadDeadline(time.Now().Add(readDeadline))

		var ksmEvt model.FileEventData
		if err := binary.Read(conn, binary.LittleEndian, &ksmEvt); err != nil {
			log.Printf("[readLoop] Read KSM event error: %v", err)
			return false
		}

		// 清理字串結尾的 Null character (\x00)
		comm := string(bytes.Trim(ksmEvt.Comm[:], "\x00"))
		filepath := string(bytes.Trim(ksmEvt.Filepath[:], "\x00"))

		// 呼叫您在 Go Service 中處理 KSM 事件的方法
		svc.ProcessKSMEvent(ksmEvt.Pid, comm, filepath, ksmEvt.IsWrite, int64(ksmEvt.Count))
	}
	return true
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

	conn, err := dialSocket(socketPath)
	if err != nil {
		log.Fatalf("無法連線至 Socket: %v", err)
	}

	// 啟動 Prometheus Metric Server(獨立 goroutine,跟讀取迴圈的生死無關)
	svc.StartMetricServer(manager.Config.SSLConf.CaPath, manager.Config.SSLConf.KeyPath, manager.Config.SSLConf.CertPath, strconv.Itoa(manager.Config.ExporterConfig.MetricsPort))

	shuttingDown := make(chan struct{})
	go func() {
		<-sigCh
		log.Println("[main] 收到終止訊號...")
		close(shuttingDown)
		manager.Stop() // 先讓 C++ 走完自己的 graceful shutdown
		conn.Close()   // C++ 都退出了才關
		cancel()
	}()

	// 外層負責重連,讀取迴圈只負責讀到壞掉為止
	for {
		normalExit := readLoop(ctx, conn)
		if normalExit {
			// ctx 被取消,代表是正常收到終止訊號要關閉,直接離開
			log.Println("[main] ctx 被取消,代表是正常收到終止訊號要關閉,直接離開...")
			break
		}

		select {
		case <-shuttingDown:
			// 已經在關閉流程中,不需要再重連
			log.Println("[main] 已經在關閉流程中,不需要再重連...")
			break
		default:
		}

		select {
		case <-ctx.Done():
			log.Println("[main] 結束 Done...")
			break
		default:
		}

		log.Println("[main] 連線異常,準備重連...")
		conn.Close()
		time.Sleep(reconnectBackoff)

		newConn, err := dialSocket(socketPath)
		if err != nil {
			log.Printf("[main] 重連失敗: %v,%v 後再試一次", err, reconnectBackoff)
			continue
		}
		conn = newConn
		log.Println("[main] 重連成功")
	}

	log.Println("[main] 主迴圈結束,執行收尾")
	manager.Stop()
	conn.Close()
}
