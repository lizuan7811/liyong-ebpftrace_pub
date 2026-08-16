package main

import (
	"context"
	"fmt"
	"liyong-ebpftrace/cmd/util"
	"liyong-ebpftrace/pkg/config"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type ExporterManager struct {
	Config *config.Config
	Cmd    *exec.Cmd
	exeDir string
	Done   chan struct{}
}

func GetXdpFwPath() (string, error) {
	dir, err := util.GetExeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "xdp_fw"), nil
}

func NewExporterManager(configPath string) (*ExporterManager, error) {
	dir, err := util.GetExeDir()
	if err != nil {
		return nil, err
	}
	fullConfigPath := filepath.Join(dir, configPath)
	conf, err := config.LoadConfig(fullConfigPath)
	if err != nil {
		return nil, fmt.Errorf("讀取設定檔失敗 (%s): %w", fullConfigPath, err)
	}
	return &ExporterManager{Config: conf, exeDir: dir}, nil
}

func (em *ExporterManager) Start(ctx context.Context) error {
	cppPath, err := GetXdpFwPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(cppPath); err != nil {
		return fmt.Errorf("找不到 xdp_fw 執行檔: %w", err)
	}

	em.Cmd = exec.CommandContext(ctx, cppPath)
	em.Cmd.Dir = em.exeDir
	em.Cmd.Stdout = os.Stdout
	em.Cmd.Stderr = os.Stderr
	// 讓 xdp_fw 自己成為 process group leader,之後可以連它衍生的子行程一起殺
	em.Cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := em.Cmd.Start(); err != nil {
		return fmt.Errorf("無法啟動 C++ 程式: %w", err)
	}

	em.Done = make(chan struct{})
	go func() {
		defer close(em.Done)
		if err := em.Cmd.Wait(); err != nil {
			log.Printf("C++ 程式退出: %v", err)
		}
	}()

	return nil
}

func (em *ExporterManager) Stop() {
	if em.Cmd == nil || em.Cmd.Process == nil {
		return
	}

	pgid := em.Cmd.Process.Pid
	log.Printf("[Stop] 發送 SIGTERM 給 Process Group: -%d", pgid)

	// 1. 先發送 SIGTERM，給 C++ 程式清理資源的時間
	err := syscall.Kill(-pgid, syscall.SIGTERM)
	if err != nil {
		log.Printf("[Stop] SIGTERM 失敗: %v", err)
	}

	// 2. 設定一個超時機制 (例如 3 秒)
	// 如果 3 秒後程式還沒死，再發送 SIGKILL 強制終止
	select {
	case <-em.Done:
		log.Println("[Stop] 子行程已優雅退出")
	case <-time.After(10 * time.Second):
		log.Println("[Stop] 超時，發送 SIGKILL 強制終止")
		syscall.Kill(-pgid, syscall.SIGKILL)
		<-em.Done // 等待最後結束
	}
}
