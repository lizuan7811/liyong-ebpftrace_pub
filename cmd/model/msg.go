package model

import (
	"bytes"
	"fmt"
)

type BPFTraceHeader struct {
	Type    uint32
	RowsNum uint32
}

type BPFTraceBody struct {
	Label  [32]byte
	Domain [32]byte
	SrcIp  [16]byte
	DstIp  [16]byte
	Count  uint64
}

// 必須與 C++ 端的 struct file_event_data 記憶體佈局完全對應
type FileEventData struct {
	Pid      uint32
	Comm     [16]byte
	Filepath [256]byte
	IsWrite  int32 // 在 C 語言中 int 通常是 4 bytes
	Count    uint64
}

func (b BPFTraceBody) String() string {
	return fmt.Sprintf("Label: %s, Count: %d", string(bytes.Trim(b.Label[:], "\x00")), b.Count)
}
