BUILD_DIR = build
BIN_DIR = bin

.PHONY: all clean build_cpp build_go

all: build_cpp build_go

build_cpp:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ../src && make -j$(nproc)
	mkdir -p $(BIN_DIR)
	cp $(BUILD_DIR)/xdp_fw $(BIN_DIR)/
	chmod +x $(BIN_DIR)/xdp_fw
	mkdir -p $(BIN_DIR)/resource
	cp -r src/resource/* $(BIN_DIR)/resource/
	# 如果 config.json 裡的憑證路徑是相對路徑,一併帶過去
	mkdir -p $(BIN_DIR)/ssl
	cp -r ssl/* $(BIN_DIR)/ssl/ 2>/dev/null || true

build_go:
	go build -o $(BIN_DIR)/liyong-ebpf ./cmd/exporter

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)