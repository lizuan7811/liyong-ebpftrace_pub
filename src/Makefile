# =========================================================
# 目錄結構 (修正路徑)
# =========================================================
PROJECT_ROOT    := $(shell pwd)
BUILD_DIR       := $(PROJECT_ROOT)/build
OBJ_DIR         := $(BUILD_DIR)/obj
BIN_DIR         := $(BUILD_DIR)/bin
SKEL_DIR        := $(PROJECT_ROOT)/skel
EBPF_SRC        := $(PROJECT_ROOT)/ebpf
USER_SRC        := $(PROJECT_ROOT)/user
USER_CONFIG_SRC := $(USER_SRC)/config
CROW_INC        := $(PROJECT_ROOT)/third_party/crow

# =========================================================
# 工具設定
# =========================================================
CLANG   := clang
BPFTOOL := bpftool
CXX     := g++
CC      := gcc

STATIC ?= 1

# =========================================================
# 編譯選項
# =========================================================
CXXFLAGS   := -std=c++20 -O2 -g \
              -D_LINUX_STAT_H \
              -DASIO_STANDALONE \
              -DCROW_USE_BOOST=0 \
              -DCROW_ENABLE_SSL \
              -DCONFIG_PATH="\"$(PROJECT_ROOT)/resource/config.json\""

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 -DDEBUG

# =========================================================
# 第三方庫 (修正路徑)
# =========================================================
NDPI_LIB := $(PROJECT_ROOT)/third_party/ndpi/lib/libndpi.a
NDPI_INC := $(PROJECT_ROOT)/third_party/ndpi/include

CURL_STATIC_DIR := $(PROJECT_ROOT)/third_party/curl-static
CURL_STATIC_LIB := $(CURL_STATIC_DIR)/lib/libcurl.a
CURL_STATIC_INC := $(CURL_STATIC_DIR)/include

JITTER_STATIC_DIR := $(PROJECT_ROOT)/third_party/jitterentropy
JITTER_LIB        := $(JITTER_STATIC_DIR)/lib/libjitterentropy.a
JITTER_INC        := $(JITTER_STATIC_DIR)/include

STATIC_LIBS_DIR := /usr/lib/x86_64-linux-gnu

LIB_SSL    := $(STATIC_LIBS_DIR)/libssl.a
LIB_CRYPTO := $(STATIC_LIBS_DIR)/libcrypto.a
LIB_Z      := $(STATIC_LIBS_DIR)/libz.a
LIB_ZSTD   := $(STATIC_LIBS_DIR)/libzstd.a
LIB_BPF    := $(STATIC_LIBS_DIR)/libbpf.a
LIB_ELF    := $(STATIC_LIBS_DIR)/libelf.a
LIB_PCAP   := $(STATIC_LIBS_DIR)/libpcap.a

TBB_CFLAGS := $(shell pkg-config --cflags tbb 2>/dev/null)
TBB_LIBS   := $(shell pkg-config --libs tbb 2>/dev/null)
ifeq ($(strip $(TBB_LIBS)),)
    TBB_LIBS := -ltbb
endif

COMMON_INC := -I$(CURL_STATIC_INC) -I$(USER_SRC) -I$(USER_CONFIG_SRC) \
              -I$(EBPF_SRC) -I$(SKEL_DIR) -I$(NDPI_INC) -I$(JITTER_INC) \
              -I$(CROW_INC) -I/usr/include -I/usr/include/asio \
              -I/usr/include/bpf $(TBB_CFLAGS)

# =========================================================
# 1. BPF 來源收集
# =========================================================
BPF_SRCS  := $(filter-out $(EBPF_SRC)/loader.c, $(wildcard $(EBPF_SRC)/*.c))
BPF_OBJS  := $(patsubst $(EBPF_SRC)/%.c, $(BUILD_DIR)/%.bpf.o, $(BPF_SRCS))
BPF_SKELS := $(patsubst $(EBPF_SRC)/%.c, $(SKEL_DIR)/%.skel.h, $(BPF_SRCS))

# =========================================================
# 2. xdp_fw 來源清單 (修正路徑)
# =========================================================
XDP_FW_SRCS := \
    $(USER_SRC)/main.cpp \
    $(USER_CONFIG_SRC)/simdjson.cpp \
    $(USER_SRC)/util/RuleParser.cpp \
    $(USER_SRC)/util/LockFreeSPSCQueue.cpp \
    $(USER_SRC)/servie/impl/L7FlowSession.cpp \
    $(USER_SRC)/servie/impl/L7DpiEngine.cpp \
    $(USER_SRC)/servie/impl/L7FlowManager.cpp \
    $(USER_CONFIG_SRC)/RiskFileUpdater.cpp \
    $(USER_CONFIG_SRC)/RiskFileSyncManager.cpp \
    $(USER_CONFIG_SRC)/SyncRiskFileConfig.cpp \
    $(USER_SRC)/util/WriteCallBack.cpp \
    $(USER_CONFIG_SRC)/xdp_fw_config.cpp \
    $(USER_SRC)/util/CommonUtil.cpp \
    $(USER_CONFIG_SRC)/RiskIndicators.cpp \
    $(USER_SRC)/model/RiskMetricInfos.cpp

XDP_FW_OBJS := $(patsubst $(PROJECT_ROOT)/%.cpp,$(OBJ_DIR)/%.o,$(XDP_FW_SRCS))

# =========================================================
# 靜態 / 動態連結旗標
# =========================================================
ifeq ($(STATIC),1)
    STATIC_LINK_FLAGS := -static-libgcc -static-libstdc++
    XDP_FW_LINK_LIBS := \
       -Wl,--start-group \
       $(NDPI_LIB) $(CURL_STATIC_LIB) $(JITTER_LIB) \
       $(LIB_BPF) $(LIB_ELF) $(LIB_PCAP) $(LIB_SSL) $(LIB_CRYPTO) $(LIB_Z) $(LIB_ZSTD) \
       -Wl,--end-group \
       $(TBB_LIBS) -lpthread -lm -ldl
else
    STATIC_LINK_FLAGS :=
    XDP_FW_LINK_LIBS := $(NDPI_LIB) $(CURL_STATIC_LIB) $(JITTER_LIB) \
       -lbpf -lelf -lpcap -lssl -lcrypto -lz -lzstd $(TBB_LIBS) -lpthread -lm -ldl
endif

# =========================================================
# 預設目標
# =========================================================
dirs:
	@mkdir -p $(BUILD_DIR) $(SKEL_DIR) $(OBJ_DIR) $(BIN_DIR)

all: dirs $(BPF_SKELS) $(BUILD_DIR)/bin/xdp_fw
	@cp -r $(PROJECT_ROOT)/resource $(BIN_DIR)/

# =========================================================
# 4. BPF 編譯
# =========================================================
$(BUILD_DIR)/%.bpf.o: $(EBPF_SRC)/%.c
	@mkdir -p $(dir $@)
	@echo "🔧 [CLANG] 編譯 BPF: $<"
	$(CLANG) $(BPF_CFLAGS) -I$(EBPF_SRC) -I/usr/include/bpf -c $< -o $@

# =========================================================
# 5. Skeleton 生成
# =========================================================
$(SKEL_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	@mkdir -p $(dir $@)
	@echo "✨ [BPFTOOL] 生成 Skel: $@"
	$(BPFTOOL) gen skeleton $< > $@

# =========================================================
# 6. Userspace .cpp 編譯
# =========================================================
$(OBJ_DIR)/%.o: $(PROJECT_ROOT)/%.cpp $(BPF_SKELS)
	@mkdir -p $(dir $@)
	@echo "⚙️  [CXX] 編譯: $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@ $(COMMON_INC)

# =========================================================
# 7. Link xdp_fw
# =========================================================
$(BUILD_DIR)/bin/xdp_fw: $(XDP_FW_OBJS) $(BPF_SKELS)
	@echo "📦 [LINK] xdp_fw... (STATIC=$(STATIC))"
	$(CXX) $(CXXFLAGS) $(STATIC_LINK_FLAGS) -o $@ $(XDP_FW_OBJS) $(XDP_FW_LINK_LIBS)

# =========================================================
# clean
# =========================================================
clean:
	rm -rf $(BUILD_DIR) $(SKEL_DIR)
	@find $(PROJECT_ROOT) -path "$(PROJECT_ROOT)/.cache" -prune -o -type f -name "*.o" -exec rm -f {} +

.PHONY: all dirs clean