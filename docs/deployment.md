# 部署操作

## 編譯與掛載

```bash
# 產生 vmlinux.h（BTF 依賴）
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 編譯（Debug 模式）
make clean && make DEBUG=1

# 確認 XDP / TC 掛載狀態
sudo bpftool net list

# 確認 bpffs 釘選狀態
ls -la /sys/fs/bpf/

# 啟用 SYN Cookie（攻擊模式下配合使用）
sudo sysctl -w net.ipv4.tcp_syncookies=1

# 手動卸載 XDP（指定網卡）
sudo ip link set dev <interface> xdp off
```

## 動態封鎖 IP

透過 SIGUSR1 通道操作（詳見 [`userspace.md`](userspace.md#sigusr1-外部管控通道)）：

```bash
echo "1.2.3.4 300" > /run/xdp_fw/block_cmd       # 封鎖 300 秒
echo "1.2.3.4 0" > /run/xdp_fw/block_cmd          # 永久封鎖
echo "1.2.3.4 2026-12-31_23:59:59" > /run/xdp_fw/block_cmd  # 預約封鎖
kill -SIGUSR1 <pid>
```

## 常用診斷指令

```bash
ip link show

ip link set dev ens33 xdp off

tc filter show dev ens33 ingress
tc filter show dev ens33 egress

bpftool prog show
bpftool net

# 對指定網卡執行，會立即清除所有堆疊的 BPF Hook
sudo tc qdisc del dev enp8s0 clsact
sudo tc qdisc del dev wlp0s20f3 clsact
```

---

## 相依套件安裝

### Curl 相關套件

```bash
sudo apt install libcurl4-openssl-dev

sudo apt update
sudo apt install libidn2-dev libpsl-dev libssl-dev zlib1g-dev

sudo apt-get update
sudo apt-get install -y libssl-dev pkg-config
sudo apt-get install libjitterentropy-dev
```

### nDPI 編譯

```bash
sudo apt update
sudo apt install -y git build-essential pkg-config autoconf automake gettext bison libtool autoconf automake libtool libpcap-dev

# 1. 複製原始碼
git clone https://github.com/ntop/nDPI.git
cd nDPI
git checkout 5.0-stable

# 2. 生成配置腳本
./autogen.sh

# 3. 配置編譯優化（關閉共享庫，只生成高效能靜態庫，並開啟 CPU 頂級優化）
CFLAGS="-O3 -march=native" ./configure --disable-shared --enable-static
# CFLAGS="-O3 -march=native -D_XOPEN_SOURCE=700" ./configure --disable-shared --enable-static

# 4. 全核編譯
make -j$(nproc)
```

若需重新配置（例如切換 glibc 環境）：

```bash
make clean
make distclean

# 重新生成配置腳本（重新偵測當前 glibc 標頭檔狀態）
./autogen.sh

# 重新配置（不主動加 CFLAGS，讓 configure 自行處理巨集定義）
./configure --disable-shared --enable-static
./configure CFLAGS="-g -O2 -D_LINUX_STAT_H"

# 重新編譯
export CFLAGS="-D_LINUX_STAT_H"
make -j$(nproc)
```

查找編譯產物：

```bash
find <nDPI_project_path> -name "*.so" -o -name "*.a" -o -name "ndpiReader" 2>/dev/null
```

編譯 main.cpp 範例：

```bash
c++ user/main.cpp .cache/simdjson.o -std=c++20 \
  -I./user -I./user/config -I./user/service -Iskel -I./build/skel \
  -O3 -lbpf -lpthread -lbpf -lpcap -lm -lpthread \
  -o main -g2
```

### jitterentropy-library 安裝

```bash
git clone https://github.com/smuellerDD/jitterentropy-library.git
cd jitterentropy-library
make
sudo make install-static install-includes
sudo ldconfig
ls -l /usr/local/lib/libjitterentropy.a
ls -l /usr/local/include/jitterentropy.h

# 若需安裝至自訂 PREFIX（如專案目錄下的 third_party）
make clean
make
make PREFIX=<your_project_path>/third_party/jitterentropy install-static install-includes
```

### Boost / TBB 模組

```bash
# Boost
sudo apt-get install libboost-all-dev

# TBB
sudo apt-get update
sudo apt-get install libtbb-dev
```

---

## 建立自建 CA 自簽憑證

```bash
openssl genrsa -out rootCA.key 4096

openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 36500 \
  -out rootCA.crt \
  -subj "/C=TW/ST=Taiwan/L=Taipei/O=Liyong/OU=IT/CN=bpffirewall.com"

openssl genrsa -out server.key 4096

openssl req -new \
  -key server.key \
  -out server.csr \
  -subj "/C=TW/ST=Taiwan/L=Taipei/O=Liyong/OU=IT/CN=bpffirewall.com"

# san.cnf 內容需包含：
# subjectAltName=DNS:liyong.bpffirewall.com,DNS:localhost,IP:127.0.0.1

openssl x509 -req \
  -in server.csr \
  -CA rootCA.crt \
  -CAkey rootCA.key \
  -CAcreateserial \
  -out server.cert \
  -days 3650 \
  -sha256 \
  -extfile san.cnf
```

> Prometheus 與 Grafana 監控部署請見 [`monitoring.md`](monitoring.md)。
