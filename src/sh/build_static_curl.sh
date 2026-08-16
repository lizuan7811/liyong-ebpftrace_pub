#!/usr/bin/env bash
# ============================================================
# 编译一个只开 HTTP/HTTPS 的瘦身版静态 libcurl.a
# 用途: 给 xdp_fw 的 RiskFileUpdater / RiskFileSyncManager 用，
#       去掉 GSSAPI/LDAP/SSH/RTMP/nghttp2/brotli/idn2/psl 等
#       系统套件版没有附静态库 (.a) 的可选协议，避免链接报错。
#
# 用法:
#   chmod +x build_static_curl.sh
#   ./build_static_curl.sh
#
# 编译完成后, libcurl.a 与 headers 会在:
#   <专案根目录>/third_party/curl-static/lib/libcurl.a
#   <专案根目录>/third_party/curl-static/include/curl/*.h
# ============================================================
set -euo pipefail

CURL_VERSION="8.20.0"   # 可去 https://curl.se/download.html 换成更新版本
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="${PROJECT_ROOT}/third_party/curl-build-tmp"
INSTALL_DIR="${PROJECT_ROOT}/third_party/curl-static"

echo "==> curl version : ${CURL_VERSION}"
echo "==> install to   : ${INSTALL_DIR}"

rm -rf "${WORK_DIR}"
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

echo "==> 下载 curl 原始码..."
curl -fsSL -O "https://curl.se/download/curl-${CURL_VERSION}.tar.gz"
tar xzf "curl-${CURL_VERSION}.tar.gz"
cd "curl-${CURL_VERSION}"

echo "==> 配置 (只开 HTTP/HTTPS, 完全静态, 关掉一堆不需要的协议)..."
# 注意: 这台机器的 linux/stat.h (kernel headers) 与 glibc sys/stat.h 有 struct stat
# 重复定义冲突 (常见于装了较新/不匹配的 linux-libc-dev，例如为了 eBPF CO-RE 装的新版 kernel headers)。
# 跟项目本身 main.cpp 用的解法一致: 预先 define _LINUX_STAT_H 让该 header 的 include guard
# 直接跳过冲突内容。这里透过 CPPFLAGS 套用到 curl configure 的所有编译测试与实际编译。
export CPPFLAGS="-D_LINUX_STAT_H ${CPPFLAGS:-}"

./configure \
    --prefix="${INSTALL_DIR}" \
    --disable-shared --enable-static \
    --enable-http --enable-proxy \
    --disable-dict --disable-file --disable-ftp --disable-gopher \
    --disable-imap --disable-mqtt --disable-pop3 --disable-rtsp \
    --disable-smb --disable-smtp --disable-telnet --disable-tftp \
    --disable-ldap --disable-ldaps \
    --without-librtmp \
    --without-libssh --without-libssh2 \
    --without-libpsl \
    --without-nghttp2 --without-nghttp3 --without-ngtcp2 \
    --without-quiche --without-msh3 \
    --without-brotli \
    --without-zstd \
    --without-libidn2 \
    --without-gssapi \
    --with-openssl=/usr \
    --with-zlib

echo "==> 编译..."
make -j"$(nproc)"

echo "==> 安装到 ${INSTALL_DIR} ..."
make install

echo "==> 完成。验证缺少哪些 symbol (应该几乎是空的):"
nm -u "${INSTALL_DIR}/lib/libcurl.a" 2>/dev/null \
    | grep -Ev '^\s*$' \
    | sort -u \
    | grep -Ei 'gss_|ldap_|ber_|ssh_|sftp_|nghttp2_|idn2_|psl_|brotli|rtmp_' \
    || echo "    (没有发现这些协议的 undefined symbol，干净)"

echo ""
echo "下一步: 在 CMakeLists.txt 把 curl 静态库路径指向:"
echo "  ${INSTALL_DIR}/lib/libcurl.a"
echo "Include 路径指向:"
echo "  ${INSTALL_DIR}/include"
