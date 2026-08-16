#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp> // 這必須在 boost/asio.hpp 之後，否則會報錯
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/unistd.h>
#include <iostream>
#include "crow/app.h"
#include <sstream>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>
#include <fcntl.h>
#include <arpa/inet.h>
#include "../model/RiskMetricInfos.hpp"
#include "../model/KsmFEMetricInfo.hpp"
#include "../model/Common.h"
#include "../model/ksm_fileevent.h"
#include "../config/xdp_fw_config.hpp"

inline const std::string TLSV1_3 = "tlsv1.3";

class ExporterService {
public:
    // 🟢 服務健康狀態
    enum class ServiceStatus : int {
        STOPPED, // 尚未啟動 / 已正常關閉
        STARTING, // 啟動中或重試中
        RUNNING, // 正常運作、有在服務
        FAILED // 目前處於失敗狀態（會持續重試）
    };

private:
    std::thread service_thread;
    std::thread uds_thread;
    std::thread ksm_reader_thread; // 專門從 /dev/ksm_dev 讀資料的執行緒
    crow::SimpleApp app;

    std::atomic<bool> running{true};
    std::atomic<bool> initialized{false};
    std::atomic<bool> uds_initialized{false};
    std::atomic<ServiceStatus> status_{ServiceStatus::STOPPED};
    int uds_server_fd{-1};

    // 重試參數
    static constexpr int MAX_RETRY = 0;
    static constexpr int RETRY_DELAY_SEC = 2;

    ExporterService() {
        startKsmReader();
    }

    // 統一的狀態切換 + log 入口
    void setStatus(ServiceStatus s) {
        ServiceStatus prev = status_.exchange(s);
        if (prev == s) return;
        switch (s) {
            case ServiceStatus::RUNNING:
                std::cout << "[METRIC] ✅ 狀態轉為 RUNNING（服務正常）" << std::endl;
                break;
            case ServiceStatus::FAILED:
                std::cerr << "[METRIC] 🚨 狀態轉為 FAILED（服務異常，請檢查！）" << std::endl;
                break;
            case ServiceStatus::STARTING:
                std::cout << "[METRIC] 🔄 狀態轉為 STARTING（正在啟動/重試中）" << std::endl;
                break;
            case ServiceStatus::STOPPED:
                std::cout << "[METRIC] ⏹ 狀態轉為 STOPPED（服務已停止）" << std::endl;
                break;
        }
    }

    // 背景執行緒：從 /dev/ksm_dev 讀取事件並直接寫入 KsmFEMetricInfo
    void startKsmReader() {
        ksm_reader_thread = std::thread([this]() {
            int dev_fd = open("/dev/ksm_dev", O_RDONLY);
            if (dev_fd < 0) {
                if (get_user_debug_level() >= LOG_LVL_DEBUG) {
                    std::cout << "[METRIC] 無法開啟 /dev/ksm_dev (可能未載入核心模組)" << std::endl;
                }
                return;
            }

            struct ksm_file_event ev;
            while (running.load()) {
                ssize_t bytes = read(dev_fd, &ev, sizeof(ev));
                if (bytes == sizeof(ev)) {
                    // 確保讀取完整的大小，避免半包
                    std::string comm_str(ev.comm);
                    std::string path_str(ev.filepath);

                    // 🟢 傳入 pid 與 is_write 更新到 KsmFEMetricInfo 中
                    KsmFEMetricInfo::instance().update_metrics(ev.pid, comm_str, path_str, ev.is_write, false);

                    if (get_user_debug_level() >= LOG_LVL_TRACE) {
                        std::cout << "[METRIC] read success, pid=" << ev.pid
                                << ", is_write=" << ev.is_write
                                << ", path=" << path_str << std::endl;
                    }
                } else if (bytes < 0) {
                    if (errno == EINTR) continue; // 被信號中斷則重試
                    if (get_user_debug_level() >= LOG_LVL_DEBUG) {
                        std::cerr << "[METRIC] read failed: " << strerror(errno)
                                << " (errno=" << errno << "), sizeof(ev)=" << sizeof(ev) << std::endl;
                    }
                    usleep(50000);
                } else {
                    if (get_user_debug_level() >= LOG_LVL_DEBUG) {
                        std::cerr << "[METRIC] read else failed: " << strerror(errno)
                                << " (errno=" << errno << "), sizeof(ev)=" << sizeof(ev) << std::endl;
                    }
                    usleep(50000);
                }
            }
            close(dev_fd);
        });
    }

    std::string ip_to_str(uint32_t ip) {
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip, str, INET_ADDRSTRLEN);
        return std::string(str);
    }

    // 嚴謹的 send_all 確保資料完整送出
    bool send_all(int fd, const void *buf, size_t len) {
        const char *p = static_cast<const char *>(buf);
        size_t sent = 0;
        while (sent < len && running.load()) {
            ssize_t n = send(fd, p + sent, len - sent, MSG_NOSIGNAL);
            if (n > 0) {
                sent += static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n < 0) {
                perror("[METRIC] send failed");
            }
            return false;
        }
        return sent == len;
    }

    inline void prepareSSLConfig(xdp_fw_config::SSLConf &sslConf) {
        if (!sslConf.is_active()) {
            return;
        }

        try {
            std::string tlsVersion = sslConf.tls_version();
            auto tokens = tlsVersion | std::views::split(',');

            bool isTls13 = false;
            for (auto &&rng: tokens) {
                std::string v{std::string_view(rng.begin(), rng.end())};
                if (CommonUtil::toLower(v) == CommonUtil::toLower(TLSV1_3)) {
                    isTls13 = true;
                }
            }

            boost::asio::ssl::context ssl_context(isTls13
                                                      ? boost::asio::ssl::context::tlsv13_server
                                                      : boost::asio::ssl::context::tlsv12_server);

            std::string certPath = CommonUtil::getAbsolute(sslConf.cert_path());
            std::string keyPath = CommonUtil::getAbsolute(sslConf.key_path());

            if (!std::filesystem::exists(certPath) || !std::filesystem::exists(keyPath)) {
                throw std::runtime_error("SSL Certificate or Key file not found: " + certPath + ", " + keyPath);
            }

            ssl_context.use_certificate_chain_file(certPath);
            ssl_context.use_private_key_file(keyPath, boost::asio::ssl::context::pem);

            if (!sslConf.ciphers1().empty()) {
                if (SSL_CTX_set_cipher_list(ssl_context.native_handle(), sslConf.ciphers1().c_str()) != 1) {
                    throw std::runtime_error("Failed to set cipher list: " + sslConf.ciphers1());
                }
            }

            ssl_context.set_options(boost::asio::ssl::context::default_workarounds |
                                    boost::asio::ssl::context::no_sslv2 |
                                    boost::asio::ssl::context::no_sslv3 |
                                    boost::asio::ssl::context::no_tlsv1 |
                                    boost::asio::ssl::context::no_tlsv1_1);

            app.ssl(std::move(ssl_context));

            if (get_user_debug_level() >= LOG_LVL_DEBUG) {
                std::cout << "[METRIC] SSL Configured successfully. TLS 1.3: " << (isTls13 ? "Yes" : "No") << std::endl;
            }
        } catch (const std::exception &e) {
            std::cerr << "[METRIC] !!! SSL Configuration Error: " << e.what() << std::endl;
            setStatus(ServiceStatus::FAILED);
        }
    }

    inline int createAndBindUdsSocket(const xdp_fw_config::ExporterConfig &expConf) {
        int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd == -1) {
            perror("[METRIC] socket creation failed");
            return -1;
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            perror("[METRIC] setsockopt failed");
            close(server_fd);
            return -1;
        }

        struct sockaddr_un addr{};
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, expConf.socket_path().c_str(), sizeof(addr.sun_path) - 1);

        unlink(expConf.socket_path().c_str());
        if (bind(server_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
            perror("[METRIC] bind failed");
            close(server_fd);
            return -1;
        }

        if (listen(server_fd, 10) == -1) {
            perror("[METRIC] listen failed");
            close(server_fd);
            return -1;
        }

        return server_fd;
    }

    // 發送 Type 1：BPF 網路風險統計資料
    // 🟢 修正：先把整份資料 snapshot 到 vector，再送出，
    // 確保 header.count 與實際送出的筆數永遠一致，避免遍歷過程中
    // map 被其他執行緒新增資料，造成 count 與 body 筆數對不上、協議位移錯亂。
    bool _send_bpftrace(int client_fd) {
        auto &map = RiskMetricInfos::instance().get_map();

        std::vector<BPFTraceBody> bodies;
        bodies.reserve(map.size());

        for (const auto &[key, data]: map) {
            BPFTraceBody bpfTraceInfo{};
            memset(&bpfTraceInfo, 0, sizeof(BPFTraceBody));

            strncpy(bpfTraceInfo.label, key.get_domain().c_str(), sizeof(bpfTraceInfo.label) - 1);
            strncpy(bpfTraceInfo.domain, key.get_domain().c_str(), sizeof(bpfTraceInfo.domain) - 1);
            strncpy(bpfTraceInfo.srcIp, ip_to_str(key.get_src_ip()).c_str(), sizeof(bpfTraceInfo.srcIp) - 1);
            strncpy(bpfTraceInfo.dstIp, ip_to_str(key.get_dst_ip()).c_str(), sizeof(bpfTraceInfo.dstIp) - 1);
            bpfTraceInfo.count = data.count;

            bodies.push_back(bpfTraceInfo);
        }

        CommMsgHeader head = {
            .type = 1,
            .count = (uint32_t) bodies.size()
        };

        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "[METRIC_BPF_DEBUG] CommMsgHeader type: " << head.type
                    << ", count: " << head.count << std::endl;
        }
        if (!send_all(client_fd, &head, sizeof(head))) {
            return false;
        }

        for (const auto &body: bodies) {
            if (!send_all(client_fd, &body, sizeof(BPFTraceBody))) {
                return false;
            }
        }
        return true;
    }

    // 發送 Type 2：Ksm 檔案監控事件 (透過 UDS)
    // 🟢 修正：同樣先建立 snapshot vector 再送出，避免 count 與實際
    // 送出的 body 筆數不一致（原本分兩次遍歷 map，中間 ksm_reader_thread
    // 可能已經插入新資料，導致協議位移、client 端解析錯亂）。
    bool _send_ksm_events(int client_fd) {
        auto &map = KsmFEMetricInfo::instance().get_map();

        size_t size_before = map.size();

        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "[METRIC_KSM_DEBUG] map.size() BEFORE iterate = " << size_before << std::endl;
        }
        std::vector<KsmFEExportBody> bodies;
        bodies.reserve(64);

        size_t iter_count = 0;
        for (auto it = map.begin(); it != map.end(); ++it) {
            iter_count++;
            const KsmFEMetricInfo::KsmFEKey &key = it->first;
            const KsmFEMetricInfo::KsmFEMetricData &data = it->second;

            KsmFEExportBody body{};
            memset(&body, 0, sizeof(KsmFEExportBody));

            std::string comm_str = key.get_comm();
            size_t comm_len = std::min(comm_str.size(), sizeof(body.comm) - 1);
            memcpy(body.comm, comm_str.data(), comm_len);
            body.comm[comm_len] = '\0';

            std::string path_str = key.get_filepath();
            size_t path_len = std::min(path_str.size(), sizeof(body.filepath) - 1);
            memcpy(body.filepath, path_str.data(), path_len);
            body.filepath[path_len] = '\0';

            body.count = data.count.load(std::memory_order_relaxed);
            body.pid = key.get_pid();
            body.is_write = key.get_is_write();

            bodies.push_back(body);
        }
        CommMsgHeader head = {.type = 2, .count = (uint32_t) bodies.size()};

        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "[METRIC_KSM_DEBUG] iterate visited " << iter_count
                    << " entries (size_before=" << size_before << ")" << std::endl;

            std::cout << "[METRIC_KSM_DEBUG] CommMsgHeader type: " << head.type
                    << ", count: " << head.count << std::endl;

            std::cout << "[METRIC_KSM_DEBUG] KsmFEExport msg type: " << head.type
                    << ", count: " << head.count << std::endl;
        }
        if (!send_all(client_fd, &head, sizeof(head))) {
            std::cerr << "[METRIC] CommMsgHeader send failed!" << std::endl;
            return false;
        }
        if (bodies.empty()) {
            std::cerr << "[METRIC] KsmFEExportBody send failed!" << std::endl;
            return true;
        }
        for (const auto &body: bodies) {
            if (!send_all(client_fd, &body, sizeof(KsmFEExportBody))) {
                std::cerr << "[METRIC] KsmFEExportBody send failed!" << std::endl;
                return false;
            }
        }
        return true;
    }

    // 處理單一 Client 連線的迴圈
    void serveClient(int client_fd) {
        struct timeval snd_tv{.tv_sec = 5, .tv_usec = 0};
        if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv)) == -1) {
            perror("[METRIC] setsockopt SO_SNDTIMEO failed");
        }
        signal(SIGPIPE, SIG_IGN);

        setStatus(ServiceStatus::RUNNING);
        int tick = 0;

        while (running.load()) {
            if (get_user_debug_level() >= LOG_LVL_TRACE) {
                std::cout << "[TICK] loop #" << (++tick)
                        << " start, running=" << running.load() << std::endl;
            }
            auto &map = KsmFEMetricInfo::instance().get_map();

            size_t mapsize = map.size();

            if (get_user_debug_level() >= LOG_LVL_TRACE) {
                std::cout << "[METRIC_KSM_DEBUG] map.size() = " << mapsize << std::endl;
            }
            if (!_send_bpftrace(client_fd)) {
                if (get_user_debug_level() >= LOG_LVL_TRACE) {
                    std::cout << "[TICK] _send_bpftrace FAILED at tick " << tick << std::endl;
                }
                setStatus(ServiceStatus::FAILED);
                break;
            }
            if (!_send_ksm_events(client_fd)) {
                if (get_user_debug_level() >= LOG_LVL_TRACE) {
                    std::cout << "[TICK] _send_ksm_events FAILED at tick " << tick << std::endl;
                }
                setStatus(ServiceStatus::FAILED);
                break;
            }
            if (get_user_debug_level() >= LOG_LVL_TRACE) {
                std::cout << "[TICK] loop #" << tick << " done, sleeping 1s" << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "[TICK] serveClient EXIT after " << tick << " ticks, running="
                    << running.load() << std::endl;
        }
        close(client_fd);
    }

    inline void initUDSService(xdp_fw_config::ExporterConfig &expConf) {
        setStatus(ServiceStatus::STARTING);
        int retry_count = 0;

        while (running.load()) {
            int server_fd = createAndBindUdsSocket(expConf);
            if (server_fd == -1) {
                setStatus(ServiceStatus::FAILED);
                if (MAX_RETRY > 0 && ++retry_count >= MAX_RETRY) {
                    std::cerr << "[METRIC] ❌ 已達最大重試次數，UDS 放棄啟動！" << std::endl;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_SEC));
                continue;
            }

            uds_server_fd = server_fd;
            setStatus(ServiceStatus::RUNNING);
            std::cout << "[METRIC] ✅ UDS Exporter 監聽中: " << expConf.socket_path() << std::endl;

            while (running.load()) {
                int client_fd = accept(server_fd, NULL, NULL);
                if (client_fd < 0) {
                    if (!running.load()) break;
                    perror("[METRIC] accept failed");
                    setStatus(ServiceStatus::FAILED);

                    if (errno == EBADF || errno == ENOTSOCK || errno == EINVAL) {
                        break; // 描述子失效，重新建立 socket
                    }
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }

                // 服務客戶端（同步單線程處理）
                serveClient(client_fd);
            }

            close(server_fd);
            uds_server_fd = -1;
        }

        setStatus(ServiceStatus::STOPPED);
    }

    void aggregate_rist_metrics(std::stringstream &ss) {
        auto &map = RiskMetricInfos::instance().get_map();
        std::map<std::string, uint64_t> aggregated_map;

        for (auto it = map.begin(); it != map.end(); ++it) {
            const auto &key = it->first;
            const auto &data = it->second;

            std::string label_key = "domain=\"" + key.get_domain() + "\"," +
                                    "src=\"" + ip_to_str(key.get_src_ip()) + "\"," +
                                    "dst=\"" + ip_to_str(key.get_dst_ip()) + "\"";

            aggregated_map[label_key] += data.count.load();
        }

        for (const auto &[label_key, total_count]: aggregated_map) {
            ss << "ebpf_risk_domain{" << label_key << "} " << total_count << "\n";
        }
    }

    void aggregate_ksm_fevnet_metrics(std::stringstream &ss) {
        // 🟢 改為讀取 KsmFEMetricInfo

        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "[ADDR_DEBUG][http_reader] KsmFEMetricInfo instance = "
                    << &KsmFEMetricInfo::instance() << std::endl;
        }
        auto &map = KsmFEMetricInfo::instance().get_map();
        std::map<std::string, uint64_t> aggregated_map;

        for (auto it = map.begin(); it != map.end(); ++it) {
            const auto &key = it->first;
            const auto &data = it->second;

            // 🟢 使用 comm + filepath 作為 Prometheus 的 label
            std::string label_key = "comm=\"" + key.get_comm() + "\"," +
                                    "filepath=\"" + key.get_filepath() + "\"";

            aggregated_map[label_key] += data.count.load();
        }

        for (const auto &[label_key, total_count]: aggregated_map) {
            ss << "kernel_file_event_total{" << label_key << "} " << total_count << "\n";
        }
    }

    inline void initService() {
        service_thread = std::thread([this]() {
            setStatus(ServiceStatus::STARTING);

            CROW_ROUTE(app, "/metrics")([this]() {
                std::stringstream ss;

                aggregate_rist_metrics(ss);

                aggregate_ksm_fevnet_metrics(ss);
                crow::response res;
                res.code = 200;
                res.set_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8");
                res.write(ss.str());

                return res;
            });

            setStatus(ServiceStatus::RUNNING);
            std::cout << "[METRIC] ✅ HTTP Exporter 已啟動，監聽 port 9090" << std::endl;

            try {
                app.port(9090).multithreaded().run();
            } catch (const std::exception &e) {
                std::cerr << "[METRIC] 🚨 HTTP Exporter 執行異常: " << e.what() << std::endl;
                setStatus(ServiceStatus::FAILED);
                return;
            }

            setStatus(ServiceStatus::STOPPED);
        });
    }

public:
    static ExporterService &instance() {
        static ExporterService inst;
        return inst;
    }

    ServiceStatus getStatus() const {
        return status_.load();
    }

    bool isHealthy() const {
        return status_.load() == ServiceStatus::RUNNING;
    }

    std::string getStatusString() const {
        switch (status_.load()) {
            case ServiceStatus::STOPPED: return "STOPPED";
            case ServiceStatus::STARTING: return "STARTING";
            case ServiceStatus::RUNNING: return "RUNNING";
            case ServiceStatus::FAILED: return "FAILED";
        }
        return "UNKNOWN";
    }

    void startUDSService(xdp_fw_config::ExporterConfig expConf) {
        if (uds_initialized.exchange(true)) return;
        // 啟動時自動開始讀取核心 KSM 事件
        uds_thread = std::thread([this, expConf]() mutable {
            initUDSService(expConf);
        });
        uds_thread.detach();
    }

    void startHttpService(xdp_fw_config::SSLConf &sslConf) {
        if (initialized.load()) return;
        prepareSSLConfig(sslConf);
        // 啟動時自動開始讀取核心 KSM 事件
        startKsmReader();
        initService();
        initialized.store(true, std::memory_order_release);
    }

    void stop() {
        if (!running.exchange(false)) return;
        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "\n[METRIC] START, Stopping metric service... !" << std::endl;
        }

        app.stop();

        if (uds_server_fd != -1) {
            shutdown(uds_server_fd, SHUT_RDWR);
        }

        if (service_thread.joinable()) {
            service_thread.join();
        }

        if (ksm_reader_thread.joinable()) {
            ksm_reader_thread.join();
        }

        setStatus(ServiceStatus::STOPPED);
        if (get_user_debug_level() >= LOG_LVL_TRACE) {
            std::cout << "\n[METRIC] END !" << std::endl;
        }
    }

    ~ExporterService() {
        stop();
    }

    ExporterService(const ExporterService &) = delete;

    ExporterService &operator=(const ExporterService &) = delete;
};
