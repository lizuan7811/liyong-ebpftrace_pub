#include "WriteCallBack.hpp"
#include <curl/curl.h>

// 處理 Curl 返回資料的 Callback
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    ((std::string *) userp)->append((char *) contents, size * nmemb);
    return size * nmemb;
}

std::string fetchOtxData(const std::string &apiKey, const std::string &remoteUrl) {
    const int MAX_RETRIES = 100;
    int retryCount = 0;

    while (retryCount < MAX_RETRIES) {
        CURL *curl = curl_easy_init();
        if (!curl) return "";

        std::string readBuffer;
        struct curl_slist *headers = NULL;
        std::string authHeader = "X-OTX-API-KEY: " + apiKey;
        headers = curl_slist_append(headers, authHeader.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, remoteUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Timeout 設定
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        CURLcode res = curl_easy_perform(curl);

        // 清理資源
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        if (res == CURLE_OK) {
            return readBuffer; // 成功，回傳資料
        } else {
            retryCount++;
            std::cerr << "Curl attempt " << retryCount << " failed: "
                    << curl_easy_strerror(res) << ". Retrying..." << std::endl;
            // 指數退避 (Exponential Backoff): 增加重試間隔，避免伺服器封鎖你
            std::this_thread::sleep_for(std::chrono::seconds(2 * retryCount));
        }
    }
    return ""; // 經過多次重試仍失敗，回傳空字串，讓外部知道徹底死掉了
}

std::string getAuthToken(const std::string &path, const std::string &username, const std::string &password) {
    // 這裡實作你讀取 auth token 的邏輯，例如讀取檔案或本地加密認證
    return "dummy_token_for_example";
}
