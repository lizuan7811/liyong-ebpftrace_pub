package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	Global         GlobalConfig         `json:"global"`
	WhiteList      PathConfig           `json:"white_list"`
	BlackList      BlackListConfig      `json:"black_list"`
	AllowPorts     AllowPortsConfig     `json:"allow_ports"`
	EnableDpi      bool                 `json:"enable_dpi"`
	RiskConfigInfo RiskConfigInfo       `json:"risk_config_info"`
	SSLConf        SSLConf              `json:"ssl_conf"`
	ExporterConfig ExporterConfig       `json:"exporter_config"`
}

type GlobalConfig struct {
	Port          int               `json:"port"`
	LogLevel      string            `json:"log_level"`
	LogPath       string            `json:"log_path"`
	RuleFilePath  string            `json:"rule_file_path"`
	RateLimit     RateLimitConfig   `json:"rate_limit"`
	TimeFormat    string            `json:"time_format"`
}

type RateLimitConfig struct {
	GlobalPPSLimit int    `json:"global_pps_limit"`
	GlobalRate     string `json:"global_rate"`
	GlobalBurst    string `json:"global_burst"`
	CustomRate     string `json:"custom_rate"`
	CustomBurst    string `json:"custom_burst"`
	FlowRate       string `json:"flow_rate"`
	FlowBurst      string `json:"flow_burst"`
}

type PathConfig struct {
	Path string `json:"path"`
}

type BlackListConfig struct {
	TempList PathConfig `json:"temp_list"`
	PermList PathConfig `json:"perm_list"`
}

type AllowPortsConfig struct {
	SrcPort []string `json:"src_port"`
	DestPort []string `json:"dest_port"`
}

type RiskConfigInfo struct {
	RemoteSourceURL      string `json:"remote_source_url"`
	FileSourcePath       string `json:"file_source_path"`
	FileSourceBinaryPath string `json:"file_source_binary_path"`
	AuthTokenPath        string `json:"auth_token_path"`
	ChecksumStoragePath  string `json:"checksum_storage_path"`
	APIKey               string `json:"api_key"`
	SyncIntervalSeconds  int    `json:"sync_interval_seconds"`
	RetryLimit           int    `json:"retry_limit"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
	ForceReload          bool   `json:"force_reload"`
}

type SSLConf struct {
	IsActive    bool   `json:"is_active"`
	EnableMtls  bool   `json:"enable_mtls"`
	CaPath      string `json:"ca_path"`
	KeyPath     string `json:"key_path"`
	CertPath    string `json:"cert_path"`
	CertPasswd  string `json:"cert_passwd"`
	TLSVersion  string `json:"tls_version"`
	Ciphers     string `json:"ciphers"`
}

type ExporterConfig struct {
	EnableExporter   bool   `json:"enable_exporter"`
	EnableSocket     bool   `json:"enable_socket"`
	SocketPath       string `json:"socket_path"`
	MetricsPort      int    `json:"metrics_port"`
	UpdateIntervalMs int    `json:"update_interval_ms"`
}

// LoadConfig 讀取並解析設定檔
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var conf Config
	err = json.Unmarshal(data, &conf)
	return &conf, err
}