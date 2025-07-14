package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config 包含了 Vyper 客户端的所有配置参数。
// 结构扁平化，符合您期望的风格。
type Config struct {
	// --- 基础连接与核心 Vyper 参数 (您的原始参数) ---
	ServerIP           string `yaml:"server_ip"`           // 必填：Vyper 服务器的 IP 地址或域名
	ServerPort         int    `yaml:"server_port"`         // 必填：Vyper 服务器的端口
	AuthToken          string `yaml:"auth_token"`          // 必填：用于认证的预共享 Auth Token (Base64 编码)
	BufferSize         int    `yaml:"buffer_size"`         // 可选：数据传输缓冲区大小 (字节)
	Timeout            int    `yaml:"timeout"`             // 可选：连接超时时间 (秒)

	// --- Vyper 协议特有参数 ---
	InitialPaddingRule int    `yaml:"initialPaddingRule"`  // 必填：初始填充规则索引 (0-255)
	ClientInfo         string `yaml:"clientInfo"`          // 可选：客户端软件信息字符串

	// --- TLS (传输层安全) 配置 ---
	TLSEnabled         bool   `yaml:"tlsEnabled"`          // 必填：是否启用 TLS (Vyper 协议必须为 true)
	TLSServerName      string `yaml:"tlsServerName"`       // 必填：TLS SNI (Server Name Indication)
	TLSInsecureSkipVerify bool   `yaml:"tlsInsecureSkipVerify"` // 必填：是否跳过服务器证书验证 (生产环境应为 false)
	TLSCACertPath      string `yaml:"tlsCACertPath"`       // 可选：自定义 CA 证书路径 (PEM 格式)
	TLSClientCertPath  string `yaml:"tlsClientCertPath"`   // 可选：客户端 TLS 证书路径 (PEM 格式，如果服务器需要)
	TLSClientKeyPath   string `yaml:"tlsClientKeyPath"`    // 可选：客户端 TLS 私钥路径 (PEM 格式)

	// --- 本地代理监听配置 ---
	ProxyListenAddress string `yaml:"proxyListenAddress"`  // 必填：本地代理监听地址
	ProxyListenPort    int    `yaml:"proxyListenPort"`     // 必填：本地代理监听端口
	ProxyProtocol      string `yaml:"proxyProtocol"`       // 可选：本地代理协议类型 (例如 "socks5", "http")
}

// LoadConfig 读取并解析 config.yaml 文件中的客户端配置。
// 它会在可执行文件目录及其 'config' 子目录中查找 config.yaml。
func LoadConfig() (*Config, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("无法获取可执行文件路径: %w", err)
	}
	execDir := filepath.Dir(execPath)

	// 定义 config.yaml 的可能路径
	configPaths := []string{
		filepath.Join(execDir, "config.yaml"),            // 可执行文件目录下
		filepath.Join(execDir, "config", "config.yaml"), // config/config.yaml
	}

	var data []byte
	var foundPath string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil { // 检查文件是否存在
			data, err = os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("无法读取配置文件 %s: %w", p, err)
			}
			foundPath = p
			break // 找到文件，停止搜索
		}
	}

	if data == nil {
		return nil, fmt.Errorf("在预期位置未找到 config.yaml: %v", configPaths)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("无法解析配置文件 %s: %w", foundPath, err)
	}

	// --- 基本验证和默认值设置 ---
	if cfg.ServerIP == "" || cfg.ServerPort == 0 {
		return nil, fmt.Errorf("缺少 Vyper 服务器连接基本信息 (server_ip, server_port)")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("auth_token 缺失，认证必需")
	}
	if !cfg.TLSEnabled {
		return nil, fmt.Errorf("Vyper 协议必须启用 TLS (tlsEnabled 需为 true)")
	}
	if cfg.TLSServerName == "" && !cfg.TLSInsecureSkipVerify {
		return nil, fmt.Errorf("TLS 已启用但 tlsServerName 缺失，且 tlsInsecureSkipVerify 为 false")
	}
	if cfg.ProxyListenAddress == "" || cfg.ProxyListenPort == 0 {
		return nil, fmt.Errorf("缺少本地代理监听信息 (proxyListenAddress, proxyListenPort)")
	}

	// 设置默认值 (如果未提供)
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 4096 // 默认缓冲区大小为 4096 字节
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 // 默认连接超时为 30 秒
	}

	return &cfg, nil
}
