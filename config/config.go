package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration parameters for the Vyper client.
// It uses a flat structure as preferred.
type Config struct {
	// --- Vyper Protocol Core Settings ---
	ServerAddress      string `yaml:"serverAddress"`       // Vyper server address (domain or IP)
	ServerPort         int    `yaml:"serverPort"`          // Vyper server port
	AuthToken          string `yaml:"authToken"`           // Pre-shared authentication token (Base64 encoded)
	InitialPaddingRule int    `yaml:"initialPaddingRule"`  // Initial padding rule index (0-255)
	ClientInfo         string `yaml:"clientInfo"`          // Optional client software info string

	// --- TLS Settings ---
	TLSEnabled         bool   `yaml:"tlsEnabled"`          // Whether TLS is enabled (must be true for Vyper)
	TLSServerName      string `yaml:"tlsServerName"`       // TLS SNI (Server Name Indication)
	TLSInsecureSkipVerify bool   `yaml:"tlsInsecureSkipVerify"` // Whether to skip server certificate verification
	TLSCACertPath      string `yaml:"tlsCACertPath"`       // Path to custom CA cert bundle for verification
	TLSClientCertPath  string `yaml:"tlsClientCertPath"`   // Path to client's TLS certificate
	TLSClientKeyPath   string `yaml:"tlsClientKeyPath"`    // Path to client's TLS private key

	// --- Local Proxy Listener Settings ---
	ProxyListenAddress string `yaml:"proxyListenAddress"`  // Local address for proxy listener
	ProxyListenPort    int    `yaml:"proxyListenPort"`     // Local port for proxy listener
	ProxyProtocol      string `yaml:"proxyProtocol"`       // Type of local proxy protocol (e.g., "socks5", "http")

	// --- General/Utility Settings ---
	BufferSize         int    `yaml:"bufferSize"`          // Buffer size for data transfer in bytes
	Timeout            int    `yaml:"timeout"`             // Connection timeout in seconds
}

// LoadConfig reads and parses the client configuration from config.yaml.
// It searches for config.yaml in the executable's directory and a 'config' subdirectory.
func LoadConfig() (*Config, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)

	// Define potential paths for config.yaml
	configPaths := []string{
		filepath.Join(execDir, "config.yaml"),            // config.yaml directly in executable dir
		filepath.Join(execDir, "config", "config.yaml"), // config/config.yaml
	}

	var data []byte
	var foundPath string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil { // Check if file exists
			data, err = os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file %s: %w", p, err)
			}
			foundPath = p
			break // Found the file, stop searching
		}
	}

	if data == nil {
		return nil, fmt.Errorf("config.yaml not found in expected locations: %v", configPaths)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file %s: %w", foundPath, err)
	}

	// --- Basic Validation and Default Values ---
	if cfg.ServerAddress == "" || cfg.ServerPort == 0 {
		return nil, fmt.Errorf("missing essential Vyper server connection details (serverAddress, serverPort)")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("authToken is missing, which is required for authentication")
	}
	if !cfg.TLSEnabled {
		return nil, fmt.Errorf("TLS must be enabled for Vyper protocol")
	}
	if cfg.TLSServerName == "" && !cfg.TLSInsecureSkipVerify {
		return nil, fmt.Errorf("TLS is enabled but tlsServerName is missing and tlsInsecureSkipVerify is false")
	}
	if cfg.ProxyListenAddress == "" || cfg.ProxyListenPort == 0 {
		return nil, fmt.Errorf("missing essential proxy listen details (proxyListenAddress, proxyListenPort)")
	}

	// Set defaults if not provided
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 4096 // Default buffer size in bytes
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 // Default connection timeout in seconds
	}

	return &cfg, nil
}
