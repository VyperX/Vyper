package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// ClientConfig holds all configuration parameters for the Vyper client.
type ClientConfig struct {
	Vyper struct {
		ServerAddress    string `yaml:"serverAddress"`
		ServerPort       int    `yaml:"serverPort"`
		AuthToken        string `yaml:"authToken"`
		InitialPaddingRule int    `yaml:"initialPaddingRule"`
		ClientInfo       string `yaml:"clientInfo"`
	} `yaml:"vyper"`
	TLS struct {
		Enabled          bool   `yaml:"enabled"`
		ServerName       string `yaml:"serverName"`
		InsecureSkipVerify bool   `yaml:"insecureSkipVerify"`
		CACertPath       string `yaml:"caCertPath"`
		ClientCertPath   string `yaml:"clientCertPath"`
		ClientKeyPath    string `yaml:"clientKeyPath"`
	} `yaml:"tls"`
	Proxy struct {
		ListenAddress string `yaml:"listenAddress"`
		ListenPort    int    `yaml:"listenPort"`
		Protocol      string `yaml:"protocol"`
	} `yaml:"proxy"`
	// General settings (optional, can be added as needed)
	BufferSize int `yaml:"bufferSize"` // Buffer size for data transfer, e.g., 4096 bytes
	Timeout    int `yaml:"timeout"`    // Connection timeout in seconds, e.g., 30 seconds
}

// LoadClientConfig reads and parses the client configuration from config.yaml.
// It searches for config.yaml in the executable's directory and a 'config' subdirectory.
func LoadClientConfig() (*ClientConfig, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}
	execDir := filepath.Dir(execPath)

	configPaths := []string{
		filepath.Join(execDir, "config.yaml"),            // config.yaml directly in executable dir
		filepath.Join(execDir, "config", "config.yaml"), // config/config.yaml
	}

	var data []byte
	var foundPath string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil {
			data, err = os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file %s: %w", p, err)
			}
			foundPath = p
			break
		}
	}

	if data == nil {
		return nil, fmt.Errorf("config.yaml not found in expected locations: %v", configPaths)
	}

	var cfg ClientConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file %s: %w", foundPath, err)
	}

	// Basic validation (can be expanded)
	if cfg.Vyper.ServerAddress == "" || cfg.Vyper.ServerPort == 0 || cfg.Vyper.AuthToken == "" {
		return nil, fmt.Errorf("missing essential Vyper server connection details (serverAddress, serverPort, authToken)")
	}
	if cfg.TLS.Enabled && cfg.TLS.ServerName == "" {
		return nil, fmt.Errorf("TLS is enabled but serverName is missing")
	}
	if cfg.Proxy.ListenAddress == "" || cfg.Proxy.ListenPort == 0 {
		return nil, fmt.Errorf("missing essential proxy listen details (listenAddress, listenPort)")
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 4096 // Default buffer size
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 // Default timeout in seconds
	}

	return &cfg, nil
}

// Example usage (for demonstration, not part of config.go)
func main() {
	cfg, err := LoadClientConfig()
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Vyper Server: %s:%d\n", cfg.Vyper.ServerAddress, cfg.Vyper.ServerPort)
	fmt.Printf("Proxy Listen: %s:%d\n", cfg.Proxy.ListenAddress, cfg.Proxy.ListenPort)
	fmt.Printf("Auth Token (first 5 chars): %s...\n", cfg.Vyper.AuthToken[:5])
	fmt.Printf("TLS Server Name: %s\n", cfg.TLS.ServerName)
	fmt.Printf("Buffer Size: %d bytes\n", cfg.BufferSize)
	fmt.Printf("Timeout: %d seconds\n", cfg.Timeout)

	// You can then use these values in your client's main logic
	// For example:
	// conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", cfg.Vyper.ServerAddress, cfg.Vyper.ServerPort), &tls.Config{...})
	// ...
	// time.Second * time.Duration(cfg.Timeout)
}
