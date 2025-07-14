package config

import (
	"os"
	"path/filepath"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ServerIP   string `yaml:"server_ip"`
	ServerPort int    `yaml:"server_port"`
	// 其他配置项可以随时添加
	BufferSize int    `yaml:"buffer_size"`
	Timeout    int    `yaml:"timeout"`
	AuthToken  string `yaml:"auth_token"`
	// ...
}

// LoadConfig 在程序当前目录下读取 config.yaml
func LoadConfig() (*Config, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	configPath := filepath.Join(filepath.Dir(execPath), "config", "config.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}
