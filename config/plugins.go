package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ferchd/gomta/plugin"
	"gopkg.in/yaml.v3"
)

// PluginConfig is the plugins.yaml document.
type PluginConfig struct {
	Workers int                 `yaml:"workers"`
	Timeout Duration            `yaml:"timeout"`
	Plugins []plugin.Definition `yaml:"plugins"`
}

// LoadPlugins reads and validates the plugin configuration.
func LoadPlugins(path string, baseDir string) (*PluginConfig, error) {
	if path == "" {
		return &PluginConfig{Workers: 8, Timeout: Duration(8_000_000_000)}, nil
	}
	if !filepath.IsAbs(path) && baseDir != "" {
		path = filepath.Join(baseDir, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read plugins config: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(os.ExpandEnv(string(raw))))
	dec.KnownFields(true)
	var cfg PluginConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse plugins config %s: %w", path, err)
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 8
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = Duration(8_000_000_000)
	}
	return &cfg, nil
}
