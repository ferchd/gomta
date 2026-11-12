// Package config loads GoMTA's YAML configuration and policy text files.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ferchd/gomta/plugin"
	"gopkg.in/yaml.v3"
)

// Duration is a YAML duration. Strings use time.ParseDuration; integers are
// seconds.
type Duration time.Duration

// Std returns the standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String implements fmt.Stringer.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Tag == "!!int" {
		n, err := strconv.Atoi(node.Value)
		if err != nil {
			return err
		}
		*d = Duration(time.Duration(n) * time.Second)
		return nil
	}
	v, err := time.ParseDuration(strings.TrimSpace(node.Value))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// Config is the root gomta.yaml document.
type Config struct {
	Hostname    string     `yaml:"hostname"`
	DataDir     string     `yaml:"data_dir"`
	DomainsFile string     `yaml:"domains_file"`
	UsersFile   string     `yaml:"users_file"`
	PluginsFile string     `yaml:"plugins_file"`
	Log         Log        `yaml:"log"`
	Limits      Limits     `yaml:"limits"`
	TLS         TLS        `yaml:"tls"`
	Listeners   []Listener `yaml:"listeners"`
	Routing     Routing    `yaml:"routing"`
	RelayNets   []string   `yaml:"relay_networks"`
	Queue       Queue      `yaml:"queue"`
	StatusAddr  string     `yaml:"status_addr"`

	// BaseDir is the directory containing the config file. Relative paths are
	// resolved against it and exposed to plugins for their own path options.
	BaseDir string `yaml:"-"`
	// Path is the config file that was loaded.
	Path string `yaml:"-"`
}

// Log configures structured logging.
type Log struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text or json
}

// Limits are connection and message limits. Listener-level values override
// these.
type Limits struct {
	MaxMessageBytes         int64    `yaml:"max_message_bytes"`
	MaxDataMemoryBytes      int64    `yaml:"max_data_memory_bytes"`
	MaxRecipients           int      `yaml:"max_recipients"`
	MaxConnections          int      `yaml:"max_connections"`
	MaxConnectionsPerIP     int      `yaml:"max_connections_per_ip"`
	MaxLineLength           int      `yaml:"max_line_length"`
	ReadTimeout             Duration `yaml:"read_timeout"`
	WriteTimeout            Duration `yaml:"write_timeout"`
	IdleTimeout             Duration `yaml:"idle_timeout"`
	MaxAuthFailures         int      `yaml:"max_auth_failures"`
	RequireTLSForAuth       bool     `yaml:"require_tls_for_auth"`
	ValidateLocalRecipients bool     `yaml:"validate_local_recipients"`
}

// TLS configures STARTTLS and implicit-TLS listeners.
type TLS struct {
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	MinVersion   string `yaml:"min_version"` // "1.2" or "1.3"
	AutoGenerate bool   `yaml:"auto_generate"`
}

// Listener is one SMTP endpoint.
type Listener struct {
	Name              string `yaml:"name"`
	Address           string `yaml:"address"`
	Mode              string `yaml:"mode"` // mta, submission, filter
	TLS               string `yaml:"tls"`  // starttls, implicit, none
	RequireAuth       bool   `yaml:"require_auth"`
	AllowInsecureAuth bool   `yaml:"allow_insecure_auth"`
	MaxMessageBytes   int64  `yaml:"max_message_bytes"`
	MaxRecipients     int    `yaml:"max_recipients"`
	Banner            string `yaml:"banner"`
}

// Routing selects delivery backends and upstream relays.
type Routing struct {
	LocalBackend    string         `yaml:"local_backend"`
	LocalOptions    map[string]any `yaml:"local_options"`
	FilterUpstream  string         `yaml:"filter_upstream"`
	FilterOptions   map[string]any `yaml:"filter_options"`
	OutboundBackend string         `yaml:"outbound_backend"`
	OutboundOptions map[string]any `yaml:"outbound_options"`
}

// Queue configures persistent retry delivery.
type Queue struct {
	Dir         string     `yaml:"dir"`
	Workers     int        `yaml:"workers"`
	MaxAttempts int        `yaml:"max_attempts"`
	Retry       []Duration `yaml:"retry_schedule"`
}

// Load reads, expands environment variables in, and validates a config file.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	expanded := os.ExpandEnv(string(raw))
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", abs, err)
	}
	cfg.Path = abs
	cfg.BaseDir = filepath.Dir(abs)
	cfg.applyDefaults()
	if err := cfg.resolvePaths(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", abs, err)
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			c.Hostname = h
		}
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.DomainsFile == "" {
		c.DomainsFile = "domains.txt"
	}
	if c.UsersFile == "" {
		c.UsersFile = "users.txt"
	}
	if c.PluginsFile == "" {
		c.PluginsFile = "plugins.yaml"
	}
	if c.Limits.MaxMessageBytes <= 0 {
		c.Limits.MaxMessageBytes = 25 * 1024 * 1024
	}
	if c.Limits.MaxDataMemoryBytes <= 0 {
		c.Limits.MaxDataMemoryBytes = 128 * 1024 * 1024
	}
	if c.Limits.MaxRecipients <= 0 {
		c.Limits.MaxRecipients = 100
	}
	if c.Limits.MaxConnections <= 0 {
		c.Limits.MaxConnections = 200
	}
	if c.Limits.MaxConnectionsPerIP <= 0 {
		c.Limits.MaxConnectionsPerIP = 20
	}
	if c.Limits.MaxLineLength <= 0 {
		c.Limits.MaxLineLength = 4096
	}
	if c.Limits.ReadTimeout <= 0 {
		c.Limits.ReadTimeout = Duration(5 * time.Minute)
	}
	if c.Limits.WriteTimeout <= 0 {
		c.Limits.WriteTimeout = Duration(5 * time.Minute)
	}
	if c.Limits.IdleTimeout <= 0 {
		c.Limits.IdleTimeout = Duration(5 * time.Minute)
	}
	if c.Limits.MaxAuthFailures <= 0 {
		c.Limits.MaxAuthFailures = 5
	}
	if !c.Limits.RequireTLSForAuth {
		// TLS is still required for AUTH unless a listener explicitly opts into
		// insecure auth on localhost.
		c.Limits.RequireTLSForAuth = true
	}
	if c.TLS.MinVersion == "" {
		c.TLS.MinVersion = "1.2"
	}
	if len(c.Listeners) == 0 {
		c.Listeners = []Listener{
			{Name: "smtp", Address: ":25", Mode: "mta", TLS: "starttls"},
			{Name: "submission", Address: ":587", Mode: "submission", TLS: "starttls", RequireAuth: true},
		}
	}
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if l.Name == "" {
			l.Name = fmt.Sprintf("listener-%d", i+1)
		}
		if l.Mode == "" {
			l.Mode = "mta"
		}
		if l.TLS == "" {
			l.TLS = "starttls"
		}
		if l.Mode == "submission" {
			l.RequireAuth = true
		}
		if l.MaxMessageBytes <= 0 {
			l.MaxMessageBytes = c.Limits.MaxMessageBytes
		}
		if l.MaxRecipients <= 0 {
			l.MaxRecipients = c.Limits.MaxRecipients
		}
	}
	if c.Routing.LocalBackend == "" {
		c.Routing.LocalBackend = "maildir"
	}
	if c.Routing.OutboundBackend == "" {
		c.Routing.OutboundBackend = "smtp"
	}
	if c.Routing.LocalOptions == nil {
		c.Routing.LocalOptions = map[string]any{}
	}
	if c.Routing.OutboundOptions == nil {
		c.Routing.OutboundOptions = map[string]any{}
	}
	if _, ok := c.Routing.LocalOptions["path"]; !ok && c.Routing.LocalBackend == "maildir" {
		c.Routing.LocalOptions["path"] = "mail"
	}
	if c.Queue.Workers <= 0 {
		c.Queue.Workers = 4
	}
	if c.Queue.MaxAttempts <= 0 {
		c.Queue.MaxAttempts = 6
	}
	if len(c.Queue.Retry) == 0 {
		c.Queue.Retry = []Duration{
			Duration(1 * time.Minute),
			Duration(5 * time.Minute),
			Duration(15 * time.Minute),
			Duration(1 * time.Hour),
			Duration(6 * time.Hour),
		}
	}
	if len(c.RelayNets) == 0 {
		c.RelayNets = []string{"127.0.0.1/32", "::1/128"}
	}
}

func (c *Config) resolvePaths() error {
	resolve := func(p string) string {
		if p == "" {
			return p
		}
		p = os.ExpandEnv(p)
		if filepath.IsAbs(p) {
			return filepath.Clean(p)
		}
		return filepath.Clean(filepath.Join(c.BaseDir, p))
	}
	c.DataDir = resolve(c.DataDir)
	c.DomainsFile = resolve(c.DomainsFile)
	c.UsersFile = resolve(c.UsersFile)
	c.PluginsFile = resolve(c.PluginsFile)
	c.TLS.CertFile = resolve(c.TLS.CertFile)
	c.TLS.KeyFile = resolve(c.TLS.KeyFile)
	if c.Queue.Dir == "" {
		c.Queue.Dir = filepath.Join(c.DataDir, "queue")
	} else {
		c.Queue.Dir = resolve(c.Queue.Dir)
	}
	if path, ok := c.Routing.LocalOptions["path"].(string); ok {
		c.Routing.LocalOptions["path"] = resolve(path)
	}
	if c.Routing.FilterOptions == nil {
		c.Routing.FilterOptions = map[string]any{}
	}
	return nil
}

// Validate checks the semantic constraints of a config.
func (c *Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.Hostname) == "" {
		errs = append(errs, errors.New("hostname is required"))
	}
	if c.Log.Format != "text" && c.Log.Format != "json" {
		errs = append(errs, fmt.Errorf("log.format must be text or json, got %q", c.Log.Format))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level must be debug, info, warn or error, got %q", c.Log.Level))
	}
	if c.TLS.MinVersion != "1.2" && c.TLS.MinVersion != "1.3" {
		errs = append(errs, fmt.Errorf("tls.min_version must be 1.2 or 1.3, got %q", c.TLS.MinVersion))
	}
	if c.Limits.MaxMessageBytes < 1024 {
		errs = append(errs, errors.New("limits.max_message_bytes must be at least 1024"))
	}
	if c.Limits.MaxDataMemoryBytes < c.Limits.MaxMessageBytes+1 {
		errs = append(errs, errors.New("limits.max_data_memory_bytes must exceed limits.max_message_bytes"))
	}
	if c.Queue.Workers < 1 {
		errs = append(errs, errors.New("queue.workers must be at least 1"))
	}
	if c.Queue.MaxAttempts < 1 {
		errs = append(errs, errors.New("queue.max_attempts must be at least 1"))
	}
	for _, d := range c.Queue.Retry {
		if d.Std() <= 0 {
			errs = append(errs, fmt.Errorf("queue.retry_schedule values must be positive, got %s", d))
		}
	}
	seenNames := map[string]bool{}
	seenAddr := map[string]bool{}
	for i, l := range c.Listeners {
		prefix := fmt.Sprintf("listener %d (%s)", i+1, l.Name)
		if seenNames[l.Name] {
			errs = append(errs, fmt.Errorf("%s: duplicate name", prefix))
		}
		seenNames[l.Name] = true
		if strings.TrimSpace(l.Address) == "" {
			errs = append(errs, fmt.Errorf("%s: address is required", prefix))
		}
		if !plugin.Mode(l.Mode).Valid() {
			errs = append(errs, fmt.Errorf("%s: invalid mode %q", prefix, l.Mode))
		}
		switch l.TLS {
		case "starttls", "implicit", "none":
		default:
			errs = append(errs, fmt.Errorf("%s: tls must be starttls, implicit or none, got %q", prefix, l.TLS))
		}
		if l.Address != "" && !strings.HasSuffix(l.Address, ":0") {
			if seenAddr[l.Address] {
				errs = append(errs, fmt.Errorf("%s: duplicate address %s", prefix, l.Address))
			}
			seenAddr[l.Address] = true
		}
		if l.AllowInsecureAuth && !strings.HasPrefix(l.Address, "127.") && !strings.HasPrefix(l.Address, "localhost") && !strings.HasPrefix(l.Address, "[::1]") {
			errs = append(errs, fmt.Errorf("%s: allow_insecure_auth is only allowed on a loopback address", prefix))
		}
	}
	for _, n := range c.RelayNets {
		if _, _, err := net.ParseCIDR(n); err != nil {
			if net.ParseIP(n) == nil {
				errs = append(errs, fmt.Errorf("relay_networks: invalid network %q", n))
			}
		}
	}
	if _, err := c.ParseRelayNetworks(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ParseRelayNetworks returns the configured relay ACL as IPNets.
func (c *Config) ParseRelayNetworks() ([]*net.IPNet, error) {
	out := make([]*net.IPNet, 0, len(c.RelayNets))
	for _, raw := range c.RelayNets {
		if ip := net.ParseIP(raw); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("relay_networks: %w", err)
		}
		out = append(out, n)
	}
	return out, nil
}

// BuildTLSMinVersion translates the config string.
func (c *Config) BuildTLSMinVersion() uint16 {
	if c.TLS.MinVersion == "1.3" {
		return 0x0304
	}
	return 0x0303
}

// RelativePath resolves p against the config directory.
func (c *Config) RelativePath(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.BaseDir, p)
}
