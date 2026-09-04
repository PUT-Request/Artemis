package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the static, bootstrap-only configuration read from config.yaml.
// Everything the DNS server manages dynamically (upstreams, special toggle,
// redirects, custom domains) lives in the SQLite DB and is hot-reloaded.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	WebUI    WebUIConfig    `yaml:"webui"`
	DoH      DoHConfig      `yaml:"doh"`
	HTTP     HTTPConfig     `yaml:"http"`
	Database DatabaseConfig `yaml:"database"`
}

type DoHConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

// HTTPConfig drives the single HTTP front that serves URL redirects
// (*.fmhy -> 302), the ".auto" TLD (<site>.auto -> first working mirror) and,
// when ShortTLD is set, base32 short-code decoding (<base32-of-url>.32 -> 302).
// All such names resolve to AnswerIP; one listener on Listen handles them.
type HTTPConfig struct {
	Enabled      bool     `yaml:"enabled"`
	Listen       string   `yaml:"listen"`
	AnswerIP     string   `yaml:"answer_ip"`
	CheckTimeout Duration `yaml:"check_timeout"`
	CacheTTL     Duration `yaml:"cache_ttl"`
	ShortTLD     string   `yaml:"short_tld"`
}

type ServerConfig struct {
	Listen     string   `yaml:"listen"`
	Timeout    Duration `yaml:"timeout"`
	ACL        []string `yaml:"acl"`
	RateLimit  int      `yaml:"rate_limit"`
	DNSCacheTTL Duration `yaml:"dns_cache_ttl"`
}

type WebUIConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type DatabaseConfig struct {
	Path          string `yaml:"path"`
	RetentionDays int    `yaml:"retention_days"`
}

// RedirectConfig describes a "<label>.<domain> -> <target>?query_param=<label>"
// redirect. Persisted in the DB (not config.yaml). The HTTP listener and DNS
// answer IP are global (config.http), not per redirect.
type RedirectConfig struct {
	Domain     string `json:"domain"`
	Target     string `json:"target"`
	QueryParam string `json:"query_param"`
}

// Duration wraps time.Duration so yaml.v3 can parse strings like "5s".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("expected a duration string, got kind %d", value.Kind)
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (c *Config) applyDefaults() {
	if c.Server.Listen == "" {
		c.Server.Listen = "127.0.0.1:53"
	}
	if c.Server.Timeout == 0 {
		c.Server.Timeout = Duration(5 * time.Second)
	}
	if c.Server.RateLimit == 0 {
		c.Server.RateLimit = 1000
	}
	if c.Server.DNSCacheTTL == 0 {
		c.Server.DNSCacheTTL = Duration(60 * time.Second)
	}
	if c.Database.Path == "" {
		c.Database.Path = "artemis.db"
	}
	if c.WebUI.Listen == "" {
		c.WebUI.Listen = "127.0.0.1:8082"
	}
	if c.DoH.Listen == "" {
		c.DoH.Listen = "127.0.0.1:8053"
	}
	if c.DoH.Path == "" {
		c.DoH.Path = "/dns-query"
	}
	// Default HTTP.Enabled before Listen: only auto-enable when the http block
	// was entirely omitted (both Enabled and Listen are zero values). An explicit
	// "enabled: false" with no listen must not be overridden.
	if !c.HTTP.Enabled && c.HTTP.Listen == "" {
		c.HTTP.Enabled = true
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = "127.0.0.1:80"
	}
	if c.HTTP.AnswerIP == "" {
		c.HTTP.AnswerIP = "127.0.0.1"
	}
	if net.ParseIP(c.HTTP.AnswerIP) == nil {
		c.HTTP.AnswerIP = "127.0.0.1"
	}
	if c.HTTP.CheckTimeout == 0 {
		c.HTTP.CheckTimeout = Duration(3 * time.Second)
	}
	if c.HTTP.CacheTTL == 0 {
		c.HTTP.CacheTTL = Duration(60 * time.Second)
	}
	if c.HTTP.ShortTLD == "" {
		c.HTTP.ShortTLD = "ba"
	}
}

func loadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	return cfg, nil
}
