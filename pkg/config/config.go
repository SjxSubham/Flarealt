package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Node     NodeConfig     `yaml:"node"`
	Server   ServerConfig   `yaml:"server"`
	Cache    CacheConfig    `yaml:"cache"`
	Security SecurityConfig `yaml:"security"`
	DNS      DNSConfig      `yaml:"dns"`
	Database DatabaseConfig `yaml:"database"`
	NATS     NATSConfig     `yaml:"nats"`
	Origins  []Origin       `yaml:"origins"`
}

type NodeConfig struct {
	ID         string `yaml:"id"`
	Region     string `yaml:"region"`
	Datacenter string `yaml:"datacenter"`
}

type ServerConfig struct {
	HTTPPort      int    `yaml:"http_port"`
	HTTPSPort     int    `yaml:"https_port"`
	AdminPort     int    `yaml:"admin_port"`
	ReadTimeout   string `yaml:"read_timeout"`
	WriteTimeout  string `yaml:"write_timeout"`
	MaxHeaderSize int    `yaml:"max_header_size"`
}

type CacheConfig struct {
	MaxSize    string `yaml:"max_size"`
	TTLDefault int    `yaml:"ttl_default"`
	RedisURL   string `yaml:"redis_url"`
	RedisDB    int    `yaml:"redis_db"`
}

type SecurityConfig struct {
	DDoSThreshold     int  `yaml:"ddos_threshold"`
	RateLimitDefault  int  `yaml:"rate_limit_default"`
	EnableWAF         bool `yaml:"enable_waf"`
	EnableBotDetect   bool `yaml:"enable_bot_detect"`
	BlockTorNodes     bool `yaml:"block_tor_nodes"`
	ChallengeOnSuspect bool `yaml:"challenge_on_suspect"`
}

type DNSConfig struct {
	ListenPort        int      `yaml:"listen_port"`
	UpstreamResolvers []string `yaml:"upstream_resolvers"`
	EnableGeoDNS      bool     `yaml:"enable_geodns"`
	TTLDefault        int      `yaml:"ttl_default"`
}

type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Database string `yaml:"database"`
	SSLMode  string `yaml:"ssl_mode"`
}

type NATSConfig struct {
	URLs []string `yaml:"urls"`
}

type Origin struct {
	Name     string `yaml:"name"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
	Weight   int    `yaml:"weight"`
	HealthCheck HealthCheck `yaml:"health_check"`
}

type HealthCheck struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
	Timeout  string `yaml:"timeout"`
	Path     string `yaml:"path"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if cfg.Server.ReadTimeout == "" {
		cfg.Server.ReadTimeout = "10s"
	}
	if cfg.Server.WriteTimeout == "" {
		cfg.Server.WriteTimeout = "10s"
	}
	if cfg.Server.MaxHeaderSize == 0 {
		cfg.Server.MaxHeaderSize = 1 << 20 // 1 MB
	}
	if cfg.Cache.TTLDefault == 0 {
		cfg.Cache.TTLDefault = 3600
	}
	if cfg.DNS.TTLDefault == 0 {
		cfg.DNS.TTLDefault = 300
	}

	return &cfg, nil
}

func (c *Config) GetReadTimeout() time.Duration {
	d, _ := time.ParseDuration(c.Server.ReadTimeout)
	return d
}

func (c *Config) GetWriteTimeout() time.Duration {
	d, _ := time.ParseDuration(c.Server.WriteTimeout)
	return d
}
