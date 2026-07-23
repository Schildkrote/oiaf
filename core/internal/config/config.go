// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server           ServerConfig   `yaml:"server"`
	Storage          StorageConfig  `yaml:"storage"`
	Security         SecurityConfig `yaml:"security"`
	Policy           PolicyConfig   `yaml:"policy"`
	Risk             RiskConfig     `yaml:"risk"`
	AD               ADConfig       `yaml:"ad"`
	allowInsecureDev bool
}

type ServerConfig struct {
	Addr           string `yaml:"addr"`
	LogLevel       string `yaml:"log_level"`
	LogFormat      string `yaml:"log_format"`
	UIEnabled      bool   `yaml:"ui_enabled"`
	MetricsEnabled bool   `yaml:"metrics_enabled"`
	TLSCertFile    string `yaml:"tls_cert_file"`
	TLSKeyFile     string `yaml:"tls_key_file"`
}

type StorageConfig struct {
	Driver string `yaml:"driver"`
}

type SecurityConfig struct {
	ChallengeTTLSeconds      int  `yaml:"challenge_ttl_seconds"`
	TOTPMaxAttempts          int  `yaml:"totp_max_attempts"`
	PushTimestampSkewSeconds int  `yaml:"push_timestamp_skew_seconds"`
	RequireSecureCookies     bool `yaml:"require_secure_cookies"`
}

type PolicyConfig struct {
	DefaultEffect string `yaml:"default_effect"`
}

type RiskConfig struct {
	Thresholds RiskThresholds `yaml:"thresholds"`
}

type RiskThresholds struct {
	Low      int `yaml:"low"`
	Elevated int `yaml:"elevated"`
	High     int `yaml:"high"`
	VeryHigh int `yaml:"very_high"`
}

type ADConfig struct {
	LDAPURL            string `yaml:"ldap_url"`
	BindDN             string `yaml:"bind_dn"`
	BindPassword       string `yaml:"bind_password"`
	BaseDN             string `yaml:"base_dn"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Addr:           "127.0.0.1:8080",
			LogLevel:       "info",
			LogFormat:      "json",
			UIEnabled:      true,
			MetricsEnabled: true,
		},
		Storage: StorageConfig{Driver: "memory"},
		Security: SecurityConfig{
			ChallengeTTLSeconds:      300,
			TOTPMaxAttempts:          5,
			PushTimestampSkewSeconds: 60,
			RequireSecureCookies:     true,
		},
		Policy: PolicyConfig{DefaultEffect: "deny"},
		Risk: RiskConfig{
			Thresholds: RiskThresholds{Low: 24, Elevated: 49, High: 74, VeryHigh: 89},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()

	if path != "" {
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}

	applyEnv(cfg)

	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v, ok := os.LookupEnv("OIAF_LISTEN_ADDR"); ok {
		cfg.Server.Addr = v
	}
	if v, ok := os.LookupEnv("OIAF_LOG_LEVEL"); ok {
		cfg.Server.LogLevel = v
	}
	if v, ok := os.LookupEnv("OIAF_LOG_FORMAT"); ok {
		cfg.Server.LogFormat = v
	}
	if v, ok := os.LookupEnv("OIAF_UI_ENABLED"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Server.UIEnabled = b
		}
	}
	if v, ok := os.LookupEnv("OIAF_METRICS_ENABLED"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Server.MetricsEnabled = b
		}
	}
	if v, ok := os.LookupEnv("OIAF_TLS_CERT_FILE"); ok {
		cfg.Server.TLSCertFile = v
	}
	if v, ok := os.LookupEnv("OIAF_TLS_KEY_FILE"); ok {
		cfg.Server.TLSKeyFile = v
	}
	if _, ok := os.LookupEnv("OIAF_DATABASE_URL"); ok {
		cfg.Storage.Driver = "postgres"
	}
	if v, ok := os.LookupEnv("OIAF_ALLOW_INSECURE_DEV"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.allowInsecureDev = b
		}
	}
	if v, ok := os.LookupEnv("OIAF_AD_LDAP_URL"); ok {
		cfg.AD.LDAPURL = v
	}
	if v, ok := os.LookupEnv("OIAF_AD_BIND_DN"); ok {
		cfg.AD.BindDN = v
	}
	if v, ok := os.LookupEnv("OIAF_AD_BIND_PASSWORD"); ok {
		cfg.AD.BindPassword = v
	}
	if v, ok := os.LookupEnv("OIAF_AD_BASE_DN"); ok {
		cfg.AD.BaseDN = v
	}
}

func (c *Config) AdminToken() string {
	return os.Getenv("OIAF_ADMIN_TOKEN")
}

func (c *Config) AdapterToken() string {
	return os.Getenv("OIAF_ADAPTER_TOKEN")
}

func (c *Config) AllowInsecureDev() bool {
	if v, ok := os.LookupEnv("OIAF_ALLOW_INSECURE_DEV"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return c.allowInsecureDev
}
