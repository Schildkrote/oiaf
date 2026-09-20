// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server           ServerConfig   `yaml:"server"`
	Storage          StorageConfig  `yaml:"storage"`
	Security         SecurityConfig `yaml:"security"`
	WebAuthn         WebAuthnConfig `yaml:"webauthn"`
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
	// Webhooks is the comma-separated list of integration-event subscriber
	// URLs (open-security-platform spine). Empty = no emission (offline).
	Webhooks string `yaml:"webhooks"`
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

// WebAuthnConfig holds the Relying Party settings for the WebAuthn MFA
// factor. RPID is the effective domain (no scheme/port), RPOrigins is a
// comma-separated list of fully qualified origins browsers connect from, and
// RPDisplayName is the human-readable name shown in authenticator prompts.
// Defaults target local development; production must override them via
// config.yaml or OIAF_WEBAUTHN_RP_ID / OIAF_WEBAUTHN_RP_ORIGINS /
// OIAF_WEBAUTHN_RP_DISPLAY_NAME. An empty RPID disables the WebAuthn factor.
type WebAuthnConfig struct {
	RPID          string `yaml:"rp_id"`
	RPDisplayName string `yaml:"rp_display_name"`
	RPOrigins     string `yaml:"rp_origins"`
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
		WebAuthn: WebAuthnConfig{
			RPID:          "localhost",
			RPDisplayName: "OIAF",
			RPOrigins:     "http://localhost:8080",
		},
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
	if v, ok := os.LookupEnv("OIAF_WEBAUTHN_RP_ID"); ok {
		cfg.WebAuthn.RPID = v
	}
	if v, ok := os.LookupEnv("OIAF_WEBAUTHN_RP_DISPLAY_NAME"); ok {
		cfg.WebAuthn.RPDisplayName = v
	}
	if v, ok := os.LookupEnv("OIAF_WEBAUTHN_RP_ORIGINS"); ok {
		cfg.WebAuthn.RPOrigins = v
	}
}

// WebAuthnOrigins splits the comma-separated RPOrigins config into a slice,
// trimming whitespace and dropping empty entries.
func (c *Config) WebAuthnOrigins() []string {
	var origins []string
	for _, o := range strings.Split(c.WebAuthn.RPOrigins, ",") {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	return origins
}

// WebAuthnEnabled reports whether the WebAuthn factor should be wired up. It
// requires both an RP ID and at least one origin.
func (c *Config) WebAuthnEnabled() bool {
	return c.WebAuthn.RPID != "" && len(c.WebAuthnOrigins()) > 0
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
