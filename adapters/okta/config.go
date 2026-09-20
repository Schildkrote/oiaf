// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds all Okta adapter settings. Configuration follows the same
// env-first pattern as the other adapters (adapters/dc-agent): every value can
// come from the environment, with an optional YAML file (OKTA_CONFIG_FILE) as
// a lower-precedence source.
//
// SECURITY: the Okta API token is only ever read from the environment
// (OIAF_OKTA_TOKEN, fallback OKTA_API_TOKEN) or from the YAML config file —
// never from command-line arguments (argv leaks into `ps` and shell history)
// and it is never logged. Config.String() and all error messages deliberately
// exclude the token.
type Config struct {
	// OIAF core sink
	ServerURL    string
	AdapterToken string

	// Okta source
	OktaBaseURL string
	OktaToken   string
	FixtureFile string // when set, events are read from this file (offline mock mode)

	// Polling / pagination
	PollInterval time.Duration
	Timeout      time.Duration
	Limit        int // per-page limit sent to /api/v1/logs (Okta max: 1000)
	MaxPages     int // safety cap on pages followed per poll

	// Detection tuning
	MFAFatigueThreshold int
	MFAFatigueWindow    time.Duration
	MaxTravelSpeedKmh   float64

	// State
	StateFile string

	// Once runs a single poll cycle and exits (useful for cron/dev/CI).
	Once bool
}

// oktaFileConfig mirrors the optional YAML config file. Environment
// variables take precedence over every field here.
type oktaFileConfig struct {
	APIToken            string  `yaml:"api_token"`
	BaseURL             string  `yaml:"base_url"`
	Domain              string  `yaml:"domain"`
	StateFile           string  `yaml:"state_file"`
	PollInterval        string  `yaml:"poll_interval"`
	Limit               int     `yaml:"limit"`
	MaxPages            int     `yaml:"max_pages"`
	MFAFatigueThreshold int     `yaml:"mfa_fatigue_threshold"`
	MFAFatigueWindow    string  `yaml:"mfa_fatigue_window"`
	MaxTravelSpeedKmh   float64 `yaml:"max_travel_speed_kmh"`
}

// loadConfig resolves configuration from env (highest precedence) and the
// optional YAML file. It validates required values but never includes the
// API token in any returned error.
func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerURL:           envOr("OIAF_SERVER", "http://127.0.0.1:8080"),
		AdapterToken:        os.Getenv("OIAF_ADAPTER_TOKEN"),
		OktaToken:           envOr("OIAF_OKTA_TOKEN", os.Getenv("OKTA_API_TOKEN")),
		OktaBaseURL:         strings.TrimSuffix(os.Getenv("OKTA_BASE_URL"), "/"),
		FixtureFile:         os.Getenv("OKTA_FIXTURE_FILE"),
		StateFile:           envOr("OKTA_STATE_FILE", ".oiaf/okta-state.json"),
		PollInterval:        30 * time.Second,
		Timeout:             30 * time.Second,
		Limit:               500,
		MaxPages:            50,
		MFAFatigueThreshold: 3,
		MFAFatigueWindow:    10 * time.Minute,
		MaxTravelSpeedKmh:   900, // roughly commercial-airliner cruise speed
		Once:                envBool("OKTA_ONCE", false),
	}

	// Optional YAML file fills values the environment did not set.
	var fileDomain string
	if path := os.Getenv("OKTA_CONFIG_FILE"); path != "" {
		fc, err := loadConfigFile(path)
		if err != nil {
			return nil, err
		}
		if cfg.OktaToken == "" {
			cfg.OktaToken = fc.APIToken
		}
		if cfg.OktaBaseURL == "" {
			cfg.OktaBaseURL = strings.TrimSuffix(fc.BaseURL, "/")
		}
		fileDomain = fc.Domain
		if os.Getenv("OKTA_STATE_FILE") == "" && fc.StateFile != "" {
			cfg.StateFile = fc.StateFile
		}
		if os.Getenv("OKTA_POLL_INTERVAL") == "" && fc.PollInterval != "" {
			d, err := time.ParseDuration(fc.PollInterval)
			if err != nil {
				return nil, fmt.Errorf("config file poll_interval: %w", err)
			}
			cfg.PollInterval = d
		}
		if os.Getenv("OKTA_LIMIT") == "" && fc.Limit > 0 {
			cfg.Limit = fc.Limit
		}
		if os.Getenv("OKTA_MAX_PAGES") == "" && fc.MaxPages > 0 {
			cfg.MaxPages = fc.MaxPages
		}
		if fc.MFAFatigueThreshold > 0 {
			cfg.MFAFatigueThreshold = fc.MFAFatigueThreshold
		}
		if fc.MFAFatigueWindow != "" {
			d, err := time.ParseDuration(fc.MFAFatigueWindow)
			if err != nil {
				return nil, fmt.Errorf("config file mfa_fatigue_window: %w", err)
			}
			cfg.MFAFatigueWindow = d
		}
		if fc.MaxTravelSpeedKmh > 0 {
			cfg.MaxTravelSpeedKmh = fc.MaxTravelSpeedKmh
		}
	}

	if d, ok := envDuration("OKTA_POLL_INTERVAL"); ok {
		cfg.PollInterval = d
	}
	if d, ok := envDuration("OKTA_TIMEOUT"); ok {
		cfg.Timeout = d
	}
	if v := envInt("OKTA_LIMIT", cfg.Limit); v > 0 {
		cfg.Limit = v
	}
	if v := envInt("OKTA_MAX_PAGES", cfg.MaxPages); v > 0 {
		cfg.MaxPages = v
	}
	if v := envInt("OKTA_MFA_FATIGUE_THRESHOLD", cfg.MFAFatigueThreshold); v > 0 {
		cfg.MFAFatigueThreshold = v
	}
	if d, ok := envDuration("OKTA_MFA_FATIGUE_WINDOW"); ok {
		cfg.MFAFatigueWindow = d
	}
	if v := envFloat("OKTA_MAX_TRAVEL_SPEED_KMH", cfg.MaxTravelSpeedKmh); v > 0 {
		cfg.MaxTravelSpeedKmh = v
	}

	// Okta allows max 1000 events per page.
	if cfg.Limit < 1 {
		cfg.Limit = 1
	}
	if cfg.Limit > 1000 {
		cfg.Limit = 1000
	}
	if cfg.PollInterval < time.Second {
		cfg.PollInterval = time.Second
	}

	// Base URL: explicit OKTA_BASE_URL wins; otherwise derive from domain.
	domain := envOr("OKTA_DOMAIN", fileDomain)
	if cfg.OktaBaseURL == "" && domain != "" {
		domain = strings.TrimSuffix(strings.TrimSpace(domain), "/")
		if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
			cfg.OktaBaseURL = domain
		} else {
			cfg.OktaBaseURL = "https://" + domain
		}
	}

	if cfg.FixtureFile == "" {
		if cfg.OktaToken == "" {
			return nil, errors.New("Okta API token required: set OIAF_OKTA_TOKEN (preferred) or OKTA_API_TOKEN, or api_token in OKTA_CONFIG_FILE; never pass tokens as command-line arguments")
		}
		if cfg.OktaBaseURL == "" {
			return nil, errors.New("Okta base URL required: set OKTA_BASE_URL or OKTA_DOMAIN")
		}
		if !strings.HasPrefix(cfg.OktaBaseURL, "http://") && !strings.HasPrefix(cfg.OktaBaseURL, "https://") {
			return nil, errors.New("OKTA_BASE_URL must include the scheme (https://)")
		}
	}

	return cfg, nil
}

func loadConfigFile(path string) (*oktaFileConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	// Warn (not fail) when the file is group/world readable — it may contain
	// the API token. On Windows the mode bits are mostly meaningless.
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr, "oiaf-okta-adapter: warning: config file %s is readable by group/others; it may contain the API token — chmod 600 recommended\n", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	var fc oktaFileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("config file: %w", err)
	}
	return &fc, nil
}

func (c *Config) signalParams() SignalParams {
	return SignalParams{
		FatigueThreshold:  c.MFAFatigueThreshold,
		FatigueWindow:     c.MFAFatigueWindow,
		MaxTravelSpeedKmh: c.MaxTravelSpeedKmh,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envFloat(key string, fallback float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func envDuration(key string) (time.Duration, bool) {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d, true
		}
	}
	return 0, false
}
