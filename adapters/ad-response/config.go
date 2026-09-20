// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	ListenAddr   string
	OIAFServer   string
	OIAFToken    string
	LDAPURL      string
	BindDN       string
	BindPassword string
	DryRun       bool
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ListenAddr:   envOr("AD_RESPONSE_LISTEN", ":9090"),
		OIAFServer:   envOr("OIAF_SERVER", "http://127.0.0.1:8080"),
		OIAFToken:    os.Getenv("OIAF_ADAPTER_TOKEN"),
		LDAPURL:      os.Getenv("AD_LDAP_URL"),
		BindDN:       os.Getenv("AD_BIND_DN"),
		BindPassword: os.Getenv("AD_BIND_PASSWORD"),
		DryRun:       envBool("AD_DRY_RUN", true),
	}
	if cfg.LDAPURL == "" {
		return nil, fmt.Errorf("AD_LDAP_URL is required")
	}
	return cfg, nil
}

type DecisionWebhook struct {
	RequestID   string   `json:"request_id"`
	AccountName string   `json:"account_name"`
	AccountSID  string   `json:"account_sid"`
	Decision    string   `json:"decision"`
	RiskScore   int      `json:"risk_score"`
	Reasons     []string `json:"reasons"`
	Action      string   `json:"action"`
}

type ActionResult struct {
	Action  string `json:"action"`
	Account string `json:"account"`
	DryRun  bool   `json:"dry_run"`
	Success bool   `json:"success"`
	Detail  string `json:"detail,omitempty"`
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
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
