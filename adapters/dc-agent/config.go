// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ServerURL        string
	AdapterToken     string
	BatchSize        int
	BatchIntervalSec int
	EventIDs         []int
	InventoryOnStart bool
	LDAPURL          string
	BindDN           string
	BindPassword     string
	BaseDN           string
	EnforcementMode  string
}

func loadConfig() (*Config, error) {
	cfg := &Config{
		ServerURL:        envOr("OIAF_SERVER", "http://127.0.0.1:8080"),
		AdapterToken:     os.Getenv("OIAF_ADAPTER_TOKEN"),
		BatchSize:        envInt("DC_AGENT_BATCH_SIZE", 200),
		BatchIntervalSec: envInt("DC_AGENT_BATCH_INTERVAL", 2),
		EventIDs:         parseEventIDs(envOr("DC_AGENT_EVENT_IDS", "4624,4625,4648,4672,4768,4769,4771,4776")),
		InventoryOnStart: envBool("DC_AGENT_INVENTORY_ON_START", true),
		LDAPURL:          os.Getenv("DC_AGENT_LDAP_URL"),
		BindDN:           os.Getenv("DC_AGENT_LDAP_BIND_DN"),
		BindPassword:     os.Getenv("DC_AGENT_LDAP_BIND_PASSWORD"),
		BaseDN:           os.Getenv("DC_AGENT_LDAP_BASE_DN"),
		EnforcementMode:  envOr("DC_AGENT_ENFORCEMENT_MODE", "monitor"),
	}
	return cfg, nil
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

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func parseEventIDs(s string) []int {
	parts := strings.Split(s, ",")
	ids := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if n, err := strconv.Atoi(p); err == nil {
			ids = append(ids, n)
		}
	}
	return ids
}
