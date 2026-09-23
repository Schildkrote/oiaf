// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"strings"
	"testing"
)

// TestLoadConfig_RejectsPlaintextNonLoopback pins the http:// rejection in
// loadConfig. Independent review mutation-tested this: replacing isLoopbackHost
// with a sloppy substring check (strings.Contains(host, "localhost")) left the
// ENTIRE suite green while loadConfig happily accepted http://localhost.evil.com
// — which would put the SSWS token on the wire in plaintext. Without this test
// the guard can silently degrade.
func TestLoadConfig_RejectsPlaintextNonLoopback(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"lookalike subdomain", "http://localhost.evil.example"},
		{"lookalike IP suffix", "http://127.0.0.1.evil.example"},
		{"plain remote host", "http://tenant-1.okta.com"},
		{"zero address", "http://0.0.0.0:8080"},
		{"shorthand loopback lookalike", "http://127.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OKTA_BASE_URL", tt.url)
			t.Setenv("OIAF_OKTA_TOKEN", "test-token")
			t.Setenv("OKTA_API_TOKEN", "")
			t.Setenv("OIAF_ADAPTER_TOKEN", "")
			t.Setenv("OKTA_CONFIG_FILE", "")
			if cfg, err := loadConfig(); err == nil {
				t.Errorf("expected %q to be rejected (plaintext to a non-loopback host), got accepted with base %q", tt.url, cfg.OktaBaseURL)
			} else if !strings.Contains(err.Error(), "https") && !strings.Contains(err.Error(), "plaintext") {
				t.Errorf("rejection reason should mention https/plaintext, got %v", err)
			}
		})
	}

	// Positive control: genuine loopback http must still be accepted, so the
	// test cannot pass by rejecting everything.
	for _, ok := range []string{"http://127.0.0.1:8080", "http://localhost:3000", "http://[::1]:8080"} {
		t.Setenv("OKTA_BASE_URL", ok)
		t.Setenv("OIAF_OKTA_TOKEN", "test-token")
		t.Setenv("OKTA_API_TOKEN", "")
		t.Setenv("OIAF_ADAPTER_TOKEN", "")
		t.Setenv("OKTA_CONFIG_FILE", "")
		if _, err := loadConfig(); err != nil {
			t.Errorf("loopback %q must be accepted for httptest, got %v", ok, err)
		}
	}
}
