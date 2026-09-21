// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWebAuthnDefaults(t *testing.T) {
	cfg := Default()
	if cfg.WebAuthn.RPID != "localhost" {
		t.Fatalf("expected default rp id localhost, got %q", cfg.WebAuthn.RPID)
	}
	if !cfg.WebAuthnEnabled() {
		t.Fatal("expected webauthn enabled by default (localhost dev settings)")
	}
	origins := cfg.WebAuthnOrigins()
	if len(origins) != 1 || origins[0] != "http://localhost:8080" {
		t.Fatalf("unexpected default origins: %v", origins)
	}
}

func TestWebAuthnOriginsParsing(t *testing.T) {
	cfg := Default()
	cfg.WebAuthn.RPOrigins = " https://a.example.com , https://b.example.com ,, "
	origins := cfg.WebAuthnOrigins()
	if len(origins) != 2 {
		t.Fatalf("expected 2 origins, got %d: %v", len(origins), origins)
	}
	if origins[0] != "https://a.example.com" || origins[1] != "https://b.example.com" {
		t.Fatalf("unexpected origins: %v", origins)
	}
}

func TestWebAuthnDisabledWithoutRPID(t *testing.T) {
	cfg := Default()
	cfg.WebAuthn.RPID = ""
	if cfg.WebAuthnEnabled() {
		t.Fatal("expected webauthn disabled without rp id")
	}
	cfg = Default()
	cfg.WebAuthn.RPOrigins = ""
	if cfg.WebAuthnEnabled() {
		t.Fatal("expected webauthn disabled without origins")
	}
}

func TestWebAuthnEnvOverrides(t *testing.T) {
	t.Setenv("OIAF_WEBAUTHN_RP_ID", "sso.example.com")
	t.Setenv("OIAF_WEBAUTHN_RP_ORIGINS", "https://sso.example.com,https://admin.example.com")
	t.Setenv("OIAF_WEBAUTHN_RP_DISPLAY_NAME", "Example SSO")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WebAuthn.RPID != "sso.example.com" {
		t.Fatalf("expected env rp id, got %q", cfg.WebAuthn.RPID)
	}
	if cfg.WebAuthn.RPDisplayName != "Example SSO" {
		t.Fatalf("expected env display name, got %q", cfg.WebAuthn.RPDisplayName)
	}
	origins := cfg.WebAuthnOrigins()
	if len(origins) != 2 || origins[0] != "https://sso.example.com" || origins[1] != "https://admin.example.com" {
		t.Fatalf("unexpected origins: %v", origins)
	}
}

func TestWebAuthnRequireUserVerificationDefaultsFalse(t *testing.T) {
	cfg := Default()
	if cfg.WebAuthn.RequireUserVerification {
		t.Fatal("require_user_verification must default to false (WebAuthn 'preferred')")
	}
}

func TestWebAuthnRequireUserVerificationYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "webauthn:\n" +
		"  rp_id: sso.example.com\n" +
		"  rp_origins: https://sso.example.com\n" +
		"  require_user_verification: true\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WebAuthn.RequireUserVerification {
		t.Fatal("expected require_user_verification=true from YAML")
	}
}

func TestWebAuthnRequireUserVerificationEnvOverride(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"1", true},
		{"TRUE", true},
		{"  true  ", true}, // surrounding whitespace tolerated
		{"false", false},
		{"0", false},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			t.Setenv("OIAF_WEBAUTHN_REQUIRE_USER_VERIFICATION", tc.value)
			cfg, err := Load("")
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.value, err)
			}
			if cfg.WebAuthn.RequireUserVerification != tc.want {
				t.Fatalf("value %q: got %v, want %v", tc.value, cfg.WebAuthn.RequireUserVerification, tc.want)
			}
		})
	}
}

// A typo in a security-relevant switch must fail startup rather than silently
// leaving user verification unenforced while the operator believes it is on.
func TestWebAuthnRequireUserVerificationEnvRejectsGarbage(t *testing.T) {
	for _, value := range []string{"yes", "enable", "ture", "2", "maybe"} {
		t.Run("value="+value, func(t *testing.T) {
			t.Setenv("OIAF_WEBAUTHN_REQUIRE_USER_VERIFICATION", value)
			cfg, err := Load("")
			if err == nil {
				t.Fatalf("expected an error for %q, got cfg=%+v", value, cfg.WebAuthn)
			}
			if cfg != nil {
				t.Fatalf("expected nil config on parse failure, got %+v", cfg)
			}
			if !strings.Contains(err.Error(), "OIAF_WEBAUTHN_REQUIRE_USER_VERIFICATION") {
				t.Fatalf("error should name the offending variable, got: %v", err)
			}
		})
	}
}
