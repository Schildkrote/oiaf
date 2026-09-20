// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package config

import "testing"

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
