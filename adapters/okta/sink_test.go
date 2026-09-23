// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestEvaluateSinkPostsToCore verifies the sink uses the existing adapter
// callback pattern (POST /v1/access/evaluate with a Bearer adapter token),
// the same contract adapters/pam and adapters/dc-agent use against OIAF core.
func TestEvaluateSinkPostsToCore(t *testing.T) {
	var (
		mu       sync.Mutex
		gotAuth  string
		gotBody  map[string]any
		gotPath  string
		gotCalls int
	)
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotCalls++
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"decision":   "challenge",
			"risk_score": 88,
			"reasons":    []string{"geo_mismatch"},
		})
	}))
	defer core.Close()

	st := NewState()
	st.Identity("alice@corp.example").Admin = true

	sink := NewEvaluateSink(core.URL, "adapter-tok", 5*time.Second, discardLogger(), st)
	sig := Signal{
		Type: SignalImpossibleTravel, Login: "alice@corp.example",
		Time: baseTime(), IP: "5.6.7.8", Geo: "Lagos, NG",
	}
	if err := sink.Emit(context.Background(), sig); err != nil {
		t.Fatalf("emit: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotCalls != 1 {
		t.Fatalf("expected exactly one evaluate call, got %d", gotCalls)
	}
	if gotPath != "/v1/access/evaluate" {
		t.Fatalf("expected evaluate endpoint, got %q", gotPath)
	}
	if gotAuth != "Bearer adapter-tok" {
		t.Fatalf("expected Bearer adapter token, got %q", gotAuth)
	}
	ident := gotBody["identity"].(map[string]any)
	if ident["username"] != "alice@corp.example" || ident["privileged"] != true {
		t.Fatalf("bad identity mapping: %v", ident)
	}
	src := gotBody["source"].(map[string]any)
	if src["geo"] != "Lagos, NG" || src["ip"] != "5.6.7.8" {
		t.Fatalf("bad source mapping: %v", src)
	}
}

// TestEvaluateSinkCoreError verifies transport/API failures surface as errors
// (the poller relies on this to stop before the cursor advances).
func TestEvaluateSinkCoreError(t *testing.T) {
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer core.Close()

	sink := NewEvaluateSink(core.URL, "bad", time.Second, discardLogger(), NewState())
	err := sink.Emit(context.Background(), Signal{Type: SignalAdminAction, Login: "x@corp.example"})
	if err == nil {
		t.Fatal("expected error on 401 from core")
	}
}

// TestLogSinkWrites verifies the offline fallback sink emits structured logs
// containing the signal data.
//
// NOTE: this test used to sit under a comment claiming it proved the sink
// "never leaks a token". It never did — it only asserted that fields were
// PRESENT, never that a secret was ABSENT. Independent review caught that a
// token injected into an error path left the whole suite green. The real
// negative coverage now lives in leak_test.go (TestNoTokenLeak_*), which
// captures slog, stdout, stderr, the returned error and the state file and
// asserts canary secrets appear in none of them.
func TestLogSinkWrites(t *testing.T) {
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	sink := NewLogSink(logger)
	if err := sink.Emit(context.Background(), Signal{
		Type: SignalLegacyAuth, Login: "u@corp.example", Time: baseTime(),
		Details: map[string]string{"credential_type": "password"},
	}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "legacy_auth") || !strings.Contains(out, "u@corp.example") {
		t.Fatalf("log sink output missing signal data: %q", out)
	}
}

// TestLoadConfigTokenRequired verifies the adapter refuses to run without a
// token (live mode) and that fixture mode needs none. Also checks the error
// message never echoes a token value.
func TestLoadConfigTokenRequired(t *testing.T) {
	// Live mode, no token -> error mentioning env vars, not values.
	t.Setenv("OIAF_OKTA_TOKEN", "")
	t.Setenv("OKTA_API_TOKEN", "")
	t.Setenv("OKTA_FIXTURE_FILE", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error when token missing")
	} else if !strings.Contains(err.Error(), "OIAF_OKTA_TOKEN") {
		t.Fatalf("error should point at the env var: %v", err)
	}

	// Token via env -> accepted; base URL derived from domain.
	t.Setenv("OIAF_OKTA_TOKEN", "tok-123")
	t.Setenv("OKTA_DOMAIN", "acme.okta.com")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("expected valid config: %v", err)
	}
	if cfg.OktaToken != "tok-123" || cfg.OktaBaseURL != "https://acme.okta.com" {
		t.Fatalf("bad config: base=%q token_present=%v", cfg.OktaBaseURL, cfg.OktaToken != "")
	}

	// Fixture mode needs no token at all (offline CI).
	t.Setenv("OIAF_OKTA_TOKEN", "")
	t.Setenv("OKTA_DOMAIN", "")
	t.Setenv("OKTA_FIXTURE_FILE", "fixture.json")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatalf("fixture mode must not require a token: %v", err)
	}
	if cfg.FixtureFile != "fixture.json" {
		t.Fatalf("fixture mode not detected: %+v", cfg)
	}
}

// TestLoadConfigYAMLFile verifies the optional YAML config file supplies the
// token and settings, and env overrides win.
func TestLoadConfigYAMLFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "okta.yaml")
	body := "api_token: yaml-token\nbase_url: https://yaml.okta.com\npoll_interval: 45s\nlimit: 250\nstate_file: /var/lib/oiaf/okta.json\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OKTA_CONFIG_FILE", path)
	t.Setenv("OIAF_OKTA_TOKEN", "")
	t.Setenv("OKTA_API_TOKEN", "")
	t.Setenv("OKTA_BASE_URL", "")
	t.Setenv("OKTA_DOMAIN", "")
	t.Setenv("OKTA_POLL_INTERVAL", "")
	t.Setenv("OKTA_LIMIT", "")
	t.Setenv("OKTA_STATE_FILE", "")
	t.Setenv("OKTA_FIXTURE_FILE", "")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.OktaToken != "yaml-token" || cfg.OktaBaseURL != "https://yaml.okta.com" {
		t.Fatalf("yaml values not applied: %+v", cfg)
	}
	if cfg.PollInterval != 45*time.Second || cfg.Limit != 250 {
		t.Fatalf("yaml tuning not applied: %+v", cfg)
	}
	if cfg.StateFile != "/var/lib/oiaf/okta.json" {
		t.Fatalf("yaml state_file not applied: %+v", cfg)
	}

	// Env beats YAML.
	t.Setenv("OIAF_OKTA_TOKEN", "env-token")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OktaToken != "env-token" {
		t.Fatalf("env should override yaml token")
	}
}

// TestLoadConfigLimitClamped verifies Okta's 1000-event page cap is enforced.
func TestLoadConfigLimitClamped(t *testing.T) {
	t.Setenv("OIAF_OKTA_TOKEN", "tok")
	t.Setenv("OKTA_BASE_URL", "https://acme.okta.com")
	t.Setenv("OKTA_FIXTURE_FILE", "")
	t.Setenv("OKTA_CONFIG_FILE", "")
	t.Setenv("OKTA_LIMIT", "5000")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Limit != 1000 {
		t.Fatalf("expected clamp to 1000, got %d", cfg.Limit)
	}
}
