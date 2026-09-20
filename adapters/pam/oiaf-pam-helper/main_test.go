// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withPAMEnv sets the PAM environment a pam_exec invocation would carry,
// plus OIAF connection settings pointed at the given server.
func withPAMEnv(t *testing.T, serverURL string) {
	t.Helper()
	t.Setenv("PAM_USER", "alice")
	t.Setenv("PAM_SERVICE", "sshd")
	t.Setenv("PAM_TYPE", "auth")
	t.Setenv("PAM_RHOST", "")
	t.Setenv("PAM_TTY", "")
	t.Setenv("OIAF_SERVER", serverURL)
	t.Setenv("OIAF_ADAPTER_TOKEN", "test-adapter-token")
	t.Setenv("OIAF_PAM_TIMEOUT", "2")
	t.Setenv("OIAF_PAM_FAIL_OPEN", "")
	t.Setenv("OIAF_PAM_TOTP_FILE", "")
}

func testConfig(t *testing.T, serverURL string) *config {
	t.Helper()
	withPAMEnv(t, serverURL)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	return cfg
}

func newTestServer(t *testing.T, evaluateBody string, verifyBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/access/evaluate":
			fmt.Fprint(w, evaluateBody)
		case strings.HasPrefix(r.URL.Path, "/v1/challenge/") && strings.HasSuffix(r.URL.Path, "/verify"):
			fmt.Fprint(w, verifyBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRunAllows(t *testing.T) {
	srv := newTestServer(t, `{"request_id":"r1","decision":"allow","risk_score":10,"reasons":["policy allow"]}`, "")
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	if code := run(context.Background(), cfg); code != exitSuccess {
		t.Fatalf("expected exit 0, got %d", code)
	}
}

func TestRunDenies(t *testing.T) {
	srv := newTestServer(t, `{"request_id":"r2","decision":"deny","risk_score":90,"reasons":["risk"]}`, "")
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	if code := run(context.Background(), cfg); code != exitAuthErr {
		t.Fatalf("expected exit 7, got %d", code)
	}
}

func TestRunAlertIsAllow(t *testing.T) {
	srv := newTestServer(t, `{"request_id":"r3","decision":"alert","risk_score":40,"reasons":["odd-hour"]}`, "")
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	if code := run(context.Background(), cfg); code != exitSuccess {
		t.Fatalf("expected exit 0 for alert, got %d", code)
	}
}

func TestRunChallengeApproved(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	totpFile := filepath.Join(t.TempDir(), "totp-secret")
	if err := os.WriteFile(totpFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	approve := true
	var verifyCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/access/evaluate":
			fmt.Fprint(w, `{"request_id":"r4","decision":"challenge","risk_score":50,"reasons":["policy"],`+
				`"challenge":{"id":"ch-1","methods":["totp"],"expires_at":"2026-01-01T00:00:00Z"}}`)
		case strings.HasSuffix(r.URL.Path, "/verify"):
			verifyCalls++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["method"] != "totp" || body["code"] == "" {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"error":"bad verify body"}`)
				return
			}
			status := "approved"
			if !approve {
				status = "failed"
			}
			fmt.Fprintf(w, `{"id":"ch-1","status":"%s"}`, status)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := testConfig(t, srv.URL)
	cfg.totpFile = totpFile
	if code := run(context.Background(), cfg); code != exitSuccess {
		t.Fatalf("expected exit 0 for approved challenge, got %d", code)
	}
	if verifyCalls != 1 {
		t.Fatalf("expected 1 verify call, got %d", verifyCalls)
	}
}

func TestRunChallengeRejected(t *testing.T) {
	totpFile := filepath.Join(t.TempDir(), "totp-secret")
	if err := os.WriteFile(totpFile, []byte("JBSWY3DPEHPK3PXP"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := newTestServer(t,
		`{"request_id":"r5","decision":"challenge","risk_score":50,"challenge":{"id":"ch-2","methods":["totp"]}}`,
		`{"id":"ch-2","status":"failed"}`)
	defer srv.Close()
	cfg := testConfig(t, srv.URL)
	cfg.totpFile = totpFile
	if code := run(context.Background(), cfg); code != exitAuthErr {
		t.Fatalf("expected exit 7 for rejected challenge, got %d", code)
	}
}

func TestRunFailClosedWhenServerDown(t *testing.T) {
	srv := newTestServer(t, `{"decision":"allow"}`, "")
	srv.Close() // server is up at test time; now down
	cfg := testConfig(t, srv.URL)
	if code := run(context.Background(), cfg); code != exitSysErr {
		t.Fatalf("expected fail-closed exit 8, got %d", code)
	}
}

func TestRunFailOpenWhenServerDown(t *testing.T) {
	srv := newTestServer(t, `{"decision":"allow"}`, "")
	srv.Close()
	cfg := testConfig(t, srv.URL)
	t.Setenv("OIAF_PAM_FAIL_OPEN", "true")
	cfg.failOpen = true
	if code := run(context.Background(), cfg); code != exitSuccess {
		t.Fatalf("expected fail-open exit 0, got %d", code)
	}
}

func TestRunNoTokenFailsClosed(t *testing.T) {
	withPAMEnv(t, "http://127.0.0.1:1")
	t.Setenv("OIAF_ADAPTER_TOKEN", "")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	cfg.failOpen = false
	if code := run(context.Background(), cfg); code != exitSysErr {
		t.Fatalf("expected exit 8 without token, got %d", code)
	}
}

func TestRunSkipsNonAuthPAMTypes(t *testing.T) {
	withPAMEnv(t, "http://127.0.0.1:1") // server never used
	t.Setenv("PAM_TYPE", "session")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if code := run(context.Background(), cfg); code != exitSuccess {
		t.Fatalf("expected exit 0 for session PAM type, got %d", code)
	}
}

func TestLoadConfigMissingUser(t *testing.T) {
	t.Setenv("PAM_USER", "")
	t.Setenv("PAM_SERVICE", "sshd")
	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error when PAM_USER is empty")
	}
}

func TestBuildRequestSudoIsHighSensitivity(t *testing.T) {
	cfg := &config{user: "alice", service: "sudo"}
	req := buildRequest(cfg)
	res, _ := req["resource"].(map[string]interface{})
	if res["sensitivity"] != "high" {
		t.Fatalf("expected high sensitivity for sudo, got %v", res["sensitivity"])
	}
	if res["name"] != "sudo" {
		t.Fatalf("expected resource name sudo, got %v", res["name"])
	}
}

func TestBuildRequestDefaultMedium(t *testing.T) {
	cfg := &config{user: "alice", service: "sshd"}
	req := buildRequest(cfg)
	res, _ := req["resource"].(map[string]interface{})
	if res["sensitivity"] != "medium" {
		t.Fatalf("expected medium sensitivity for sshd, got %v", res["sensitivity"])
	}
	ident, _ := req["identity"].(map[string]interface{})
	if ident["username"] != "alice" {
		t.Fatalf("expected username alice, got %v", ident["username"])
	}
}

func TestBuildRequestForwardsGroups(t *testing.T) {
	cfg := &config{user: "alice", service: "ssh", groups: []string{"users", "Admins"}}
	req := buildRequest(cfg)
	ident, _ := req["identity"].(map[string]interface{})
	groups, ok := ident["groups"].([]string)
	if !ok {
		t.Fatalf("expected groups in identity, got %T", ident["groups"])
	}
	if len(groups) != 2 || groups[0] != "users" || groups[1] != "Admins" {
		t.Fatalf("unexpected groups: %v", groups)
	}
}

func TestBuildRequestOmitsGroupsWhenUnknown(t *testing.T) {
	cfg := &config{user: "alice", service: "ssh"}
	req := buildRequest(cfg)
	ident, _ := req["identity"].(map[string]interface{})
	if _, ok := ident["groups"]; ok {
		t.Fatal("expected no groups key when groups are unknown")
	}
}

func TestLoadConfigParsesGroups(t *testing.T) {
	t.Setenv("PAM_USER", "alice")
	t.Setenv("PAM_SERVICE", "ssh")
	t.Setenv("OIAF_PAM_GROUPS", "users, Admins ,dev")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	want := []string{"users", "Admins", "dev"}
	if len(cfg.groups) != len(want) {
		t.Fatalf("expected %v, got %v", want, cfg.groups)
	}
	for i := range want {
		if cfg.groups[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, cfg.groups)
		}
	}
}

func TestOpenTTYIgnoresNull(t *testing.T) {
	if f := openTTY("/dev/null"); f != nil {
		f.Close()
		t.Fatal("expected nil for /dev/null")
	}
	if f := openTTY(""); f != nil {
		f.Close()
		t.Fatal("expected nil for empty path")
	}
}
