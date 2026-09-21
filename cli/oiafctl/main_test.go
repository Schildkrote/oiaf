// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// --- oiafctl credential + status-gate tests ---------------------------------
//
// apiDo sends "Authorization: Bearer <admin token>" and, before this test file
// existed, had NO coverage at all. An earlier commit message claimed these
// clients were "pinned" when in fact no test existed — hence this file.
//
// Two properties matter:
//   1. the admin token must never reach a redirect target (net/http strips
//      Authorization only on hostname change, comparing hostnames with the port
//      stripped, so same-host/different-port forwards the credential)
//   2. a refused 3xx must be reported as an ERROR, not as success — the old
//      `>= 400` gate returned nil for a 302, so an admin command that did
//      nothing reported that it succeeded

const ctlProbeToken = "OIAFCTL-ADMIN-PROBE-do-not-leak"

func ctlRedirectTarget(t *testing.T, code int) (coreURL string, gotAuth *atomic.Value, hits *int32) {
	t.Helper()
	gotAuth = &atomic.Value{}
	gotAuth.Store("")
	hits = new(int32)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(target.Close)

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+r.URL.Path)
		w.WriteHeader(code)
	}))
	t.Cleanup(core.Close)
	return core.URL, gotAuth, hits
}

func TestApiDo_NoAdminTokenLeakOnRedirect(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			coreURL, gotAuth, hits := ctlRedirectTarget(t, code)

			var result map[string]interface{}
			err := apiDo(globalOpts{server: coreURL, token: ctlProbeToken},
				http.MethodGet, "/v1/policies", nil, &result)

			if err == nil {
				t.Errorf("status %d must be reported as an error, got nil", code)
			}
			if got := atomic.LoadInt32(hits); got != 0 {
				t.Errorf("SECURITY: redirect target hit %d time(s) for status %d", got, code)
			}
			if v := gotAuth.Load().(string); v != "" {
				t.Errorf("SECURITY: admin token reached the redirect target: %q", v)
			}
		})
	}
}

func TestApiDo_ThreeXXIsNotSuccess(t *testing.T) {
	// A 302 with a JSON body must NOT be decoded and returned as a valid result.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"decision":"allow","policies":999}`))
	}))
	defer core.Close()

	var result map[string]interface{}
	err := apiDo(globalOpts{server: core.URL, token: "tok"},
		http.MethodGet, "/v1/policies", nil, &result)
	if err == nil {
		t.Fatalf("a refused 302 must be an error; got nil with result %v", result)
	}
	if !strings.Contains(err.Error(), "302") {
		t.Errorf("error should name the status code, got %v", err)
	}
}

func TestApiDo_TwoXXStillWorks(t *testing.T) {
	// Positive control: tightening the gate must not break normal CLI use, and
	// the legitimate core must still receive the admin token.
	var gotAuth, gotPath, gotMethod string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decision":"challenge","risk_score":42}`))
	}))
	defer core.Close()

	var result map[string]interface{}
	err := apiDo(globalOpts{server: core.URL + "/", token: "admin-token"},
		http.MethodPost, "/v1/access/evaluate", bytes.NewReader([]byte(`{"x":1}`)), &result)
	if err != nil {
		t.Fatalf("200 must succeed, got %v", err)
	}
	if gotAuth != "Bearer admin-token" {
		t.Errorf("the legitimate core must still receive the admin token, got %q", gotAuth)
	}
	// The trailing slash on server must not produce a double-slash path.
	if gotPath != "/v1/access/evaluate" {
		t.Errorf("path mangled by trailing-slash handling: %q", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method not passed through: %q", gotMethod)
	}
	if result["decision"] != "challenge" {
		t.Errorf("response body not decoded into result: %v", result)
	}
}

func TestApiDo_ServerErrorMessage(t *testing.T) {
	// The >=400 branch formats {"error": ...} specially; verify that survives
	// the gate change and does not dump raw attacker text into the CLI output.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"insufficient scope"}`))
	}))
	defer core.Close()

	err := apiDo(globalOpts{server: core.URL, token: "tok"}, http.MethodGet, "/v1/policies", nil, nil)
	if err == nil {
		t.Fatal("expected an error for 403")
	}
	if !strings.Contains(err.Error(), "insufficient scope") {
		t.Errorf("structured error message not surfaced: %v", err)
	}
}

func TestIsNotSuccess_Oiafctl(t *testing.T) {
	for code, want := range map[int]bool{
		100: true, 199: true,
		200: false, 201: false, 204: false, 299: false,
		301: true, 302: true, 303: true, 307: true, 308: true, 399: true,
		400: true, 401: true, 403: true, 404: true, 429: true,
		500: true, 502: true, 503: true,
	} {
		if got := isNotSuccess(code); got != want {
			t.Errorf("isNotSuccess(%d) = %v, want %v", code, got, want)
		}
	}
}
