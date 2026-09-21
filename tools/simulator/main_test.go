// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// --- simulator credential + status-gate tests -------------------------------
//
// apiCall sends "Authorization: Bearer <adapter token>" and, before this file
// existed, had NO coverage at all. An earlier commit message claimed these
// clients were "pinned" when no test existed — hence this file.
//
// cmdApprovePush reports success based on apiCall's error, so a refused 3xx
// returning nil would make the simulator print a successful push approval for a
// request that never reached the server.

const simProbeToken = "SIMULATOR-BEARER-PROBE-do-not-leak"

func simRedirectTarget(t *testing.T, code int) (coreURL string, gotAuth *atomic.Value, hits *int32) {
	t.Helper()
	gotAuth = &atomic.Value{}
	gotAuth.Store("")
	hits = new(int32)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"approved"}`))
	}))
	t.Cleanup(target.Close)

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+r.URL.Path)
		w.WriteHeader(code)
	}))
	t.Cleanup(core.Close)
	return core.URL, gotAuth, hits
}

func TestApiCall_NoBearerLeakOnRedirect(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			coreURL, gotAuth, hits := simRedirectTarget(t, code)

			_, err := apiCall(coreURL, simProbeToken, http.MethodPost, "/v1/push/approve", nil)
			if err == nil {
				t.Errorf("status %d must be reported as an error, got nil", code)
			}
			if got := atomic.LoadInt32(hits); got != 0 {
				t.Errorf("SECURITY: redirect target hit %d time(s) for status %d", got, code)
			}
			if v := gotAuth.Load().(string); v != "" {
				t.Errorf("SECURITY: bearer token reached the redirect target: %q", v)
			}
		})
	}
}

func TestApiCall_ThreeXXIsNotSuccess(t *testing.T) {
	// A 302 carrying a plausible success body must not be returned as one.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`{"status":"approved","risk_score":0}`))
	}))
	defer core.Close()

	result, err := apiCall(core.URL, "tok", http.MethodPost, "/v1/push/approve", nil)
	if err == nil {
		t.Fatalf("a refused 302 must be an error; got nil with result %v", result)
	}
	if result != nil {
		t.Errorf("no result should be returned for a refused redirect, got %v", result)
	}
	if !strings.Contains(err.Error(), "302") {
		t.Errorf("error should name the status code, got %v", err)
	}
}

func TestApiCall_TwoXXStillWorks(t *testing.T) {
	// Positive control: tightening the gate must not break normal use, and the
	// legitimate core must still receive the bearer token.
	var gotAuth, gotPath string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"approved","risk_score":12}`))
	}))
	defer core.Close()

	result, err := apiCall(core.URL+"/", "adapter-token", http.MethodPost, "/v1/push/approve", nil)
	if err != nil {
		t.Fatalf("200 must succeed, got %v", err)
	}
	if gotAuth != "Bearer adapter-token" {
		t.Errorf("the legitimate core must still receive the bearer token, got %q", gotAuth)
	}
	if gotPath != "/v1/push/approve" {
		t.Errorf("path mangled by trailing-slash handling: %q", gotPath)
	}
	if result["status"] != "approved" {
		t.Errorf("response body not decoded: %v", result)
	}
}

func TestIsNotSuccess_Simulator(t *testing.T) {
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
