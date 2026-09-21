// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- dc-agent bearer-token leak regression ----------------------------------
//
// adapters/dc-agent carries its OWN http.Client and never imported
// tools/adapter-sdk, so the SDK redirect fix did not protect it. Independent
// review flagged this after a commit message incorrectly claimed dc-agent was
// covered by that fix.
//
// Flush() and HealthCheck() both set "Authorization: Bearer <adapter token>".
// net/http follows 3xx transparently and strips Authorization only on HOSTNAME
// change — with the port stripped — so a 302 to the same hostname on a
// different port forwarded the token. This ships in tag v0.2.0-mfa.

const dcProbeBearer = "DC-AGENT-BEARER-PROBE-do-not-leak"

// redirectCore stands up an "attacker" listener plus a core that redirects to
// it on the same hostname (httptest binds 127.0.0.1) but a different port.
func redirectCore(t *testing.T, code int) (coreURL string, gotAuth *atomic.Value, hits *int32) {
	t.Helper()
	gotAuth = &atomic.Value{}
	gotAuth.Store("")
	hits = new(int32)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":0,"decisions":[]}`))
	}))
	t.Cleanup(target.Close)

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+r.URL.Path)
		w.WriteHeader(code)
	}))
	t.Cleanup(core.Close)
	return core.URL, gotAuth, hits
}

// discard returns a logger that swallows output; the tests assert on HTTP
// behaviour, not on log text.
func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSenderFlush_NoBearerLeakOnRedirect(t *testing.T) {
	for _, code := range []int{
		http.StatusMovedPermanently,  // 301
		http.StatusFound,             // 302
		http.StatusSeeOther,          // 303
		http.StatusTemporaryRedirect, // 307
		http.StatusPermanentRedirect, // 308
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			coreURL, gotAuth, hits := redirectCore(t, code)
			s := NewSender(coreURL, dcProbeBearer, 10, time.Second, discard())

			s.Flush(context.Background(), []EventRecord{{AccountSID: "S-1"}})

			if got := atomic.LoadInt32(hits); got != 0 {
				t.Errorf("SECURITY: redirect target hit %d time(s) for status %d — Flush must not follow redirects", got, code)
			}
			if v := gotAuth.Load().(string); v != "" {
				t.Errorf("SECURITY: bearer token reached the redirect target: %q", v)
			}
		})
	}
}

func TestSenderHealthCheck_NoBearerLeakOnRedirect(t *testing.T) {
	coreURL, gotAuth, hits := redirectCore(t, http.StatusFound)
	s := NewSender(coreURL, dcProbeBearer, 10, time.Second, discard())

	err := s.HealthCheck(context.Background())
	if err == nil {
		t.Error("expected HealthCheck to fail on a refused redirect")
	}
	if atomic.LoadInt32(hits) != 0 || gotAuth.Load().(string) != "" {
		t.Errorf("SECURITY: HealthCheck followed the redirect (hits=%d auth=%q)",
			atomic.LoadInt32(hits), gotAuth.Load().(string))
	}
}

// TestSenderThreeXXIsNotSuccess pins the status-gate fix. The old
// `>= http.StatusBadRequest` gate counted a 302 as SUCCESS and then decoded its
// empty body, silently dropping the batch's events.
func TestSenderThreeXXIsNotSuccess(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308, 100} {
		if !isNotSuccess(code) {
			t.Errorf("isNotSuccess(%d) = false; a %d response must not count as success", code, code)
		}
	}
	for _, code := range []int{200, 201, 202, 204, 299} {
		if isNotSuccess(code) {
			t.Errorf("isNotSuccess(%d) = true; 2xx must still count as success", code)
		}
	}
	for _, code := range []int{400, 401, 403, 404, 429, 500, 502, 503} {
		if !isNotSuccess(code) {
			t.Errorf("isNotSuccess(%d) = false; %d must be an error", code, code)
		}
	}
}

// TestSenderTwoXXStillWorks guards against over-correction: with the tightened
// gate, a healthy core must still accept batches and report decisions.
func TestSenderTwoXXStillWorks(t *testing.T) {
	var gotAuth string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1,"decisions":[{"account_sid":"S-1","account_name":"corp","decision":"challenge","risk_score":77}]}`))
	}))
	defer core.Close()

	s := NewSender(core.URL, "good-token", 10, time.Second, discard())
	s.Flush(context.Background(), []EventRecord{{AccountSID: "S-1"}})

	if gotAuth != "Bearer good-token" {
		t.Errorf("the legitimate core must still receive the bearer token, got %q", gotAuth)
	}
	if err := s.HealthCheck(context.Background()); err != nil {
		t.Errorf("204 on /healthz must be success, got %v", err)
	}
}

// TestNewSenderTrimsTrailingSlash pins the fix for a 307 footgun: a configured
// base URL with a trailing slash produced "https://core//v1/ad/events", which a
// real reverse proxy answers with a 307 — previously followed, with the token.
func TestNewSenderTrimsTrailingSlash(t *testing.T) {
	var gotPath string
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer core.Close()

	s := NewSender(core.URL+"/", "tok", 10, time.Second, discard())
	s.Flush(context.Background(), []EventRecord{{AccountSID: "S-1"}})

	if gotPath != "/v1/ad/events" {
		t.Errorf("trailing slash in baseURL produced path %q, want /v1/ad/events", gotPath)
	}
	if !strings.HasPrefix(s.baseURL, "http") || strings.HasSuffix(s.baseURL, "/") {
		t.Errorf("baseURL should be trimmed of its trailing slash, got %q", s.baseURL)
	}
}
