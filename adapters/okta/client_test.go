// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mustEvent(t *testing.T, uuid, eventType string, published time.Time) LogEvent {
	t.Helper()
	return LogEvent{
		UUID:      uuid,
		Published: published,
		EventType: eventType,
	}
}

// TestFetchLogsPagination verifies the client follows rel="next" Link headers
// across pages, requests with the SSWS auth header, and stops when the Link
// header is absent.
func TestFetchLogsPagination(t *testing.T) {
	var gotAuth []string
	var pages atomic.Int32

	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/logs" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("adapter must be read-only: got %s", r.Method)
		}
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))

		page := int(pages.Add(1))
		w.Header().Set("Content-Type", "application/json")
		if page < 3 {
			w.Header().Set("Link", `<`+"http://"+r.Host+`/api/v1/logs?after=`+string(rune('0'+page))+`>; rel="next"`)
		}
		events := []LogEvent{
			mustEvent(t, string(rune('a'+page))+"-1", "user.session.start", base.Add(time.Duration(page)*time.Minute)),
			mustEvent(t, string(rune('a'+page))+"-2", "user.session.start", base.Add(time.Duration(page)*time.Minute+time.Second)),
		}
		json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	events, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 2})
	if err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if len(events) != 6 {
		t.Fatalf("expected 6 events across 3 pages, got %d", len(events))
	}
	if int(pages.Load()) != 3 {
		t.Fatalf("expected 3 page fetches, got %d", pages.Load())
	}
	for _, a := range gotAuth {
		if a != "SSWS test-token" {
			t.Fatalf("expected SSWS auth header, got %q", a)
		}
	}
}

// TestFetchLogsMaxPages verifies the page cap returns partial results with
// ErrTooManyPages so the poller can checkpoint instead of looping forever.
func TestFetchLogsMaxPages(t *testing.T) {
	// The server always advertises a next page, so the ONLY thing that can stop
	// the loop is the MaxPages cap. Two guards make a removed cap fail fast
	// instead of hanging CI until the job times out:
	//   1. a context deadline, so FetchLogs returns an error rather than looping
	//   2. a request counter asserted against MaxPages, which proves the CAP
	//      stopped the loop and not the deadline
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.Header().Set("Link", "<http://"+r.Host+`/api/v1/logs?after=x>; rel="next"`)
		json.NewEncoder(w).Encode([]LogEvent{mustEvent(t, "e1", "user.session.start", time.Now())})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	events, err := c.FetchLogs(ctx, FetchLogsParams{Limit: 1, MaxPages: 2})
	if !errors.Is(err, ErrTooManyPages) {
		t.Fatalf("expected ErrTooManyPages, got %v (the MaxPages cap did not stop the loop)", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 partial events, got %d", len(events))
	}
	// Exactly MaxPages fetches: the cap, not the deadline, terminated the loop.
	if got := atomic.LoadInt32(&requests); got != 2 {
		t.Errorf("expected exactly 2 page fetches (MaxPages), got %d — the cap is not bounding the loop", got)
	}
}

// TestFetchLogsSinceUntilParams verifies the cursor is translated into Okta's
// since/until query parameters.
func TestFetchLogsSinceUntilParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	since := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	until := time.Date(2026, 9, 1, 13, 0, 0, 0, time.UTC)
	c := NewClient(srv.URL, "test-token", 5*time.Second)
	if _, err := c.FetchLogs(context.Background(), FetchLogsParams{Since: since, Until: until, Limit: 100}); err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	// since is stepped 1ms back (Okta 'since' is exclusive; the poller dedupes
	// by UUID), until is passed through, and sort order must be ascending.
	if !strings.Contains(gotQuery, "since=2026-09-01T11%3A59%3A59.999Z") {
		t.Errorf("expected since stepped 1ms back, got query %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "until=2026-09-01T13%3A00%3A00Z") {
		t.Errorf("expected until param, got query %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "sortOrder=ASCENDING") {
		t.Errorf("expected ascending sort, got query %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "limit=100") {
		t.Errorf("expected limit param, got query %q", gotQuery)
	}
}

// TestFetchLogsAuthFailure verifies 401/403 responses fail immediately with
// ErrAuth (no retry storm) and that the token never leaks into the error.
func TestFetchLogsAuthFailure(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(code)
			w.Write([]byte(`{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`))
		}))

		c := NewClient(srv.URL, "super-secret-token", 5*time.Second)
		c.maxBackoff = 10 * time.Millisecond
		_, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 10})
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("status %d: expected ErrAuth, got %v", code, err)
		}
		if calls.Load() != 1 {
			t.Fatalf("status %d: auth failures must not be retried, got %d calls", code, calls.Load())
		}
		if strings.Contains(err.Error(), "super-secret-token") {
			t.Fatalf("status %d: token leaked into error: %v", code, err)
		}
		srv.Close()
	}
}

// TestFetchLogsRateLimitBackoff verifies 429 responses are retried (honoring
// Retry-After) and eventually succeed.
func TestFetchLogsRateLimitBackoff(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		json.NewEncoder(w).Encode([]LogEvent{mustEvent(t, "e1", "user.session.start", time.Now())})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	c.maxBackoff = 50 * time.Millisecond
	events, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 10})
	if err != nil {
		t.Fatalf("FetchLogs after 429s: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if n := calls.Load(); n != 3 {
		t.Fatalf("expected 3 calls (2x429 + success), got %d", n)
	}
}

// TestFetchLogsServerErrorRetry verifies transient 5xx responses are retried.
func TestFetchLogsServerErrorRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("[]"))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	c.maxBackoff = 20 * time.Millisecond
	if _, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 10}); err != nil {
		t.Fatalf("FetchLogs: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected retry after 503, got %d calls", calls.Load())
	}
}

// TestFetchLogsRetriesExhausted verifies the client gives up with an error
// after maxAttempts transient failures.
func TestFetchLogsRetriesExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	c.maxBackoff = 5 * time.Millisecond
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 10})
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if !strings.Contains(err.Error(), "giving up after retries") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestNextLink covers Link-header parsing, including absent, self-only, and
// multi-relation headers.
func TestNextLink(t *testing.T) {
	cases := []struct {
		header string
		want   string
	}{
		{"", ""},
		{`<https://x.okta.com/api/v1/logs?after=abc>; rel="self"`, ""},
		{`<https://x.okta.com/api/v1/logs?after=abc>; rel="next"`, "https://x.okta.com/api/v1/logs?after=abc"},
		{`<https://x/api/v1/logs?a=1>; rel="self", <https://x/api/v1/logs?after=2>; rel="next"`, "https://x/api/v1/logs?after=2"},
		{`<https://x/next>; rel="next", <https://x/self>; rel="self"`, "https://x/next"},
	}
	for _, tc := range cases {
		if got := nextLink(tc.header); got != tc.want {
			t.Errorf("nextLink(%q) = %q, want %q", tc.header, got, tc.want)
		}
	}
}

// --- Pagination credential-leak tests --------------------------------------
// Regression coverage for a token-exfiltration path found in independent
// review: doFetchPage attaches the SSWS Authorization header to whatever URL
// it is handed, and the next-page URL came straight from the remote response's
// Link header. A compromised or misconfigured endpoint could therefore point
// pagination at an attacker host and collect the API token. These tests must
// fail if the host/scheme validation is removed.

// sentinelToken is distinctive so that asserting it never appears in a request
// to the wrong host is unambiguous.
const sentinelToken = "SSWS-SENTINEL-TOKEN-do-not-leak"

func TestFetchLogs_RefusesToFollowPaginationToAnotherHost(t *testing.T) {
	var attackerAuth atomic.Value // stores string
	attackerAuth.Store("")
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerAuth.Store(r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer attacker.Close()

	// Legitimate tenant whose first page points pagination at the attacker.
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/logs?after=abc>; rel="next"`, attacker.URL))
		_, _ = w.Write([]byte(`[{"id":"e1","uuid":"01","published":"2026-09-20T12:00:00Z","eventType":"user.session.start"}]`))
	}))
	defer tenant.Close()

	c := NewClient(tenant.URL, sentinelToken, 5*time.Second)
	_, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 100, MaxPages: 5})
	if err == nil {
		t.Fatal("expected FetchLogs to refuse an unsafe pagination link, got nil error")
	}
	if !errors.Is(err, ErrUnsafeNextURL) {
		t.Errorf("expected ErrUnsafeNextURL, got %v", err)
	}
	if got := attackerAuth.Load().(string); got != "" {
		t.Errorf("SECURITY: API token was sent to the attacker host: %q", got)
	}
}

func TestFetchLogs_AllowsPaginationOnSameHost(t *testing.T) {
	var pages int32
	var authOK int32
	var tenantHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tenantHost == "" {
			tenantHost = r.Host
		}
		if r.Host != tenantHost {
			t.Errorf("request went to unexpected host %q (want %q)", r.Host, tenantHost)
		}
		if r.Header.Get("Authorization") == "SSWS "+sentinelToken {
			atomic.AddInt32(&authOK, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt32(&pages, 1) == 1 {
			// Same host as the tenant: must be followed.
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/api/v1/logs?after=abc>; rel="next"`, r.Host))
		}
		_, _ = w.Write([]byte(`[{"id":"e1","uuid":"01","published":"2026-09-20T12:00:00Z","eventType":"user.session.start"}]`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, sentinelToken, 5*time.Second)
	events, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 100, MaxPages: 5})
	if err != nil {
		t.Fatalf("same-host pagination should succeed, got %v", err)
	}
	if got := atomic.LoadInt32(&pages); got != 2 {
		t.Errorf("expected 2 pages fetched, got %d", got)
	}
	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
	if got, want := atomic.LoadInt32(&authOK), atomic.LoadInt32(&pages); got != want {
		t.Errorf("token should be sent on every same-host request: %d of %d", got, want)
	}
}

func TestValidateNextURL_RejectsUnsafeTargets(t *testing.T) {
	c := &Client{baseURL: "https://tenant-1.okta.com"}
	tests := []struct {
		name string
		raw  string
	}{
		{"other tenant host", "https://evil.example.com/api/v1/logs"},
		{"same host different port", "https://tenant-1.okta.com:8443/api/v1/logs"},
		{"plaintext to remote host", "http://tenant-1.okta.com/api/v1/logs"},
		{"empty", ""},
		{"missing host", "/api/v1/logs?after=abc"},
		{"unparseable", "https://%zz.invalid/api"},
		{"userinfo trick", "https://tenant-1.okta.com@evil.example.com/api/v1/logs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.validateNextURL(tt.raw)
			if err == nil {
				t.Errorf("expected rejection of %q, got accepted URL %q", tt.raw, got)
				return
			}
			if !errors.Is(err, ErrUnsafeNextURL) {
				t.Errorf("expected ErrUnsafeNextURL, got %v", err)
			}
		})
	}
}

func TestValidateNextURL_AllowsHTTPSOnSameHost(t *testing.T) {
	c := &Client{baseURL: "https://tenant-1.okta.com"}
	got, err := c.validateNextURL("https://tenant-1.okta.com/api/v1/logs?after=abc")
	if err != nil {
		t.Fatalf("expected same-host https link to be accepted, got %v", err)
	}
	if got == "" {
		t.Error("expected a non-empty validated URL")
	}
}

func TestValidateNextURL_LoopbackHTTPAllowedOnlyForLoopbackTenant(t *testing.T) {
	// httptest servers listen on 127.0.0.1 over http; blocking that would break
	// every offline test. Loopback http must stay permitted, but a loopback link
	// must NOT be accepted when the configured tenant is a remote https host.
	loopback := &Client{baseURL: "http://127.0.0.1:9999"}
	if _, err := loopback.validateNextURL("http://127.0.0.1:9999/api/v1/logs?after=abc"); err != nil {
		t.Errorf("loopback http should be allowed for a loopback tenant, got %v", err)
	}
	remote := &Client{baseURL: "https://tenant-1.okta.com"}
	if _, err := remote.validateNextURL("http://127.0.0.1:9999/api/v1/logs"); err == nil {
		t.Error("loopback http must be rejected when the tenant is a remote https host")
	}
}

// --- debugData robustness ---------------------------------------------------
// Okta's debugContext.debugData is free-form. With a plain map[string]string a
// single non-string value failed the ENTIRE page decode, which was retried 5x
// and wedged the poll loop permanently — a silent stall caused by one odd
// event. These tests pin the tolerant decoding.

func TestDebugData_ToleratesNonStringValues(t *testing.T) {
	// A page mixing every JSON value type in debugData must decode fully.
	page := `[
		{"uuid":"u1","published":"2026-09-20T12:00:00Z","eventType":"user.session.start",
		 "debugContext":{"debugData":{"requestUri":"/imap/mailbox"}}},
		{"uuid":"u2","published":"2026-09-20T12:01:00Z","eventType":"user.session.start",
		 "debugContext":{"debugData":{"count":42,"enabled":true,"missing":null,"nested":{"a":1},"list":[1,2]}}},
		{"uuid":"u3","published":"2026-09-20T12:02:00Z","eventType":"user.session.start",
		 "debugContext":{"debugData":null}},
		{"uuid":"u4","published":"2026-09-20T12:03:00Z","eventType":"user.session.start"}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, page)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	events, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 100, MaxPages: 2})
	if err != nil {
		t.Fatalf("a non-string debugData value must not fail the page decode, got %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected all 4 events decoded, got %d", len(events))
	}

	// Strings keep their exact value (load-bearing for isLegacyAuth matching).
	if got := events[0].Context.DebugData["requestUri"]; got != "/imap/mailbox" {
		t.Errorf("string value mangled: got %q", got)
	}
	// Non-strings become their compact JSON text, so substring matching still works.
	got := events[1].Context.DebugData
	if got["count"] != "42" {
		t.Errorf("number not stringified: got %q", got["count"])
	}
	if got["enabled"] != "true" {
		t.Errorf("bool not stringified: got %q", got["enabled"])
	}
	if got["missing"] != "" {
		t.Errorf("null should become empty string: got %q", got["missing"])
	}
	if !strings.Contains(got["nested"], `"a"`) {
		t.Errorf("nested object not preserved as JSON text: got %q", got["nested"])
	}
	if !strings.Contains(got["list"], "1") {
		t.Errorf("array not preserved as JSON text: got %q", got["list"])
	}
}

func TestDebugData_LegacyAuthStillDetectsAcrossValueTypes(t *testing.T) {
	// The whole reason debugData is decoded: isLegacyAuth substring-matches it.
	// A non-string value carrying "/imap" must still be detected rather than
	// silently lost.
	raw := []byte(`{"debugContext":{"debugData":{"proxy":{"url":"/imap/inbox"}}}}`)
	var ev LogEvent
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !isLegacyAuth(&ev) {
		t.Error("isLegacyAuth missed an /imap URL nested inside a non-string debugData value")
	}
}
