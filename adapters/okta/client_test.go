// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "<http://"+r.Host+`/api/v1/logs?after=x>; rel="next"`)
		json.NewEncoder(w).Encode([]LogEvent{mustEvent(t, "e1", "user.session.start", time.Now())})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-token", 5*time.Second)
	events, err := c.FetchLogs(context.Background(), FetchLogsParams{Limit: 1, MaxPages: 2})
	if !errors.Is(err, ErrTooManyPages) {
		t.Fatalf("expected ErrTooManyPages, got %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 partial events, got %d", len(events))
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
