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
	"sync"
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

// --- Flush rejection must be observable (closes mutation (c)) ----------------
//
// The leak tests above all use discard() loggers, so nothing observes what Flush
// does with a rejected batch. Independent review dropped the isNotSuccess gate
// from Flush and the WHOLE suite stayed green: a refused-redirect 302 would
// re-create the original silent AD-event loss, and an attacker-controlled 4xx
// body would be decoded and logged as fake "baseline deviation" warnings.
// These tests record log output so that mutation is caught.

// recordingHandler captures slog records so a test can assert on what was
// logged — the discard() logger cannot, which is precisely the blind spot.
type recordingHandler struct {
	mu       sync.Mutex
	records  []string
	attrs    map[string][]string
	levelMin slog.Level
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{attrs: map[string][]string{}, levelMin: slog.LevelDebug}
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Message)
	r.Attrs(func(a slog.Attr) bool {
		h.attrs[a.Key] = append(h.attrs[a.Key], a.Value.String())
		return true
	})
	return nil
}

// messages returns a snapshot of every logged message.
func (h *recordingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.records))
	copy(out, h.records)
	return out
}

// values returns every value logged under a given key.
func (h *recordingHandler) values(key string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.attrs[key]))
	copy(out, h.attrs[key])
	return out
}

func (h *recordingHandler) logged(msg string) bool {
	for _, m := range h.messages() {
		if m == msg {
			return true
		}
	}
	return false
}

func TestSenderFlush_RejectedBatchIsLoggedAndNotDecoded(t *testing.T) {
	// A hostile core returns 502 whose body carries crafted decisions. If Flush
	// decoded it anyway, those decisions would be logged as genuine baseline
	// deviations — fabricated security signal. The gate must prevent that.
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"accepted":2,"decisions":[
			{"account_sid":"S-FAKE","account_name":"attacker","decision":"challenge","risk_score":99},
			{"account_sid":"S-FAKE2","account_name":"attacker2","decision":"deny","risk_score":100}]}`))
	}))
	defer hostile.Close()

	h := newRecordingHandler()
	s := NewSender(hostile.URL, "tok", 10, time.Second, slog.New(h))
	s.Flush(context.Background(), []EventRecord{{AccountSID: "S-1"}})

	// (i) the rejection is actually logged, with the status
	if !h.logged("server rejected batch") {
		t.Errorf("Flush did not log 'server rejected batch'; recorded messages: %v", h.messages())
	}
	if got := h.values("status"); len(got) == 0 || got[0] != "502" {
		t.Errorf("rejection log should carry status 502, got %v", got)
	}

	// (ii) NOT ONE fabricated decision may be logged
	for _, m := range h.messages() {
		if m == "baseline deviation detected" {
			t.Errorf("SECURITY: Flush decoded an error body and logged fabricated decisions: %v", h.messages())
		}
	}
	for _, v := range h.values("account") {
		if strings.Contains(v, "attacker") {
			t.Errorf("SECURITY: attacker-controlled account name reached the logs: %v", h.values("account"))
		}
	}
}

func TestSenderFlush_RefusedRedirectIsRejectedNotDecoded(t *testing.T) {
	// The exact scenario mutation (c) exposed: with redirects refused, a 302
	// arrives with an empty body. The old >=400 gate treated that as SUCCESS,
	// decode failed silently, and the AD events vanished with only a Debug log.
	var hits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1,"decisions":[]}`))
	}))
	defer target.Close()

	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+r.URL.Path)
		w.WriteHeader(http.StatusFound) // 302, empty body
	}))
	defer core.Close()

	h := newRecordingHandler()
	s := NewSender(core.URL, "tok", 10, time.Second, slog.New(h))
	s.Flush(context.Background(), []EventRecord{{AccountSID: "S-1"}, {AccountSID: "S-2"}})

	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("SECURITY: the redirect was followed %d time(s)", got)
	}
	// The batch must be visibly rejected, not silently swallowed.
	if !h.logged("server rejected batch") {
		t.Errorf("a refused 302 must be logged as a rejection, otherwise %d AD events are lost silently; recorded: %v", 2, h.messages())
	}
	if got := h.values("status"); len(got) == 0 || got[0] != "302" {
		t.Errorf("rejection log should carry status 302, got %v", got)
	}
	if got := h.values("count"); len(got) == 0 || got[0] != "2" {
		t.Errorf("rejection log should report the number of dropped events, got %v", got)
	}
}

func TestSenderFlush_AcceptsValidDecisions(t *testing.T) {
	// Positive control: the gate must not suppress legitimate decisions, or the
	// two tests above could pass by breaking Flush entirely.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1,"decisions":[{"account_sid":"S-1","account_name":"corp","decision":"challenge","risk_score":77}]}`))
	}))
	defer core.Close()

	h := newRecordingHandler()
	s := NewSender(core.URL, "tok", 10, time.Second, slog.New(h))
	s.Flush(context.Background(), []EventRecord{{AccountSID: "S-1"}})

	if !h.logged("baseline deviation detected") {
		t.Errorf("POSITIVE CONTROL FAILED: a valid 200 decision was not logged, so the rejection tests above prove nothing; recorded: %v", h.messages())
	}
	if h.logged("server rejected batch") {
		t.Errorf("a valid 200 batch must not be logged as rejected; recorded: %v", h.messages())
	}
	if got := h.values("risk_score"); len(got) == 0 || got[0] != "77" {
		t.Errorf("decision detail not logged, got %v", got)
	}
}
