// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

// --- Token-leak negative test ----------------------------------------------
//
// Independent review found the damning gap: injecting the SSWS token into an
// error path (`fmt.Errorf("... token %q ...", c.token)`) left the ENTIRE suite
// green. Every other test asserts that data is *present*; none asserted that a
// secret is *absent*. A leak in any slog call, sink, state marshal, or error
// wrapper would have shipped silently into a public AGPL repo.
//
// This test runs a real poll cycle through run() with two canary secrets and
// asserts they appear in NO output channel: slog records, stdout, stderr, the
// error returned by run(), the persisted state file, or the config-load
// warnings. It includes a positive control (a deliberately leaking logger) so
// the test cannot pass vacuously.

const (
	canaryOktaToken    = "CANARY-SSWS-OKTA-9f3e2b1a"
	canaryAdapterToken = "CANARY-BEARER-ADAPTER-7d4c5e6f"
)

// leakCapture collects every channel a secret could escape through.
type leakCapture struct {
	mu      sync.Mutex
	logs    strings.Builder // slog output
	stdoutF *os.File        // redirected os.Stdout
	stderrF *os.File        // redirected os.Stderr
}

// startCapture redirects os.Stdout/os.Stderr into temp files and returns a
// logger writing into a buffer. The caller must call stop().
func startCapture(t *testing.T) (*leakCapture, *slog.Logger, func()) {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "stdout.txt")
	errPath := filepath.Join(dir, "stderr.txt")

	stdoutF, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create stdout capture: %v", err)
	}
	stderrF, err := os.Create(errPath)
	if err != nil {
		t.Fatalf("create stderr capture: %v", err)
	}

	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutF, stderrF

	c := &leakCapture{stdoutF: stdoutF, stderrF: stderrF}
	// Debug level so every record is captured, including trace chatter.
	logger := slog.New(slog.NewJSONHandler(&c.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	stop := func() {
		os.Stdout, os.Stderr = origOut, origErr
		_ = stdoutF.Close()
		_ = stderrF.Close()
	}
	return c, logger, stop
}

// everything concatenates all captured channels plus the extra material the
// caller supplies (returned error, state-file bytes).
func (c *leakCapture) everything(t *testing.T, statePath string, runErr error) string {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()

	var b strings.Builder
	b.WriteString(c.logs.String())

	// Re-open the redirected files (they were closed by stop()).
	for _, p := range []string{c.stdoutF.Name(), c.stderrF.Name()} {
		if data, err := os.ReadFile(p); err == nil {
			b.Write(data)
		}
	}
	if runErr != nil {
		b.WriteString(runErr.Error())
	}
	if statePath != "" {
		if data, err := os.ReadFile(statePath); err == nil {
			b.Write(data)
		}
	}
	return b.String()
}

// assertNoCanary fails the test if either secret appears anywhere.
func assertNoCanary(t *testing.T, blob, where string) {
	t.Helper()
	for _, canary := range []string{canaryOktaToken, canaryAdapterToken} {
		if strings.Contains(blob, canary) {
			t.Errorf("SECURITY LEAK: %s found in %s output:\n%s", canary, where, truncateForLog(blob, 1200))
		}
	}
}

func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("... [%d more bytes]", len(s)-n)
}

// oktaServerWithEvents serves one page of System Log events that DO trigger a
// signal, so the sink and logging paths actually run. Without a signal being
// emitted, the test would exercise almost nothing and could pass vacuously.
func oktaServerWithEvents(t *testing.T, events []LogEvent, authHeaderWant string) *httptest.Server {
	t.Helper()
	var served int32
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authHeaderWant != "" && r.Header.Get("Authorization") != authHeaderWant {
			t.Errorf("expected Authorization %q, got %q", authHeaderWant, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		served++
		_ = json.NewEncoder(w).Encode(events)
	}))
}

// adminEvent is an event type in the admin-action family, so Detect() emits a
// signal and the sink path runs.
func adminEvent(uuid, login string, when time.Time) LogEvent {
	return LogEvent{
		UUID:      uuid,
		Published: when,
		EventType: "group.user_membership.add",
		Outcome:   Outcome{Result: "SUCCESS"},
		Actor:     Actor{AlternateID: login},
	}
}

// TestNoTokenLeak_LiveCycle_LogSink runs run() against a mock Okta tenant in
// live mode with the offline LogSink, capturing every output channel.
func TestNoTokenLeak_LiveCycle_LogSink(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	events := []LogEvent{adminEvent("leak-1", "admin@corp.example", t0)}

	srv := oktaServerWithEvents(t, events, "SSWS "+canaryOktaToken)
	defer srv.Close()

	c, logger, stop := startCapture(t)
	defer stop()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	cfg := &Config{
		StateFile:    statePath,
		OktaBaseURL:  srv.URL,
		OktaToken:    canaryOktaToken,
		AdapterToken: "", // forces LogSink
		Limit:        100,
		MaxPages:     5,
		Once:         true,
		PollInterval: 10 * time.Millisecond,
		Timeout:      2 * time.Second,
	}

	runErr := run(context.Background(), cfg, logger)
	stop() // flush redirected files before reading them

	// Sanity: the cycle must actually have done work, or the test proves nothing.
	if runErr != nil {
		t.Fatalf("run() should succeed, got %v", runErr)
	}
	blob := c.everything(t, statePath, runErr)
	if !strings.Contains(blob, "admin_action") {
		t.Errorf("POSITIVE CONTROL FAILED: no signal was emitted/logged, so the leak assertions below are vacuous. Captured: %s", truncateForLog(blob, 800))
	}
	assertNoCanary(t, blob, "live-cycle LogSink")
}

// TestNoTokenLeak_LiveCycle_EvaluateSink exercises the path where BOTH secrets
// exist: the SSWS token to Okta and the adapter bearer token to OIAF core.
func TestNoTokenLeak_LiveCycle_EvaluateSink(t *testing.T) {
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	events := []LogEvent{adminEvent("leak-2", "admin@corp.example", t0)}

	srv := oktaServerWithEvents(t, events, "SSWS "+canaryOktaToken)
	defer srv.Close()

	// Mock OIAF core: returns a decision so the "okta signal scored" log path runs.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow","risk_score":10,"reasons":["test"]}`))
	}))
	defer core.Close()

	c, logger, stop := startCapture(t)
	defer stop()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	cfg := &Config{
		StateFile:    statePath,
		OktaBaseURL:  srv.URL,
		OktaToken:    canaryOktaToken,
		AdapterToken: canaryAdapterToken, // forces EvaluateSink
		ServerURL:    core.URL,
		Limit:        100,
		MaxPages:     5,
		Once:         true,
		PollInterval: 10 * time.Millisecond,
		Timeout:      2 * time.Second,
	}

	runErr := run(context.Background(), cfg, logger)
	stop()

	if runErr != nil {
		t.Fatalf("run() should succeed, got %v", runErr)
	}
	blob := c.everything(t, statePath, runErr)
	if !strings.Contains(blob, "okta signal scored") {
		t.Errorf("POSITIVE CONTROL FAILED: the EvaluateSink scoring log never ran, so leak assertions are vacuous. Captured: %s", truncateForLog(blob, 800))
	}
	assertNoCanary(t, blob, "live-cycle EvaluateSink")
}

// TestNoTokenLeak_ErrorPaths covers the failure paths, where errors are most
// likely to embed request details. This is precisely the path mutation D
// exploited: an error string carrying the token.
func TestNoTokenLeak_ErrorPaths(t *testing.T) {
	c, logger, stop := startCapture(t)
	defer stop()

	var errs []error

	// (a) Auth failure: 401 from Okta. The error text is logged by Run and
	// returned; it must not carry the token.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errorCode":"E0000011","errorSummary":"Invalid token provided"}`))
	}))
	defer authSrv.Close()
	ac := NewClient(authSrv.URL, canaryOktaToken, 2*time.Second)
	_, err := ac.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 2})
	if err == nil {
		t.Fatal("expected an auth error")
	}
	errs = append(errs, err)
	logger.Error("auth failure", "error", err)

	// (b) Transport error to an unreachable host: *url.Error embeds the URL.
	bc := NewClient("http://127.0.0.1:1", canaryOktaToken, 500*time.Millisecond)
	// Transport errors are retried with exponential backoff (1s, 2s, 4s, 8s) up
	// to the default 60s cap. Without this the test burns ~15s of real sleeping
	// to prove something about a string; keep the leak assertion fast so CI
	// actually runs it rather than skipping it as slow.
	bc.maxBackoff = 10 * time.Millisecond
	_, err = bc.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatal("expected a transport error")
	}
	errs = append(errs, err)
	logger.Error("transport failure", "error", err)

	// (c) Rate-limit exhaustion: 429 forever, error carries Retry-After details.
	rlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer rlSrv.Close()
	rc := NewClient(rlSrv.URL, canaryOktaToken, 2*time.Second)
	rc.maxBackoff = 10 * time.Millisecond
	_, err = rc.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 1})
	if err == nil {
		t.Fatal("expected a rate-limit error")
	}
	errs = append(errs, err)
	logger.Error("rate limit exhausted", "error", err)

	// (d) Unsafe pagination link rejection (the Fix 1 path).
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer hostile.Close()
	tenant := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/logs?after=x>; rel="next"`, hostile.URL))
		_, _ = w.Write([]byte(`[{"id":"e","uuid":"e","published":"2026-09-20T12:00:00Z","eventType":"user.session.start"}]`))
	}))
	defer tenant.Close()
	tc := NewClient(tenant.URL, canaryOktaToken, 2*time.Second)
	_, err = tc.FetchLogs(context.Background(), FetchLogsParams{Limit: 10, MaxPages: 5})
	if !errors.Is(err, ErrUnsafeNextURL) {
		t.Fatalf("expected ErrUnsafeNextURL, got %v", err)
	}
	errs = append(errs, err)
	logger.Error("unsafe pagination link", "error", err)

	// (e) Sink failure: the error bubbles into the poller's Error log.
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	st := NewState()
	save := func() error { return st.Save(statePath, time.Now()) }
	cfg := &Config{StateFile: statePath, Limit: 10, MaxPages: 2, Once: true, PollInterval: time.Millisecond}
	// NOTE: this error deliberately does NOT contain a canary. The point is to
	// prove the *product's* error/logging paths are clean; a test-authored
	// string carrying the canary would be logged faithfully and fail the test
	// for the wrong reason. Harness correctness is proven separately by
	// TestLeakCaptureDetectsALeak.
	badSink := &erroringSink{err: errors.New("core rejected signal (simulated failure)")}
	// The shipped sample fixture triggers all six signal families, so the sink
	// path definitely runs (see fixture_test.go).
	fixtureSrc, ferr := NewFixtureSource(filepath.Join("testdata", "sample_okta_logs.json"))
	if ferr != nil {
		t.Fatalf("fixture source: %v", ferr)
	}
	p := NewPoller(
		fixtureSrc,
		NewDetector(defaultParams()), badSink, st, save, cfg, logger)
	_ = p.Run(context.Background())
	_ = save()

	stop()
	blob := c.everything(t, statePath, errors.Join(errs...))
	assertNoCanary(t, blob, "error paths")

	// Positive control: the erroring sink's message DID reach the capture, so
	// the assertions above were not vacuous. (It carries the canary by
	// construction, which is why we assert absence only after confirming the
	// blob is non-empty and mentions the sink failure.)
	if !strings.Contains(blob, "signal emission failed") {
		t.Errorf("POSITIVE CONTROL FAILED: sink-failure log never appeared, so error-path leak assertions are vacuous. Captured: %s", truncateForLog(blob, 800))
	}
}

// TestNoTokenLeak_ConfigErrors verifies loadConfig's user-facing errors and
// warnings (written directly to os.Stderr) never echo a token value.
func TestNoTokenLeak_ConfigErrors(t *testing.T) {
	// loadConfig() takes no logger: its warning goes straight to os.Stderr via
	// fmt.Fprintf, which the capture harness redirects. Hence the blank logger.
	c, _, stop := startCapture(t)
	defer stop()

	dir := t.TempDir()
	// A group/world-readable config file triggers loadConfigFile's stderr
	// warning. The YAML shape is FLAT (see oktaFileConfig); there is no YAML
	// field for the adapter token, so that one comes from the environment.
	cfgPath := filepath.Join(dir, "okta.yaml")
	body := fmt.Sprintf("api_token: \"%s\"\nbase_url: \"https://tenant-1.okta.com\"\n", canaryOktaToken)
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("OKTA_CONFIG_FILE", cfgPath)
	t.Setenv("OIAF_OKTA_TOKEN", "")
	t.Setenv("OKTA_API_TOKEN", "")
	t.Setenv("OIAF_ADAPTER_TOKEN", canaryAdapterToken)

	cfg, err := loadConfig()
	stop()
	if err != nil {
		t.Fatalf("loadConfig should succeed with a YAML config, got %v", err)
	}
	if cfg.OktaToken != canaryOktaToken {
		t.Errorf("config did not load the token from YAML (got %q) — the leak assertions below would be vacuous", cfg.OktaToken)
	}
	if cfg.AdapterToken != canaryAdapterToken {
		t.Errorf("config did not load the adapter token from env (got %q) — the leak assertions below would be vacuous", cfg.AdapterToken)
	}

	blob := c.everything(t, "", nil)
	// Positive control: the warning path must actually have fired, otherwise we
	// only proved that a silent function does not leak.
	if !strings.Contains(blob, "readable by group/others") {
		t.Errorf("POSITIVE CONTROL FAILED: the world-readable config warning never fired, so this test proves nothing. Captured: %s", truncateForLog(blob, 800))
	}
	assertNoCanary(t, blob, "config errors and warnings")
}

// TestLeakCaptureDetectsALeak is the meta-test / positive control for the
// capture harness itself: if a secret is written to each channel, the harness
// MUST see it. Without this, every assertion above could pass because the
// capture was broken rather than because the code is clean.
func TestLeakCaptureDetectsALeak(t *testing.T) {
	c, logger, stop := startCapture(t)
	defer stop()

	// Write the canaries through every channel the harness claims to watch.
	logger.Error("leaky log", "token", canaryOktaToken)
	fmt.Fprint(os.Stdout, "stdout leak "+canaryAdapterToken)
	fmt.Fprint(os.Stderr, "stderr leak "+canaryOktaToken)
	runErr := fmt.Errorf("error leak %s", canaryAdapterToken)

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	if err := os.WriteFile(statePath, []byte(`{"cursor":"`+canaryOktaToken+`"}`), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	stop()
	blob := c.everything(t, statePath, runErr)

	for _, want := range []string{canaryOktaToken, canaryAdapterToken} {
		if !strings.Contains(blob, want) {
			t.Fatalf("HARNESS BROKEN: capture did not see %q written through the channels; all other leak tests are therefore vacuous", want)
		}
	}
	// And confirm each channel is individually visible.
	for _, probe := range []struct{ name, needle string }{
		{"slog", "leaky log"},
		{"stdout", "stdout leak"},
		{"stderr", "stderr leak"},
		{"runErr", "error leak"},
		{"state file", `"cursor"`},
	} {
		if !strings.Contains(blob, probe.needle) {
			t.Errorf("HARNESS BROKEN: %s channel not captured (missing %q)", probe.name, probe.needle)
		}
	}
}

// erroringSink always fails, to drive the poller's sink-error logging path.
type erroringSink struct{ err error }

func (s *erroringSink) Emit(ctx context.Context, sig Signal) error { return s.err }
func (s *erroringSink) Close() error                               { return nil }
