// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
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

// TestStateRoundTrip verifies the cursor and detection memory survive a
// save/load cycle, including dedupe-set reindexing.
func TestStateRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	st := NewState()
	now := baseTime()
	st.Cursor = now
	st.LastUUID = "ev-1"
	st.MarkProcessed("ev-1")
	id := st.Identity("alice@corp.example")
	id.LastGeo = "Berlin, DE"
	id.Devices = []string{"Chrome|Mozilla"}

	if err := st.Save(path, now); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("state file must be 0600, got %o", perm)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !loaded.Cursor.Equal(now) {
		t.Fatalf("cursor lost: %v", loaded.Cursor)
	}
	if !loaded.AlreadyProcessed("ev-1") {
		t.Fatal("dedupe set not reindexed after load")
	}
	if loaded.AlreadyProcessed("never-seen") {
		t.Fatal("false positive in dedupe set")
	}
	if loaded.Identities["alice@corp.example"].LastGeo != "Berlin, DE" {
		t.Fatal("identity memory lost")
	}
}

// TestLoadStateMissingFile verifies a first run starts clean rather than
// erroring.
func TestLoadStateMissingFile(t *testing.T) {
	st, err := LoadState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing state file must not error: %v", err)
	}
	if !st.Cursor.IsZero() || len(st.RecentUUIDs) != 0 {
		t.Fatal("fresh state expected")
	}
}

// TestLoadStateCorruptFile verifies a corrupt state file errors instead of
// silently restarting (which would reprocess the whole retention window).
func TestLoadStateCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); err == nil {
		t.Fatal("expected error on corrupt state file")
	}
}

// TestMarkProcessedBound verifies the dedupe window stays bounded.
func TestMarkProcessedBound(t *testing.T) {
	st := NewState()
	for i := 0; i < maxRecentUUIDs+100; i++ {
		st.MarkProcessed("u-" + strings.Repeat("x", i%8) + string(rune('a'+i%26)) + string(rune(i)))
	}
	if len(st.RecentUUIDs) > maxRecentUUIDs {
		t.Fatalf("dedupe window unbounded: %d", len(st.RecentUUIDs))
	}
}

// recordingSink captures emitted signals for assertions.
type recordingSink struct {
	mu      sync.Mutex
	Signals []Signal
	errOn   func(Signal) error
}

func (r *recordingSink) Emit(_ context.Context, s Signal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.errOn != nil {
		if err := r.errOn(s); err != nil {
			return err
		}
	}
	r.Signals = append(r.Signals, s)
	return nil
}

func (r *recordingSink) Close() error { return nil }

func (r *recordingSink) types() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.Signals))
	for _, s := range r.Signals {
		out = append(out, s.Type)
	}
	return out
}

func testCfg(t *testing.T) *Config {
	t.Helper()
	return &Config{
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Limit:     100,
		MaxPages:  10,
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestPollerCursorAndDedupe verifies the full offline loop against a mock
// Okta: first poll processes events and advances the cursor; a re-run with
// overlapping data (events re-served because 'since' steps 1ms back)
// processes nothing new; and later events are picked up from the cursor.
func TestPollerCursorAndDedupe(t *testing.T) {
	t0 := baseTime()
	allEvents := []LogEvent{
		*signInEvent("e1", "alice@corp.example", t0, 52.52, 13.405, "Berlin", "DE"),
		*signInEvent("e2", "alice@corp.example", t0.Add(time.Hour), 53.551, 9.993, "Hamburg", "DE"),
	}

	var sinceParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sinceParam = r.URL.Query().Get("since")
		// Serve everything at/after the since param (mocking Okta's windowing).
		var out []LogEvent
		for _, ev := range allEvents {
			if sinceParam == "" || !ev.Published.Before(mustParseTime(sinceParam)) {
				out = append(out, ev)
			}
		}
		json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	cfg := testCfg(t)
	cfg.PollInterval = time.Millisecond // unused: we call PollOnce directly
	st, err := LoadState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	det := NewDetector(defaultParams())
	save := func() error { return st.Save(cfg.StateFile, time.Now()) }
	p := NewPoller(NewLiveSource(NewClient(srv.URL, "tok", 5*time.Second)), det, sink, st, save, cfg, discardLogger())

	// First poll: both events, new_geo signal for the second one.
	processed, emitted, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if processed != 2 {
		t.Fatalf("poll 1: expected 2 events, got %d", processed)
	}
	if emitted != 1 {
		t.Fatalf("poll 1: expected 1 signal (new_geo), got %d: %v", emitted, sink.types())
	}
	if !st.Cursor.Equal(allEvents[1].Published) {
		t.Fatalf("cursor should be at last event, got %v", st.Cursor)
	}

	// Second poll with no new events: Okta's exclusive-since stepping means
	// the server may re-serve the boundary event; UUID dedupe must swallow it.
	processed, emitted, err = p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if processed != 0 || emitted != 0 {
		t.Fatalf("poll 2 must be a no-op (dedupe), got processed=%d emitted=%d %v", processed, emitted, sink.types())
	}

	// State must have been persisted; reload and confirm the cursor survives.
	reloaded, err := LoadState(cfg.StateFile)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !reloaded.Cursor.Equal(allEvents[1].Published) {
		t.Fatalf("persisted cursor mismatch: %v", reloaded.Cursor)
	}

	// New event after the cursor gets picked up exactly once.
	allEvents = append(allEvents, *signInEvent("e3", "alice@corp.example", t0.Add(2*time.Hour), 53.551, 9.993, "Hamburg", "DE"))
	processed, _, err = p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("poll 3: %v", err)
	}
	if processed != 1 {
		t.Fatalf("poll 3: expected exactly the new event, got %d (since=%q)", processed, sinceParam)
	}
}

// TestPollerStopsOnSinkFailure verifies at-least-once semantics: when
// emission fails, the cursor does not advance past the failed event and the
// event replays on the next poll.
func TestPollerStopsOnSinkFailure(t *testing.T) {
	t0 := baseTime()
	events := []LogEvent{
		*signInEvent("e1", "alice@corp.example", t0, 52.52, 13.405, "Berlin", "DE"),
		*signInEvent("e2", "alice@corp.example", t0.Add(time.Hour), 53.551, 9.993, "Hamburg", "DE"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(events)
	}))
	defer srv.Close()

	cfg := testCfg(t)
	st, _ := LoadState(cfg.StateFile)
	fail := errors.New("core down")
	sink := &recordingSink{errOn: func(s Signal) error {
		if s.Type == SignalNewGeo {
			return fail
		}
		return nil
	}}
	det := NewDetector(defaultParams())
	save := func() error { return st.Save(cfg.StateFile, time.Now()) }
	p := NewPoller(NewLiveSource(NewClient(srv.URL, "tok", 5*time.Second)), det, sink, st, save, cfg, discardLogger())

	processed, _, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("poll should succeed even when emission fails mid-batch: %v", err)
	}
	if processed != 1 {
		t.Fatalf("expected only e1 committed, got %d", processed)
	}
	if !st.Cursor.Equal(events[0].Published) {
		t.Fatalf("cursor must not advance past failed event: %v", st.Cursor)
	}

	// Sink recovers: replay processes both remaining (e2 was not committed).
	sink.errOn = nil
	processed, emitted, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// e1 replays (server serves all events; UUID dedupe skips it), e2 emits.
	if emitted != 1 {
		t.Fatalf("expected new_geo on replay, got %d: %v", emitted, sink.types())
	}
	if processed != 1 {
		t.Fatalf("expected e2 processed on replay, got %d", processed)
	}
}

// TestFixtureSourceOffline verifies the fixture mode runs the whole pipeline
// with zero network: file -> detect -> sink, cursor persisted.
func TestFixtureSourceOffline(t *testing.T) {
	t0 := baseTime()
	fixture := []LogEvent{
		*signInEvent("f1", "mallory@corp.example", t0, 52.52, 13.405, "Berlin", "DE"),
		*signInEvent("f2", "mallory@corp.example", t0.Add(10*time.Minute), 40.7128, -74.006, "New York", "US"),
	}
	data, _ := json.Marshal(map[string]any{"events": fixture})
	fixturePath := filepath.Join(t.TempDir(), "okta-fixture.json")
	if err := os.WriteFile(fixturePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	src, err := NewFixtureSource(fixturePath)
	if err != nil {
		t.Fatalf("fixture load: %v", err)
	}
	cfg := testCfg(t)
	st, _ := LoadState(cfg.StateFile)
	sink := &recordingSink{}
	save := func() error { return st.Save(cfg.StateFile, time.Now()) }
	p := NewPoller(src, NewDetector(defaultParams()), sink, st, save, cfg, discardLogger())

	processed, emitted, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if processed != 2 {
		t.Fatalf("expected 2 fixture events, got %d", processed)
	}
	if !hasSignalTypes(sink.types(), SignalImpossibleTravel) {
		t.Fatalf("expected impossible_travel from fixture, got %v", sink.types())
	}
	if emitted < 1 {
		t.Fatalf("expected emitted signals, got %d", emitted)
	}

	// Re-run: fully deduped.
	processed, emitted, err = p.PollOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if processed != 0 || emitted != 0 {
		t.Fatalf("fixture re-run must be a no-op, got processed=%d emitted=%d", processed, emitted)
	}
}

// TestFixtureSourceSortsOutOfOrder verifies fixtures are processed
// oldest-first even when the file is not sorted.
func TestFixtureSourceSortsOutOfOrder(t *testing.T) {
	t0 := baseTime()
	later := signInEvent("f2", "x@corp.example", t0.Add(time.Hour), 0, 0, "", "")
	earlier := signInEvent("f1", "x@corp.example", t0, 0, 0, "", "")
	data, _ := json.Marshal([]LogEvent{*later, *earlier}) // deliberately reversed
	path := filepath.Join(t.TempDir(), "fx.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewFixtureSource(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := src.Fetch(context.Background(), time.Time{}, time.Time{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].UUID != "f1" {
		t.Fatalf("expected oldest-first ordering, got %v", events)
	}
}

// TestPollerAuthFailureIsFatal verifies Run returns ErrAuth promptly instead
// of looping forever on a revoked token.
func TestPollerAuthFailureIsFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := testCfg(t)
	cfg.PollInterval = time.Millisecond
	st, _ := LoadState(cfg.StateFile)
	save := func() error { return st.Save(cfg.StateFile, time.Now()) }
	p := NewPoller(
		NewLiveSource(NewClient(srv.URL, "bad-token", 2*time.Second)),
		NewDetector(defaultParams()), &recordingSink{}, st, save, cfg, discardLogger())

	err := p.Run(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth to be fatal, got %v", err)
	}
}

func hasSignalTypes(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

func mustParseTime(s string) time.Time {
	// Okta returns RFC3339Nano with a trailing Z; the client queries with the
	// same format, so this round-trips in tests.
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		panic(err)
	}
	return t
}
