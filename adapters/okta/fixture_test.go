// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestSampleFixtureEndToEnd runs the committed sample fixture
// (testdata/sample_okta_logs.json) through the full offline pipeline and
// asserts the documented risk-signal families fire. This doubles as a
// regression check on the fixture file itself, which operators use for demos.
func TestSampleFixtureEndToEnd(t *testing.T) {
	src, err := NewFixtureSource(filepath.Join("testdata", "sample_okta_logs.json"))
	if err != nil {
		t.Fatalf("fixture load: %v", err)
	}

	cfg := &Config{
		StateFile: filepath.Join(t.TempDir(), "state.json"),
		Limit:     100,
		MaxPages:  10,
	}
	st, err := LoadState(cfg.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	det := NewDetector(defaultParams())
	save := func() error { return st.Save(cfg.StateFile, time.Now()) }
	p := NewPoller(src, det, sink, st, save, cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	processed, emitted, err := p.PollOnce(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if processed != 5 {
		t.Fatalf("expected 5 fixture events, got %d", processed)
	}
	if emitted == 0 {
		t.Fatal("expected signals from sample fixture")
	}

	types := sink.types()
	for _, want := range []string{SignalImpossibleTravel, SignalNewDevice, SignalNewGeo, SignalMFADeny, SignalLegacyAuth, SignalAdminAction} {
		if !hasSignalTypes(types, want) {
			t.Errorf("expected %s signal from sample fixture, got %v", want, types)
		}
	}
}
