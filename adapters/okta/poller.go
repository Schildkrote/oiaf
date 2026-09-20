// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Poller drives one poll cycle: fetch events after the cursor (deduped by
// UUID), detect risk signals, emit them downstream, commit detection memory
// and advance the cursor. State is saved after every cycle so a crash
// neither reprocesses nor gaps events.
//
// Delivery semantics: at-least-once with UUID dedupe. The cursor only
// advances past events whose signals were emitted successfully; if emission
// fails mid-batch we stop before that event, so the next poll replays from
// the last committed timestamp. Duplicates that slip through (same event
// re-fetched before the state save) are filtered by RecentUUIDs.
type Poller struct {
	source   EventSource
	detector *Detector
	sink     Sink
	state    *State
	stateFn  func() error
	logger   *slog.Logger
	cfg      *Config
}

func NewPoller(source EventSource, det *Detector, sink Sink, st *State, save func() error, cfg *Config, logger *slog.Logger) *Poller {
	return &Poller{
		source:   source,
		detector: det,
		sink:     sink,
		state:    st,
		stateFn:  save,
		logger:   logger,
		cfg:      cfg,
	}
}

// PollOnce runs a single poll cycle and returns how many events were
// processed and how many signals were emitted.
func (p *Poller) PollOnce(ctx context.Context) (processed, emitted int, err error) {
	events, err := p.source.Fetch(ctx, p.state.Cursor, time.Time{}, p.cfg.Limit, p.cfg.MaxPages)
	if err != nil {
		return 0, 0, err
	}

	for i := range events {
		ev := &events[i]
		if p.state.AlreadyProcessed(ev.UUID) {
			continue
		}

		signals := p.detector.Detect(ev, p.state)
		failed := false
		for _, sig := range signals {
			if err := p.sink.Emit(ctx, sig); err != nil {
				// Stop before advancing the cursor past an undelivered event:
				// the next poll replays it. Auth failures on the OIAF side are
				// permanent-ish — surface them loudly rather than retry-looping.
				p.logger.Error("signal emission failed; stopping batch before cursor advance",
					"event_uuid", ev.UUID, "signal", sig.Type, "login", sig.Login, "error", err)
				failed = true
				break
			}
			emitted++
		}
		if failed {
			break
		}

		p.detector.Commit(ev, p.state)
		p.state.MarkProcessed(ev.UUID)
		if ev.Published.After(p.state.Cursor) {
			p.state.Cursor = ev.Published
			p.state.LastUUID = ev.UUID
		}
		processed++
	}

	if saveErr := p.stateFn(); saveErr != nil {
		return processed, emitted, fmt.Errorf("save state: %w", saveErr)
	}
	if errors.Is(err, ErrTooManyPages) {
		p.logger.Info("page cap reached; continuing from cursor next cycle", "processed", processed)
		err = nil
	}
	return processed, emitted, err
}

// Run polls until ctx is cancelled. Poll errors are logged and backed off
// (the cursor keeps whatever progress was saved), so a flapping Okta tenant or
// OIAF core never kills the adapter — it just retries on the next interval.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("okta adapter started",
		"poll_interval", p.cfg.PollInterval.String(),
		"fixture_mode", p.cfg.FixtureFile != "",
	)
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	for {
		processed, emitted, err := p.PollOnce(ctx)
		if err != nil {
			if errors.Is(err, ErrAuth) {
				// A revoked/expired Okta token will not fix itself; fail fast
				// so supervisors (systemd/compose) surface it instead of
				// silently idling.
				return err
			}
			p.logger.Error("poll cycle failed", "error", err)
		} else if processed > 0 {
			p.logger.Info("poll cycle complete", "events", processed, "signals", emitted)
		}

		if p.cfg.Once {
			return nil
		}
		select {
		case <-ctx.Done():
			p.logger.Info("okta adapter stopping")
			return nil
		case <-ticker.C:
		}
	}
}
