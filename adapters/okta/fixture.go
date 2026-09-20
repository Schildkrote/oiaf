// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"
)

// fixtureSource implements the same event-source contract as the live Okta
// client but reads events from a local JSON fixture file. This is the
// adapter's offline mock mode (OKTA_FIXTURE_FILE): CI and development run
// with zero network. The fixture format is either a bare JSON array of Okta
// log events, or {"events": [...]} — both are accepted.
type fixtureSource struct {
	events []LogEvent
}

// EventSource abstracts where log events come from (live Okta API vs.
// fixture), so the poller logic is identical in both modes.
type EventSource interface {
	// Fetch returns events in [since, until] oldest-first, honoring the
	// page cap semantics of the live client.
	Fetch(ctx context.Context, since, until time.Time, limit, maxPages int) ([]LogEvent, error)
}

// NewFixtureSource loads and validates a fixture file.
func NewFixtureSource(path string) (*fixtureSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fixture file: %w", err)
	}
	var events []LogEvent
	if err := json.Unmarshal(data, &events); err != nil {
		var wrapped struct {
			Events []LogEvent `json:"events"`
		}
		if err2 := json.Unmarshal(data, &wrapped); err2 != nil {
			return nil, fmt.Errorf("parse fixture file: %w", errors.Join(err, err2))
		}
		events = wrapped.Events
	}
	// Fixtures must be processed oldest-first regardless of file order.
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Published.Before(events[j].Published)
	})
	return &fixtureSource{events: events}, nil
}

func (f *fixtureSource) Fetch(_ context.Context, since, until time.Time, _, _ int) ([]LogEvent, error) {
	var out []LogEvent
	for _, ev := range f.events {
		if !since.IsZero() && !ev.Published.After(since) {
			continue
		}
		if !until.IsZero() && ev.Published.After(until) {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

// liveSource adapts the Okta Client to the EventSource interface.
type liveSource struct {
	client *Client
}

func NewLiveSource(c *Client) *liveSource { return &liveSource{client: c} }

func (l *liveSource) Fetch(ctx context.Context, since, until time.Time, limit, maxPages int) ([]LogEvent, error) {
	events, err := l.client.FetchLogs(ctx, FetchLogsParams{
		Since:    since,
		Until:    until,
		Limit:    limit,
		MaxPages: maxPages,
	})
	// ErrTooManyPages is partial success: return what we have; the poller
	// persists the cursor and continues next cycle.
	if err != nil && !errors.Is(err, ErrTooManyPages) {
		return events, err
	}
	return events, nil
}
