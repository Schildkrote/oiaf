//go:build !windows

// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
)

type EventSource struct {
	cfg    *Config
	logger *slog.Logger
}

func NewEventSource(cfg *Config, logger *slog.Logger) (*EventSource, error) {
	return &EventSource{cfg: cfg, logger: logger}, nil
}

func (s *EventSource) Subscribe(ctx context.Context, out chan<- EventRecord) error {
	s.logger.Warn("EvtSubscribe is only available on Windows; running in stub mode")
	<-ctx.Done()
	return nil
}

func (s *EventSource) Close() {}

func buildQuery(eventIDs []int) string {
	return fmt.Sprintf("event_ids=%v", eventIDs)
}
