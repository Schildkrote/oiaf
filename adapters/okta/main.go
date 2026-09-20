// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// oiaf-okta-adapter ingests the Okta System Log (/api/v1/logs), derives risk
// signals (impossible travel, new geo/device, failed-MFA/fatigue, legacy
// auth, admin actions) and feeds them to OIAF core for risk scoring.
//
// It is strictly READ-ONLY toward Okta: it only issues authenticated GETs and
// never enforces decisions back into the tenant (see docs/adapters/okta.md).
//
// Credentials: the Okta API token comes from OIAF_OKTA_TOKEN (preferred) or
// OKTA_API_TOKEN, or the optional YAML config file (OKTA_CONFIG_FILE) — never
// from argv, and it is never logged.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("adapter error", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *Config, logger *slog.Logger) error {
	st, err := LoadState(cfg.StateFile)
	if err != nil {
		return err
	}
	save := func() error { return st.Save(cfg.StateFile, time.Now()) }

	var source EventSource
	if cfg.FixtureFile != "" {
		source, err = NewFixtureSource(cfg.FixtureFile)
		if err != nil {
			return err
		}
		logger.Info("fixture mode: reading events from local file (offline)", "path", cfg.FixtureFile)
	} else {
		source = NewLiveSource(NewClient(cfg.OktaBaseURL, cfg.OktaToken, cfg.Timeout))
	}

	// Sink selection follows the dc-agent/pam convention: with an adapter
	// token we POST signals to the OIAF core for risk scoring; without one we
	// fall back to structured logging (useful in offline/dev mode).
	var sink Sink
	if cfg.AdapterToken != "" {
		sink = NewEvaluateSink(cfg.ServerURL, cfg.AdapterToken, cfg.Timeout, logger, st)
	} else {
		sink = NewLogSink(logger)
		logger.Warn("OIAF_ADAPTER_TOKEN not set: logging signals locally instead of scoring them via OIAF core")
	}
	defer sink.Close()

	detector := NewDetector(cfg.signalParams())
	poller := NewPoller(source, detector, sink, st, save, cfg, logger)

	// Persist state on shutdown too, so a SIGTERM mid-run never loses cursor
	// progress made since the last save.
	defer func() {
		if err := save(); err != nil {
			logger.Error("final state save failed", "error", err)
		}
	}()

	if !st.Cursor.IsZero() {
		logger.Info("resuming from cursor", "cursor", st.Cursor.UTC().Format(time.RFC3339))
	} else {
		logger.Info("no cursor found; will read from the start of Okta log retention")
	}

	return poller.Run(ctx)
}
