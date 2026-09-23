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
	// The credential scrubber is installed BEFORE any logging happens, because the
	// first thing this process can do is fail — and a config-load failure is
	// exactly the kind of error string that can echo the token it failed to parse.
	//
	// The token is resolved here from the same precedence loadConfig uses
	// (OIAF_OKTA_TOKEN, then OKTA_API_TOKEN) so the scrubber is live even when
	// loadConfig itself is what fails. loadConfig may still fill the token in from
	// the YAML config file afterwards; rebindRedaction below keeps the scrubber
	// pointed at whatever token ends up actually being used.
	//
	// INVARIANT THIS RELIES ON: cfg.OktaToken is assigned only during loadConfig
	// and never refreshed at runtime (no OAuth token rotation in this adapter), so
	// a closure capturing a string is not a staleness hazard. If the adapter ever
	// grows token refresh, this must become a func() string indirection instead —
	// a captured stale token would silently stop redacting, which is a failure that
	// looks like success.
	tokenNow := envOr("OIAF_OKTA_TOKEN", os.Getenv("OKTA_API_TOKEN"))
	redact := func(s string) string { return redactCredential(s, tokenNow) }

	handler := newRedactingHandler(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		redact)
	logger := slog.New(handler)
	slog.SetDefault(logger)

	cfg, err := loadConfig()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// The YAML config file may have supplied a token the env did not. Rebind the
	// logger's scrubber to the token actually in use, so nothing downstream logs
	// against a credential the scrubber does not know about.
	if cfg.OktaToken != tokenNow {
		logger = rebindRedaction(logger, cfg.OktaToken)
		slog.SetDefault(logger)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, logger); err != nil {
		logger.Error("adapter error", "error", err)
		os.Exit(1)
	}
}

// rebindRedaction rebuilds a logger whose handler scrubs `token` instead of the
// token captured at startup. It returns the original logger unchanged when the
// handler is not one of ours, so a caller that swapped in its own handler is
// never silently wrapped twice.
func rebindRedaction(logger *slog.Logger, token string) *slog.Logger {
	h, ok := logger.Handler().(*redactingHandler)
	if !ok {
		return logger
	}
	return slog.New(&redactingHandler{
		inner:  h.inner,
		redact: func(s string) string { return redactCredential(s, token) },
	})
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
