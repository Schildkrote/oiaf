// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

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

	if err := runService(ctx, cfg, logger); err != nil {
		logger.Error("service error", "error", err)
		os.Exit(1)
	}
}

func runService(ctx context.Context, cfg *Config, logger *slog.Logger) error {
	sender := NewSender(cfg.ServerURL, cfg.AdapterToken, cfg.BatchSize, time.Duration(cfg.BatchIntervalSec)*time.Second, logger)
	defer sender.Close()

	source, err := NewEventSource(cfg, logger)
	if err != nil {
		return err
	}
	defer source.Close()

	logger.Info("dc-agent started",
		"server", cfg.ServerURL,
		"batch_size", cfg.BatchSize,
		"event_ids", cfg.EventIDs,
	)

	events := make(chan EventRecord, cfg.BatchSize*2)

	go func() {
		if err := source.Subscribe(ctx, events); err != nil && ctx.Err() == nil {
			logger.Error("event source error", "error", err)
		}
	}()

	batch := make([]EventRecord, 0, cfg.BatchSize)
	ticker := time.NewTicker(time.Duration(cfg.BatchIntervalSec) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				sender.Flush(ctx, batch)
			}
			logger.Info("dc-agent stopped")
			return nil

		case ev, ok := <-events:
			if !ok {
				if len(batch) > 0 {
					sender.Flush(ctx, batch)
				}
				return nil
			}
			batch = append(batch, ev)
			if len(batch) >= cfg.BatchSize {
				sender.Flush(ctx, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				sender.Flush(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}
