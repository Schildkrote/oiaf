//go:build !windows

// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"log/slog"
)

func runAsWindowsService(cfg *Config, logger *slog.Logger) error {
	return runService(context.Background(), cfg, logger)
}
