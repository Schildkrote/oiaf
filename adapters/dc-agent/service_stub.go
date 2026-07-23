//go:build !windows

// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
)

func runAsWindowsService(cfg *Config, logger *slog.Logger) error {
	return runService(context.Background(), cfg, logger)
}
