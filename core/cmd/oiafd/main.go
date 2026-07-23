// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/audit"
	"github.com/Schildkrote/oiaf/core/internal/auth"
	"github.com/Schildkrote/oiaf/core/internal/challenge"
	"github.com/Schildkrote/oiaf/core/internal/config"
	"github.com/Schildkrote/oiaf/core/internal/discovery"
	"github.com/Schildkrote/oiaf/core/internal/inventory"
	"github.com/Schildkrote/oiaf/core/internal/logging"
	"github.com/Schildkrote/oiaf/core/internal/mfa"
	"github.com/Schildkrote/oiaf/core/internal/policy"
	"github.com/Schildkrote/oiaf/core/internal/risk"
	"github.com/Schildkrote/oiaf/core/internal/server"
	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	logger := logging.Setup(cfg.Server.LogLevel, cfg.Server.LogFormat)

	store := storage.NewMemoryStore()
	defer store.Close()

	if err := ensureToken(cfg.AdminToken(), "OIAF_ADMIN_TOKEN", "admin-token", logger); err != nil {
		logger.Error("failed to ensure admin token", "error", err)
		os.Exit(1)
	}
	if err := ensureToken(cfg.AdapterToken(), "OIAF_ADAPTER_TOKEN", "adapter-token", logger); err != nil {
		logger.Error("failed to ensure adapter token", "error", err)
		os.Exit(1)
	}

	authSvc := auth.New(store)
	auditSvc := audit.New(store)
	policyEngine := policy.NewBuiltinEngine(store)
	riskEngine := risk.NewRuleEngine(risk.Thresholds{
		Low:      cfg.Risk.Thresholds.Low,
		Elevated: cfg.Risk.Thresholds.Elevated,
		High:     cfg.Risk.Thresholds.High,
		VeryHigh: cfg.Risk.Thresholds.VeryHigh,
	})
	totpSvc := mfa.NewTOTPService(store)
	pushSvc := mfa.NewPushService(store, cfg.Security.PushTimestampSkewSeconds)
	challengeSvc := challenge.New(store, totpSvc, pushSvc, auditSvc, cfg.Security.ChallengeTTLSeconds, cfg.Security.TOTPMaxAttempts)

	discoveryEngine := discovery.NewEngine(store, discovery.DefaultWeights())

	var inventoryScanner *inventory.Scanner
	if cfg.AD.LDAPURL != "" {
		inventoryScanner = inventory.NewScanner(inventory.Config{
			LDAPURL:            cfg.AD.LDAPURL,
			BindDN:             cfg.AD.BindDN,
			BindPassword:       cfg.AD.BindPassword,
			BaseDN:             cfg.AD.BaseDN,
			InsecureSkipVerify: cfg.AD.InsecureSkipVerify,
		}, store)
	}

	ctx := context.Background()
	if _, err := authSvc.RegisterToken(ctx, cfg.AdminToken(), "admin", types.RoleAdmin); err != nil {
		logger.Error("failed to register admin token", "error", err)
		os.Exit(1)
	}
	if _, err := authSvc.RegisterToken(ctx, cfg.AdapterToken(), "adapter", types.RoleAdapter); err != nil {
		logger.Error("failed to register adapter token", "error", err)
		os.Exit(1)
	}

	srv := server.New(cfg, store, logger, authSvc, auditSvc, policyEngine, riskEngine, challengeSvc, totpSvc, pushSvc, discoveryEngine, inventoryScanner)

	runCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	case <-runCtx.Done():
		logger.Info("shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}

func ensureToken(current, envKey, fileName string, logger *slog.Logger) error {
	if current != "" {
		return nil
	}

	token, err := generateToken()
	if err != nil {
		return err
	}

	dir := ".oiaf"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return err
	}

	if err := os.Setenv(envKey, token); err != nil {
		return err
	}

	logger.Warn("generated a new token and saved it to disk; set the environment variable to override",
		"env", envKey, "path", path)
	return nil
}

func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
