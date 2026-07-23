//go:build windows

// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log/slog"
	"os"

	"golang.org/x/sys/windows/svc"
)

const serviceName = "OIAFDCAgent"

type agentService struct {
	cfg    *Config
	logger *slog.Logger
}

func (s *agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runService(ctx, s.cfg, s.logger)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-errCh
				return false, 0
			}
		case err := <-errCh:
			if err != nil {
				s.logger.Error("service error", "error", err)
			}
			return false, 0
		}
	}
}

func runAsWindowsService(cfg *Config, logger *slog.Logger) error {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return runService(context.Background(), cfg, logger)
	}
	return svc.Run(serviceName, &agentService{cfg: cfg, logger: logger})
}

func init() {
	if _, err := svc.IsWindowsService(); err == nil {
		os.Setenv("DC_AGENT_SERVICE_MODE", "windows")
	}
}
