// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/Schildkrote/oiaf/core/internal/api"
	"github.com/Schildkrote/oiaf/core/internal/audit"
	"github.com/Schildkrote/oiaf/core/internal/auth"
	"github.com/Schildkrote/oiaf/core/internal/bus"
	"github.com/Schildkrote/oiaf/core/internal/challenge"
	"github.com/Schildkrote/oiaf/core/internal/config"
	"github.com/Schildkrote/oiaf/core/internal/discovery"
	"github.com/Schildkrote/oiaf/core/internal/inventory"
	"github.com/Schildkrote/oiaf/core/internal/mfa"
	"github.com/Schildkrote/oiaf/core/internal/middleware"
	"github.com/Schildkrote/oiaf/core/internal/policy"
	"github.com/Schildkrote/oiaf/core/internal/risk"
	"github.com/Schildkrote/oiaf/core/internal/storage"
)

type Server struct {
	cfg       *config.Config
	logger    *slog.Logger
	store     storage.Store
	auth      *auth.Authenticator
	audit     *audit.Service
	policy    *policy.BuiltinEngine
	risk      *risk.RuleEngine
	challenge *challenge.Service
	totp      *mfa.TOTPService
	push      *mfa.PushService
	discovery *discovery.Engine
	inventory *inventory.Scanner
	bus       *bus.Emitter
	http      *http.Server
}

func New(cfg *config.Config, store storage.Store, logger *slog.Logger, authSvc *auth.Authenticator, auditSvc *audit.Service, policyEngine *policy.BuiltinEngine, riskEngine *risk.RuleEngine, challengeSvc *challenge.Service, totpSvc *mfa.TOTPService, pushSvc *mfa.PushService, discoveryEngine *discovery.Engine, inventoryScanner *inventory.Scanner, busEmitter *bus.Emitter) *Server {
	s := &Server{
		cfg:       cfg,
		logger:    logger,
		store:     store,
		auth:      authSvc,
		audit:     auditSvc,
		policy:    policyEngine,
		risk:      riskEngine,
		challenge: challengeSvc,
		totp:      totpSvc,
		push:      pushSvc,
		discovery: discoveryEngine,
		inventory: inventoryScanner,
		bus:       busEmitter,
	}
	s.http = &http.Server{
		Addr:    cfg.Server.Addr,
		Handler: s.Handler(),
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	mux.HandleFunc("GET /version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": "0.1.0", "name": "oiaf"})
	})

	if s.cfg.Server.MetricsEnabled {
		mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("# oiaf metrics placeholder\n"))
		})
	}

	apiHandler := api.NewHandler(s.store, s.auth, s.audit, s.policy, s.risk, s.challenge, s.totp, s.push, s.discovery, s.inventory, s.bus, s.logger)
	authMiddleware := auth.Middleware(s.auth)
	apiHandler.RegisterRoutes(mux, authMiddleware)

	if s.cfg.Server.UIEnabled {
		mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body><h1>OIAF Admin UI</h1><p>Coming soon.</p></body></html>"))
		})
	}

	var handler http.Handler = mux
	handler = middleware.RequestLogger(s.logger)(handler)
	handler = middleware.BodyLimit(1 << 20)(handler)
	handler = middleware.Recover(s.logger)(handler)
	handler = middleware.SecurityHeaders(handler)
	handler = middleware.RequestID(handler)

	return handler
}

func (s *Server) Start() error {
	s.logger.Info("starting server", "addr", s.cfg.Server.Addr)
	if s.cfg.Server.TLSCertFile != "" && s.cfg.Server.TLSKeyFile != "" {
		return s.http.ListenAndServeTLS(s.cfg.Server.TLSCertFile, s.cfg.Server.TLSKeyFile)
	}
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
