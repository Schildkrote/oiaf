// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	sdk "github.com/Schildkrote/oiaf/tools/adapter-sdk"
)

// Sink delivers risk signals downstream. This mirrors how the other adapters
// feed the core (adapters/dc-agent POSTs batches with a Bearer adapter token;
// adapters/pam calls the SDK's EvaluateAccess): signals are translated into
// OIAF AccessRequests and POSTed to the core's /v1/access/evaluate, where
// core/internal/risk scores them under the adapter's bearer token. The
// adapter itself never enforces anything back into Okta — read-only in,
// decisions stay in OIAF core.
type Sink interface {
	Emit(ctx context.Context, sig Signal) error
	Close() error
}

// EvaluateSink POSTs each signal to the OIAF core as an access evaluation.
type EvaluateSink struct {
	client *sdk.Client
	logger *slog.Logger
	st     *State
}

// NewEvaluateSink builds a sink against the OIAF core REST API.
func NewEvaluateSink(serverURL, adapterToken string, timeout time.Duration, logger *slog.Logger, st *State) *EvaluateSink {
	return &EvaluateSink{
		client: sdk.New(serverURL, adapterToken, sdk.WithTimeout(timeout)),
		logger: logger,
		st:     st,
	}
}

func (s *EvaluateSink) Emit(ctx context.Context, sig Signal) error {
	req := signalToAccessRequest(sig, s.st)
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal access request: %w", err)
	}
	raw, err := s.client.EvaluateAccess(ctx, body)
	if err != nil {
		return fmt.Errorf("evaluate signal %s for %s: %w", sig.Type, sig.Login, err)
	}
	var decision struct {
		Decision  string   `json:"decision"`
		RiskScore int      `json:"risk_score"`
		Reasons   []string `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &decision); err == nil {
		s.logger.Info("okta signal scored",
			"signal", sig.Type,
			"login", sig.Login,
			"decision", decision.Decision,
			"risk_score", decision.RiskScore,
			"reasons", strings.Join(decision.Reasons, ","),
		)
	} else {
		s.logger.Info("okta signal submitted", "signal", sig.Type, "login", sig.Login)
	}
	return nil
}

func (s *EvaluateSink) Close() error { return nil }

// signalToAccessRequest maps an Okta-derived signal onto the OIAF
// AccessRequest shape the risk engine understands. Mapping decisions:
//
//   - Identity.Username: the Okta login (username/email per the design doc's
//     correlation note).
//   - Identity.Privileged: true when the identity has been seen performing
//     admin actions (state memory).
//   - Identity.UsualGeo: the identity's most frequent historical geo, so the
//     engine's geo_mismatch rule fires for impossible-travel/new-geo signals.
//   - Source.IP/Geo: from the event.
//   - Device.Managed: false — Okta System Log gives us no managed-device
//     attestation for unmanaged sign-ins; the engine's unmanaged_device rule
//     applies. For new_device signals we deliberately leave Compliant false
//     so the signal raises risk.
//   - Context.MFARecent: true only for successful MFA-adjacent events;
//     failure/deny signals set it false so no_recent_mfa adds weight.
//   - Resource.Sensitivity: high for admin actions (privilege surface),
//     medium for everything else.
//   - Protocol.Name: the Okta event type for auditability.
func signalToAccessRequest(sig Signal, st *State) map[string]any {
	sensitivity := "medium"
	privileged := false
	mfaRecent := false
	if st != nil {
		if idState, ok := st.Identities[sig.Login]; ok {
			privileged = idState.Admin
		}
	}
	switch sig.Type {
	case SignalAdminAction:
		sensitivity = "high"
	case SignalMFAFail, SignalMFADeny, SignalMFAFatigue, SignalImpossibleTravel, SignalNewDevice, SignalLegacyAuth:
		sensitivity = "high"
	}

	ident := map[string]any{
		"username":   sig.Login,
		"type":       "person",
		"privileged": privileged,
	}
	if st != nil {
		if idState, ok := st.Identities[sig.Login]; ok && idState.LastGeo != "" {
			ident["usual_geo"] = idState.LastGeo
		}
	}

	source := map[string]any{}
	if sig.IP != "" {
		source["ip"] = sig.IP
	}
	if sig.Geo != "" {
		source["geo"] = sig.Geo
	}

	req := map[string]any{
		"identity": ident,
		"resource": map[string]any{
			"type":        "okta_signin",
			"name":        "okta:" + sig.Type,
			"sensitivity": sensitivity,
		},
		"protocol": map[string]any{"name": "okta_sso"},
		"source":   source,
		"device":   map[string]any{"managed": false, "compliant": sig.Type == SignalAuthFailure},
		"context": map[string]any{
			"mfa_recent":  mfaRecent,
			"interactive": true,
		},
	}
	// NOTE: sig.Details (distance, speed, fail_count…) are logged by the sink
	// for operators; types.AccessRequest has no free-form field the risk
	// engine reads, so they are deliberately not smuggled into the request.
	return req
}

// LogSink writes signals as structured log lines instead of POSTing them.
// Used when no OIAF core token is configured (offline/mock mode), keeping the
// adapter runnable with zero external dependencies.
type LogSink struct {
	logger *slog.Logger
}

func NewLogSink(logger *slog.Logger) *LogSink { return &LogSink{logger: logger} }

func (s *LogSink) Emit(_ context.Context, sig Signal) error {
	s.logger.Warn("okta risk signal",
		"signal", sig.Type,
		"login", sig.Login,
		"time", sig.Time.UTC().Format(time.RFC3339),
		"ip", sig.IP,
		"geo", sig.Geo,
		"details", sig.Details,
	)
	return nil
}

func (s *LogSink) Close() error { return nil }
