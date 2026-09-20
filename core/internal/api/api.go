// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/audit"
	"github.com/Schildkrote/oiaf/core/internal/auth"
	"github.com/Schildkrote/oiaf/core/internal/bus"
	"github.com/Schildkrote/oiaf/core/internal/challenge"
	"github.com/Schildkrote/oiaf/core/internal/discovery"
	"github.com/Schildkrote/oiaf/core/internal/inventory"
	"github.com/Schildkrote/oiaf/core/internal/mfa"
	"github.com/Schildkrote/oiaf/core/internal/policy"
	"github.com/Schildkrote/oiaf/core/internal/risk"
	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Handler struct {
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
	logger    *slog.Logger
}

func NewHandler(store storage.Store, authSvc *auth.Authenticator, auditSvc *audit.Service, policyEngine *policy.BuiltinEngine, riskEngine *risk.RuleEngine, challengeSvc *challenge.Service, totpSvc *mfa.TOTPService, pushSvc *mfa.PushService, discoveryEngine *discovery.Engine, inventoryScanner *inventory.Scanner, busEmitter *bus.Emitter, logger *slog.Logger) *Handler {
	return &Handler{
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
		logger:    logger,
	}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authMiddleware func(http.Handler) http.Handler) {
	protected := func(fn http.HandlerFunc) http.Handler {
		return authMiddleware(http.HandlerFunc(fn))
	}

	mux.Handle("POST /v1/access/evaluate", protected(h.handleAccessEvaluate))
	mux.Handle("POST /v1/challenge/{id}/verify", protected(h.handleChallengeVerify))
	mux.Handle("GET /v1/challenges", protected(h.handleListChallenges))

	mux.Handle("GET /v1/identities", protected(h.handleListIdentities))
	mux.Handle("POST /v1/identities", protected(h.handleCreateIdentity))
	mux.Handle("GET /v1/identities/{id}", protected(h.handleGetIdentity))
	mux.Handle("PUT /v1/identities/{id}", protected(h.handleUpdateIdentity))
	mux.Handle("DELETE /v1/identities/{id}", protected(h.handleDeleteIdentity))

	mux.Handle("POST /v1/identities/{id}/factors/totp/enroll", protected(h.handleTOTPEnroll))
	mux.Handle("POST /v1/identities/{id}/factors/totp/activate", protected(h.handleTOTPActivate))

	mux.Handle("POST /v1/devices", protected(h.handleCreateDevice))
	mux.Handle("GET /v1/devices", protected(h.handleListDevices))
	mux.Handle("GET /v1/devices/{id}", protected(h.handleGetDevice))
	mux.Handle("DELETE /v1/devices/{id}", protected(h.handleDeleteDevice))
	mux.Handle("POST /v1/devices/{id}/approve-challenge", protected(h.handleApproveChallenge))

	mux.Handle("GET /v1/policies", protected(h.handleListPolicies))
	mux.Handle("POST /v1/policies", protected(h.handleCreatePolicy))
	mux.Handle("POST /v1/policies/test", protected(h.handleTestPolicy))
	mux.Handle("GET /v1/policies/{id}", protected(h.handleGetPolicy))
	mux.Handle("PUT /v1/policies/{id}", protected(h.handleUpdatePolicy))
	mux.Handle("DELETE /v1/policies/{id}", protected(h.handleDeletePolicy))

	mux.Handle("GET /v1/adapters", protected(h.handleListAdapters))
	mux.Handle("POST /v1/adapters", protected(h.handleCreateAdapter))
	mux.Handle("GET /v1/adapters/{id}", protected(h.handleGetAdapter))
	mux.Handle("DELETE /v1/adapters/{id}", protected(h.handleDeleteAdapter))
	mux.Handle("POST /v1/adapters/{id}/rotate-token", protected(h.handleRotateAdapterToken))

	mux.Handle("GET /v1/audit/events", protected(h.handleListAuditEvents))
	mux.Handle("GET /v1/audit/verify", protected(h.handleVerifyAudit))

	mux.Handle("POST /v1/ad/events", protected(h.handleADEvents))
	mux.Handle("GET /v1/ad/profiles", protected(h.handleADProfiles))
	mux.Handle("POST /v1/ad/inventory/scan", protected(h.handleADInventoryScan))
}

func (h *Handler) handleAccessEvaluate(w http.ResponseWriter, r *http.Request) {
	var req types.AccessRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	riskResult, err := h.risk.Score(ctx, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "risk scoring failed")
		return
	}

	policyDecision, err := h.policy.Evaluate(ctx, req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	requestID := types.NewID()
	decision := policyDecision.Effect
	reasons := append(policyDecision.Reasons, riskResult.Reasons...)
	var challengeInfo *types.ChallengeInfo

	if riskResult.Level == "critical" {
		decision = types.DecisionDeny
		reasons = append(reasons, "risk_level_critical_override")
	} else if riskResult.Level == "very_high" && decision != types.DecisionDeny {
		decision = types.DecisionChallenge
		reasons = append(reasons, "risk_level_very_high_challenge")
	}

	switch decision {
	case types.DecisionChallenge:
		methods := []types.MFAMethod{types.MFAMethodTOTP}
		if policyDecision.Challenge != nil && len(policyDecision.Challenge.Methods) > 0 {
			methods = policyDecision.Challenge.Methods
		}
		identityID := req.Identity.Username
		if identity, lookupErr := h.store.Identities(ctx).GetByUsername(ctx, req.Identity.Username); lookupErr == nil {
			identityID = identity.ID
		}
		ch, err := h.challenge.Create(ctx, identityID, requestID, methods)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to create challenge")
			return
		}
		challengeInfo = &types.ChallengeInfo{
			ID:        ch.ID,
			Methods:   ch.Methods,
			ExpiresAt: ch.ExpiresAt,
		}
	case types.DecisionAlert:
		decision = types.DecisionAllow
		reasons = append(reasons, "alert_logged")
	}

	h.audit.Emit(ctx, "access.evaluate",
		types.AuditActor{Type: types.ActorUser, ID: req.Identity.Username},
		types.AuditTarget{Type: types.TargetResource, ID: req.Resource.Name},
		decision, riskResult.Score, reasons, nil)

	// Integration event (opt-in, best-effort): OIAF decisions on the OSP spine.
	if h.bus != nil {
		h.bus.Emit("access.decided", "evaluate", requestID,
			map[string]any{
				"request_id": requestID,
				"identity":   req.Identity.Username,
				"resource":   req.Resource.Name,
			},
			map[string]any{
				"decision":   decision,
				"risk_score": riskResult.Score,
				"reasons":    reasons,
			})
	}

	resp := types.AccessDecision{
		RequestID: requestID,
		Decision:  decision,
		RiskScore: riskResult.Score,
		Reasons:   reasons,
		Challenge: challengeInfo,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var body struct {
		Method    string    `json:"method"`
		Code      string    `json:"code"`
		DeviceID  string    `json:"device_id"`
		Number    int       `json:"number"`
		Signature string    `json:"signature"`
		Timestamp time.Time `json:"timestamp"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	var ch *types.Challenge
	var err error

	switch body.Method {
	case "totp":
		ch, err = h.challenge.VerifyTOTP(ctx, id, body.Code)
	case "push":
		ch, err = h.challenge.VerifyPush(ctx, id, body.DeviceID, body.Number, body.Signature, body.Timestamp)
	default:
		writeError(w, http.StatusBadRequest, "unsupported method")
		return
	}

	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Integration event (opt-in, best-effort): challenge resolution on the spine.
	if h.bus != nil {
		h.bus.Emit("challenge.verified", "verify", ch.ID,
			map[string]any{"request_id": ch.RequestID, "identity_id": ch.IdentityID},
			map[string]any{"method": body.Method, "status": string(ch.Status)})
	}

	writeJSON(w, http.StatusOK, ch)
}

func (h *Handler) handleListChallenges(w http.ResponseWriter, r *http.Request) {
	challenges, err := h.challenge.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list challenges")
		return
	}
	writeJSON(w, http.StatusOK, challenges)
}

func (h *Handler) handleListIdentities(w http.ResponseWriter, r *http.Request) {
	identities, err := h.store.Identities(r.Context()).List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}
	writeJSON(w, http.StatusOK, identities)
}

func (h *Handler) handleCreateIdentity(w http.ResponseWriter, r *http.Request) {
	var identity types.Identity
	if err := decodeJSON(r, &identity); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	identity.ID = types.NewID()
	now := time.Now().UTC()
	identity.CreatedAt = now
	identity.UpdatedAt = now

	if err := h.store.Identities(r.Context()).Create(r.Context(), &identity); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create identity")
		return
	}
	writeJSON(w, http.StatusCreated, identity)
}

func (h *Handler) handleGetIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	identity, err := h.store.Identities(r.Context()).Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

func (h *Handler) handleUpdateIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	existing, err := h.store.Identities(ctx).Get(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "identity not found")
		return
	}

	var update types.Identity
	if err := decodeJSON(r, &update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	update.ID = existing.ID
	update.CreatedAt = existing.CreatedAt
	update.UpdatedAt = time.Now().UTC()

	if err := h.store.Identities(ctx).Update(ctx, &update); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update identity")
		return
	}
	writeJSON(w, http.StatusOK, update)
}

func (h *Handler) handleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.Identities(r.Context()).Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete identity")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	factor, secret, uri, err := h.totp.Enroll(ctx, id, "OIAF")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enroll totp")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"factor_id":   factor.ID,
		"secret":      secret,
		"otpauth_uri": uri,
		"status":      factor.Status,
	})
}

func (h *Handler) handleTOTPActivate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	var body struct {
		FactorID string `json:"factor_id"`
		Code     string `json:"code"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.totp.Activate(ctx, id, body.FactorID, body.Code); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "active"})
}

func (h *Handler) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IdentityID string `json:"identity_id"`
		Name       string `json:"name"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	device, secret, err := h.push.RegisterDevice(r.Context(), body.IdentityID, body.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to register device")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"device": device,
		"secret": secret,
	})
}

func (h *Handler) handleListDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := h.store.Devices(r.Context()).List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list devices")
		return
	}
	writeJSON(w, http.StatusOK, devices)
}

func (h *Handler) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	device, err := h.store.Devices(r.Context()).Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, device)
}

func (h *Handler) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.Devices(r.Context()).Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete device")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleApproveChallenge(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")

	var body struct {
		ChallengeID string    `json:"challenge_id"`
		Number      int       `json:"number"`
		Signature   string    `json:"signature"`
		Timestamp   time.Time `json:"timestamp"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	ch, err := h.challenge.VerifyPush(ctx, body.ChallengeID, deviceID, body.Number, body.Signature, body.Timestamp)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ch)
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.Policies(r.Context()).List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list policies")
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p types.Policy
	if err := decodeJSON(r, &p); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	p.ID = types.NewID()
	now := time.Now().UTC()
	p.CreatedAt = now
	p.UpdatedAt = now

	if err := h.store.Policies(r.Context()).Create(r.Context(), &p); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create policy")
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (h *Handler) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := h.store.Policies(r.Context()).Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *Handler) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	existing, err := h.store.Policies(ctx).Get(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	var update types.Policy
	if err := decodeJSON(r, &update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	update.ID = existing.ID
	update.CreatedAt = existing.CreatedAt
	update.UpdatedAt = time.Now().UTC()

	if err := h.store.Policies(ctx).Update(ctx, &update); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update policy")
		return
	}
	writeJSON(w, http.StatusOK, update)
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.Policies(r.Context()).Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleTestPolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy  types.Policy        `json:"policy"`
		Request types.AccessRequest `json:"request"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()
	decision, err := h.policy.Evaluate(ctx, body.Request)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	writeJSON(w, http.StatusOK, decision)
}

func (h *Handler) handleListAdapters(w http.ResponseWriter, r *http.Request) {
	adapters, err := h.store.Adapters(r.Context()).List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list adapters")
		return
	}
	writeJSON(w, http.StatusOK, adapters)
}

func (h *Handler) handleCreateAdapter(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name    string `json:"name"`
		Type    string `json:"type"`
		Enabled bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	token, err := auth.GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	hash, err := auth.HashToken(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash token")
		return
	}

	adapter := &types.Adapter{
		ID:        types.NewID(),
		Name:      body.Name,
		Type:      body.Type,
		TokenHash: hash,
		Enabled:   body.Enabled,
		CreatedAt: time.Now().UTC(),
	}

	if err := h.store.Adapters(r.Context()).Create(r.Context(), adapter); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create adapter")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"adapter": adapter,
		"token":   token,
	})
}

func (h *Handler) handleGetAdapter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	adapter, err := h.store.Adapters(r.Context()).Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "adapter not found")
		return
	}
	writeJSON(w, http.StatusOK, adapter)
}

func (h *Handler) handleDeleteAdapter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.Adapters(r.Context()).Delete(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete adapter")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleRotateAdapterToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()

	adapter, err := h.store.Adapters(ctx).Get(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "adapter not found")
		return
	}

	token, err := auth.GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	hash, err := auth.HashToken(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash token")
		return
	}

	adapter.TokenHash = hash
	if err := h.store.Adapters(ctx).Create(ctx, adapter); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update adapter")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"adapter": adapter,
		"token":   token,
	})
}

func (h *Handler) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filter := storage.AuditFilter{
		IdentityID:   q.Get("identity_id"),
		ResourceType: q.Get("resource_type"),
		Decision:     q.Get("decision"),
		Type:         q.Get("type"),
		Since:        q.Get("since"),
		Until:        q.Get("until"),
	}

	if v := q.Get("risk_score_min"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.RiskScoreMin = n
		}
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}

	events, err := h.audit.List(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit events")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (h *Handler) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	valid, count, err := h.audit.Verify(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "verification failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid": valid,
		"count": count,
	})
}

func (h *Handler) handleADEvents(w http.ResponseWriter, r *http.Request) {
	var batch types.ADAuthEventBatch
	if err := decodeJSON(r, &batch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx := r.Context()

	decisions, err := h.discovery.Ingest(ctx, batch.Events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "event ingestion failed")
		return
	}

	for i := range batch.Events {
		ev := &batch.Events[i]
		h.audit.Emit(ctx, "ad.auth_event",
			types.AuditActor{Type: types.ActorUser, ID: ev.AccountName},
			types.AuditTarget{Type: types.TargetIdentity, ID: ev.AccountSID},
			types.DecisionAllow, 0, nil,
			map[string]interface{}{
				"event_id":     ev.EventID,
				"logon_type":   ev.LogonType,
				"auth_package": ev.AuthPackage,
				"source_ip":    ev.SourceIP,
				"target_spn":   ev.TargetSPN,
				"dc_name":      ev.DCName,
				"event_type":   ev.EventType,
			},
		)
	}

	for _, d := range decisions {
		h.audit.Emit(ctx, "ad.baseline_deviation",
			types.AuditActor{Type: types.ActorUser, ID: d.AccountName},
			types.AuditTarget{Type: types.TargetIdentity, ID: d.AccountSID},
			d.Decision, d.RiskScore, d.Reasons, nil,
		)
	}

	writeJSON(w, http.StatusAccepted, types.ADAuthEventBatchResponse{
		Accepted:  len(batch.Events),
		Decisions: decisions,
	})
}

func (h *Handler) handleADProfiles(w http.ResponseWriter, r *http.Request) {
	profiles, err := h.discovery.Profiles(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list profiles")
		return
	}
	writeJSON(w, http.StatusOK, profiles)
}

func (h *Handler) handleADInventoryScan(w http.ResponseWriter, r *http.Request) {
	if h.inventory == nil {
		writeError(w, http.StatusServiceUnavailable, "inventory scanner not configured")
		return
	}

	summary, err := h.inventory.Scan(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "inventory scan failed: "+err.Error())
		return
	}

	h.audit.Emit(r.Context(), "ad.inventory_scan",
		types.AuditActor{Type: types.ActorSystem, ID: "oiaf"},
		types.AuditTarget{Type: types.TargetIdentity, ID: "ad-inventory"},
		types.DecisionAllow, 0, nil,
		map[string]interface{}{
			"total_accounts":      summary.TotalAccounts,
			"service_accounts":    summary.ServiceAccounts,
			"privileged_accounts": summary.PrivilegedAccounts,
			"stale_accounts":      summary.StaleAccounts,
		},
	)

	writeJSON(w, http.StatusOK, summary)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
