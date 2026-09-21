// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/audit"
	"github.com/Schildkrote/oiaf/core/internal/auth"
	"github.com/Schildkrote/oiaf/core/internal/challenge"
	"github.com/Schildkrote/oiaf/core/internal/mfa"
	"github.com/Schildkrote/oiaf/core/internal/policy"
	"github.com/Schildkrote/oiaf/core/internal/risk"
	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
	"github.com/Schildkrote/oiaf/core/internal/webauthntest"
)

// ceremonyOptions mirrors the JSON shape of the begin endpoints: the library's
// publicKey options plus the factor binding.
type ceremonyOptions struct {
	FactorID  string `json:"factor_id"`
	Status    string `json:"status"`
	PublicKey struct {
		Challenge      string `json:"challenge"`
		RelyingPartyID string `json:"rpId"`
		RelyingParty   struct {
			ID string `json:"id"`
		} `json:"rp"`
	} `json:"publicKey"`
}

// newWebAuthnTestHandler builds an API handler with the WebAuthn factor
// enabled over a memory store. Auth middleware is pass-through: these tests
// cover endpoint wiring, not token handling (auth has its own tests).
func newWebAuthnTestHandler(t *testing.T) (http.Handler, storage.Store, *mfa.WebAuthnService) {
	t.Helper()
	store := storage.NewMemoryStore()
	authSvc := auth.New(store)
	auditSvc := audit.New(store)
	policyEngine := policy.NewBuiltinEngine(store)
	riskEngine := risk.NewRuleEngine(risk.DefaultThresholds())
	totpSvc := mfa.NewTOTPService(store)
	pushSvc := mfa.NewPushService(store, 60)
	webauthnSvc, err := mfa.NewWebAuthnService(store, mfa.WebAuthnSettings{
		RPID:          webauthntest.RPID,
		RPDisplayName: "OIAF Test",
		RPOrigins:     []string{webauthntest.Origin},
	})
	if err != nil {
		t.Fatal(err)
	}
	challengeSvc := challenge.New(store, totpSvc, pushSvc, webauthnSvc, auditSvc, 300, 5)
	handler := NewHandler(store, authSvc, auditSvc, policyEngine, riskEngine, challengeSvc, totpSvc, pushSvc, webauthnSvc, nil, nil, nil, slog.Default())

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux, func(next http.Handler) http.Handler { return next })
	return mux, store, webauthnSvc
}

func doRaw(t *testing.T, h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// enrollIdentityWebAuthn registers an active credential via the REST
// endpoints and returns the software authenticator holding its private key.
func enrollIdentityWebAuthn(t *testing.T, h http.Handler, store storage.Store, identityID string) *webauthntest.Authenticator {
	t.Helper()
	authenticator := webauthntest.NewAuthenticator()

	w := doRaw(t, h, http.MethodPost, "/v1/identities/"+identityID+"/factors/webauthn/registration/begin", []byte(`{}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("registration begin: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var beginResp ceremonyOptions
	if err := json.Unmarshal(w.Body.Bytes(), &beginResp); err != nil {
		t.Fatal(err)
	}
	if beginResp.FactorID == "" {
		t.Fatal("expected factor_id in begin response")
	}
	if beginResp.Status != string(types.FactorStatusPendingActivation) {
		t.Fatalf("expected pending_activation, got %s", beginResp.Status)
	}

	payload := authenticator.CreationResponse(beginResp.PublicKey.Challenge, webauthntest.Origin, beginResp.PublicKey.RelyingParty.ID)
	w = doRaw(t, h, http.MethodPost, "/v1/identities/"+identityID+"/factors/webauthn/registration/"+beginResp.FactorID+"/finish", payload)
	if w.Code != http.StatusOK {
		t.Fatalf("registration finish: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var finishResp struct {
		FactorID string `json:"factor_id"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &finishResp); err != nil {
		t.Fatal(err)
	}
	if finishResp.Status != string(types.FactorStatusActive) {
		t.Fatalf("expected active, got %s", finishResp.Status)
	}

	// The factor must be persisted and active in the store.
	factors, err := store.Factors(t.Context()).ListByIdentity(t.Context(), identityID)
	if err != nil {
		t.Fatal(err)
	}
	if len(factors) != 1 || factors[0].Status != types.FactorStatusActive {
		t.Fatalf("expected 1 active factor, got %+v", factors)
	}
	return authenticator
}

func TestWebAuthnEndpointsRegistrationAndVerification(t *testing.T) {
	h, store, _ := newWebAuthnTestHandler(t)

	authenticator := enrollIdentityWebAuthn(t, h, store, "id-1")

	// Identity-scoped verification begin returns assertion options.
	w := doRaw(t, h, http.MethodPost, "/v1/identities/id-1/factors/webauthn/verification/begin", []byte(`{}`))
	if w.Code != http.StatusOK {
		t.Fatalf("verification begin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var beginResp ceremonyOptions
	if err := json.Unmarshal(w.Body.Bytes(), &beginResp); err != nil {
		t.Fatal(err)
	}
	if beginResp.PublicKey.Challenge == "" {
		t.Fatal("expected challenge in verification begin")
	}

	// Finish with the signed assertion.
	assertion := authenticator.AssertionResponse(beginResp.PublicKey.Challenge, webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	w = doRaw(t, h, http.MethodPost, "/v1/identities/id-1/factors/webauthn/verification/finish", assertion)
	if w.Code != http.StatusOK {
		t.Fatalf("verification finish: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var verifyResp struct {
		Verified bool `json:"verified"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &verifyResp); err != nil {
		t.Fatal(err)
	}
	if !verifyResp.Verified {
		t.Fatal("expected verified=true")
	}
}

func TestWebAuthnChallengeEndpoints(t *testing.T) {
	h, store, _ := newWebAuthnTestHandler(t)
	ctx := t.Context()

	authenticator := enrollIdentityWebAuthn(t, h, store, "id-1")

	// Create a webauthn challenge directly in the store (as the policy path
	// in /v1/access/evaluate would).
	ch := &types.Challenge{
		ID:          types.NewID(),
		IdentityID:  "id-1",
		RequestID:   "req-1",
		Methods:     []types.MFAMethod{types.MFAMethodWebAuthn},
		Status:      types.ChallengeStatusPending,
		Nonce:       types.NewID(),
		MaxAttempts: 5,
		ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.Challenges(ctx).Create(ctx, ch); err != nil {
		t.Fatal(err)
	}

	// Begin returns raw CredentialAssertion options JSON.
	w := doRaw(t, h, http.MethodPost, "/v1/challenge/"+ch.ID+"/webauthn/begin", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge begin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var assertion ceremonyOptions
	if err := json.Unmarshal(w.Body.Bytes(), &assertion); err != nil {
		t.Fatal(err)
	}
	if assertion.PublicKey.Challenge == "" {
		t.Fatalf("expected challenge in assertion options: %s", w.Body.String())
	}

	// Finish with a valid signed response approves the challenge.
	payload := authenticator.AssertionResponse(assertion.PublicKey.Challenge, webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	w = doRaw(t, h, http.MethodPost, "/v1/challenge/"+ch.ID+"/webauthn/finish", payload)
	if w.Code != http.StatusOK {
		t.Fatalf("challenge finish: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resolved types.Challenge
	if err := json.Unmarshal(w.Body.Bytes(), &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.Status != types.ChallengeStatusApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}
	// Session state must never leak to clients.
	if bytes.Contains(w.Body.Bytes(), []byte("WebAuthnSession")) || resolved.WebAuthnSession != "" {
		t.Fatal("challenge response must not expose webauthn session state")
	}
}

func TestWebAuthnChallengeBeginRejectsWrongMethod(t *testing.T) {
	h, store, _ := newWebAuthnTestHandler(t)
	ctx := t.Context()

	enrollIdentityWebAuthn(t, h, store, "id-1")

	ch := &types.Challenge{
		ID:          types.NewID(),
		IdentityID:  "id-1",
		RequestID:   "req-1",
		Methods:     []types.MFAMethod{types.MFAMethodTOTP},
		Status:      types.ChallengeStatusPending,
		MaxAttempts: 5,
		ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.Challenges(ctx).Create(ctx, ch); err != nil {
		t.Fatal(err)
	}

	w := doRaw(t, h, http.MethodPost, "/v1/challenge/"+ch.ID+"/webauthn/begin", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for totp-only challenge, got %d: %s", w.Code, w.Body.String())
	}
}

func TestWebAuthnEndpointsUnconfiguredReturns503(t *testing.T) {
	// Handler with a nil WebAuthn service (factor disabled).
	store := storage.NewMemoryStore()
	authSvc := auth.New(store)
	auditSvc := audit.New(store)
	handler := NewHandler(store, authSvc, auditSvc, policy.NewBuiltinEngine(store), risk.NewRuleEngine(risk.DefaultThresholds()),
		challenge.New(store, mfa.NewTOTPService(store), mfa.NewPushService(store, 60), nil, auditSvc, 300, 5),
		mfa.NewTOTPService(store), mfa.NewPushService(store, 60), nil, nil, nil, nil, slog.Default())
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux, func(next http.Handler) http.Handler { return next })

	for _, path := range []string{
		"/v1/identities/id-1/factors/webauthn/registration/begin",
		"/v1/identities/id-1/factors/webauthn/verification/begin",
		"/v1/identities/id-1/factors/webauthn/verification/finish",
		"/v1/challenge/ch-1/webauthn/begin",
		"/v1/challenge/ch-1/webauthn/finish",
	} {
		w := doRaw(t, mux, http.MethodPost, path, []byte(`{}`))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: expected 503, got %d: %s", path, w.Code, w.Body.String())
		}
	}
}

func TestWebAuthnFinishRegistrationUnknownFactor(t *testing.T) {
	h, _, _ := newWebAuthnTestHandler(t)

	payload := []byte(`{"id":"eA","rawId":"eA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YUQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB9"}}`)
	w := doRaw(t, h, http.MethodPost, "/v1/identities/id-1/factors/webauthn/registration/unknown-factor/finish", payload)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown factor, got %d: %s", w.Code, w.Body.String())
	}
}
