// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
	"github.com/Schildkrote/oiaf/core/internal/webauthntest"
)

func testSettings() WebAuthnSettings {
	return WebAuthnSettings{
		RPID:          webauthntest.RPID,
		RPDisplayName: "OIAF Test",
		RPOrigins:     []string{webauthntest.Origin},
	}
}

func newTestService(t *testing.T) (*WebAuthnService, storage.Store) {
	t.Helper()
	store := storage.NewMemoryStore()
	svc, err := NewWebAuthnService(store, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func rawRequest(payload []byte) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
}

// registerCredential runs a full registration ceremony with a software
// authenticator and returns the active factor plus the authenticator holding
// the private key (needed to sign assertions later).
func registerCredential(t *testing.T, svc *WebAuthnService, ctx context.Context, identityID string) (*types.Factor, *webauthntest.Authenticator) {
	t.Helper()
	auth := webauthntest.NewAuthenticator()

	factor, creation, err := svc.BeginRegistration(ctx, identityID)
	if err != nil {
		t.Fatal(err)
	}
	if factor.Status != types.FactorStatusPendingActivation {
		t.Fatalf("expected pending_activation, got %s", factor.Status)
	}
	if factor.Method != types.MFAMethodWebAuthn {
		t.Fatalf("expected webauthn, got %s", factor.Method)
	}
	if creation.Response.RelyingParty.ID != webauthntest.RPID {
		t.Fatalf("unexpected rp id: %s", creation.Response.RelyingParty.ID)
	}

	payload := auth.CreationResponse(creation.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID)
	factor, err = svc.FinishRegistration(ctx, identityID, factor.ID, rawRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if factor.Status != types.FactorStatusActive {
		t.Fatalf("expected active, got %s", factor.Status)
	}
	return factor, auth
}

func TestWebAuthnNewServiceRejectsMissingOrigins(t *testing.T) {
	store := storage.NewMemoryStore()
	if _, err := NewWebAuthnService(store, WebAuthnSettings{RPID: "localhost"}); err == nil {
		t.Fatal("expected error for missing origins")
	}
}

func TestWebAuthnBeginRegistrationCreatesPendingFactor(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	factor, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if factor.Status != types.FactorStatusPendingActivation {
		t.Fatalf("expected pending_activation, got %s", factor.Status)
	}
	// The pending factor holds the serialized ceremony session.
	var session map[string]any
	if err := json.Unmarshal(factor.Credentials, &session); err != nil {
		t.Fatalf("pending factor credentials must hold session JSON: %v", err)
	}
	if len(creation.Response.Challenge) < 16 {
		t.Fatal("expected a challenge of at least 16 bytes")
	}

	stored, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != types.FactorStatusPendingActivation {
		t.Fatalf("stored factor expected pending_activation, got %s", stored.Status)
	}
}

func TestWebAuthnRegistrationFullCeremony(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	factor, _ := registerCredential(t, svc, ctx, "id-1")

	stored, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != types.FactorStatusActive {
		t.Fatalf("expected active, got %s", stored.Status)
	}
	// After finish, Credentials must hold the credential record, not the session.
	var credential map[string]any
	if err := json.Unmarshal(stored.Credentials, &credential); err != nil {
		t.Fatalf("active factor credentials must hold credential JSON: %v", err)
	}
	if _, ok := credential["id"]; !ok {
		t.Fatal("expected credential record with id field")
	}
	if _, ok := credential["challenge"]; ok {
		t.Fatal("credential record must not retain the ceremony session")
	}
}

func TestWebAuthnFinishRegistrationWrongIdentity(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	factor, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	auth := webauthntest.NewAuthenticator()
	payload := auth.CreationResponse(creation.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID)

	if _, err := svc.FinishRegistration(ctx, "id-other", factor.ID, rawRequest(payload)); err == nil {
		t.Fatal("expected error for foreign identity")
	}
}

func TestWebAuthnFinishRegistrationTwice(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	factor, _ := registerCredential(t, svc, ctx, "id-1")

	payload := []byte(`{"id":"x","rawId":"eA","type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YUQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB9"}}`)
	if _, err := svc.FinishRegistration(ctx, "id-1", factor.ID, rawRequest(payload)); err == nil {
		t.Fatal("expected error finishing an already active factor")
	}
}

func TestWebAuthnFinishRegistrationBadOrigin(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	factor, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	auth := webauthntest.NewAuthenticator()
	// A browser response claiming a non-allowlisted origin must be rejected.
	payload := auth.CreationResponse(creation.Response.Challenge.String(), "http://evil.example.com", webauthntest.RPID)
	if _, err := svc.FinishRegistration(ctx, "id-1", factor.ID, rawRequest(payload)); err == nil {
		t.Fatal("expected error for mismatched origin")
	}
	factorAfter, err := svc.store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if factorAfter.Status != types.FactorStatusPendingActivation {
		t.Fatalf("failed ceremony must leave factor pending, got %s", factorAfter.Status)
	}
}

func TestWebAuthnVerificationFullCeremony(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	factor, auth := registerCredential(t, svc, ctx, "id-1")

	assertion, sessionJSON, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assertion.Response.AllowedCredentials) != 1 {
		t.Fatalf("expected 1 allowed credential, got %d", len(assertion.Response.AllowedCredentials))
	}

	payload := auth.AssertionResponse(assertion.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	valid, err := svc.FinishVerification(ctx, "id-1", sessionJSON, rawRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid assertion")
	}

	// The sign counter must be persisted back onto the stored credential.
	stored, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	var credential struct {
		Authenticator struct {
			SignCount uint32 `json:"signCount"`
		} `json:"authenticator"`
	}
	if err := json.Unmarshal(stored.Credentials, &credential); err != nil {
		t.Fatal(err)
	}
	if credential.Authenticator.SignCount != 1 {
		t.Fatalf("expected sign counter 1, got %d", credential.Authenticator.SignCount)
	}
}

func TestWebAuthnVerificationBadSignature(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	registerCredential(t, svc, ctx, "id-1")

	assertion, sessionJSON, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}

	// An impostor authenticator (different credential ID and key) must fail:
	// its credential is not registered for the identity.
	impostor := webauthntest.NewAuthenticator()
	payload := impostor.AssertionResponse(assertion.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	valid, err := svc.FinishVerification(ctx, "id-1", sessionJSON, rawRequest(payload))
	if valid || err == nil {
		t.Fatalf("expected invalid assertion for impostor key, got valid=%v err=%v", valid, err)
	}
}

func TestWebAuthnVerificationReplayedAssertion(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	_, auth := registerCredential(t, svc, ctx, "id-1")

	// Ceremony 1: valid assertion.
	assertion1, session1, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.AssertionResponse(assertion1.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	valid, err := svc.FinishVerification(ctx, "id-1", session1, rawRequest(payload))
	if err != nil || !valid {
		t.Fatalf("expected first ceremony to succeed: valid=%v err=%v", valid, err)
	}

	// Ceremony 2: replaying the ceremony-1 payload must fail because the
	// fresh ceremony binds a different challenge.
	_, session2, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	valid, err = svc.FinishVerification(ctx, "id-1", session2, rawRequest(payload))
	if valid || err == nil {
		t.Fatalf("expected replayed assertion to fail, got valid=%v err=%v", valid, err)
	}
}

func TestWebAuthnBeginVerificationWithoutCredentials(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)

	if _, _, err := svc.BeginVerification(ctx, "nobody"); err == nil {
		t.Fatal("expected error for identity without credentials")
	}
}

func TestWebAuthnIdentityScopedCeremony(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	_, auth := registerCredential(t, svc, ctx, "id-1")

	// Finish without a parked session must fail.
	if _, err := svc.FinishIdentityVerification(ctx, "id-2", rawRequest([]byte(`{}`))); err == nil {
		t.Fatal("expected error without parked session")
	}

	assertion, err := svc.BeginIdentityVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}

	payload := auth.AssertionResponse(assertion.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	valid, err := svc.FinishIdentityVerification(ctx, "id-1", rawRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid identity-scoped assertion")
	}

	// The parked session is single-use.
	if _, err := svc.FinishIdentityVerification(ctx, "id-1", rawRequest(payload)); err == nil {
		t.Fatal("expected error replaying a consumed session")
	}
}

func TestWebAuthnMultipleCredentials(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	_, auth1 := registerCredential(t, svc, ctx, "id-1")
	registerCredential(t, svc, ctx, "id-1")

	assertion, sessionJSON, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assertion.Response.AllowedCredentials) != 2 {
		t.Fatalf("expected 2 allowed credentials, got %d", len(assertion.Response.AllowedCredentials))
	}

	// Either credential can satisfy the ceremony.
	payload := auth1.AssertionResponse(assertion.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	valid, err := svc.FinishVerification(ctx, "id-1", sessionJSON, rawRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid assertion with first of two credentials")
	}
}

func TestWebAuthnUserHandleUsesIdentityID(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	// An identity record with a display name must surface in registration
	// options, while the user handle stays the raw identity ID (opaque, per
	// RFC 8266 — authorization must not bind to display names).
	identity := &types.Identity{
		ID:          "id-1",
		Username:    "alice",
		DisplayName: "Alice Example",
		Type:        types.IdentityTypePerson,
	}
	if err := store.Identities(ctx).Create(ctx, identity); err != nil {
		t.Fatal(err)
	}

	_, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	userEntity := creation.Response.User
	if userEntity.DisplayName != "Alice Example" {
		t.Fatalf("expected display name Alice Example, got %q", userEntity.DisplayName)
	}
	handle, ok := userEntity.ID.(protocol.URLEncodedBase64)
	if !ok {
		t.Fatalf("unexpected user id type %T", userEntity.ID)
	}
	if string(handle) != "id-1" {
		t.Fatalf("expected user handle id-1, got %q", string(handle))
	}
}
