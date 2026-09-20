// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package challenge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Schildkrote/oiaf/core/internal/audit"
	"github.com/Schildkrote/oiaf/core/internal/mfa"
	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
	"github.com/Schildkrote/oiaf/core/internal/webauthntest"
)

// newWebAuthnTestService wires a challenge orchestrator with an enabled
// WebAuthn factor over a memory store.
func newWebAuthnTestService(t *testing.T) (*Service, *mfa.WebAuthnService, storage.Store) {
	t.Helper()
	store := storage.NewMemoryStore()
	auditSvc := audit.New(store)
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
	svc := New(store, totpSvc, pushSvc, webauthnSvc, auditSvc, 300, 5)
	return svc, webauthnSvc, store
}

// enrollWebAuthn registers an active WebAuthn credential for an identity and
// returns the software authenticator holding its private key.
func enrollWebAuthn(t *testing.T, ctx context.Context, webauthnSvc *mfa.WebAuthnService, identityID string) *webauthntest.Authenticator {
	t.Helper()
	auth := webauthntest.NewAuthenticator()

	factor, creation, err := webauthnSvc.BeginRegistration(ctx, identityID)
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.CreationResponse(creation.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(payload))
	if _, err := webauthnSvc.FinishRegistration(ctx, identityID, factor.ID, req); err != nil {
		t.Fatal(err)
	}
	return auth
}

func TestWebAuthnChallengeEndToEnd(t *testing.T) {
	ctx := context.Background()
	svc, webauthnSvc, store := newWebAuthnTestService(t)

	auth := enrollWebAuthn(t, ctx, webauthnSvc, "id-1")

	// A policy selects the webauthn method; the orchestrator creates a
	// challenge for it.
	ch, err := svc.Create(ctx, "id-1", "req-1", []types.MFAMethod{types.MFAMethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Status != types.ChallengeStatusPending {
		t.Fatalf("expected pending, got %s", ch.Status)
	}

	// Begin the assertion ceremony; the session must ride on the challenge.
	optionsJSON, err := svc.BeginWebAuthn(ctx, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	var creation protocol.CredentialAssertion
	if err := json.Unmarshal(optionsJSON, &creation); err != nil {
		t.Fatal(err)
	}
	if creation.Response.RelyingPartyID != webauthntest.RPID {
		t.Fatalf("unexpected rp id %q", creation.Response.RelyingPartyID)
	}

	stored, err := store.Challenges(ctx).Get(ctx, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.WebAuthnSession == "" {
		t.Fatal("expected ceremony session stored on challenge")
	}

	// Finish with a real signed assertion for the ceremony challenge.
	assertion := auth.AssertionResponse(creation.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(assertion))
	resolved, err := svc.FinishWebAuthn(ctx, ch.ID, req)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Status != types.ChallengeStatusApproved {
		t.Fatalf("expected approved, got %s", resolved.Status)
	}
	if resolved.ResolvedAt == nil {
		t.Fatal("expected resolved_at to be set")
	}

	// The ceremony session is cleared (single use).
	after, err := store.Challenges(ctx).Get(ctx, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.WebAuthnSession != "" {
		t.Fatal("expected ceremony session cleared after resolution")
	}
}

func TestWebAuthnChallengeFinishWithoutBegin(t *testing.T) {
	ctx := context.Background()
	svc, webauthnSvc, _ := newWebAuthnTestService(t)
	enrollWebAuthn(t, ctx, webauthnSvc, "id-1")

	ch, err := svc.Create(ctx, "id-1", "req-1", []types.MFAMethod{types.MFAMethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	if _, err := svc.FinishWebAuthn(ctx, ch.ID, req); err == nil {
		t.Fatal("expected error finishing without begin")
	}
}

func TestWebAuthnChallengeRejectsOtherMethodPolicy(t *testing.T) {
	ctx := context.Background()
	svc, webauthnSvc, _ := newWebAuthnTestService(t)
	enrollWebAuthn(t, ctx, webauthnSvc, "id-1")

	// A TOTP-only challenge must not accept the webauthn path.
	ch, err := svc.Create(ctx, "id-1", "req-1", []types.MFAMethod{types.MFAMethodTOTP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BeginWebAuthn(ctx, ch.ID); err == nil {
		t.Fatal("expected error for challenge that does not allow webauthn")
	}
}

func TestWebAuthnChallengeBadSignatureFails(t *testing.T) {
	ctx := context.Background()
	svc, webauthnSvc, store := newWebAuthnTestService(t)
	enrollWebAuthn(t, ctx, webauthnSvc, "id-1")

	ch, err := svc.Create(ctx, "id-1", "req-1", []types.MFAMethod{types.MFAMethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}
	optionsJSON, err := svc.BeginWebAuthn(ctx, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	var creation protocol.CredentialAssertion
	if err := json.Unmarshal(optionsJSON, &creation); err != nil {
		t.Fatal(err)
	}

	// An impostor authenticator signs with the right challenge but an
	// unregistered credential; the ceremony must fail and consume an attempt.
	impostor := webauthntest.NewAuthenticator()
	assertion := impostor.AssertionResponse(creation.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID, []byte("id-1"))
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(assertion))
	if _, err := svc.FinishWebAuthn(ctx, ch.ID, req); err == nil {
		t.Fatal("expected error for impostor assertion")
	}

	stored, err := store.Challenges(ctx).Get(ctx, ch.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Attempts != 1 {
		t.Fatalf("expected 1 attempt consumed, got %d", stored.Attempts)
	}
	if stored.Status != types.ChallengeStatusPending {
		t.Fatalf("expected still pending, got %s", stored.Status)
	}
}

func TestWebAuthnChallengeNilServiceFailsCleanly(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	// Orchestrator without a WebAuthn service (factor disabled in config).
	svc := New(store, mfa.NewTOTPService(store), mfa.NewPushService(store, 60), nil, audit.New(store), 300, 5)

	ch, err := svc.Create(ctx, "id-1", "req-1", []types.MFAMethod{types.MFAMethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BeginWebAuthn(ctx, ch.ID); err == nil {
		t.Fatal("expected error when webauthn factor not configured")
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{}`)))
	if _, err := svc.FinishWebAuthn(ctx, ch.ID, req); err == nil {
		t.Fatal("expected error when webauthn factor not configured")
	}
}

func TestWebAuthnChallengeExpired(t *testing.T) {
	ctx := context.Background()
	svc, webauthnSvc, store := newWebAuthnTestService(t)
	enrollWebAuthn(t, ctx, webauthnSvc, "id-1")

	ch, err := svc.Create(ctx, "id-1", "req-1", []types.MFAMethod{types.MFAMethodWebAuthn})
	if err != nil {
		t.Fatal(err)
	}
	// Force the challenge into the past.
	ch.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := store.Challenges(ctx).Update(ctx, ch); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BeginWebAuthn(ctx, ch.ID); err == nil {
		t.Fatal("expected error for expired challenge")
	}
}
