// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// --- Cross-user credential scoping ---------------------------------------
//
// These are the regression net for the property that keeps WebAuthn from
// becoming an account-takeover primitive: a credential registered to identity A
// must never satisfy a ceremony for identity B. The go-webauthn library
// enforces this (session.UserID == user.WebAuthnID, allowed-credential
// ownership, and credential lookup scoped to the user's own credentials), so
// these tests pass today. They exist so that a future "simplification" of
// WebAuthnService.user() — for example loading all factors instead of
// ListByIdentity — fails loudly rather than silently allowing cross-user
// assertion replay.

func TestWebAuthnCrossUserCredentialRejected(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	for _, id := range []struct{ id, user string }{{"id-alice", "alice"}, {"id-bob", "bob"}} {
		identity := &types.Identity{
			ID: id.id, Username: id.user, Type: types.IdentityTypePerson,
		}
		if err := store.Identities(ctx).Create(ctx, identity); err != nil {
			t.Fatal(err)
		}
	}

	// Alice registers her hardware key; Bob registers his own.
	_, authAlice := registerCredential(t, svc, ctx, "id-alice")
	_, authBob := registerCredential(t, svc, ctx, "id-bob")

	// Bob begins a legitimate ceremony.
	assertion, sessionBob, err := svc.BeginVerification(ctx, "id-bob")
	if err != nil {
		t.Fatal(err)
	}

	// Attack: Alice's authenticator signs Bob's challenge. Her credential is
	// not in Bob's allowedCredentials, so this must be rejected.
	payload := authAlice.AssertionResponse(
		assertion.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-bob"),
	)
	valid, err := svc.FinishVerification(ctx, "id-bob", sessionBob, rawRequest(payload))
	if valid || err == nil {
		t.Fatalf("Alice's credential satisfied Bob's ceremony: valid=%v err=%v", valid, err)
	}

	// Bob's own credential against the same ceremony must still be accepted,
	// proving the rejection above was about identity scoping and not a broken
	// ceremony or a consumed session.
	payload = authBob.AssertionResponse(
		assertion.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-bob"),
	)
	valid, err = svc.FinishVerification(ctx, "id-bob", sessionBob, rawRequest(payload))
	if err != nil || !valid {
		t.Fatalf("expected Bob's own credential to succeed: valid=%v err=%v", valid, err)
	}
}

func TestWebAuthnCrossUserSessionRejected(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	for _, id := range []string{"id-alice", "id-bob"} {
		identity := &types.Identity{ID: id, Username: id, Type: types.IdentityTypePerson}
		if err := store.Identities(ctx).Create(ctx, identity); err != nil {
			t.Fatal(err)
		}
	}
	_, authAlice := registerCredential(t, svc, ctx, "id-alice")
	registerCredential(t, svc, ctx, "id-bob")

	// Begin ceremonies for both identities; each binds its own challenge and
	// its own user handle in the server-side session.
	assertionAlice, sessionAlice, err := svc.BeginVerification(ctx, "id-alice")
	if err != nil {
		t.Fatal(err)
	}
	_, sessionBob, err := svc.BeginVerification(ctx, "id-bob")
	if err != nil {
		t.Fatal(err)
	}

	// Attack: transplant Alice's session into a finish call for Bob's identity.
	// The session's UserID is Alice's handle, so it must not validate as Bob.
	payload := authAlice.AssertionResponse(
		assertionAlice.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-alice"),
	)
	valid, err := svc.FinishVerification(ctx, "id-bob", sessionAlice, rawRequest(payload))
	if valid || err == nil {
		t.Fatalf("Alice's session validated for Bob: valid=%v err=%v", valid, err)
	}

	// Sanity: the same payload against Alice's own ceremony is accepted, so
	// the rejection is attributable to the identity mismatch.
	valid, err = svc.FinishVerification(ctx, "id-alice", sessionAlice, rawRequest(payload))
	if err != nil || !valid {
		t.Fatalf("expected Alice's own ceremony to succeed: valid=%v err=%v", valid, err)
	}
	_ = sessionBob
}

func TestWebAuthnWrongUserHandleRejected(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	for _, id := range []string{"id-alice", "id-bob"} {
		identity := &types.Identity{ID: id, Username: id, Type: types.IdentityTypePerson}
		if err := store.Identities(ctx).Create(ctx, identity); err != nil {
			t.Fatal(err)
		}
	}
	_, authBob := registerCredential(t, svc, ctx, "id-bob")

	assertion, sessionBob, err := svc.BeginVerification(ctx, "id-bob")
	if err != nil {
		t.Fatal(err)
	}

	// Attack: Bob's real key, but the assertion claims Alice's user handle.
	payload := authBob.AssertionResponse(
		assertion.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-alice"),
	)
	valid, err := svc.FinishVerification(ctx, "id-bob", sessionBob, rawRequest(payload))
	if valid || err == nil {
		t.Fatalf("mismatched user handle accepted: valid=%v err=%v", valid, err)
	}
}

// --- Registration ceremony expiry ----------------------------------------

func TestWebAuthnRegistrationExpires(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	factor, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if factor.Status != types.FactorStatusPendingActivation {
		t.Fatalf("expected pending_activation, got %s", factor.Status)
	}

	// Age the pending ceremony past sessionTTL. MemoryStore holds pointers, so
	// mutating the stored factor ages the real record.
	stored, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.CreatedAt = stored.CreatedAt.Add(-2 * sessionTTL)
	if err := store.Factors(ctx).Update(ctx, stored); err != nil {
		t.Fatal(err)
	}

	// A genuine, correctly-signed registration response must still be refused
	// because the ceremony itself has expired. The payload is real (valid CBOR
	// attestation, real ES256 signature over the issued challenge) — the same
	// construction TestWebAuthnRegistrationFullCeremony proves is ACCEPTED on a
	// fresh ceremony — so rejection here is attributable to expiry alone. A
	// malformed body (e.g. "{}") could fail for an unrelated reason and still
	// make this test pass, which is why the payload is genuine.
	auth := webauthntest.NewAuthenticator()
	payload := auth.CreationResponse(
		creation.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
	)
	_, err = svc.FinishRegistration(ctx, "id-1", factor.ID, rawRequest(payload))
	if err == nil {
		t.Fatal("expected expired registration ceremony to be rejected")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected an expiry error, got: %v", err)
	}

	// The factor must remain pending, not active: expiry must not activate it.
	after, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != types.FactorStatusPendingActivation {
		t.Fatalf("expired ceremony changed status to %s", after.Status)
	}
}

func TestWebAuthnRegistrationRejectsZeroCreatedAt(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)

	factor, _, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}

	// A pending factor with no CreatedAt did not come from a valid ceremony;
	// the expiry check must fail closed rather than treat it as fresh.
	stored, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	stored.CreatedAt = time.Time{}
	if err := store.Factors(ctx).Update(ctx, stored); err != nil {
		t.Fatal(err)
	}

	// The expiry check runs BEFORE the body is unmarshalled, and the assertion
	// below requires the error to be specifically the expiry error — so a `{}`
	// body is sufficient here and cannot mask a different failure mode.
	if _, err := svc.FinishRegistration(ctx, "id-1", factor.ID, rawRequest([]byte(`{}`))); err == nil {
		t.Fatal("expected zero CreatedAt to be rejected")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected an expiry error, got: %v", err)
	}

	// The factor must still be pending: a fail-closed rejection must not
	// activate anything.
	after, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != types.FactorStatusPendingActivation {
		t.Fatalf("zero-CreatedAt rejection changed status to %s", after.Status)
	}
}

// --- User verification enforcement ---------------------------------------
//
// require_user_verification must actually change server-side behaviour, not
// merely be advertised to the browser. These tests assert both directions:
// "required" rejects a ceremony whose authenticator reported only user
// presence, while the default ("preferred") accepts it. Without this pair the
// knob could be dead code and every test would still pass.

func newTestServiceWithUV(t *testing.T, requireUV bool) (*WebAuthnService, storage.Store) {
	t.Helper()
	store := storage.NewMemoryStore()
	settings := testSettings()
	settings.RequireUserVerification = requireUV
	svc, err := NewWebAuthnService(store, settings)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

// registerCredentialWith runs a full registration using a specific
// authenticator, so the UV flag of the registering device is controllable.
func registerCredentialWith(t *testing.T, svc *WebAuthnService, ctx context.Context, identityID string, auth *webauthntest.Authenticator) *types.Factor {
	t.Helper()
	factor, creation, err := svc.BeginRegistration(ctx, identityID)
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.CreationResponse(creation.Response.Challenge.String(), webauthntest.Origin, webauthntest.RPID)
	finished, err := svc.FinishRegistration(ctx, identityID, factor.ID, rawRequest(payload))
	if err != nil {
		t.Fatal(err)
	}
	if finished.Status != types.FactorStatusActive {
		t.Fatalf("expected active factor, got %s", finished.Status)
	}
	return finished
}

// TestWebAuthnRegistrationRequiresUserVerificationWhenConfigured closes the
// registration-side counterpart of the assertion UV tests. It is the test that
// a mutation breaking registrationFlags() (UV always set regardless of
// NoUserVerified) would be caught by — without it, registration could silently
// accept an unverified authenticator even under require_user_verification.
func TestWebAuthnRegistrationRequiresUserVerificationWhenConfigured(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestServiceWithUV(t, true)

	// An authenticator that performs user-presence only (no PIN/biometric).
	auth := webauthntest.NewAuthenticator()
	auth.NoUserVerified = true

	factor, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.CreationResponse(
		creation.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
	)
	// Under require_user_verification the library rejects a registration whose
	// authenticator data lacks the UV flag.
	if _, err := svc.FinishRegistration(ctx, "id-1", factor.ID, rawRequest(payload)); err == nil {
		t.Fatal("UV-less registration accepted while require_user_verification=true")
	}

	// The factor must remain pending: a rejected registration must not activate
	// a credential, or the unverified authenticator would be usable.
	after, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != types.FactorStatusPendingActivation {
		t.Fatalf("rejected UV-less registration left factor %s, want pending_activation", after.Status)
	}
}

// TestWebAuthnRegistrationAllowsUnverifiedWhenPreferred is the paired positive:
// under the default (preferred), the same UV-less authenticator IS accepted, so
// the rejection above is attributable to the require flag and not to a broken
// ceremony. One-directional UV tests prove nothing; this is the other direction.
func TestWebAuthnRegistrationAllowsUnverifiedWhenPreferred(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestServiceWithUV(t, false) // default: preferred

	auth := webauthntest.NewAuthenticator()
	auth.NoUserVerified = true

	factor, creation, err := svc.BeginRegistration(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.CreationResponse(
		creation.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
	)
	finished, err := svc.FinishRegistration(ctx, "id-1", factor.ID, rawRequest(payload))
	if err != nil {
		t.Fatalf("UV-less registration should succeed under 'preferred': %v", err)
	}
	if finished.Status != types.FactorStatusActive {
		t.Fatalf("expected active factor under preferred, got %s", finished.Status)
	}
}

func TestWebAuthnUserVerificationRequiredRejectsUnverified(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestServiceWithUV(t, true)

	auth := webauthntest.NewAuthenticator()
	registerCredentialWith(t, svc, ctx, "id-1", auth)

	// The authenticator reports user presence only (no PIN/biometric). With
	// userVerification=required the ceremony must be rejected.
	auth.NoUserVerified = true
	assertion, session, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.AssertionResponse(
		assertion.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-1"),
	)
	valid, err := svc.FinishVerification(ctx, "id-1", session, rawRequest(payload))
	if valid || err == nil {
		t.Fatalf("UV-less assertion accepted while required: valid=%v err=%v", valid, err)
	}
	// go-webauthn wraps the underlying "user verification required but flag not
	// set" in a generic validation error, so assert on rejection + the wrapper
	// rather than the inner text. The security property (UV-less refused while
	// required) is the valid==false / err!=nil above; the paired
	// ...RequiredAcceptsVerified test proves the rejection is specific to the
	// missing UV flag and not a broken ceremony.
	if !strings.Contains(err.Error(), "finish verification") {
		t.Fatalf("expected a verification failure, got: %v", err)
	}
}

func TestWebAuthnUserVerificationRequiredAcceptsVerified(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestServiceWithUV(t, true)

	auth := webauthntest.NewAuthenticator()
	registerCredentialWith(t, svc, ctx, "id-1", auth)

	assertion, session, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.AssertionResponse(
		assertion.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-1"),
	)
	valid, err := svc.FinishVerification(ctx, "id-1", session, rawRequest(payload))
	if err != nil || !valid {
		t.Fatalf("UV-bearing assertion should succeed when required: valid=%v err=%v", valid, err)
	}
}

func TestWebAuthnUserVerificationPreferredAcceptsUnverified(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestServiceWithUV(t, false) // default: preferred

	auth := webauthntest.NewAuthenticator()
	registerCredentialWith(t, svc, ctx, "id-1", auth)

	auth.NoUserVerified = true
	assertion, session, err := svc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := auth.AssertionResponse(
		assertion.Response.Challenge.String(),
		webauthntest.Origin,
		webauthntest.RPID,
		[]byte("id-1"),
	)
	valid, err := svc.FinishVerification(ctx, "id-1", session, rawRequest(payload))
	if err != nil || !valid {
		t.Fatalf("'preferred' should accept a UV-less ceremony: valid=%v err=%v", valid, err)
	}
}

func TestWebAuthnSettingsAdvertiseUserVerificationRequirement(t *testing.T) {
	ctx := context.Background()

	// The assertion options handed to the browser must carry the configured
	// requirement, otherwise a real authenticator is never told to verify.
	requiredSvc, _ := newTestServiceWithUV(t, true)
	registerCredential(t, requiredSvc, ctx, "id-1")
	assertion, _, err := requiredSvc.BeginVerification(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := assertion.Response.UserVerification; got != protocol.VerificationRequired {
		t.Fatalf("expected %q, got %q", protocol.VerificationRequired, got)
	}

	preferredSvc, _ := newTestServiceWithUV(t, false)
	registerCredential(t, preferredSvc, ctx, "id-2")
	assertion, _, err = preferredSvc.BeginVerification(ctx, "id-2")
	if err != nil {
		t.Fatal(err)
	}
	if got := assertion.Response.UserVerification; got != protocol.VerificationPreferred {
		t.Fatalf("expected %q, got %q", protocol.VerificationPreferred, got)
	}
}
