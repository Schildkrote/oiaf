// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

// WebAuthnSettings carries the Relying Party configuration for WebAuthn
// ceremonies.
//
// Design decision (RP ID config surface): RPID is the effective domain of the
// OIAF deployment (e.g. "sso.example.com") and RPOrigins are the fully
// qualified origins browsers connect from (e.g. "https://sso.example.com").
// They are surfaced in config.yaml under `webauthn:` with OIAF_WEBAUTHN_*
// environment overrides, matching how the AD config surface works. The
// defaults ("localhost" / "http://localhost:8080") exist so development and
// the test suite work out of the box; production deployments MUST set a real
// RP ID and origins — browsers refuse WebAuthn ceremonies on mismatched
// origins.
type WebAuthnSettings struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	// RequireUserVerification selects protocol.VerificationRequired (true) over
	// protocol.VerificationPreferred (false, the default). With "preferred" the
	// authenticator is asked for UV but a ceremony that skipped it still
	// succeeds, so UV is requested rather than enforced.
	RequireUserVerification bool
}

// WebAuthnService implements the WebAuthn (FIDO2/passkey) MFA factor,
// following the same service pattern as TOTPService and PushService.
//
// Credential storage reuses the existing storage interfaces:
//   - A registration ceremony creates a types.Factor with Method=webauthn and
//     Status=pending_activation. While pending, Factor.Credentials holds the
//     JSON-serialized library SessionData (the in-flight ceremony state); on
//     successful finish it is replaced by the JSON-serialized credential
//     record (public key, sign counter, flags) and the factor goes active.
//   - Verification ceremony sessions for the challenge-orchestrator path live
//     on types.Challenge.WebAuthnSession, mirroring how PushNumber/Nonce ride
//     on the challenge (durable, single-use).
//
// The identity-scoped verification endpoints (no challenge involved) use a
// short-lived in-memory session map keyed by ceremony challenge. Sessions are
// server-side state: handing them to the client would allow assertion replay
// (a client-forged session could carry an old challenge). This matches the
// MemoryStore-only reality of the codebase; the challenge path is the durable
// one for a future PostgresStore.
//
// Everything persistent stays inside FactorStore/ChallengeStore, so a future
// PostgresStore needs no new tables beyond the factors/challenges it already
// plans for (credentials map to a bytea column).
type WebAuthnService struct {
	store    storage.Store
	lib      *webauthn.WebAuthn
	settings WebAuthnSettings

	mu       sync.Mutex
	sessions map[string]pendingSession // keyed by ceremony challenge
}

// pendingSession is an in-flight identity-scoped verification ceremony with
// its expiry, so abandoned ceremonies do not accumulate forever.
type pendingSession struct {
	session   webauthn.SessionData
	expiresAt time.Time
}

// sessionTTL bounds how long an identity-scoped verification ceremony stays
// usable. It matches the default challenge TTL (300s) so both WebAuthn paths
// behave consistently.
const sessionTTL = 5 * time.Minute

// NewWebAuthnService creates the WebAuthn factor service. It fails fast if
// the Relying Party settings are invalid (e.g. no origins configured).
func NewWebAuthnService(store storage.Store, settings WebAuthnSettings) (*WebAuthnService, error) {
	// userVerification drives both ceremonies: it is advertised in the creation
	// and assertion options, and the library rejects an assertion whose
	// authenticator data lacks the UV flag when it is "required". The default
	// stays "preferred" so existing deployments keep their behaviour;
	// RequireUserVerification upgrades it to server-side enforcement.
	userVerification := protocol.VerificationPreferred
	if settings.RequireUserVerification {
		userVerification = protocol.VerificationRequired
	}

	lib, err := webauthn.New(&webauthn.Config{
		RPID:          settings.RPID,
		RPDisplayName: settings.RPDisplayName,
		RPOrigins:     settings.RPOrigins,
		// MFA-style ceremonies: no attestation needed (keeps registration
		// friction low).
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: userVerification,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	return &WebAuthnService{store: store, lib: lib, settings: settings, sessions: make(map[string]pendingSession)}, nil
}

// BeginRegistration starts a WebAuthn registration ceremony for an identity.
// It creates a pending_activation factor (mirroring TOTPService.Enroll) whose
// Credentials field temporarily holds the ceremony session, and returns the
// PublicKeyCredentialCreationOptions for the browser.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, identityID string) (*types.Factor, *protocol.CredentialCreation, error) {
	user, err := s.user(ctx, identityID)
	if err != nil {
		return nil, nil, err
	}

	creation, session, err := s.lib.BeginRegistration(user)
	if err != nil {
		return nil, nil, fmt.Errorf("begin registration: %w", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("encode registration session: %w", err)
	}

	factor := &types.Factor{
		ID:          types.NewID(),
		IdentityID:  identityID,
		Method:      types.MFAMethodWebAuthn,
		Status:      types.FactorStatusPendingActivation,
		Credentials: sessionJSON, // replaced by the credential record on finish
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.store.Factors(ctx).Create(ctx, factor); err != nil {
		return nil, nil, err
	}

	return factor, creation, nil
}

// FinishRegistration completes a registration ceremony. The request body must
// be the raw JSON result of navigator.credentials.create() from the browser.
// On success the pending factor transitions to active and stores the verified
// credential record.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, identityID string, factorID string, r *http.Request) (*types.Factor, error) {
	factor, err := s.store.Factors(ctx).Get(ctx, factorID)
	if err != nil {
		return nil, err
	}
	if factor.IdentityID != identityID || factor.Method != types.MFAMethodWebAuthn {
		return nil, fmt.Errorf("factor not found for identity")
	}
	if factor.Status != types.FactorStatusPendingActivation {
		return nil, fmt.Errorf("factor already activated")
	}
	// Registration ceremonies expire server-side, so an abandoned ceremony
	// cannot be finished indefinitely. Reuses sessionTTL so both WebAuthn paths
	// behave consistently. Fails closed on a missing/zero CreatedAt: a pending
	// factor written by BeginRegistration always carries one, so a zero value
	// means the record did not come from a valid ceremony.
	if factor.CreatedAt.IsZero() || time.Since(factor.CreatedAt) > sessionTTL {
		return nil, fmt.Errorf("registration ceremony expired")
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(factor.Credentials, &session); err != nil {
		return nil, fmt.Errorf("corrupt registration session: %w", err)
	}

	user, err := s.user(ctx, identityID)
	if err != nil {
		return nil, err
	}

	credential, err := s.lib.FinishRegistration(user, session, r)
	if err != nil {
		return nil, fmt.Errorf("finish registration: %w", err)
	}

	credJSON, err := json.Marshal(credential)
	if err != nil {
		return nil, fmt.Errorf("encode credential: %w", err)
	}
	factor.Credentials = credJSON
	factor.Status = types.FactorStatusActive
	if err := s.store.Factors(ctx).Update(ctx, factor); err != nil {
		return nil, err
	}

	return factor, nil
}

// BeginVerification starts an assertion ceremony for an identity. It returns
// the PublicKeyCredentialRequestOptions for the browser plus the serialized
// session data, which the caller (challenge orchestrator) persists on the
// challenge until FinishVerification.
func (s *WebAuthnService) BeginVerification(ctx context.Context, identityID string) (*protocol.CredentialAssertion, []byte, error) {
	user, err := s.user(ctx, identityID)
	if err != nil {
		return nil, nil, err
	}
	if len(user.credentials) == 0 {
		return nil, nil, fmt.Errorf("no active webauthn credentials for identity")
	}

	assertion, session, err := s.lib.BeginLogin(user)
	if err != nil {
		return nil, nil, fmt.Errorf("begin verification: %w", err)
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return nil, nil, fmt.Errorf("encode verification session: %w", err)
	}
	return assertion, sessionJSON, nil
}

// BeginIdentityVerification starts an identity-scoped verification ceremony
// (no challenge involved) and parks the session in the service's in-memory
// map for FinishIdentityVerification. Starting a new ceremony replaces any
// in-flight one for the same identity. Expired sessions are pruned on each
// call, so the map stays bounded in practice.
func (s *WebAuthnService) BeginIdentityVerification(ctx context.Context, identityID string) (*protocol.CredentialAssertion, error) {
	assertion, sessionJSON, err := s.BeginVerification(ctx, identityID)
	if err != nil {
		return nil, err
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return nil, fmt.Errorf("encode verification session: %w", err)
	}

	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, ps := range s.sessions {
		if ps.expiresAt.Before(now) {
			delete(s.sessions, key)
		}
	}
	s.sessions[identityID] = pendingSession{session: session, expiresAt: now.Add(sessionTTL)}

	return assertion, nil
}

// FinishIdentityVerification completes an identity-scoped ceremony started by
// BeginIdentityVerification. The parked session is consumed single-use: an
// expired or missing session fails with a clear error.
func (s *WebAuthnService) FinishIdentityVerification(ctx context.Context, identityID string, r *http.Request) (bool, error) {
	s.mu.Lock()
	ps, ok := s.sessions[identityID]
	delete(s.sessions, identityID)
	s.mu.Unlock()

	if !ok {
		return false, fmt.Errorf("no webauthn ceremony in progress; call begin first")
	}
	if time.Now().After(ps.expiresAt) {
		return false, fmt.Errorf("webauthn ceremony expired")
	}

	sessionJSON, err := json.Marshal(ps.session)
	if err != nil {
		return false, fmt.Errorf("encode verification session: %w", err)
	}
	return s.FinishVerification(ctx, identityID, sessionJSON, r)
}

// FinishVerification validates the raw JSON result of
// navigator.credentials.get() against the stored session. On success the
// credential's sign counter (and clone warning) are persisted back to the
// matching factor. The request body is consumed, mirroring the library's
// FinishLogin contract.
func (s *WebAuthnService) FinishVerification(ctx context.Context, identityID string, sessionJSON []byte, r *http.Request) (bool, error) {
	var session webauthn.SessionData
	if err := json.Unmarshal(sessionJSON, &session); err != nil {
		return false, fmt.Errorf("corrupt verification session: %w", err)
	}

	user, err := s.user(ctx, identityID)
	if err != nil {
		return false, err
	}

	// Buffer the body so verification failures can be reported without the
	// library having consumed the request.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false, fmt.Errorf("read assertion response: %w", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	credential, err := s.lib.FinishLogin(user, session, r)
	if err != nil {
		return false, fmt.Errorf("finish verification: %w", err)
	}

	if err := s.persistCounter(ctx, identityID, credential); err != nil {
		// The ceremony itself succeeded; a counter-persistence failure must
		// not deny the user, but it degrades clone detection, so surface it.
		return true, fmt.Errorf("persist sign counter: %w", err)
	}
	return true, nil
}

// persistCounter writes the updated sign counter/clone warning from a
// successful assertion back to the stored credential record.
func (s *WebAuthnService) persistCounter(ctx context.Context, identityID string, updated *webauthn.Credential) error {
	factors, err := s.store.Factors(ctx).ListByIdentity(ctx, identityID)
	if err != nil {
		return err
	}
	for _, f := range factors {
		if f.Method != types.MFAMethodWebAuthn || f.Status != types.FactorStatusActive {
			continue
		}
		var stored webauthn.Credential
		if err := json.Unmarshal(f.Credentials, &stored); err != nil {
			continue
		}
		if !bytes.Equal(stored.ID, updated.ID) {
			continue
		}
		stored.Authenticator.SignCount = updated.Authenticator.SignCount
		stored.Authenticator.CloneWarning = updated.Authenticator.CloneWarning
		credJSON, err := json.Marshal(&stored)
		if err != nil {
			return err
		}
		f.Credentials = credJSON
		return s.store.Factors(ctx).Update(ctx, f)
	}
	return fmt.Errorf("credential not found for identity")
}

// webauthnUser adapts an OIAF identity to the library's webauthn.User
// interface. The user handle is the identity ID; per RFC 8266 / WebAuthn spec
// it is opaque and all authorization decisions bind to it.
type webauthnUser struct {
	identityID  string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte { return []byte(u.identityID) }

func (u *webauthnUser) WebAuthnName() string {
	if u.displayName != "" {
		return u.displayName
	}
	return u.identityID
}

func (u *webauthnUser) WebAuthnDisplayName() string { return u.WebAuthnName() }

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// user builds the webauthn.User for an identity, loading all active WebAuthn
// credentials from the factor store. Display name falls back to the identity
// record when present, else the raw ID.
func (s *WebAuthnService) user(ctx context.Context, identityID string) (*webauthnUser, error) {
	user := &webauthnUser{identityID: identityID}

	if identity, err := s.store.Identities(ctx).Get(ctx, identityID); err == nil {
		switch {
		case identity.DisplayName != "":
			user.displayName = identity.DisplayName
		case identity.Username != "":
			user.displayName = identity.Username
		}
	}

	factors, err := s.store.Factors(ctx).ListByIdentity(ctx, identityID)
	if err != nil {
		return nil, err
	}
	for _, f := range factors {
		if f.Method != types.MFAMethodWebAuthn || f.Status != types.FactorStatusActive {
			continue
		}
		var credential webauthn.Credential
		if err := json.Unmarshal(f.Credentials, &credential); err != nil {
			// Skip unreadable credential records rather than failing the whole
			// ceremony; they can be re-registered.
			continue
		}
		user.credentials = append(user.credentials, credential)
	}
	return user, nil
}
