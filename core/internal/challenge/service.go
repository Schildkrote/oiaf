// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package challenge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/audit"
	"github.com/Schildkrote/oiaf/core/internal/mfa"
	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Service struct {
	store       storage.Store
	totp        *mfa.TOTPService
	push        *mfa.PushService
	webauthn    *mfa.WebAuthnService
	audit       *audit.Service
	ttl         time.Duration
	maxAttempts int
}

// New creates the challenge orchestrator. webauthnSvc may be nil when the
// WebAuthn factor is not configured; challenges selecting the webauthn method
// then fail with a clear error instead of panicking.
func New(store storage.Store, totpSvc *mfa.TOTPService, pushSvc *mfa.PushService, webauthnSvc *mfa.WebAuthnService, auditSvc *audit.Service, ttlSeconds int, maxAttempts int) *Service {
	return &Service{
		store:       store,
		totp:        totpSvc,
		push:        pushSvc,
		webauthn:    webauthnSvc,
		audit:       auditSvc,
		ttl:         time.Duration(ttlSeconds) * time.Second,
		maxAttempts: maxAttempts,
	}
}

func (s *Service) Create(ctx context.Context, identityID string, requestID string, methods []types.MFAMethod) (*types.Challenge, error) {
	pushNumber := 0
	for _, m := range methods {
		if m == types.MFAMethodPush {
			n, err := s.push.GenerateNumber()
			if err != nil {
				return nil, err
			}
			pushNumber = n
			break
		}
	}

	ch := &types.Challenge{
		ID:          types.NewID(),
		IdentityID:  identityID,
		RequestID:   requestID,
		Methods:     methods,
		Status:      types.ChallengeStatusPending,
		PushNumber:  pushNumber,
		Nonce:       types.NewID(),
		Attempts:    0,
		MaxAttempts: s.maxAttempts,
		ExpiresAt:   time.Now().UTC().Add(s.ttl),
		CreatedAt:   time.Now().UTC(),
	}

	if err := s.store.Challenges(ctx).Create(ctx, ch); err != nil {
		return nil, err
	}

	s.audit.Emit(ctx, "challenge.created",
		types.AuditActor{Type: types.ActorSystem, ID: "system"},
		types.AuditTarget{Type: types.TargetChallenge, ID: ch.ID},
		types.DecisionChallenge, 0, nil, nil)

	return ch, nil
}

func (s *Service) VerifyTOTP(ctx context.Context, challengeID string, code string) (*types.Challenge, error) {
	ch, err := s.preVerify(ctx, challengeID)
	if err != nil {
		return nil, err
	}

	ch.Attempts++
	valid, err := s.totp.Verify(ctx, ch.IdentityID, code)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if valid {
		ch.Status = types.ChallengeStatusApproved
		ch.ResolvedAt = &now
		s.store.Challenges(ctx).Update(ctx, ch)
		s.audit.Emit(ctx, "challenge.verified",
			types.AuditActor{Type: types.ActorUser, ID: ch.IdentityID},
			types.AuditTarget{Type: types.TargetChallenge, ID: ch.ID},
			types.DecisionAllow, 0, []string{"totp_verified"}, nil)
		return ch, nil
	}

	if ch.Attempts >= ch.MaxAttempts {
		ch.Status = types.ChallengeStatusFailed
	}
	s.store.Challenges(ctx).Update(ctx, ch)
	s.audit.Emit(ctx, "challenge.failed",
		types.AuditActor{Type: types.ActorUser, ID: ch.IdentityID},
		types.AuditTarget{Type: types.TargetChallenge, ID: ch.ID},
		types.DecisionDeny, 0, []string{"totp_invalid"}, nil)
	return nil, fmt.Errorf("invalid code")
}

func (s *Service) VerifyPush(ctx context.Context, challengeID string, deviceID string, number int, signature string, timestamp time.Time) (*types.Challenge, error) {
	ch, err := s.preVerify(ctx, challengeID)
	if err != nil {
		return nil, err
	}

	ch.Attempts++

	if number != ch.PushNumber {
		s.store.Challenges(ctx).Update(ctx, ch)
		return nil, fmt.Errorf("number mismatch")
	}

	if err := s.push.VerifyApproval(ctx, deviceID, challengeID, number, signature, timestamp); err != nil {
		if ch.Attempts >= ch.MaxAttempts {
			ch.Status = types.ChallengeStatusFailed
		}
		s.store.Challenges(ctx).Update(ctx, ch)
		return nil, fmt.Errorf("push verification failed: %w", err)
	}

	now := time.Now().UTC()
	ch.Status = types.ChallengeStatusApproved
	ch.ResolvedAt = &now
	s.store.Challenges(ctx).Update(ctx, ch)
	s.audit.Emit(ctx, "challenge.verified",
		types.AuditActor{Type: types.ActorUser, ID: ch.IdentityID},
		types.AuditTarget{Type: types.TargetChallenge, ID: ch.ID},
		types.DecisionAllow, 0, []string{"push_verified"}, nil)
	return ch, nil
}

// BeginWebAuthn starts a WebAuthn assertion ceremony for a pending challenge
// and stores the ceremony session on the challenge. The returned options must
// be passed to the browser (navigator.credentials.get); the matching call is
// FinishWebAuthn. The challenge must allow the webauthn method.
func (s *Service) BeginWebAuthn(ctx context.Context, challengeID string) ([]byte, error) {
	if s.webauthn == nil {
		return nil, fmt.Errorf("webauthn factor not configured")
	}

	ch, err := s.store.Challenges(ctx).Get(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if ch.Status != types.ChallengeStatusPending {
		return nil, fmt.Errorf("challenge already resolved")
	}
	if time.Now().After(ch.ExpiresAt) {
		ch.Status = types.ChallengeStatusExpired
		s.store.Challenges(ctx).Update(ctx, ch)
		return nil, fmt.Errorf("challenge expired")
	}
	if !s.allowsMethod(ch, types.MFAMethodWebAuthn) {
		return nil, fmt.Errorf("challenge does not allow webauthn")
	}

	assertion, sessionJSON, err := s.webauthn.BeginVerification(ctx, ch.IdentityID)
	if err != nil {
		return nil, err
	}

	// The ceremony session rides on the challenge (like PushNumber/Nonce), so
	// no extra storage surface is needed. Starting a new ceremony overwrites
	// any in-flight one; the latest options are the only valid ones.
	ch.WebAuthnSession = string(sessionJSON)
	if err := s.store.Challenges(ctx).Update(ctx, ch); err != nil {
		return nil, err
	}

	return json.Marshal(assertion)
}

// FinishWebAuthn completes a WebAuthn assertion ceremony started by
// BeginWebAuthn. The HTTP request body must carry the raw JSON result of
// navigator.credentials.get(). Attempt accounting mirrors the other verify
// methods; on success the challenge is approved and the ceremony session is
// cleared (single use).
func (s *Service) FinishWebAuthn(ctx context.Context, challengeID string, r *http.Request) (*types.Challenge, error) {
	if s.webauthn == nil {
		return nil, fmt.Errorf("webauthn factor not configured")
	}

	ch, err := s.preVerify(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if !s.allowsMethod(ch, types.MFAMethodWebAuthn) {
		return nil, fmt.Errorf("challenge does not allow webauthn")
	}
	if ch.WebAuthnSession == "" {
		return nil, fmt.Errorf("no webauthn ceremony in progress; call begin first")
	}

	ch.Attempts++
	session := ch.WebAuthnSession
	ch.WebAuthnSession = "" // single-use ceremony state

	valid, verifyErr := s.webauthn.FinishVerification(ctx, ch.IdentityID, []byte(session), r)

	now := time.Now().UTC()
	if valid {
		ch.Status = types.ChallengeStatusApproved
		ch.ResolvedAt = &now
		s.store.Challenges(ctx).Update(ctx, ch)
		s.audit.Emit(ctx, "challenge.verified",
			types.AuditActor{Type: types.ActorUser, ID: ch.IdentityID},
			types.AuditTarget{Type: types.TargetChallenge, ID: ch.ID},
			types.DecisionAllow, 0, []string{"webauthn_verified"}, nil)
		return ch, verifyErr // verifyErr non-nil only for counter-persistence degradation
	}

	if ch.Attempts >= ch.MaxAttempts {
		ch.Status = types.ChallengeStatusFailed
	}
	s.store.Challenges(ctx).Update(ctx, ch)
	s.audit.Emit(ctx, "challenge.failed",
		types.AuditActor{Type: types.ActorUser, ID: ch.IdentityID},
		types.AuditTarget{Type: types.TargetChallenge, ID: ch.ID},
		types.DecisionDeny, 0, []string{"webauthn_invalid"}, nil)
	if verifyErr == nil {
		verifyErr = fmt.Errorf("invalid assertion")
	}
	return nil, verifyErr
}

// preVerify loads a challenge and enforces the common lifecycle gates:
// pending status, expiry, and remaining attempts. Callers increment Attempts
// themselves after preVerify returns.
func (s *Service) preVerify(ctx context.Context, challengeID string) (*types.Challenge, error) {
	ch, err := s.store.Challenges(ctx).Get(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if ch.Status != types.ChallengeStatusPending {
		return nil, fmt.Errorf("challenge already resolved")
	}
	if time.Now().After(ch.ExpiresAt) {
		ch.Status = types.ChallengeStatusExpired
		s.store.Challenges(ctx).Update(ctx, ch)
		return nil, fmt.Errorf("challenge expired")
	}
	if ch.Attempts >= ch.MaxAttempts {
		ch.Status = types.ChallengeStatusFailed
		s.store.Challenges(ctx).Update(ctx, ch)
		return nil, fmt.Errorf("too many attempts")
	}
	return ch, nil
}

func (s *Service) allowsMethod(ch *types.Challenge, method types.MFAMethod) bool {
	for _, m := range ch.Methods {
		if m == method {
			return true
		}
	}
	return false
}

func (s *Service) Get(ctx context.Context, id string) (*types.Challenge, error) {
	return s.store.Challenges(ctx).Get(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]*types.Challenge, error) {
	return s.store.Challenges(ctx).List(ctx)
}
