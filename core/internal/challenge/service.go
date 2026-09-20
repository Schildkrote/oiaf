// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package challenge

import (
	"context"
	"fmt"
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
	audit       *audit.Service
	ttl         time.Duration
	maxAttempts int
}

func New(store storage.Store, totpSvc *mfa.TOTPService, pushSvc *mfa.PushService, auditSvc *audit.Service, ttlSeconds int, maxAttempts int) *Service {
	return &Service{
		store:       store,
		totp:        totpSvc,
		push:        pushSvc,
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

func (s *Service) Get(ctx context.Context, id string) (*types.Challenge, error) {
	return s.store.Challenges(ctx).Get(ctx, id)
}

func (s *Service) List(ctx context.Context) ([]*types.Challenge, error) {
	return s.store.Challenges(ctx).List(ctx)
}
