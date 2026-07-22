// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type TOTPService struct {
	store storage.Store
}

func NewTOTPService(store storage.Store) *TOTPService {
	return &TOTPService{store: store}
}

func (s *TOTPService) Enroll(ctx context.Context, identityID string, issuer string) (*types.Factor, string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: identityID,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("generate totp: %w", err)
	}

	factor := &types.Factor{
		ID:         types.NewID(),
		IdentityID: identityID,
		Method:     types.MFAMethodTOTP,
		Status:     types.FactorStatusPendingActivation,
		Secret:     key.Secret(),
		CreatedAt:  time.Now().UTC(),
	}

	if err := s.store.Factors(ctx).Create(ctx, factor); err != nil {
		return nil, "", "", err
	}

	return factor, key.Secret(), key.URL(), nil
}

func (s *TOTPService) Activate(ctx context.Context, identityID string, factorID string, code string) error {
	factor, err := s.store.Factors(ctx).Get(ctx, factorID)
	if err != nil {
		return err
	}
	if factor.IdentityID != identityID {
		return fmt.Errorf("factor not found for identity")
	}
	if factor.Status != types.FactorStatusPendingActivation {
		return fmt.Errorf("factor already activated")
	}

	valid := totp.Validate(code, factor.Secret)
	if !valid {
		return fmt.Errorf("invalid totp code")
	}

	factor.Status = types.FactorStatusActive
	return s.store.Factors(ctx).Update(ctx, factor)
}

func (s *TOTPService) Verify(ctx context.Context, identityID string, code string) (bool, error) {
	factors, err := s.store.Factors(ctx).ListByIdentity(ctx, identityID)
	if err != nil {
		return false, err
	}
	for _, f := range factors {
		if f.Method == types.MFAMethodTOTP && f.Status == types.FactorStatusActive {
			if totp.Validate(code, f.Secret) {
				return true, nil
			}
			valid, err := totp.ValidateCustom(code, f.Secret, time.Now().Add(-30*time.Second), totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if err == nil && valid {
				return true, nil
			}
		}
	}
	return false, nil
}

func GenerateCode(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", err
	}
	return code, nil
}
