// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

func TestTOTPEnroll(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewTOTPService(store)

	factor, secret, url, err := svc.Enroll(ctx, "id-1", "OIAF")
	if err != nil {
		t.Fatal(err)
	}
	if factor.Status != types.FactorStatusPendingActivation {
		t.Fatalf("expected pending_activation, got %s", factor.Status)
	}
	if factor.Method != types.MFAMethodTOTP {
		t.Fatalf("expected totp, got %s", factor.Method)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if url == "" {
		t.Fatal("expected non-empty url")
	}
}

func TestTOTPActivateValidCode(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewTOTPService(store)

	factor, secret, _, err := svc.Enroll(ctx, "id-1", "OIAF")
	if err != nil {
		t.Fatal(err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	err = svc.Activate(ctx, "id-1", factor.ID, code)
	if err != nil {
		t.Fatal(err)
	}

	f, err := store.Factors(ctx).Get(ctx, factor.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f.Status != types.FactorStatusActive {
		t.Fatalf("expected active, got %s", f.Status)
	}
}

func TestTOTPActivateInvalidCode(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewTOTPService(store)

	factor, _, _, err := svc.Enroll(ctx, "id-1", "OIAF")
	if err != nil {
		t.Fatal(err)
	}

	err = svc.Activate(ctx, "id-1", factor.ID, "000000")
	if err == nil {
		t.Fatal("expected error for invalid code")
	}
}

func TestTOTPVerifyValidCode(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewTOTPService(store)

	factor, secret, _, err := svc.Enroll(ctx, "id-1", "OIAF")
	if err != nil {
		t.Fatal(err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Activate(ctx, "id-1", factor.ID, code); err != nil {
		t.Fatal(err)
	}

	code, err = totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	valid, err := svc.Verify(ctx, "id-1", code)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid")
	}
}

func TestTOTPVerifyInvalidCode(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewTOTPService(store)

	factor, secret, _, err := svc.Enroll(ctx, "id-1", "OIAF")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Activate(ctx, "id-1", factor.ID, code); err != nil {
		t.Fatal(err)
	}

	valid, err := svc.Verify(ctx, "id-1", "000000")
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("expected invalid")
	}
}

func TestGenerateCodeProduces6Digits(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewTOTPService(store)

	_, secret, _, err := svc.Enroll(ctx, "id-1", "OIAF")
	if err != nil {
		t.Fatal(err)
	}

	code, err := GenerateCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("expected 6 digits, got %d: %s", len(code), code)
	}
}
