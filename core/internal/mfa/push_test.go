// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
)

func TestPushRegisterDevice(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewPushService(store, 60)

	device, secret, err := svc.RegisterDevice(ctx, "id-1", "My Phone")
	if err != nil {
		t.Fatal(err)
	}
	if device.ID == "" {
		t.Fatal("expected non-empty device ID")
	}
	if device.IdentityID != "id-1" {
		t.Fatalf("expected id-1, got %s", device.IdentityID)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if !device.Managed || !device.Compliant {
		t.Fatal("expected managed and compliant")
	}
}

func TestPushGenerateNumber(t *testing.T) {
	store := storage.NewMemoryStore()
	svc := NewPushService(store, 60)

	for i := 0; i < 100; i++ {
		n, err := svc.GenerateNumber()
		if err != nil {
			t.Fatal(err)
		}
		if n < 0 || n > 99 {
			t.Fatalf("expected 0-99, got %d", n)
		}
	}
}

func TestPushVerifyApprovalValidSignature(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewPushService(store, 60)

	device, secret, err := svc.RegisterDevice(ctx, "id-1", "My Phone")
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Now()
	number := 42
	challengeID := "challenge-1"
	sig := ComputePushSignature(secret, challengeID, number, ts)

	err = svc.VerifyApproval(ctx, device.ID, challengeID, number, sig, ts)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPushVerifyApprovalInvalidSignature(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewPushService(store, 60)

	device, _, err := svc.RegisterDevice(ctx, "id-1", "My Phone")
	if err != nil {
		t.Fatal(err)
	}

	err = svc.VerifyApproval(ctx, device.ID, "challenge-1", 42, "invalid-sig", time.Now())
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestPushVerifyApprovalExpiredTimestamp(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := NewPushService(store, 60)

	device, secret, err := svc.RegisterDevice(ctx, "id-1", "My Phone")
	if err != nil {
		t.Fatal(err)
	}

	ts := time.Now().Add(-2 * time.Minute)
	number := 42
	challengeID := "challenge-1"
	sig := ComputePushSignature(secret, challengeID, number, ts)

	err = svc.VerifyApproval(ctx, device.ID, challengeID, number, sig, ts)
	if err == nil {
		t.Fatal("expected error for expired timestamp")
	}
}

func TestComputePushSignatureConsistency(t *testing.T) {
	secret := "test-secret"
	ts := time.Now()
	sig1 := ComputePushSignature(secret, "c-1", 10, ts)
	sig2 := ComputePushSignature(secret, "c-1", 10, ts)
	if sig1 != sig2 {
		t.Fatal("expected consistent signatures")
	}
	sig3 := ComputePushSignature(secret, "c-2", 10, ts)
	if sig1 == sig3 {
		t.Fatal("expected different signatures for different challenges")
	}
}
