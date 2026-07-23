// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

func TestIdentityCRUD(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.Identities(ctx)

	id := &types.Identity{
		ID:       "id-1",
		Username: "alice",
		Type:     types.IdentityTypePerson,
		Groups:   []string{"Users"},
	}
	if err := s.Create(ctx, id); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "alice" {
		t.Fatalf("expected alice, got %s", got.Username)
	}

	got, err = s.GetByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "id-1" {
		t.Fatalf("expected id-1, got %s", got.ID)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	id.DisplayName = "Alice W"
	if err := s.Update(ctx, id); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Alice W" {
		t.Fatalf("expected Alice W, got %s", got.DisplayName)
	}

	if err := s.Delete(ctx, "id-1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(ctx, "id-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestPolicyCRUD(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.Policies(ctx)

	p := &types.Policy{
		ID:       "p-1",
		Enabled:  true,
		Priority: 10,
		Effect:   types.DecisionAllow,
	}
	if err := s.Create(ctx, p); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "p-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Priority != 10 {
		t.Fatalf("expected 10, got %d", got.Priority)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	p.Priority = 20
	if err := s.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get(ctx, "p-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Priority != 20 {
		t.Fatalf("expected 20, got %d", got.Priority)
	}

	if err := s.Delete(ctx, "p-1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(ctx, "p-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestChallengeCreateAndUpdate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.Challenges(ctx)

	c := &types.Challenge{
		ID:         "c-1",
		IdentityID: "id-1",
		RequestID:  "r-1",
		Methods:    []types.MFAMethod{types.MFAMethodTOTP},
		Status:     types.ChallengeStatusPending,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(5 * time.Minute),
	}
	if err := s.Create(ctx, c); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.ChallengeStatusPending {
		t.Fatalf("expected pending, got %s", got.Status)
	}

	c.Status = types.ChallengeStatusApproved
	if err := s.Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get(ctx, "c-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.ChallengeStatusApproved {
		t.Fatalf("expected approved, got %s", got.Status)
	}
}

func TestAuditEventAppendAndVerify(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.AuditEvents(ctx)

	for i := 0; i < 5; i++ {
		e := &types.AuditEvent{
			ID:        types.NewID(),
			Timestamp: time.Now().UTC(),
			Type:      "access_decision",
			Actor:     types.AuditActor{Type: types.ActorUser, ID: "user-1"},
			Target:    types.AuditTarget{Type: types.TargetResource, ID: "res-1"},
		}
		if err := s.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	valid, count, err := s.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid chain")
	}
	if count != 5 {
		t.Fatalf("expected 5, got %d", count)
	}

	events, err := s.List(ctx, AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(events); i++ {
		if events[i].PreviousHash != events[i-1].Hash {
			t.Fatalf("hash chain broken at index %d", i)
		}
	}
}

func TestAuditEventListWithFilters(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.AuditEvents(ctx)

	e1 := &types.AuditEvent{
		ID:        "e-1",
		Timestamp: time.Now().UTC(),
		Type:      "access_decision",
		Actor:     types.AuditActor{Type: types.ActorUser, ID: "user-1"},
		Target:    types.AuditTarget{Type: types.TargetResource, ID: "res-1"},
		Decision:  types.DecisionAllow,
		RiskScore: 10,
	}
	e2 := &types.AuditEvent{
		ID:        "e-2",
		Timestamp: time.Now().UTC(),
		Type:      "access_decision",
		Actor:     types.AuditActor{Type: types.ActorUser, ID: "user-2"},
		Target:    types.AuditTarget{Type: types.TargetResource, ID: "res-2"},
		Decision:  types.DecisionDeny,
		RiskScore: 80,
	}
	if err := s.Append(ctx, e1); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(ctx, e2); err != nil {
		t.Fatal(err)
	}

	result, err := s.List(ctx, AuditFilter{Decision: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != "e-2" {
		t.Fatalf("expected e-2, got %v", result)
	}

	result, err = s.List(ctx, AuditFilter{IdentityID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != "e-1" {
		t.Fatalf("expected e-1, got %v", result)
	}

	result, err = s.List(ctx, AuditFilter{RiskScoreMin: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != "e-2" {
		t.Fatalf("expected e-2, got %v", result)
	}

	result, err = s.List(ctx, AuditFilter{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
}

func TestAuthTokenCreateAndRevoke(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.AuthTokens(ctx)

	tok := &types.AuthToken{
		ID:        "t-1",
		TokenHash: "hash-abc",
		Role:      types.RoleAdmin,
		Name:      "admin-token",
		CreatedAt: time.Now(),
	}
	if err := s.Create(ctx, tok); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetByHash(ctx, "hash-abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "admin-token" {
		t.Fatalf("expected admin-token, got %s", got.Name)
	}

	if err := s.Revoke(ctx, "t-1"); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetByHash(ctx, "hash-abc")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Revoked {
		t.Fatal("expected revoked")
	}
}

func TestFactorCRUD(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.Factors(ctx)

	f := &types.Factor{
		ID:         "f-1",
		IdentityID: "id-1",
		Method:     types.MFAMethodTOTP,
		Status:     types.FactorStatusPendingActivation,
		Secret:     "secret123",
		CreatedAt:  time.Now(),
	}
	if err := s.Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "f-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.FactorStatusPendingActivation {
		t.Fatalf("expected pending_activation, got %s", got.Status)
	}

	list, err := s.ListByIdentity(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	f.Status = types.FactorStatusActive
	if err := s.Update(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get(ctx, "f-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != types.FactorStatusActive {
		t.Fatalf("expected active, got %s", got.Status)
	}

	if err := s.Delete(ctx, "f-1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(ctx, "f-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestDeviceCRUD(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	s := store.Devices(ctx)

	d := &types.Device{
		ID:         "d-1",
		IdentityID: "id-1",
		Name:       "iPhone",
		Managed:    true,
		Compliant:  true,
		CreatedAt:  time.Now(),
	}
	if err := s.Create(ctx, d); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get(ctx, "d-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "iPhone" {
		t.Fatalf("expected iPhone, got %s", got.Name)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	list, err = s.ListByIdentity(ctx, "id-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1, got %d", len(list))
	}

	if err := s.Delete(ctx, "d-1"); err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(ctx, "d-1")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}
