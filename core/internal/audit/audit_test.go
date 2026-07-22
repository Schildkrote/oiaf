// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

func TestEmitCreatesEventsWithHashChain(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := New(store)

	actor := types.AuditActor{Type: types.ActorUser, ID: "user-1"}
	target := types.AuditTarget{Type: types.TargetResource, ID: "res-1"}

	for i := 0; i < 3; i++ {
		err := svc.Emit(ctx, "access_decision", actor, target, types.DecisionAllow, 10, []string{"ok"}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	events, err := svc.List(ctx, storage.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	if events[0].PreviousHash != "" {
		t.Fatal("first event should have empty previous hash")
	}
	for i := 1; i < len(events); i++ {
		if events[i].PreviousHash != events[i-1].Hash {
			t.Fatalf("hash chain broken at index %d", i)
		}
	}
}

func TestVerifyReturnsTrueForValidChain(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := New(store)

	actor := types.AuditActor{Type: types.ActorAdmin, ID: "admin-1"}
	target := types.AuditTarget{Type: types.TargetPolicy, ID: "pol-1"}

	for i := 0; i < 5; i++ {
		err := svc.Emit(ctx, "policy_change", actor, target, types.DecisionAllow, 0, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	valid, count, err := svc.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("expected valid chain")
	}
	if count != 5 {
		t.Fatalf("expected 5, got %d", count)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	svc := New(store)

	actor := types.AuditActor{Type: types.ActorSystem, ID: "system"}
	target := types.AuditTarget{Type: types.TargetIdentity, ID: "id-1"}

	err := svc.Emit(ctx, "identity_create", actor, target, types.DecisionAllow, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = svc.Emit(ctx, "identity_update", actor, target, types.DecisionAllow, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	events, err := svc.List(ctx, storage.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2, got %d", len(events))
	}
	if events[1].PreviousHash != events[0].Hash {
		t.Fatal("second event previous_hash must match first event hash")
	}
	if events[0].Hash == "" {
		t.Fatal("first event hash must not be empty")
	}
	if events[0].Hash == events[1].Hash {
		t.Fatal("event hashes must be unique")
	}
}
