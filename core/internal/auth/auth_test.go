// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

func TestCreateTokenAndValidate(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	a := New(store)

	tokenStr, tok, err := a.CreateToken(ctx, "test-token", types.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}
	if tok.Role != types.RoleAdmin {
		t.Fatalf("expected admin role, got %s", tok.Role)
	}

	validated, err := a.Validate(ctx, tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if validated.ID != tok.ID {
		t.Fatalf("expected %s, got %s", tok.ID, validated.ID)
	}
}

func TestValidateRejectsInvalidToken(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	a := New(store)

	_, err := a.Validate(ctx, "invalid-token-value")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateRejectsRevokedToken(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	a := New(store)

	tokenStr, tok, err := a.CreateToken(ctx, "revoke-me", types.RoleService)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Revoke(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}

	_, err = a.Validate(ctx, tokenStr)
	if err == nil {
		t.Fatal("expected error for revoked token")
	}
}

func TestRegisterToken(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	a := New(store)

	plain := "my-known-plaintext-token"
	tok, err := a.RegisterToken(ctx, plain, "known-token", types.RoleAuditor)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Name != "known-token" {
		t.Fatalf("expected known-token, got %s", tok.Name)
	}

	validated, err := a.Validate(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	if validated.ID != tok.ID {
		t.Fatalf("expected %s, got %s", tok.ID, validated.ID)
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Fatalf("expected 64 chars, got %d", len(token))
	}
	for _, c := range token {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("unexpected char %c", c)
		}
	}
}

func TestHashToken(t *testing.T) {
	hash, err := HashToken("my-secret")
	if err != nil {
		t.Fatal(err)
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("my-secret"))
	if err != nil {
		t.Fatal("hash should match plaintext")
	}
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong"))
	if err == nil {
		t.Fatal("hash should not match wrong plaintext")
	}
}
