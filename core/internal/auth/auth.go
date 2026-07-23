// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Authenticator struct {
	store storage.Store
}

func New(store storage.Store) *Authenticator {
	return &Authenticator{store: store}
}

func (a *Authenticator) CreateToken(ctx context.Context, name string, role types.Role) (string, *types.AuthToken, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate token: %w", err)
	}
	tokenStr := hex.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(tokenStr), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, fmt.Errorf("hash token: %w", err)
	}
	tok := &types.AuthToken{
		ID:        types.NewID(),
		TokenHash: string(hash),
		Role:      role,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	if err := a.store.AuthTokens(ctx).Create(ctx, tok); err != nil {
		return "", nil, err
	}
	return tokenStr, tok, nil
}

func (a *Authenticator) RegisterToken(ctx context.Context, plainToken string, name string, role types.Role) (*types.AuthToken, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainToken), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash token: %w", err)
	}
	tok := &types.AuthToken{
		ID:        types.NewID(),
		TokenHash: string(hash),
		Role:      role,
		Name:      name,
		CreatedAt: time.Now().UTC(),
	}
	if err := a.store.AuthTokens(ctx).Create(ctx, tok); err != nil {
		return nil, err
	}
	return tok, nil
}

func (a *Authenticator) Validate(ctx context.Context, tokenStr string) (*types.AuthToken, error) {
	tokens, err := a.store.AuthTokens(ctx).List(ctx)
	if err != nil {
		return nil, err
	}
	for _, tok := range tokens {
		if tok.Revoked {
			continue
		}
		if tok.ExpiresAt != nil && time.Now().After(*tok.ExpiresAt) {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(tok.TokenHash), []byte(tokenStr)); err == nil {
			return tok, nil
		}
	}
	return nil, fmt.Errorf("invalid token")
}

func (a *Authenticator) Revoke(ctx context.Context, id string) error {
	return a.store.AuthTokens(ctx).Revoke(ctx, id)
}

func GenerateToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func HashToken(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}
