// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package storage

import (
	"context"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Store interface {
	Identities(ctx context.Context) IdentityStore
	Devices(ctx context.Context) DeviceStore
	Resources(ctx context.Context) ResourceStore
	Adapters(ctx context.Context) AdapterStore
	Policies(ctx context.Context) PolicyStore
	Challenges(ctx context.Context) ChallengeStore
	Factors(ctx context.Context) FactorStore
	AuthTokens(ctx context.Context) AuthTokenStore
	AuditEvents(ctx context.Context) AuditEventStore
	BehaviouralProfiles(ctx context.Context) BehaviouralProfileStore
	Close() error
}

type IdentityStore interface {
	Create(ctx context.Context, identity *types.Identity) error
	Get(ctx context.Context, id string) (*types.Identity, error)
	GetByUsername(ctx context.Context, username string) (*types.Identity, error)
	List(ctx context.Context) ([]*types.Identity, error)
	Update(ctx context.Context, identity *types.Identity) error
	Delete(ctx context.Context, id string) error
}

type DeviceStore interface {
	Create(ctx context.Context, device *types.Device) error
	Get(ctx context.Context, id string) (*types.Device, error)
	List(ctx context.Context) ([]*types.Device, error)
	ListByIdentity(ctx context.Context, identityID string) ([]*types.Device, error)
	Delete(ctx context.Context, id string) error
}

type ResourceStore interface {
	Create(ctx context.Context, resource *types.Resource) error
	Get(ctx context.Context, id string) (*types.Resource, error)
	List(ctx context.Context) ([]*types.Resource, error)
	Delete(ctx context.Context, id string) error
}

type AdapterStore interface {
	Create(ctx context.Context, adapter *types.Adapter) error
	Get(ctx context.Context, id string) (*types.Adapter, error)
	List(ctx context.Context) ([]*types.Adapter, error)
	Delete(ctx context.Context, id string) error
}

type PolicyStore interface {
	Create(ctx context.Context, policy *types.Policy) error
	Get(ctx context.Context, id string) (*types.Policy, error)
	List(ctx context.Context) ([]*types.Policy, error)
	Update(ctx context.Context, policy *types.Policy) error
	Delete(ctx context.Context, id string) error
}

type ChallengeStore interface {
	Create(ctx context.Context, challenge *types.Challenge) error
	Get(ctx context.Context, id string) (*types.Challenge, error)
	Update(ctx context.Context, challenge *types.Challenge) error
	List(ctx context.Context) ([]*types.Challenge, error)
}

type FactorStore interface {
	Create(ctx context.Context, factor *types.Factor) error
	Get(ctx context.Context, id string) (*types.Factor, error)
	ListByIdentity(ctx context.Context, identityID string) ([]*types.Factor, error)
	Update(ctx context.Context, factor *types.Factor) error
	Delete(ctx context.Context, id string) error
}

type AuthTokenStore interface {
	Create(ctx context.Context, token *types.AuthToken) error
	GetByHash(ctx context.Context, hash string) (*types.AuthToken, error)
	List(ctx context.Context) ([]*types.AuthToken, error)
	Revoke(ctx context.Context, id string) error
}

type AuditEventStore interface {
	Append(ctx context.Context, event *types.AuditEvent) error
	List(ctx context.Context, filter AuditFilter) ([]*types.AuditEvent, error)
	GetLastHash(ctx context.Context) (string, error)
	Verify(ctx context.Context) (bool, int, error)
}

type AuditFilter struct {
	IdentityID   string
	ResourceType string
	Decision     string
	RiskScoreMin int
	Type         string
	Since        string
	Until        string
	Limit        int
}

type BehaviouralProfileStore interface {
	Get(ctx context.Context, accountSID string) (*types.BehaviouralProfile, error)
	Upsert(ctx context.Context, profile *types.BehaviouralProfile) error
	List(ctx context.Context) ([]*types.BehaviouralProfile, error)
	Delete(ctx context.Context, accountSID string) error
}
