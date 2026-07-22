// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

type MemoryStore struct {
	mu            sync.RWMutex
	identities    map[string]*types.Identity
	devices       map[string]*types.Device
	resources     map[string]*types.Resource
	adapters      map[string]*types.Adapter
	policies      map[string]*types.Policy
	challenges    map[string]*types.Challenge
	factors       map[string]*types.Factor
	authTokens    map[string]*types.AuthToken
	auditEvents   []*types.AuditEvent
	auditLastHash string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identities: make(map[string]*types.Identity),
		devices:    make(map[string]*types.Device),
		resources:  make(map[string]*types.Resource),
		adapters:   make(map[string]*types.Adapter),
		policies:   make(map[string]*types.Policy),
		challenges: make(map[string]*types.Challenge),
		factors:    make(map[string]*types.Factor),
		authTokens: make(map[string]*types.AuthToken),
	}
}

func (m *MemoryStore) Identities(_ context.Context) IdentityStore  { return &memoryIdentityStore{m} }
func (m *MemoryStore) Devices(_ context.Context) DeviceStore       { return &memoryDeviceStore{m} }
func (m *MemoryStore) Resources(_ context.Context) ResourceStore   { return &memoryResourceStore{m} }
func (m *MemoryStore) Adapters(_ context.Context) AdapterStore     { return &memoryAdapterStore{m} }
func (m *MemoryStore) Policies(_ context.Context) PolicyStore      { return &memoryPolicyStore{m} }
func (m *MemoryStore) Challenges(_ context.Context) ChallengeStore { return &memoryChallengeStore{m} }
func (m *MemoryStore) Factors(_ context.Context) FactorStore       { return &memoryFactorStore{m} }
func (m *MemoryStore) AuthTokens(_ context.Context) AuthTokenStore { return &memoryAuthTokenStore{m} }
func (m *MemoryStore) AuditEvents(_ context.Context) AuditEventStore {
	return &memoryAuditEventStore{m}
}
func (m *MemoryStore) Close() error { return nil }

type memoryIdentityStore struct{ m *MemoryStore }

func (s *memoryIdentityStore) Create(_ context.Context, identity *types.Identity) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.identities[identity.ID] = identity
	return nil
}

func (s *memoryIdentityStore) Get(_ context.Context, id string) (*types.Identity, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.identities[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryIdentityStore) GetByUsername(_ context.Context, username string) (*types.Identity, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	for _, v := range s.m.identities {
		if v.Username == username {
			return v, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", username)
}

func (s *memoryIdentityStore) List(_ context.Context) ([]*types.Identity, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.Identity, 0, len(s.m.identities))
	for _, v := range s.m.identities {
		result = append(result, v)
	}
	return result, nil
}

func (s *memoryIdentityStore) Update(_ context.Context, identity *types.Identity) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if _, ok := s.m.identities[identity.ID]; !ok {
		return fmt.Errorf("not found: %s", identity.ID)
	}
	s.m.identities[identity.ID] = identity
	return nil
}

func (s *memoryIdentityStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.identities, id)
	return nil
}

type memoryDeviceStore struct{ m *MemoryStore }

func (s *memoryDeviceStore) Create(_ context.Context, device *types.Device) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.devices[device.ID] = device
	return nil
}

func (s *memoryDeviceStore) Get(_ context.Context, id string) (*types.Device, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.devices[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryDeviceStore) List(_ context.Context) ([]*types.Device, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.Device, 0, len(s.m.devices))
	for _, v := range s.m.devices {
		result = append(result, v)
	}
	return result, nil
}

func (s *memoryDeviceStore) ListByIdentity(_ context.Context, identityID string) ([]*types.Device, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	var result []*types.Device
	for _, v := range s.m.devices {
		if v.IdentityID == identityID {
			result = append(result, v)
		}
	}
	return result, nil
}

func (s *memoryDeviceStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.devices, id)
	return nil
}

type memoryResourceStore struct{ m *MemoryStore }

func (s *memoryResourceStore) Create(_ context.Context, resource *types.Resource) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.resources[resource.ID] = resource
	return nil
}

func (s *memoryResourceStore) Get(_ context.Context, id string) (*types.Resource, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.resources[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryResourceStore) List(_ context.Context) ([]*types.Resource, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.Resource, 0, len(s.m.resources))
	for _, v := range s.m.resources {
		result = append(result, v)
	}
	return result, nil
}

func (s *memoryResourceStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.resources, id)
	return nil
}

type memoryAdapterStore struct{ m *MemoryStore }

func (s *memoryAdapterStore) Create(_ context.Context, adapter *types.Adapter) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.adapters[adapter.ID] = adapter
	return nil
}

func (s *memoryAdapterStore) Get(_ context.Context, id string) (*types.Adapter, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.adapters[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryAdapterStore) List(_ context.Context) ([]*types.Adapter, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.Adapter, 0, len(s.m.adapters))
	for _, v := range s.m.adapters {
		result = append(result, v)
	}
	return result, nil
}

func (s *memoryAdapterStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.adapters, id)
	return nil
}

type memoryPolicyStore struct{ m *MemoryStore }

func (s *memoryPolicyStore) Create(_ context.Context, policy *types.Policy) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.policies[policy.ID] = policy
	return nil
}

func (s *memoryPolicyStore) Get(_ context.Context, id string) (*types.Policy, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.policies[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryPolicyStore) List(_ context.Context) ([]*types.Policy, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.Policy, 0, len(s.m.policies))
	for _, v := range s.m.policies {
		result = append(result, v)
	}
	return result, nil
}

func (s *memoryPolicyStore) Update(_ context.Context, policy *types.Policy) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if _, ok := s.m.policies[policy.ID]; !ok {
		return fmt.Errorf("not found: %s", policy.ID)
	}
	s.m.policies[policy.ID] = policy
	return nil
}

func (s *memoryPolicyStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.policies, id)
	return nil
}

type memoryChallengeStore struct{ m *MemoryStore }

func (s *memoryChallengeStore) Create(_ context.Context, challenge *types.Challenge) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.challenges[challenge.ID] = challenge
	return nil
}

func (s *memoryChallengeStore) Get(_ context.Context, id string) (*types.Challenge, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.challenges[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryChallengeStore) Update(_ context.Context, challenge *types.Challenge) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if _, ok := s.m.challenges[challenge.ID]; !ok {
		return fmt.Errorf("not found: %s", challenge.ID)
	}
	s.m.challenges[challenge.ID] = challenge
	return nil
}

func (s *memoryChallengeStore) List(_ context.Context) ([]*types.Challenge, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.Challenge, 0, len(s.m.challenges))
	for _, v := range s.m.challenges {
		result = append(result, v)
	}
	return result, nil
}

type memoryFactorStore struct{ m *MemoryStore }

func (s *memoryFactorStore) Create(_ context.Context, factor *types.Factor) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.factors[factor.ID] = factor
	return nil
}

func (s *memoryFactorStore) Get(_ context.Context, id string) (*types.Factor, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	v, ok := s.m.factors[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	return v, nil
}

func (s *memoryFactorStore) ListByIdentity(_ context.Context, identityID string) ([]*types.Factor, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	var result []*types.Factor
	for _, v := range s.m.factors {
		if v.IdentityID == identityID {
			result = append(result, v)
		}
	}
	return result, nil
}

func (s *memoryFactorStore) Update(_ context.Context, factor *types.Factor) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	if _, ok := s.m.factors[factor.ID]; !ok {
		return fmt.Errorf("not found: %s", factor.ID)
	}
	s.m.factors[factor.ID] = factor
	return nil
}

func (s *memoryFactorStore) Delete(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	delete(s.m.factors, id)
	return nil
}

type memoryAuthTokenStore struct{ m *MemoryStore }

func (s *memoryAuthTokenStore) Create(_ context.Context, token *types.AuthToken) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	s.m.authTokens[token.ID] = token
	return nil
}

func (s *memoryAuthTokenStore) GetByHash(_ context.Context, hash string) (*types.AuthToken, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	for _, v := range s.m.authTokens {
		if v.TokenHash == hash {
			return v, nil
		}
	}
	return nil, fmt.Errorf("not found: %s", hash)
}

func (s *memoryAuthTokenStore) List(_ context.Context) ([]*types.AuthToken, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	result := make([]*types.AuthToken, 0, len(s.m.authTokens))
	for _, v := range s.m.authTokens {
		result = append(result, v)
	}
	return result, nil
}

func (s *memoryAuthTokenStore) Revoke(_ context.Context, id string) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	v, ok := s.m.authTokens[id]
	if !ok {
		return fmt.Errorf("not found: %s", id)
	}
	v.Revoked = true
	return nil
}

type memoryAuditEventStore struct{ m *MemoryStore }

func (s *memoryAuditEventStore) Append(_ context.Context, event *types.AuditEvent) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	event.PreviousHash = s.m.auditLastHash
	event.Hash = computeAuditHash(s.m.auditLastHash, event)
	s.m.auditLastHash = event.Hash
	s.m.auditEvents = append(s.m.auditEvents, event)
	return nil
}

func (s *memoryAuditEventStore) List(_ context.Context, filter AuditFilter) ([]*types.AuditEvent, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	var result []*types.AuditEvent
	for _, e := range s.m.auditEvents {
		if filter.Type != "" && e.Type != filter.Type {
			continue
		}
		if filter.Decision != "" && string(e.Decision) != filter.Decision {
			continue
		}
		if filter.IdentityID != "" && e.Actor.ID != filter.IdentityID {
			continue
		}
		if filter.ResourceType != "" && e.Target.Type != types.TargetType(filter.ResourceType) {
			continue
		}
		if filter.RiskScoreMin > 0 && e.RiskScore < filter.RiskScoreMin {
			continue
		}
		if filter.Since != "" {
			since, err := time.Parse(time.RFC3339, filter.Since)
			if err == nil && e.Timestamp.Before(since) {
				continue
			}
		}
		if filter.Until != "" {
			until, err := time.Parse(time.RFC3339, filter.Until)
			if err == nil && e.Timestamp.After(until) {
				continue
			}
		}
		result = append(result, e)
		if filter.Limit > 0 && len(result) >= filter.Limit {
			break
		}
	}
	return result, nil
}

func (s *memoryAuditEventStore) GetLastHash(_ context.Context) (string, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	return s.m.auditLastHash, nil
}

func (s *memoryAuditEventStore) Verify(_ context.Context) (bool, int, error) {
	s.m.mu.RLock()
	defer s.m.mu.RUnlock()
	prevHash := ""
	for i, e := range s.m.auditEvents {
		expected := computeAuditHash(prevHash, e)
		if e.Hash != expected {
			return false, i, nil
		}
		prevHash = e.Hash
	}
	return true, len(s.m.auditEvents), nil
}

func computeAuditHash(prevHash string, event *types.AuditEvent) string {
	type auditEventNoHash struct {
		ID           string                 `json:"id"`
		Timestamp    time.Time              `json:"timestamp"`
		Type         string                 `json:"type"`
		Actor        types.AuditActor       `json:"actor"`
		Target       types.AuditTarget      `json:"target"`
		Decision     types.Decision         `json:"decision,omitempty"`
		RiskScore    int                    `json:"risk_score,omitempty"`
		Reasons      []string               `json:"reasons,omitempty"`
		Metadata     map[string]interface{} `json:"metadata,omitempty"`
		PreviousHash string                 `json:"previous_hash"`
	}
	noHash := auditEventNoHash{
		ID:           event.ID,
		Timestamp:    event.Timestamp,
		Type:         event.Type,
		Actor:        event.Actor,
		Target:       event.Target,
		Decision:     event.Decision,
		RiskScore:    event.RiskScore,
		Reasons:      event.Reasons,
		Metadata:     event.Metadata,
		PreviousHash: prevHash,
	}
	data, _ := json.Marshal(noHash)
	h := sha256.Sum256(append([]byte(prevHash), data...))
	return hex.EncodeToString(h[:])
}
