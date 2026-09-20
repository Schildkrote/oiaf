// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

func mustConditions(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newTestStore(t *testing.T, policies ...*types.Policy) *storage.MemoryStore {
	t.Helper()
	store := storage.NewMemoryStore()
	ctx := context.Background()
	for _, p := range policies {
		if err := store.Policies(ctx).Create(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestBuiltinEngine_ChallengeForSSHAdmins(t *testing.T) {
	cond := map[string]interface{}{
		"all": []interface{}{
			map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"},
			map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "Admins"},
		},
	}
	p := &types.Policy{
		ID:         "p1",
		Enabled:    true,
		Priority:   10,
		Effect:     types.DecisionChallenge,
		Conditions: mustConditions(t, cond),
		Challenge:  &types.ChallengeSpec{Methods: []types.MFAMethod{types.MFAMethodTOTP}},
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	store := newTestStore(t, p)
	engine := NewBuiltinEngine(store)

	req := types.AccessRequest{
		Identity: types.AccessIdentity{Username: "alice", Groups: []string{"Admins"}, Type: "person"},
		Resource: types.AccessResource{Type: "ssh", Name: "prod-server", Sensitivity: "high"},
	}
	dec, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Effect != types.DecisionChallenge {
		t.Fatalf("expected challenge, got %s", dec.Effect)
	}
}

func TestBuiltinEngine_DenyServiceAccountInteractive(t *testing.T) {
	cond := map[string]interface{}{
		"all": []interface{}{
			map[string]interface{}{"path": "identity.type", "op": "eq", "value": "service_account"},
			map[string]interface{}{"path": "context.interactive", "op": "eq", "value": true},
		},
	}
	p := &types.Policy{
		ID:         "p1",
		Enabled:    true,
		Priority:   100,
		Effect:     types.DecisionDeny,
		Conditions: mustConditions(t, cond),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	store := newTestStore(t, p)
	engine := NewBuiltinEngine(store)

	req := types.AccessRequest{
		Identity: types.AccessIdentity{Username: "svc-deploy", Type: "service_account"},
		Resource: types.AccessResource{Type: "api", Name: "internal-api", Sensitivity: "medium"},
		Context:  types.AccessContext{Interactive: true},
	}
	dec, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Effect != types.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.Effect)
	}
}

func TestBuiltinEngine_DefaultDenyHighSensitivity(t *testing.T) {
	store := newTestStore(t)
	engine := NewBuiltinEngine(store)

	req := types.AccessRequest{
		Identity: types.AccessIdentity{Username: "bob", Type: "person"},
		Resource: types.AccessResource{Type: "db", Name: "secrets-db", Sensitivity: "high"},
	}
	dec, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Effect != types.DecisionDeny {
		t.Fatalf("expected deny, got %s", dec.Effect)
	}
}

func TestBuiltinEngine_ConditionOperators(t *testing.T) {
	tests := []struct {
		name     string
		cond     map[string]interface{}
		req      types.AccessRequest
		expected bool
	}{
		{
			name:     "eq true",
			cond:     map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"},
			req:      types.AccessRequest{Resource: types.AccessResource{Type: "ssh"}},
			expected: true,
		},
		{
			name:     "eq false",
			cond:     map[string]interface{}{"path": "resource.type", "op": "eq", "value": "rdp"},
			req:      types.AccessRequest{Resource: types.AccessResource{Type: "ssh"}},
			expected: false,
		},
		{
			name:     "neq true",
			cond:     map[string]interface{}{"path": "resource.type", "op": "neq", "value": "rdp"},
			req:      types.AccessRequest{Resource: types.AccessResource{Type: "ssh"}},
			expected: true,
		},
		{
			name:     "neq false",
			cond:     map[string]interface{}{"path": "resource.type", "op": "neq", "value": "ssh"},
			req:      types.AccessRequest{Resource: types.AccessResource{Type: "ssh"}},
			expected: false,
		},
		{
			name:     "contains true",
			cond:     map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "Admins"},
			req:      types.AccessRequest{Identity: types.AccessIdentity{Groups: []string{"Admins", "Users"}}},
			expected: true,
		},
		{
			name:     "contains false",
			cond:     map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "SuperAdmins"},
			req:      types.AccessRequest{Identity: types.AccessIdentity{Groups: []string{"Admins", "Users"}}},
			expected: false,
		},
		{
			name:     "not_contains true",
			cond:     map[string]interface{}{"path": "identity.groups", "op": "not_contains", "value": "SuperAdmins"},
			req:      types.AccessRequest{Identity: types.AccessIdentity{Groups: []string{"Admins"}}},
			expected: true,
		},
		{
			name:     "not_contains false",
			cond:     map[string]interface{}{"path": "identity.groups", "op": "not_contains", "value": "Admins"},
			req:      types.AccessRequest{Identity: types.AccessIdentity{Groups: []string{"Admins"}}},
			expected: false,
		},
		{
			name:     "in true",
			cond:     map[string]interface{}{"path": "resource.sensitivity", "op": "in", "value": []interface{}{"high", "critical"}},
			req:      types.AccessRequest{Resource: types.AccessResource{Sensitivity: "high"}},
			expected: true,
		},
		{
			name:     "in false",
			cond:     map[string]interface{}{"path": "resource.sensitivity", "op": "in", "value": []interface{}{"high", "critical"}},
			req:      types.AccessRequest{Resource: types.AccessResource{Sensitivity: "low"}},
			expected: false,
		},
		{
			name:     "not_in true",
			cond:     map[string]interface{}{"path": "resource.sensitivity", "op": "not_in", "value": []interface{}{"high", "critical"}},
			req:      types.AccessRequest{Resource: types.AccessResource{Sensitivity: "low"}},
			expected: true,
		},
		{
			name:     "not_in false",
			cond:     map[string]interface{}{"path": "resource.sensitivity", "op": "not_in", "value": []interface{}{"high", "critical"}},
			req:      types.AccessRequest{Resource: types.AccessResource{Sensitivity: "high"}},
			expected: false,
		},
		{
			name:     "exists true",
			cond:     map[string]interface{}{"path": "source.ip", "op": "exists"},
			req:      types.AccessRequest{Source: types.AccessSource{IP: "10.0.0.1"}},
			expected: true,
		},
		{
			name:     "exists false",
			cond:     map[string]interface{}{"path": "source.ip", "op": "exists"},
			req:      types.AccessRequest{Source: types.AccessSource{}},
			expected: false,
		},
		{
			name:     "not_exists true",
			cond:     map[string]interface{}{"path": "source.ip", "op": "not_exists"},
			req:      types.AccessRequest{Source: types.AccessSource{}},
			expected: true,
		},
		{
			name:     "not_exists false",
			cond:     map[string]interface{}{"path": "source.ip", "op": "not_exists"},
			req:      types.AccessRequest{Source: types.AccessSource{IP: "10.0.0.1"}},
			expected: false,
		},
		{
			name:     "gt true",
			cond:     map[string]interface{}{"path": "risk_score", "op": "gt", "value": 50},
			req:      types.AccessRequest{},
			expected: false,
		},
		{
			name:     "lt true",
			cond:     map[string]interface{}{"path": "context.interactive", "op": "eq", "value": false},
			req:      types.AccessRequest{Context: types.AccessContext{Interactive: false}},
			expected: true,
		},
		{
			name:     "regex true",
			cond:     map[string]interface{}{"path": "identity.username", "op": "regex", "value": "^svc-.*"},
			req:      types.AccessRequest{Identity: types.AccessIdentity{Username: "svc-deploy"}},
			expected: true,
		},
		{
			name:     "regex false",
			cond:     map[string]interface{}{"path": "identity.username", "op": "regex", "value": "^svc-.*"},
			req:      types.AccessRequest{Identity: types.AccessIdentity{Username: "alice"}},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqMap, err := requestToMap(tt.req)
			if err != nil {
				t.Fatal(err)
			}
			result, err := evaluateConditions(mustConditions(t, tt.cond), reqMap)
			if err != nil {
				t.Fatal(err)
			}
			if result != tt.expected {
				t.Fatalf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestBuiltinEngine_NumericOperators(t *testing.T) {
	reqMap := map[string]interface{}{"score": float64(75)}

	gtCond := mustConditions(t, map[string]interface{}{"path": "score", "op": "gt", "value": 50})
	result, err := evaluateConditions(gtCond, reqMap)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected gt to be true")
	}

	ltCond := mustConditions(t, map[string]interface{}{"path": "score", "op": "lt", "value": 50})
	result, err = evaluateConditions(ltCond, reqMap)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected lt to be false")
	}
}

func TestBuiltinEngine_Composition(t *testing.T) {
	req := types.AccessRequest{
		Identity: types.AccessIdentity{Username: "alice", Groups: []string{"Admins"}, Type: "person"},
		Resource: types.AccessResource{Type: "ssh", Sensitivity: "high"},
	}
	reqMap, err := requestToMap(req)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("all true", func(t *testing.T) {
		cond := map[string]interface{}{
			"all": []interface{}{
				map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"},
				map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "Admins"},
			},
		}
		result, err := evaluateConditions(mustConditions(t, cond), reqMap)
		if err != nil {
			t.Fatal(err)
		}
		if !result {
			t.Fatal("expected true")
		}
	})

	t.Run("all false", func(t *testing.T) {
		cond := map[string]interface{}{
			"all": []interface{}{
				map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"},
				map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "SuperAdmins"},
			},
		}
		result, err := evaluateConditions(mustConditions(t, cond), reqMap)
		if err != nil {
			t.Fatal(err)
		}
		if result {
			t.Fatal("expected false")
		}
	})

	t.Run("any true", func(t *testing.T) {
		cond := map[string]interface{}{
			"any": []interface{}{
				map[string]interface{}{"path": "resource.type", "op": "eq", "value": "rdp"},
				map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "Admins"},
			},
		}
		result, err := evaluateConditions(mustConditions(t, cond), reqMap)
		if err != nil {
			t.Fatal(err)
		}
		if !result {
			t.Fatal("expected true")
		}
	})

	t.Run("any false", func(t *testing.T) {
		cond := map[string]interface{}{
			"any": []interface{}{
				map[string]interface{}{"path": "resource.type", "op": "eq", "value": "rdp"},
				map[string]interface{}{"path": "identity.groups", "op": "contains", "value": "SuperAdmins"},
			},
		}
		result, err := evaluateConditions(mustConditions(t, cond), reqMap)
		if err != nil {
			t.Fatal(err)
		}
		if result {
			t.Fatal("expected false")
		}
	})

	t.Run("not true", func(t *testing.T) {
		inner := map[string]interface{}{"path": "resource.type", "op": "eq", "value": "rdp"}
		innerRaw := mustConditions(t, inner)
		cond := map[string]interface{}{"not": json.RawMessage(innerRaw)}
		result, err := evaluateConditions(mustConditions(t, cond), reqMap)
		if err != nil {
			t.Fatal(err)
		}
		if !result {
			t.Fatal("expected true")
		}
	})

	t.Run("not false", func(t *testing.T) {
		inner := map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"}
		innerRaw := mustConditions(t, inner)
		cond := map[string]interface{}{"not": json.RawMessage(innerRaw)}
		result, err := evaluateConditions(mustConditions(t, cond), reqMap)
		if err != nil {
			t.Fatal(err)
		}
		if result {
			t.Fatal("expected false")
		}
	})
}

func TestBuiltinEngine_PriorityOrdering(t *testing.T) {
	allowCond := map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"}
	denyCond := map[string]interface{}{"path": "resource.type", "op": "eq", "value": "ssh"}

	allowPolicy := &types.Policy{
		ID:         "allow-low",
		Enabled:    true,
		Priority:   1,
		Effect:     types.DecisionAllow,
		Conditions: mustConditions(t, allowCond),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	denyPolicy := &types.Policy{
		ID:         "deny-high",
		Enabled:    true,
		Priority:   100,
		Effect:     types.DecisionDeny,
		Conditions: mustConditions(t, denyCond),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	store := newTestStore(t, allowPolicy, denyPolicy)
	engine := NewBuiltinEngine(store)

	req := types.AccessRequest{
		Identity: types.AccessIdentity{Username: "alice", Type: "person"},
		Resource: types.AccessResource{Type: "ssh", Sensitivity: "medium"},
	}
	dec, err := engine.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Effect != types.DecisionDeny {
		t.Fatalf("expected deny (higher priority wins), got %s", dec.Effect)
	}
}
