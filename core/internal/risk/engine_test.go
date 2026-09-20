// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package risk

import (
	"context"
	"testing"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

func newEngine() *RuleEngine {
	return NewRuleEngine(DefaultThresholds())
}

func baseRequest() types.AccessRequest {
	return types.AccessRequest{
		Identity: types.AccessIdentity{Type: "person", UsualGeo: "US"},
		Resource: types.AccessResource{Sensitivity: "low"},
		Context:  types.AccessContext{MFARecent: true},
		Device:   types.AccessDevice{Managed: true, Compliant: true},
		Source:   types.AccessSource{Geo: "US", Reputation: "good"},
	}
}

func TestRuleEngine_PrivilegedGroup(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Identity.Groups = []string{"Admins"}
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 25 {
		t.Fatalf("expected 25, got %d", result.Score)
	}
}

func TestRuleEngine_HighSensitivity(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Resource.Sensitivity = "high"
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 20 {
		t.Fatalf("expected 20, got %d", result.Score)
	}
}

func TestRuleEngine_NoRecentMFA(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Context.MFARecent = false
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 15 {
		t.Fatalf("expected 15, got %d", result.Score)
	}
}

func TestRuleEngine_ServiceAccountInteractive(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Identity.Type = "service_account"
	req.Context.Interactive = true
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 60 {
		t.Fatalf("expected 60, got %d", result.Score)
	}
}

func TestRuleEngine_NTLMProtocol(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Protocol.Name = "ntlm"
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 20 {
		t.Fatalf("expected 20, got %d", result.Score)
	}
}

func TestRuleEngine_BadIPReputation(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Source.Reputation = "bad"
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 40 {
		t.Fatalf("expected 40, got %d", result.Score)
	}
}

func TestRuleEngine_ScoreCappedAt100(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Identity.Groups = []string{"Admins"}
	req.Identity.Privileged = true
	req.Resource.Sensitivity = "critical"
	req.Context.MFARecent = false
	req.Context.Interactive = true
	req.Identity.Type = "service_account"
	req.Protocol.Name = "ntlm"
	req.Source.Reputation = "bad"
	req.Device.Managed = false
	req.Device.Compliant = false
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 100 {
		t.Fatalf("expected 100, got %d", result.Score)
	}
}

func TestRuleEngine_RiskLevels(t *testing.T) {
	tests := []struct {
		name  string
		score int
		level string
	}{
		{"low", 20, "low"},
		{"elevated", 40, "elevated"},
		{"high", 60, "high"},
		{"very_high", 80, "very_high"},
		{"critical", 95, "critical"},
	}
	e := newEngine()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.level(tt.score)
			if got != tt.level {
				t.Fatalf("expected %s, got %s", tt.level, got)
			}
		})
	}
}

func TestRuleEngine_MultipleRulesCombine(t *testing.T) {
	e := newEngine()
	req := baseRequest()
	req.Identity.Groups = []string{"Admins"}
	req.Resource.Sensitivity = "high"
	req.Context.MFARecent = false
	result, err := e.Score(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	expected := 25 + 20 + 15
	if result.Score != expected {
		t.Fatalf("expected %d, got %d", expected, result.Score)
	}
	if len(result.Reasons) != 3 {
		t.Fatalf("expected 3 reasons, got %d", len(result.Reasons))
	}
}
