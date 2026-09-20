// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package risk

import (
	"context"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

type Engine interface {
	Score(ctx context.Context, req types.AccessRequest) (types.RiskResult, error)
}

type RuleEngine struct {
	thresholds Thresholds
}

type Thresholds struct {
	Low      int
	Elevated int
	High     int
	VeryHigh int
}

func DefaultThresholds() Thresholds {
	return Thresholds{Low: 24, Elevated: 49, High: 74, VeryHigh: 89}
}

func NewRuleEngine(t Thresholds) *RuleEngine {
	return &RuleEngine{thresholds: t}
}

func (e *RuleEngine) Score(ctx context.Context, req types.AccessRequest) (types.RiskResult, error) {
	score := 0
	var reasons []string

	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}

	if req.Identity.Privileged || containsGroup(req.Identity.Groups, "Admins") || containsGroup(req.Identity.Groups, "Domain Admins") {
		add(25, "privileged_group")
	}

	switch req.Resource.Sensitivity {
	case "high":
		add(20, "resource_sensitivity_high")
	case "critical":
		add(30, "resource_sensitivity_critical")
	}

	if !req.Context.MFARecent {
		add(15, "no_recent_mfa")
	}

	if req.Source.Geo != "" && req.Identity.UsualGeo != "" && req.Source.Geo != req.Identity.UsualGeo {
		add(30, "geo_mismatch")
	}

	switch req.Protocol.Name {
	case "ntlm":
		add(20, "weak_protocol_ntlm")
	case "ldap_simple_bind_cleartext":
		add(30, "cleartext_ldap_bind")
	}

	if req.Identity.Type == "service_account" && req.Context.Interactive {
		add(60, "service_account_interactive")
	}

	if req.Context.BaselineDeviation {
		add(50, "service_account_baseline_deviation")
	}

	if req.Identity.LastLogonDays > 90 {
		add(20, "stale_account")
	}

	if req.Identity.PasswordNeverExpires {
		add(15, "password_never_expires")
	}

	if req.Identity.HasSPN && !req.Identity.IsGMSA {
		add(25, "spn_bearing_unmanaged")
	}

	if req.Identity.Privileged && req.Identity.LastLogonDays > 30 {
		add(40, "privileged_stale")
	}

	if !req.Device.Managed {
		add(15, "unmanaged_device")
	}

	if !req.Device.Compliant {
		add(25, "noncompliant_device")
	}

	switch req.Source.Reputation {
	case "bad":
		add(40, "bad_ip_reputation")
	case "unknown":
		add(5, "unknown_ip_reputation")
	}

	if score > 100 {
		score = 100
	}

	level := e.level(score)

	return types.RiskResult{
		Score:   score,
		Level:   level,
		Reasons: reasons,
	}, nil
}

func (e *RuleEngine) level(score int) string {
	t := e.thresholds
	switch {
	case score <= t.Low:
		return "low"
	case score <= t.Elevated:
		return "elevated"
	case score <= t.High:
		return "high"
	case score <= t.VeryHigh:
		return "very_high"
	default:
		return "critical"
	}
}

func containsGroup(groups []string, target string) bool {
	for _, g := range groups {
		if g == target {
			return true
		}
	}
	return false
}
