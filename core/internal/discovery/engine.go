// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"math"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

const (
	minObservationDays   = 7
	classifyThreshold    = 0.75
	baselineMinFrequency = 0.05
	maxInterArrivalKeep  = 1000
)

type Weights struct {
	Temporal  float64
	Source    float64
	Target    float64
	LogonType float64
	Protocol  float64
	ADAttrs   float64
}

func DefaultWeights() Weights {
	return Weights{
		Temporal:  0.25,
		Source:    0.20,
		Target:    0.20,
		LogonType: 0.15,
		Protocol:  0.10,
		ADAttrs:   0.10,
	}
}

type Engine struct {
	store   storage.Store
	weights Weights
}

func NewEngine(store storage.Store, w Weights) *Engine {
	return &Engine{store: store, weights: w}
}

func (e *Engine) Ingest(ctx context.Context, events []types.ADAuthEvent) ([]types.ADEventDecision, error) {
	var decisions []types.ADEventDecision

	for i := range events {
		ev := &events[i]
		if ev.AccountSID == "" {
			continue
		}

		profile, err := e.store.BehaviouralProfiles(ctx).Get(ctx, ev.AccountSID)
		if err != nil {
			profile = newProfile(ev)
		}

		updateProfile(profile, ev)

		if !profile.Classified && e.observationWindowMet(profile) {
			score := e.classify(profile)
			profile.ClassificationScore = score
			if score >= classifyThreshold {
				profile.Classified = true
				profile.ClassifiedAt = time.Now().UTC()
				profile.Baseline = buildBaseline(profile)
			}
		}

		if err := e.store.BehaviouralProfiles(ctx).Upsert(ctx, profile); err != nil {
			return decisions, err
		}

		if profile.Classified && profile.Baseline != nil {
			if deviates(profile.Baseline, ev) {
				decisions = append(decisions, types.ADEventDecision{
					AccountSID:  ev.AccountSID,
					AccountName: ev.AccountName,
					Decision:    types.DecisionDeny,
					RiskScore:   100,
					Reasons:     []string{"service_account_baseline_deviation"},
				})
			}
		}
	}

	return decisions, nil
}

func (e *Engine) Profiles(ctx context.Context) ([]*types.BehaviouralProfile, error) {
	return e.store.BehaviouralProfiles(ctx).List(ctx)
}

func (e *Engine) observationWindowMet(p *types.BehaviouralProfile) bool {
	return p.ObservationEnd.Sub(p.ObservationStart) >= time.Duration(minObservationDays)*24*time.Hour &&
		p.TotalAuthCount >= 10
}

func (e *Engine) classify(p *types.BehaviouralProfile) float64 {
	w := e.weights
	score := w.Temporal*temporalRegularity(p) +
		w.Source*sourceConsistency(p) +
		w.Target*targetConsistency(p) +
		w.LogonType*logonTypePurity(p) +
		w.Protocol*protocolPurity(p)
	return score
}

func temporalRegularity(p *types.BehaviouralProfile) float64 {
	total := 0
	for _, v := range p.TimeOfDayHistogram {
		total += v
	}
	if total == 0 {
		return 0
	}
	entropy := 0.0
	for _, v := range p.TimeOfDayHistogram {
		if v > 0 {
			prob := float64(v) / float64(total)
			entropy -= prob * math.Log2(prob)
		}
	}
	maxEntropy := math.Log2(24)
	if maxEntropy == 0 {
		return 0
	}
	return 1 - entropy/maxEntropy
}

func sourceConsistency(p *types.BehaviouralProfile) float64 {
	n := len(p.SourceIPs)
	if n == 0 {
		return 0
	}
	return 1.0 / float64(n)
}

func targetConsistency(p *types.BehaviouralProfile) float64 {
	n := len(p.TargetSPNs)
	if n == 0 {
		return 1.0
	}
	return 1.0 / float64(n)
}

func logonTypePurity(p *types.BehaviouralProfile) float64 {
	total := 0
	maxCount := 0
	for _, v := range p.LogonTypes {
		total += v
		if v > maxCount {
			maxCount = v
		}
	}
	if total == 0 {
		return 0
	}
	return float64(maxCount) / float64(total)
}

func protocolPurity(p *types.BehaviouralProfile) float64 {
	total := 0
	maxCount := 0
	for _, v := range p.AuthPackages {
		total += v
		if v > maxCount {
			maxCount = v
		}
	}
	if total == 0 {
		return 0
	}
	return float64(maxCount) / float64(total)
}

func buildBaseline(p *types.BehaviouralProfile) *types.ServiceAccountBaseline {
	b := &types.ServiceAccountBaseline{}
	total := float64(p.TotalAuthCount)
	if total == 0 {
		return b
	}
	threshold := int(math.Ceil(total * baselineMinFrequency))

	for ip, count := range p.SourceIPs {
		if count >= threshold {
			b.AllowedSourceIPs = append(b.AllowedSourceIPs, ip)
		}
	}
	for spn, count := range p.TargetSPNs {
		if count >= threshold {
			b.AllowedTargetSPNs = append(b.AllowedTargetSPNs, spn)
		}
	}
	for lt, count := range p.LogonTypes {
		if count >= threshold {
			b.AllowedLogonTypes = append(b.AllowedLogonTypes, lt)
		}
	}
	for proto, count := range p.AuthPackages {
		if count >= threshold {
			b.AllowedProtocols = append(b.AllowedProtocols, proto)
		}
	}

	for hour, count := range p.TimeOfDayHistogram {
		if count >= threshold {
			b.AllowedTimeWindows = append(b.AllowedTimeWindows, types.TimeWindow{
				StartMinuteOfDay: hour * 60,
				EndMinuteOfDay:   (hour + 1) * 60,
			})
		}
	}

	return b
}

func deviates(b *types.ServiceAccountBaseline, ev *types.ADAuthEvent) bool {
	if ev.SourceIP != "" && len(b.AllowedSourceIPs) > 0 && !containsStr(b.AllowedSourceIPs, ev.SourceIP) {
		return true
	}
	if ev.TargetSPN != "" && len(b.AllowedTargetSPNs) > 0 && !containsStr(b.AllowedTargetSPNs, ev.TargetSPN) {
		return true
	}
	if ev.LogonType != 0 && len(b.AllowedLogonTypes) > 0 && !containsInt(b.AllowedLogonTypes, ev.LogonType) {
		return true
	}
	if ev.AuthPackage != "" && len(b.AllowedProtocols) > 0 && !containsStr(b.AllowedProtocols, ev.AuthPackage) {
		return true
	}
	if len(b.AllowedTimeWindows) > 0 {
		minuteOfDay := ev.Timestamp.Hour()*60 + ev.Timestamp.Minute()
		inWindow := false
		for _, tw := range b.AllowedTimeWindows {
			if minuteOfDay >= tw.StartMinuteOfDay && minuteOfDay < tw.EndMinuteOfDay {
				inWindow = true
				break
			}
		}
		if !inWindow {
			return true
		}
	}
	return false
}

func newProfile(ev *types.ADAuthEvent) *types.BehaviouralProfile {
	now := time.Now().UTC()
	return &types.BehaviouralProfile{
		AccountSID:       ev.AccountSID,
		SamAccountName:   ev.AccountName,
		ObservationStart: now,
		ObservationEnd:   now,
		SourceIPs:        make(map[string]int),
		TargetSPNs:       make(map[string]int),
		LogonTypes:       make(map[int]int),
		AuthPackages:     make(map[string]int),
	}
}

func updateProfile(p *types.BehaviouralProfile, ev *types.ADAuthEvent) {
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	p.TotalAuthCount++
	if now.After(p.ObservationEnd) {
		p.ObservationEnd = now
	}
	if now.Before(p.ObservationStart) {
		p.ObservationStart = now
	}

	p.TimeOfDayHistogram[now.Hour()]++
	p.DayOfWeekHistogram[int(now.Weekday())]++

	if ev.SourceIP != "" {
		p.SourceIPs[ev.SourceIP]++
	}
	if ev.TargetSPN != "" {
		p.TargetSPNs[ev.TargetSPN]++
	}
	if ev.LogonType != 0 {
		p.LogonTypes[ev.LogonType]++
	}
	if ev.AuthPackage != "" {
		p.AuthPackages[ev.AuthPackage]++
	}

	if !p.LastEventTime.IsZero() {
		delta := now.Sub(p.LastEventTime).Seconds()
		if delta > 0 {
			p.InterArrivalSum += delta
			p.InterArrivalSumSq += delta * delta
			p.InterArrivalCount++
		}
	}
	p.LastEventTime = now
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsInt(slice []int, n int) bool {
	for _, v := range slice {
		if v == n {
			return true
		}
	}
	return false
}
