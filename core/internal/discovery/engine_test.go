// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

func newTestEvent(sid, name, ip, spn string, ts time.Time) types.ADAuthEvent {
	return types.ADAuthEvent{
		AccountSID:  sid,
		AccountName: name,
		SourceIP:    ip,
		TargetSPN:   spn,
		LogonType:   3,
		AuthPackage: "Kerberos",
		Timestamp:   ts,
	}
}

// ingestRegularServiceAccount feeds a steady pattern: one IP, one SPN, one
// hour of day, one logon type, one auth package, across more than the 7-day
// observation window with more than 10 events. It returns the engine and the
// profile after ingest.
func ingestRegularServiceAccount(t *testing.T, store storage.Store) (*Engine, *types.BehaviouralProfile) {
	t.Helper()
	e := NewEngine(store, DefaultWeights())
	ctx := context.Background()

	start := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	var events []types.ADAuthEvent
	for i := 0; i < 12; i++ {
		events = append(events, newTestEvent(
			"S-1-5-21-abc-1001", "svc-billing", "10.0.0.5", "MSSQLSvc/db01",
			start.AddDate(0, 0, i),
		))
	}
	_, err := e.Ingest(ctx, events)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	profile, err := store.BehaviouralProfiles(ctx).Get(ctx, "S-1-5-21-abc-1001")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	return e, profile
}

func TestServiceAccountGetsClassified(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	_, profile := ingestRegularServiceAccount(t, store)

	if !profile.Classified {
		t.Fatalf("expected profile to be classified; score=%.3f", profile.ClassificationScore)
	}
	if profile.ClassificationScore < classifyThreshold {
		t.Fatalf("expected score >= %v, got %v", classifyThreshold, profile.ClassificationScore)
	}
	if profile.Baseline == nil {
		t.Fatal("expected baseline to be built")
	}
	if len(profile.Baseline.AllowedSourceIPs) != 1 || profile.Baseline.AllowedSourceIPs[0] != "10.0.0.5" {
		t.Fatalf("unexpected baseline source IPs: %v", profile.Baseline.AllowedSourceIPs)
	}
	if len(profile.Baseline.AllowedTargetSPNs) != 1 || profile.Baseline.AllowedTargetSPNs[0] != "MSSQLSvc/db01" {
		t.Fatalf("unexpected baseline target SPNs: %v", profile.Baseline.AllowedTargetSPNs)
	}
}

func TestRegularEventsProduceNoDecisions(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	e := NewEngine(store, DefaultWeights())
	ctx := context.Background()

	start := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	var events []types.ADAuthEvent
	for i := 0; i < 12; i++ {
		events = append(events, newTestEvent("S-1-5-21-abc-2002", "svc-payroll", "10.0.1.5", "MSSQLSvc/db02", start.AddDate(0, 0, i)))
	}
	decisions, err := e.Ingest(ctx, events)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(decisions) != 0 {
		t.Fatalf("expected no decisions for in-baseline events, got %v", decisions)
	}
}

func TestBaselineDeviationProducesDeny(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	e, profile := ingestRegularServiceAccount(t, store)
	if !profile.Classified {
		t.Fatal("precondition: profile should be classified")
	}

	ctx := context.Background()
	// Same account, same hour — but a new source IP that is not in the baseline.
	deviant := newTestEvent("S-1-5-21-abc-1001", "svc-billing", "10.9.9.9", "MSSQLSvc/db01",
		time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC))
	decisions, err := e.Ingest(ctx, []types.ADAuthEvent{deviant})
	if err != nil {
		t.Fatalf("ingest deviant: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected exactly 1 decision, got %d: %v", len(decisions), decisions)
	}
	d := decisions[0]
	if d.Decision != types.DecisionDeny {
		t.Fatalf("expected deny, got %v", d.Decision)
	}
	if len(d.Reasons) == 0 || d.Reasons[0] != "service_account_baseline_deviation" {
		t.Fatalf("expected baseline deviation reason, got %v", d.Reasons)
	}
}

func TestTargetSPNDeviationProducesDeny(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	e, _ := ingestRegularServiceAccount(t, store)
	ctx := context.Background()

	deviant := newTestEvent("S-1-5-21-abc-1001", "svc-billing", "10.0.0.5", "W32time/otherhost",
		time.Date(2026, 7, 20, 9, 30, 0, 0, time.UTC))
	decisions, err := e.Ingest(ctx, []types.ADAuthEvent{deviant})
	if err != nil {
		t.Fatalf("ingest deviant: %v", err)
	}
	if len(decisions) != 1 || decisions[0].Decision != types.DecisionDeny {
		t.Fatalf("expected deny for SPN deviation, got %v", decisions)
	}
}

func TestUnclassifiedProfileProducesNoDecisions(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	e := NewEngine(store, DefaultWeights())
	ctx := context.Background()

	// Only 3 events: below the 10-event observation floor, so no
	// classification and no baseline, even though they deviate from each other.
	start := time.Date(2026, 7, 1, 9, 0, 0, 0, time.UTC)
	events := []types.ADAuthEvent{
		newTestEvent("S-1-5-21-abc-3003", "svc-new", "10.0.0.5", "MSSQLSvc/db01", start),
		newTestEvent("S-1-5-21-abc-3003", "svc-new", "10.0.0.6", "MSSQLSvc/db01", start.Add(time.Hour)),
		newTestEvent("S-1-5-21-abc-3003", "svc-new", "10.0.0.7", "MSSQLSvc/db01", start.Add(2*time.Hour)),
	}
	decisions, err := e.Ingest(ctx, events)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(decisions) != 0 {
		t.Fatalf("expected no decisions before classification, got %v", decisions)
	}
}

func TestEventWithoutSIDIsSkipped(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	e := NewEngine(store, DefaultWeights())
	ctx := context.Background()

	ev := newTestEvent("", "no-sid", "10.0.0.5", "spn", time.Now())
	decisions, err := e.Ingest(ctx, []types.ADAuthEvent{ev})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if len(decisions) != 0 {
		t.Fatalf("expected decisions skipped for empty SID, got %v", decisions)
	}
	profiles, err := store.BehaviouralProfiles(ctx).List(ctx)
	if err != nil {
		t.Fatalf("list profiles: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected no profiles for empty SID, got %d", len(profiles))
	}
}

func TestClassifyScoringPenalisesIrregularBehaviour(t *testing.T) {
	store := storage.NewMemoryStore()
	defer store.Close()
	e := NewEngine(store, DefaultWeights())
	ctx := context.Background()

	// Chaotic pattern: many IPs, many hours, mixed logon types — should score
	// well below the classification threshold even after the observation
	// window is met.
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	var events []types.ADAuthEvent
	logonTypes := []int{3, 5, 10}
	packages := []string{"Kerberos", "NTLM"}
	for i := 0; i < 14; i++ {
		ev := newTestEvent(
			"S-1-5-21-abc-4004", "svc-chaos",
			"10.0.0."+string(rune('0'+i)), "SPN-"+string(rune('a'+i)),
			start.AddDate(0, 0, i).Add(time.Duration(i%24)*time.Hour),
		)
		ev.LogonType = logonTypes[i%len(logonTypes)]
		ev.AuthPackage = packages[i%len(packages)]
		events = append(events, ev)
	}
	_, err := e.Ingest(ctx, events)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	profile, err := store.BehaviouralProfiles(ctx).Get(ctx, "S-1-5-21-abc-4004")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if profile.Classified {
		t.Fatalf("expected chaotic profile to stay unclassified, score=%.3f", profile.ClassificationScore)
	}
}
