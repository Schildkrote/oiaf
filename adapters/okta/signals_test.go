// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"
	"time"
)

func baseTime() time.Time {
	return time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
}

func defaultParams() SignalParams {
	return SignalParams{FatigueThreshold: 3, FatigueWindow: 10 * time.Minute, MaxTravelSpeedKmh: 900}
}

func signInEvent(uuid, login string, at time.Time, lat, lon float64, city, country string) *LogEvent {
	return &LogEvent{
		UUID:      uuid,
		Published: at,
		EventType: "user.session.start",
		Outcome:   Outcome{Result: "SUCCESS"},
		Actor:     Actor{AlternateID: login, Type: "User"},
		Client: EventClient{
			IPAddress: "1.2.3.4",
			UserAgent: UserAgent{RawUserAgent: "Mozilla/5.0"},
			Geographic: Geographic{
				City:        city,
				Country:     country,
				Geolocation: &Geo{Lat: lat, Lon: lon},
			},
		},
	}
}

// TestDetectImpossibleTravel verifies a physically impossible location jump
// raises the signal, and a plausible one does not.
func TestDetectImpossibleTravel(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()

	// Berlin -> New York in 30 minutes (~6400 km in 0.5h = ~12800 km/h).
	first := signInEvent("u1", "alice@corp.example", baseTime(), 52.52, 13.405, "Berlin", "DE")
	d.Commit(first, st)

	travel := signInEvent("u2", "alice@corp.example", baseTime().Add(30*time.Minute), 40.7128, -74.006, "New York", "US")
	sigs := d.Detect(travel, st)
	if !hasSignal(sigs, SignalImpossibleTravel) {
		t.Fatalf("expected impossible_travel signal, got %v", signalTypes(sigs))
	}
	d.Commit(travel, st)

	// New York -> Hamburg 8 hours later (~6200 km in 8h = ~775 km/h):
	// under the 900 km/h ceiling, so plausible.
	plausible := signInEvent("u3", "alice@corp.example", baseTime().Add(8*time.Hour+30*time.Minute), 53.551, 9.993, "Hamburg", "DE")
	sigs = d.Detect(plausible, st)
	if hasSignal(sigs, SignalImpossibleTravel) {
		t.Fatalf("did not expect impossible_travel for NY->Hamburg at sane speed, got %v", signalTypes(sigs))
	}
}

// TestDetectNewGeoAndDevice verifies first-sighting baselines: no signal on
// the first event, new geo/device signals on unfamiliar ones.
func TestDetectNewGeoAndDevice(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()

	first := signInEvent("u1", "bob@corp.example", baseTime(), 48.13, 11.58, "Munich", "DE")
	if sigs := d.Detect(first, st); len(sigs) != 0 {
		t.Fatalf("first sighting must be baseline, got %v", signalTypes(sigs))
	}
	d.Commit(first, st)

	// Same geo, new device fingerprint (different UA).
	second := signInEvent("u2", "bob@corp.example", baseTime().Add(time.Hour), 48.13, 11.58, "Munich", "DE")
	second.Client.UserAgent.RawUserAgent = "curl/8.0"
	sigs := d.Detect(second, st)
	if !hasSignal(sigs, SignalNewDevice) {
		t.Fatalf("expected new_device, got %v", signalTypes(sigs))
	}
	if hasSignal(sigs, SignalNewGeo) {
		t.Fatalf("same geo must not raise new_geo, got %v", signalTypes(sigs))
	}
	d.Commit(second, st)

	// Known geo again: no new_geo. But far future time to avoid travel math noise.
	third := signInEvent("u3", "bob@corp.example", baseTime().Add(2*time.Hour), 48.13, 11.58, "Munich", "DE")
	if sigs := d.Detect(third, st); hasSignal(sigs, SignalNewGeo) {
		t.Fatalf("previously-seen geo must not raise new_geo, got %v", signalTypes(sigs))
	}
}

// TestDetectMFAFatigue verifies repeated MFA failures inside the window raise
// mfa_fail each time and mfa_fatigue once the threshold is crossed.
func TestDetectMFAFatigue(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()

	mk := func(uuid string, at time.Time) *LogEvent {
		return &LogEvent{
			UUID:      uuid,
			Published: at,
			EventType: "user.mfa.okta_verify.verify",
			Outcome:   Outcome{Result: "FAILURE", Reason: "User rejected"},
			Actor:     Actor{AlternateID: "carol@corp.example"},
			Client:    EventClient{IPAddress: "9.9.9.9"},
		}
	}

	sigs := d.Detect(mk("m1", baseTime()), st)
	d.Commit(mk("m1", baseTime()), st)
	if !hasSignal(sigs, SignalMFAFail) || hasSignal(sigs, SignalMFAFatigue) {
		t.Fatalf("first failure: want mfa_fail only, got %v", signalTypes(sigs))
	}

	sigs = d.Detect(mk("m2", baseTime().Add(time.Minute)), st)
	if hasSignal(sigs, SignalMFAFatigue) {
		t.Fatalf("second failure must not be fatigue yet, got %v", signalTypes(sigs))
	}
	d.Commit(mk("m2", baseTime().Add(time.Minute)), st)

	// Third failure crosses the threshold (Detect appends the current event
	// to the recorded failures before counting).
	ev3 := mk("m3", baseTime().Add(2*time.Minute))
	sigs = d.Detect(ev3, st)
	if !hasSignal(sigs, SignalMFAFatigue) {
		t.Fatalf("third failure: expected mfa_fatigue, got %v", signalTypes(sigs))
	}
	d.Commit(ev3, st)

	// Fatigue window expiry: an 11-minute-old failure set must not count.
	st2 := NewState()
	d2 := NewDetector(defaultParams())
	d2.Detect(mk("n1", baseTime()), st2)
	d2.Commit(mk("n1", baseTime()), st2)
	d2.Detect(mk("n2", baseTime().Add(time.Minute)), st2)
	d2.Commit(mk("n2", baseTime().Add(time.Minute)), st2)
	sigs = d2.Detect(mk("n3", baseTime().Add(15*time.Minute)), st2)
	if hasSignal(sigs, SignalMFAFatigue) {
		t.Fatalf("failures outside window must not raise fatigue, got %v", signalTypes(sigs))
	}
}

// TestDetectMFADeny verifies Okta Verify push denials raise mfa_deny.
func TestDetectMFADeny(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()
	ev := &LogEvent{
		UUID:      "d1",
		Published: baseTime(),
		EventType: "user.mfa.okta_verify.deny",
		Outcome:   Outcome{Result: "FAILURE", Reason: "User rejected push"},
		Actor:     Actor{AlternateID: "dave@corp.example"},
	}
	sigs := d.Detect(ev, st)
	if !hasSignal(sigs, SignalMFADeny) {
		t.Fatalf("expected mfa_deny, got %v", signalTypes(sigs))
	}
}

// TestDetectLegacyAuth verifies password/basic-auth credential types and
// legacy transport debug data raise legacy_auth.
func TestDetectLegacyAuth(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()

	cases := []struct {
		name string
		ev   *LogEvent
	}{
		{"password credential", &LogEvent{
			UUID: "l1", Published: baseTime(), EventType: "user.authentication.authenticate",
			Outcome: Outcome{Result: "SUCCESS"}, Actor: Actor{AlternateID: "eve@corp.example"},
			AuthContext: AuthCtx{CredentialType: "password"},
		}},
		{"basic_auth credential", &LogEvent{
			UUID: "l2", Published: baseTime(), EventType: "user.authentication.authenticate",
			Outcome: Outcome{Result: "SUCCESS"}, Actor: Actor{AlternateID: "eve@corp.example"},
			AuthContext: AuthCtx{CredentialType: "basic_auth"},
		}},
		{"IMAP transport in debug data", &LogEvent{
			UUID: "l3", Published: baseTime(), EventType: "user.authentication.authenticate",
			Outcome: Outcome{Result: "SUCCESS"}, Actor: Actor{AlternateID: "eve@corp.example"},
			Context: DebugCtx{DebugData: map[string]string{"requestUri": "/imap/mailbox"}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sigs := d.Detect(tc.ev, st)
			if !hasSignal(sigs, SignalLegacyAuth) {
				t.Fatalf("expected legacy_auth, got %v", signalTypes(sigs))
			}
		})
	}

	// A modern MFA sign-in must not be flagged legacy.
	modern := &LogEvent{
		UUID: "l4", Published: baseTime(), EventType: "user.authentication.sso",
		Outcome: Outcome{Result: "SUCCESS"}, Actor: Actor{AlternateID: "eve@corp.example"},
		AuthContext: AuthCtx{CredentialType: "otp"},
	}
	if sigs := d.Detect(modern, st); hasSignal(sigs, SignalLegacyAuth) {
		t.Fatalf("modern sign-in flagged legacy: %v", signalTypes(sigs))
	}
}

// TestDetectAdminAction verifies admin/privilege events raise admin_action
// and mark the identity privileged in state.
func TestDetectAdminAction(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()

	ev := &LogEvent{
		UUID: "a1", Published: baseTime(), EventType: "group.user_membership.add",
		Outcome: Outcome{Result: "SUCCESS"}, Actor: Actor{AlternateID: "admin@corp.example"},
		Targets: []Target{{AlternateID: "victim@corp.example", Type: "User"}},
	}
	sigs := d.Detect(ev, st)
	if !hasSignal(sigs, SignalAdminAction) {
		t.Fatalf("expected admin_action, got %v", signalTypes(sigs))
	}
	d.Commit(ev, st)
	if !st.Identities["admin@corp.example"].Admin {
		t.Fatal("expected identity to be marked admin after commit")
	}

	for _, et := range []string{"user.account.update_profile", "system.role.admin.assign", "policy.rule.update", "application.user_management.grant"} {
		e := &LogEvent{UUID: "x", Published: baseTime(), EventType: et, Actor: Actor{AlternateID: "admin@corp.example"}, Outcome: Outcome{Result: "SUCCESS"}}
		if sigs := d.Detect(e, st); !hasSignal(sigs, SignalAdminAction) {
			t.Fatalf("event %s: expected admin_action, got %v", et, signalTypes(sigs))
		}
	}
}

// TestDetectAuthFailure verifies failed sign-ins raise auth_failure but MFA
// failures don't double-raise it (they get their own signals).
func TestDetectAuthFailure(t *testing.T) {
	d := NewDetector(defaultParams())
	st := NewState()

	failed := &LogEvent{
		UUID: "f1", Published: baseTime(), EventType: "user.session.start",
		Outcome: Outcome{Result: "FAILURE", Reason: "INVALID_CREDENTIALS"},
		Actor:   Actor{AlternateID: "frank@corp.example"},
	}
	sigs := d.Detect(failed, st)
	if !hasSignal(sigs, SignalAuthFailure) {
		t.Fatalf("expected auth_failure, got %v", signalTypes(sigs))
	}

	mfaFailed := &LogEvent{
		UUID: "f2", Published: baseTime(), EventType: "user.mfa.okta_verify.verify",
		Outcome: Outcome{Result: "FAILURE", Reason: "rejected"},
		Actor:   Actor{AlternateID: "frank@corp.example"},
	}
	sigs = d.Detect(mfaFailed, st)
	if hasSignal(sigs, SignalAuthFailure) {
		t.Fatalf("MFA failure must not double-raise auth_failure, got %v", signalTypes(sigs))
	}

	success := &LogEvent{
		UUID: "f3", Published: baseTime(), EventType: "user.session.start",
		Outcome: Outcome{Result: "SUCCESS"}, Actor: Actor{AlternateID: "frank@corp.example"},
	}
	if sigs := d.Detect(success, st); hasSignal(sigs, SignalAuthFailure) {
		t.Fatalf("successful sign-in raised auth_failure: %v", signalTypes(sigs))
	}
}

// TestSignalToAccessRequest verifies the mapping into the OIAF risk-engine
// request shape: privileged flag from admin memory, usual_geo baseline,
// source geo, and sensitivity escalation for high-severity signals.
func TestSignalToAccessRequest(t *testing.T) {
	st := NewState()
	idState := st.Identity("gina@corp.example")
	idState.Admin = true
	idState.LastGeo = "Berlin, DE"

	sig := Signal{
		Type: SignalImpossibleTravel, Login: "gina@corp.example",
		Time: baseTime(), IP: "5.6.7.8", Geo: "Lagos, NG",
	}
	req := signalToAccessRequest(sig, st)

	ident := req["identity"].(map[string]any)
	if ident["privileged"] != true {
		t.Errorf("expected privileged=true for known admin, got %v", ident["privileged"])
	}
	if ident["usual_geo"] != "Berlin, DE" {
		t.Errorf("expected usual_geo baseline, got %v", ident["usual_geo"])
	}
	src := req["source"].(map[string]any)
	if src["geo"] != "Lagos, NG" || src["ip"] != "5.6.7.8" {
		t.Errorf("expected source geo/ip, got %v", src)
	}
	res := req["resource"].(map[string]any)
	if res["sensitivity"] != "high" {
		t.Errorf("expected high sensitivity for impossible travel, got %v", res["sensitivity"])
	}
	if res["name"] != "okta:impossible_travel" {
		t.Errorf("expected signal in resource name, got %v", res["name"])
	}
}

func hasSignal(sigs []Signal, t string) bool {
	for _, s := range sigs {
		if s.Type == t {
			return true
		}
	}
	return false
}

func signalTypes(sigs []Signal) []string {
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.Type)
	}
	return out
}
