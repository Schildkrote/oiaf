// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"math"
	"strconv"
	"strings"
	"time"
)

// Signal kinds emitted by this adapter. Each maps to a risk-signal family in
// docs/adapters/okta.md and is translated into an OIAF AccessRequest that the
// core risk engine (core/internal/risk) scores.
const (
	SignalImpossibleTravel = "impossible_travel"
	SignalNewGeo           = "new_geo"
	SignalNewDevice        = "new_device"
	SignalMFAFail          = "mfa_fail"
	SignalMFADeny          = "mfa_deny"
	SignalMFAFatigue       = "mfa_fatigue"
	SignalLegacyAuth       = "legacy_auth"
	SignalAdminAction      = "admin_action"
	SignalAuthFailure      = "auth_failure"
)

// Signal is one detected risk signal derived from an Okta log event.
type Signal struct {
	Type    string            `json:"type"`
	Login   string            `json:"login"`
	Time    time.Time         `json:"time"`
	IP      string            `json:"ip,omitempty"`
	Geo     string            `json:"geo,omitempty"`
	Details map[string]string `json:"details,omitempty"`
}

// SignalParams tunes detection thresholds (from config).
type SignalParams struct {
	FatigueThreshold  int
	FatigueWindow     time.Duration
	MaxTravelSpeedKmh float64
}

// Detector turns Okta log events into risk signals using per-identity memory
// (State). Detection is intentionally deterministic and offline: it never
// calls out to third-party geo/IP services.
type Detector struct {
	params SignalParams
}

func NewDetector(p SignalParams) *Detector {
	return &Detector{params: p}
}

// legacyAuthEventTypes are Okta event types indicating authentication with
// legacy/weak protocols (password-only or basic-auth transports such as
// IMAP/POP/SMTP legacy clients, ROPC).
var legacyCredentialTypes = map[string]bool{
	"password":   true,
	"basic_auth": true,
}

// adminEventTypePrefixes cover admin actions and privilege changes: account
// updates, role/group membership changes, factor lifecycle, policy lifecycle,
// session clearing and network-zone edits.
var adminEventTypePrefixes = []string{
	"user.account.",
	"user.mfa.factor.",
	"user.role.",
	"system.role.",
	"group.user_membership.",
	"group.privilege.",
	"policy.lifecycle.",
	"policy.rule.",
	"application.user_management.",
	"user.session.clear",
	"zone.",
}

// mfaEventTypePrefixes covers MFA verification attempts, including Okta Verify
// push denials (docs/adapters/okta.md: user.mfa.okta_verify.deny).
var mfaEventTypePrefixes = []string{
	"user.mfa.",
	"system.mfa.",
	"user.authentication.mfa.",
}

// Detect examines one event against the identity's memory and returns the
// signals it raises. It does not mutate state; call Commit after the event has
// been successfully delivered downstream.
func (d *Detector) Detect(ev *LogEvent, st *State) []Signal {
	login := ev.ActorLogin()
	if login == "" {
		return nil
	}
	idState := st.Identity(login)

	var signals []Signal
	base := func(t string, details map[string]string) Signal {
		return Signal{
			Type:    t,
			Login:   login,
			Time:    ev.Published,
			IP:      ev.Client.IPAddress,
			Geo:     ev.GeoLabel(),
			Details: details,
		}
	}

	// --- Impossible travel / new geolocation -------------------------------
	geo := ev.GeoLabel()
	if ev.Published.After(idState.LastSeen) || idState.LastSeen.IsZero() {
		if geoLoc := ev.Client.Geographic.Geolocation; geoLoc != nil && idState.HasGeo {
			km := haversineKm(idState.LastLat, idState.LastLon, geoLoc.Lat, geoLoc.Lon)
			hrs := ev.Published.Sub(idState.LastSeen).Hours()
			if hrs > 0 {
				speed := km / hrs
				if speed > d.params.MaxTravelSpeedKmh {
					signals = append(signals, base(SignalImpossibleTravel, map[string]string{
						"from_geo":    idState.LastGeo,
						"to_geo":      geo,
						"distance_km": strconvFormatFloat(km),
						"speed_kmh":   strconvFormatFloat(speed),
					}))
				}
			}
		}
		if geo != "" && len(idState.Geos) > 0 && !containsString(idState.Geos, geo) {
			signals = append(signals, base(SignalNewGeo, map[string]string{
				"geo":        geo,
				"known_geos": strings.Join(idState.Geos, ";"),
			}))
		}
	}

	// --- New device ---------------------------------------------------------
	if fp := ev.DeviceFingerprint(); fp != "" && len(idState.Devices) > 0 && !containsString(idState.Devices, fp) {
		signals = append(signals, base(SignalNewDevice, map[string]string{
			"user_agent": ev.Client.UserAgent.RawUserAgent,
		}))
	}

	// --- Legacy authentication ----------------------------------------------
	if isLegacyAuth(ev) {
		signals = append(signals, base(SignalLegacyAuth, map[string]string{
			"event_type":      ev.EventType,
			"credential_type": ev.AuthContext.CredentialType,
		}))
	}

	// --- Failed MFA / MFA fatigue --------------------------------------------
	if isMFAEvent(ev) {
		res := strings.ToUpper(ev.Outcome.Result)
		denied := strings.EqualFold(ev.EventType, "user.mfa.okta_verify.deny")
		switch {
		case denied:
			// A push deny is its own signal (deliberate rejection), not a
			// generic verification failure.
			signals = append(signals, base(SignalMFADeny, map[string]string{
				"event_type": ev.EventType,
			}))
		case res == "FAILURE":
			signals = append(signals, base(SignalMFAFail, map[string]string{
				"event_type": ev.EventType,
				"reason":     ev.Outcome.Reason,
			}))
		}
		if denied || res == "FAILURE" {
			fails := pruneMFATimes(append(idState.MFAFails, ev.Published), ev.Published, d.params.FatigueWindow)
			if len(fails) >= d.params.FatigueThreshold {
				signals = append(signals, base(SignalMFAFatigue, map[string]string{
					"fail_count": strconvItoa(len(fails)),
					"window":     d.params.FatigueWindow.String(),
				}))
			}
		}
	}

	// --- Admin actions / privilege changes ------------------------------------
	if isAdminEvent(ev) {
		target := ""
		for _, t := range ev.Targets {
			if t.AlternateID != "" && t.AlternateID != login {
				target = t.AlternateID
				break
			}
		}
		signals = append(signals, base(SignalAdminAction, map[string]string{
			"event_type": ev.EventType,
			"target":     target,
			"outcome":    ev.Outcome.Result,
		}))
	}

	// --- Generic auth failure (failed sign-in) ---------------------------------
	if strings.ToUpper(ev.Outcome.Result) == "FAILURE" && isAuthEvent(ev) && !isMFAEvent(ev) {
		signals = append(signals, base(SignalAuthFailure, map[string]string{
			"event_type": ev.EventType,
			"reason":     ev.Outcome.Reason,
		}))
	}

	return signals
}

// Commit updates the identity's detection memory after an event has been
// processed (called whether or not signals were raised).
func (d *Detector) Commit(ev *LogEvent, st *State) {
	login := ev.ActorLogin()
	if login == "" {
		return
	}
	idState := st.Identity(login)
	if ev.Published.Before(idState.LastSeen) {
		return // out-of-order event: don't rewind memory
	}
	idState.LastSeen = ev.Published

	if geo := ev.GeoLabel(); geo != "" {
		idState.LastGeo = geo
		idState.Geos = appendBounded(idState.Geos, geo, maxGeosPerIdentity)
	}
	if loc := ev.Client.Geographic.Geolocation; loc != nil {
		idState.LastLat = loc.Lat
		idState.LastLon = loc.Lon
		idState.HasGeo = true
	}
	if fp := ev.DeviceFingerprint(); fp != "" {
		idState.Devices = appendBounded(idState.Devices, fp, maxDevicesPerIdentity)
	}
	if isAdminEvent(ev) {
		idState.Admin = true
	}
	// Record failed MFA events so Detect can count fatigue across events.
	if isMFAEvent(ev) {
		res := strings.ToUpper(ev.Outcome.Result)
		if res == "FAILURE" || strings.EqualFold(ev.EventType, "user.mfa.okta_verify.deny") {
			idState.MFAFails = pruneMFATimes(append(idState.MFAFails, ev.Published), ev.Published, d.params.FatigueWindow)
			if len(idState.MFAFails) > maxMFAFailsPerIdentity {
				idState.MFAFails = idState.MFAFails[len(idState.MFAFails)-maxMFAFailsPerIdentity:]
			}
		}
	}
}

// appendBounded keeps the most recent entries, deduplicating: a value already
// present is moved to the end; the list is capped at max.
func appendBounded(list []string, v string, max int) []string {
	out := make([]string, 0, len(list)+1)
	for _, s := range list {
		if s != v {
			out = append(out, s)
		}
	}
	out = append(out, v)
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}

func pruneMFATimes(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	out := make([]time.Time, 0, len(times))
	for _, t := range times {
		if !t.Before(cutoff) {
			out = append(out, t)
		}
	}
	return out
}

func isMFAEvent(ev *LogEvent) bool {
	for _, p := range mfaEventTypePrefixes {
		if strings.HasPrefix(ev.EventType, p) {
			return true
		}
	}
	return false
}

func isAdminEvent(ev *LogEvent) bool {
	for _, p := range adminEventTypePrefixes {
		if strings.HasPrefix(ev.EventType, p) {
			return true
		}
	}
	return false
}

// isAuthEvent matches sign-in / authentication events per the design doc
// (user.session.start, user.authentication.sso, policy.evaluate_sign_on).
func isAuthEvent(ev *LogEvent) bool {
	return strings.HasPrefix(ev.EventType, "user.session.") ||
		strings.HasPrefix(ev.EventType, "user.authentication.") ||
		strings.HasPrefix(ev.EventType, "policy.evaluate_sign_on")
}

// isLegacyAuth flags legacy/weak authentication: password- or basic-auth
// credential types, or ROPC/basic-auth transports (IMAP, POP, SMTP) recorded
// in the event debug data.
func isLegacyAuth(ev *LogEvent) bool {
	if legacyCredentialTypes[strings.ToLower(ev.AuthContext.CredentialType)] {
		return true
	}
	for _, v := range ev.Context.DebugData {
		lv := strings.ToLower(v)
		if strings.Contains(lv, "grant_type=password") ||
			strings.HasPrefix(lv, "basic ") ||
			strings.Contains(lv, "/imap") ||
			strings.Contains(lv, "/pop") ||
			strings.Contains(lv, "/smtp") {
			return true
		}
	}
	return false
}

// haversineKm returns the great-circle distance between two points in km.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0
	rad := func(d float64) float64 { return d * math.Pi / 180 }
	dLat := rad(lat2 - lat1)
	dLon := rad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(rad(lat1))*math.Cos(rad(lat2))*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthRadiusKm * math.Asin(math.Sqrt(a))
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func strconvFormatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

func strconvItoa(i int) string {
	return strconv.Itoa(i)
}
