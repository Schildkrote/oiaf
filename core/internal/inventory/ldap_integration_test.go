// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

//go:build ldap_integration

package inventory

// Integration test for the AD inventory scanner against a REAL directory server.
//
// WHY THIS IS NOT REDUNDANT WITH scanner_test.go: every unit test there builds an
// *ldap.Entry by hand and sets exactly the attributes it cares about. That construction
// is precisely what hides the two defects that only appear against a live directory:
//
//   - F3: parseEntry read GetAttributeValue("distinguishedName"). distinguishedName is
//     a CONSTRUCTED attribute that a real directory does not return in search results
//     even when requested, so OU was always "" in production — while the unit test,
//     which set the attribute itself, passed.
//   - F4: isPrivilegedEntry reads primaryGroupID, but fetchAccounts did not REQUEST it.
//     A directory does not send unrequested attributes, so the SID-based privilege
//     signal could never fire — again invisible to a hand-built entry.
//
// A server round-trip is the only way to observe "requested" and "returned" diverging.
//
// RUN IT:  make test-ldap   (or test/ldap/run-integration.sh)
// The harness starts osixia/openldap in docker, loads a schema emulating the AD
// attributes, and exports OIAF_TEST_LDAP_URL. Without that variable the test skips, so
// `go test ./...` in CI is unaffected.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Schildkrote/oiaf/core/internal/storage"
)

func ldapURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("OIAF_TEST_LDAP_URL")
	if u == "" {
		t.Skip("OIAF_TEST_LDAP_URL not set; run test/ldap/run-integration.sh " +
			"(or `make test-ldap`) to start the directory server")
	}
	return u
}

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	return NewScanner(Config{
		LDAPURL:      ldapURL(t),
		BindDN:       os.Getenv("OIAF_TEST_LDAP_BIND_DN"),
		BindPassword: os.Getenv("OIAF_TEST_LDAP_BIND_PASSWORD"),
		BaseDN:       envOr("OIAF_TEST_LDAP_BASE_DN", "dc=corp,dc=example,dc=com"),
	}, storage.NewMemoryStore())
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// TestIntegration_ScanAgainstRealDirectory is the headline end-to-end proof: connect,
// bind, search, parse, classify, persist. Expected counts come from testdata.ldif,
// documented per-entry there.
func TestIntegration_ScanAgainstRealDirectory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := newScanner(t)
	summary, err := s.Scan(ctx)
	if err != nil {
		t.Fatalf("Scan against a real directory failed: %v", err)
	}
	t.Logf("summary: %+v", summary)

	// 9 accounts in testdata.ldif: 8 user + 1 computer.
	if summary.TotalAccounts != 9 {
		t.Errorf("TotalAccounts = %d, want 9 — the search filter or the base DN is "+
			"wrong, or the schema did not load", summary.TotalAccounts)
	}
	if summary.UserAccounts != 8 {
		t.Errorf("UserAccounts = %d, want 8", summary.UserAccounts)
	}
	if summary.ComputerAccounts != 1 {
		t.Errorf("ComputerAccounts = %d, want 1 (SRV01)", summary.ComputerAccounts)
	}
	// svc_sql (2 SPNs), svc_gmsa (gMSA marker), SRV01 (SPN) = 3.
	if summary.ServiceAccounts != 3 {
		t.Errorf("ServiceAccounts = %d, want 3", summary.ServiceAccounts)
	}
	// domadmin (memberOf Domain Admins) + backupop (primaryGroupID 551) = 2.
	if summary.PrivilegedAccounts != 2 {
		t.Errorf("PrivilegedAccounts = %d, want 2 (domadmin via memberOf, backupop via "+
			"primaryGroupID). If this is 1, one of the two privilege signals is dead: "+
			"memberOf-only means primaryGroupID is not being requested (F4); "+
			"primaryGroupID-only means the memberOf name match is dead (F2). "+
			"If this is 3, the loose 'admin' substring match is back and "+
			"assistant/Admin-Assistants is being flagged.", summary.PrivilegedAccounts)
	}
	if summary.DisabledAccounts != 1 {
		t.Errorf("DisabledAccounts = %d, want 1 (old_svc, UAC 514)", summary.DisabledAccounts)
	}
	// Only old_svc is stale: lastLogonTimestamp 2020-01-01. never_used carries the
	// "never" sentinel and must NOT be stale.
	if summary.StaleAccounts != 1 {
		t.Errorf("StaleAccounts = %d, want 1 (old_svc). If this is high (near "+
			"TotalAccounts), parseFileTime is overflowing int64 again and every real "+
			"timestamp lands centuries in the past (F1). If this is 0, the FILETIME "+
			"conversion is producing a zero time for a valid value.", summary.StaleAccounts)
	}
}

// TestIntegration_OUIsPopulatedFromEntryDN is the direct F3 pin. OU can only be read
// from entry.DN against a real server; if it came from a constructed attribute every
// value here would be "".
func TestIntegration_OUIsPopulatedFromEntryDN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := newScanner(t)
	recs, err := s.fetchRecords(ctx)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	want := map[string]string{
		"jdoe":       "Staff",
		"domadmin":   "Staff",
		"backupop":   "Staff",
		"assistant":  "Staff",
		"never_used": "Staff",
		"old_svc":    "Service Accounts",
		"svc_sql":    "Service Accounts",
		"svc_gmsa":   "Service Accounts",
		"SRV01$":     "Workstations",
	}

	empty := 0
	for _, r := range recs {
		expect, known := want[r.SamAccountName]
		if !known {
			continue
		}
		if r.OU == "" {
			empty++
			t.Errorf("%s: OU is EMPTY. A real directory does not return "+
				"distinguishedName as an attribute, so it must be read from entry.DN "+
				"(F3).", r.SamAccountName)
			continue
		}
		if r.OU != expect {
			t.Errorf("%s: OU = %q, want %q", r.SamAccountName, r.OU, expect)
		}
	}
	if empty == len(recs) && len(recs) > 0 {
		t.Errorf("EVERY OU was empty — this is the F3 regression in full: OU comes from " +
			"a constructed attribute the directory never sends")
	}
}

// TestIntegration_PrivilegedClassificationPerAccount pins which specific accounts are
// privileged, so the summary count cannot be right for the wrong reason (e.g. two
// different accounts flagged instead of the two intended).
func TestIntegration_PrivilegedClassificationPerAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := newScanner(t)
	recs, err := s.fetchRecords(ctx)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	expectPriv := map[string]bool{
		"domadmin":  true,  // memberOf Domain Admins DN
		"backupop":  true,  // primaryGroupID 551 — requires the attribute to be REQUESTED
		"jdoe":      false, // Domain Users only
		"assistant": false, // Admin-Assistants: name contains "admin", grants nothing
		"old_svc":   false,
		"svc_sql":   false,
	}

	byName := map[string]bool{}
	for _, r := range recs {
		byName[r.SamAccountName] = r.IsPrivileged
	}

	for name, want := range expectPriv {
		got, seen := byName[name]
		if !seen {
			t.Errorf("%s was not returned by the scan at all", name)
			continue
		}
		if got != want {
			t.Errorf("%s: IsPrivileged = %v, want %v", name, got, want)
		}
	}

	// backupop is the case a unit test cannot catch: its privilege comes ONLY from
	// primaryGroupID, which the directory does not send unless it was requested.
	if got, seen := byName["backupop"]; seen && !got {
		t.Errorf("backupop is privileged via primaryGroupID 551 but was NOT flagged. " +
			"This is F4: primaryGroupID must be in fetchAccounts' requested attribute " +
			"list, or the SID signal can never fire against a real directory.")
	}
}

// TestIntegration_TimestampsAreRecentNotAncient is the direct F1 pin. The harness sets
// lastLogonTimestamp to "now" for most accounts; if parseFileTime overflows, those come
// back centuries in the past even though the raw values are present-day.
func TestIntegration_TimestampsAreRecentNotAncient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s := newScanner(t)
	recs, err := s.fetchRecords(ctx)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}

	// old_svc is deliberately ancient (2020) and stale; everything else with a
	// timestamp was set to now by the harness.
	const ancient = "old_svc"
	now := time.Now().UTC()

	checked := 0
	for _, r := range recs {
		if r.SamAccountName == ancient || r.LastLogonTimestamp.IsZero() {
			continue
		}
		checked++
		age := now.Sub(r.LastLogonTimestamp)
		if age < 0 {
			age = -age
		}
		if age > 24*time.Hour {
			t.Errorf("%s: lastLogonTimestamp parsed as %v (%.0f days from now), but the "+
				"harness set it to within the last few minutes. A large discrepancy "+
				"means the FILETIME tick scaling is wrong — most likely int64 overflow "+
				"in ft*100, which wrapped 2020 to 1435 (F1).",
				r.SamAccountName, r.LastLogonTimestamp, age.Hours()/24)
		}
	}
	if checked == 0 {
		t.Error("no account carried a usable lastLogonTimestamp — either the harness did " +
			"not substitute __RECENT_FILETIME__ or parseFileTime is returning zero for " +
			"valid values")
	}

	// And the ancient one really must be ancient, so the test cannot pass by parsing
	// everything to zero.
	for _, r := range recs {
		if r.SamAccountName == ancient {
			if r.LastLogonTimestamp.IsZero() {
				t.Errorf("%s: a valid 2020 FILETIME parsed to the zero time, so staleness "+
					"cannot be detected at all", ancient)
			} else if y := r.LastLogonTimestamp.Year(); y != 2020 {
				t.Errorf("%s: parsed year = %d, want 2020 (raw FILETIME 132223104000000000)",
					ancient, y)
			}
		}
	}
}

// TestIntegration_ScanIsIdempotent guards the upsert path: scanning twice must not
// duplicate identities in the store, which is what makes the scanner safe to run on a
// schedule rather than once at boot.
func TestIntegration_ScanIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	store := storage.NewMemoryStore()
	s := NewScanner(Config{
		LDAPURL:      ldapURL(t),
		BindDN:       os.Getenv("OIAF_TEST_LDAP_BIND_DN"),
		BindPassword: os.Getenv("OIAF_TEST_LDAP_BIND_PASSWORD"),
		BaseDN:       envOr("OIAF_TEST_LDAP_BASE_DN", "dc=corp,dc=example,dc=com"),
	}, store)

	first, err := s.Scan(ctx)
	if err != nil {
		t.Fatalf("first Scan failed: %v", err)
	}
	afterFirst, err := store.Identities(ctx).List(ctx)
	if err != nil {
		t.Fatalf("list after first scan: %v", err)
	}

	second, err := s.Scan(ctx)
	if err != nil {
		t.Fatalf("second Scan failed: %v", err)
	}
	afterSecond, err := store.Identities(ctx).List(ctx)
	if err != nil {
		t.Fatalf("list after second scan: %v", err)
	}

	t.Logf("first=%d identities, second=%d identities (summary totals %d/%d)",
		len(afterFirst), len(afterSecond), first.TotalAccounts, second.TotalAccounts)

	if len(afterSecond) != len(afterFirst) {
		t.Errorf("scanning twice changed the identity count from %d to %d: the upsert is "+
			"inserting duplicates, so the scanner cannot be run on a schedule",
			len(afterFirst), len(afterSecond))
	}
	if first.TotalAccounts != second.TotalAccounts {
		t.Errorf("summary totals differ between identical scans (%d vs %d): "+
			"classification is not deterministic", first.TotalAccounts, second.TotalAccounts)
	}
}

// TestIntegration_ConnectionFailureIsReportedNotSwallowed checks the error path: a
// scanner pointed at an unreachable directory must fail loudly rather than return a
// zeroed summary that looks like "the directory has no accounts".
func TestIntegration_ConnectionFailureIsReportedNotSwallowed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	s := NewScanner(Config{
		// Port 1 is reserved and nothing listens there.
		LDAPURL: fmt.Sprintf("ldap://127.0.0.1:1"),
		BaseDN:  "dc=corp,dc=example,dc=com",
	}, storage.NewMemoryStore())

	summary, err := s.Scan(ctx)
	if err == nil {
		t.Fatalf("Scan against an unreachable directory returned no error and summary %+v "+
			"— a silent zeroed summary is indistinguishable from an empty directory, "+
			"which would hide a total monitoring outage", summary)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "connect") &&
		!strings.Contains(strings.ToLower(err.Error()), "refused") {
		t.Logf("error is not obviously a connection failure: %v", err)
	}
	if summary.TotalAccounts != 0 {
		t.Errorf("a failed scan reported %d accounts", summary.TotalAccounts)
	}
}
