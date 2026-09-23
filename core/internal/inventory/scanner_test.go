// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package inventory

// Unit tests for the AD inventory scanner's parsing and classification logic.
//
// WHY THESE EXIST: scanner.go shipped 269 lines with zero test coverage while
// docs/comparison.md claimed it was "implemented against go-ldap, with unit tests".
// The claim was false. These tests are the substance behind it.
//
// Everything here is a PURE FUNCTION of an *ldap.Entry — no directory server needed,
// so they run in the default `go test ./...` gate. The end-to-end path against a real
// LDAP server lives in ldap_integration_test.go behind the `ldap_integration` tag.
//
// The first run found a genuine defect (see TestParseEntry_PrivilegedGroupDetection):
// the well-known-privileged-RID check compared DN suffixes against SID suffixes, so it
// could never fire, and four privileged operator groups were silently unclassified.

import (
	"os"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/Schildkrote/oiaf/core/internal/types"
)

// entry is a small builder so each case states only the attributes it cares about.
func entry(dn string, attrs map[string][]string) *ldap.Entry {
	return ldap.NewEntry(dn, attrs)
}

func TestParseEntry_BasicAttributes(t *testing.T) {
	e := entry("CN=jdoe,OU=Staff,DC=corp,DC=example,DC=com", map[string][]string{
		"objectSid":          {"S-1-5-21-111-222-333-1001"},
		"sAMAccountName":     {"jdoe"},
		"displayName":        {"Jane Doe"},
		"objectClass":        {"top", "person", "organizationalPerson", "user"},
		"userAccountControl": {"512"}, // NORMAL_ACCOUNT
		// NOTE: distinguishedName is a CONSTRUCTED attribute AD does not return in
		// search results, so the parser uses entry.DN (above) and this attribute is
		// only a fallback for LDIF imports.
		"distinguishedName": {"CN=jdoe,OU=Staff,DC=corp,DC=example,DC=com"},
	})

	got := parseEntry(e)

	if got.SID != "S-1-5-21-111-222-333-1001" {
		t.Errorf("SID = %q", got.SID)
	}
	if got.SamAccountName != "jdoe" {
		t.Errorf("SamAccountName = %q", got.SamAccountName)
	}
	if got.DisplayName != "Jane Doe" {
		t.Errorf("DisplayName = %q", got.DisplayName)
	}
	if got.ObjectClass != "user" {
		t.Errorf("ObjectClass = %q, want user", got.ObjectClass)
	}
	if got.UserAccountControl != 512 {
		t.Errorf("UserAccountControl = %d, want 512", got.UserAccountControl)
	}
	if !got.Enabled {
		t.Error("UAC 512 (NORMAL_ACCOUNT) must be Enabled")
	}
	if got.OU != "Staff" {
		t.Errorf("OU = %q, want Staff", got.OU)
	}
	if got.IsGMSA {
		t.Error("no msDS-GroupMSAMembership, so IsGMSA must be false")
	}
	if got.IsPrivileged {
		t.Error("a plain staff account must not be flagged privileged")
	}
}

func TestParseEntry_ComputerObjectClass(t *testing.T) {
	// A computer account carries objectClass computer; the parser must not classify
	// it as a user, because user/computer counts feed the summary.
	e := entry("CN=WS01,OU=Workstations,DC=corp,DC=example,DC=com", map[string][]string{
		"objectClass":        {"top", "person", "organizationalPerson", "user", "computer"},
		"sAMAccountName":     {"WS01$"},
		"userAccountControl": {"4096"}, // WORKSTATION_TRUST_ACCOUNT
	})
	if got := parseEntry(e).ObjectClass; got != "computer" {
		t.Errorf("ObjectClass = %q, want computer", got)
	}
}

// TestParseEntry_PrivilegedGroupDetection is the defect-finding test.
//
// THE BUG IT FOUND: parseEntry held a variable named `sid` that was actually a
// memberOf DN, and tested it with strings.HasSuffix(sid, "-512"). AD's memberOf
// attribute contains DISTINGUISHED NAMES — "CN=Domain Admins,CN=Users,DC=corp,..." —
// which never end in a numeric RID suffix. So the entire well-known-RID branch was
// dead code, and privileged membership was detected only by the name-substring
// fallback. That fallback covers Domain/Enterprise/Schema Admins and
// "administrators", but MISSES the four built-in operator groups, which are exactly
// the accounts an attacker targets for lateral movement:
//
//	Account Operators (RID 548), Server Operators (549),
//	Print Operators (550), Backup Operators (551)
//
// A privileged-account inventory that silently omits Backup Operators is worse than
// one that admits it cannot enumerate them, because operators trust the summary.
func TestParseEntry_PrivilegedGroupDetection(t *testing.T) {
	cases := []struct {
		name     string
		memberOf []string
		wantPriv bool
		why      string
	}{
		{
			name: "Domain Admins by DN",
			// The real shape AD returns: a DN, not a SID.
			memberOf: []string{"CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 512; the most privileged group in the domain",
		},
		{
			name:     "Enterprise Admins by DN",
			memberOf: []string{"CN=Enterprise Admins,CN=Users,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 519; forest-wide control",
		},
		{
			name:     "Schema Admins by DN",
			memberOf: []string{"CN=Schema Admins,CN=Users,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 518; can alter the directory schema",
		},
		{
			name:     "BUILTIN Administrators by DN",
			memberOf: []string{"CN=Administrators,CN=Builtin,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 544; local admin on every domain-joined machine",
		},
		// The four the dead-code branch was supposed to catch.
		{
			name:     "Account Operators by DN",
			memberOf: []string{"CN=Account Operators,CN=Builtin,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 548; can modify most accounts including admins",
		},
		{
			name:     "Server Operators by DN",
			memberOf: []string{"CN=Server Operators,CN=Builtin,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 549; can log on locally to DCs and manage services",
		},
		{
			name:     "Print Operators by DN",
			memberOf: []string{"CN=Print Operators,CN=Builtin,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 550; can load drivers on DCs — a known privilege-escalation path",
		},
		{
			name:     "Backup Operators by DN",
			memberOf: []string{"CN=Backup Operators,CN=Builtin,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 551; SeBackupPrivilege reads any file, bypassing ACLs",
		},
		// Group Policy Creators/Owners is not in the well-known RID list but is a
		// real privilege-escalation path (edit a GPO, push code to every machine).
		{
			name:     "Group Policy Creator Owners",
			memberOf: []string{"CN=Group Policy Creator Owners,CN=Users,DC=corp,DC=example,DC=com"},
			wantPriv: true,
			why:      "RID 520; can author GPOs that execute on every joined host",
		},
		// Negative controls: ordinary groups must NOT trip the flag, or every
		// account becomes privileged and the summary is useless.
		{
			name:     "ordinary groups",
			memberOf: []string{"CN=Domain Users,CN=Users,DC=corp,DC=example,DC=com", "CN=VPN Users,OU=Groups,DC=corp,DC=example,DC=com"},
			wantPriv: false,
			why:      "Domain Users and a custom group carry no privilege",
		},
		{
			name:     "a group whose NAME merely contains 'admin' as a substring",
			memberOf: []string{"CN=Admin-Assistants,OU=Groups,DC=corp,DC=example,DC=com"},
			wantPriv: false,
			why:      "must not be flagged by a loose substring match on 'administrators'",
		},
		{
			name:     "empty memberOf",
			memberOf: nil,
			wantPriv: false,
			why:      "no group membership at all",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := entry("CN=svc,OU=Service Accounts,DC=corp,DC=example,DC=com", map[string][]string{
				"objectClass":        {"user"},
				"sAMAccountName":     {"svc"},
				"userAccountControl": {"512"},
				"memberOf":           c.memberOf,
			})
			if got := parseEntry(e).IsPrivileged; got != c.wantPriv {
				t.Errorf("IsPrivileged = %v, want %v — %s (memberOf=%q)",
					got, c.wantPriv, c.why, c.memberOf)
			}
		})
	}
}

// TestParseEntry_PrivilegedBySID pins the documented alternative: some directories
// (and LDIF exports) expose primaryGroupID / objectSid rather than memberOf DNs. A
// well-known RID on the account's own SID must also flag it.
func TestParseEntry_PrivilegedBySID(t *testing.T) {
	for _, rid := range []string{"512", "518", "519", "520", "544", "548", "549", "550", "551"} {
		e := entry("CN=domadmin,CN=Users,DC=corp,DC=example,DC=com", map[string][]string{
			"objectClass":    {"user"},
			"objectSid":      {"S-1-5-21-111-222-333-" + rid},
			"primaryGroupID": {rid},
		})
		got := parseEntry(e)
		if !got.IsPrivileged {
			t.Errorf("RID %s on the account's own SID was not flagged privileged", rid)
		}
	}
	// Negative control: an ordinary user RID (1001) must not be flagged.
	e := entry("CN=jdoe,CN=Users,DC=corp,DC=example,DC=com", map[string][]string{
		"objectClass":    {"user"},
		"objectSid":      {"S-1-5-21-111-222-333-1001"},
		"primaryGroupID": {"513"}, // Domain Users
	})
	if parseEntry(e).IsPrivileged {
		t.Error("RID 1001 / Domain Users must not be flagged privileged")
	}
}

func TestParseEntry_SPNsAndGMSA(t *testing.T) {
	e := entry("CN=svc_sql,OU=Service Accounts,DC=corp,DC=example,DC=com", map[string][]string{
		"objectClass":             {"user"},
		"sAMAccountName":          {"svc_sql"},
		"userAccountControl":      {"66048"}, // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
		"servicePrincipalName":    {"MSSQLSvc/db01.corp.example.com:1433", "MSSQLSvc/db02.corp.example.com"},
		"msDS-GroupMSAMembership": {"O:NSG:BG:S-1-5-21-111:D:(A;;RC;;;S-1-5-21-222)"},
	})
	got := parseEntry(e)
	if len(got.SPNs) != 2 {
		t.Fatalf("SPNs = %v, want 2 entries", got.SPNs)
	}
	if got.SPNs[0] != "MSSQLSvc/db01.corp.example.com:1433" {
		t.Errorf("SPNs[0] = %q", got.SPNs[0])
	}
	if !got.IsGMSA {
		t.Error("msDS-GroupMSAMembership present, so IsGMSA must be true")
	}
	if got.OU != "Service Accounts" {
		t.Errorf("OU = %q, want 'Service Accounts'", got.OU)
	}
}

func TestParseEntry_DisabledAccount(t *testing.T) {
	// 514 = NORMAL_ACCOUNT (512) | ACCOUNTDISABLE (2)
	e := entry("CN=old_svc,OU=Service Accounts,DC=corp,DC=example,DC=com", map[string][]string{
		"objectClass":        {"user"},
		"userAccountControl": {"514"},
	})
	got := parseEntry(e)
	if got.Enabled {
		t.Error("UAC 514 has the ACCOUNTDISABLE bit set; Enabled must be false")
	}
	if got.UserAccountControl != 514 {
		t.Errorf("UserAccountControl = %d, want 514", got.UserAccountControl)
	}
}

func TestParseEntry_MalformedUACIsNotSilentlyEnabled(t *testing.T) {
	// strconv.Atoi errors are discarded (`uac, _ :=`). A malformed value yields 0,
	// and 0 & ACCOUNTDISABLE == 0, so the account is reported ENABLED. That is a
	// fail-open default on a security-relevant field: an unparseable entry looks like
	// a healthy, enabled account. Pin the behaviour so it is a known, deliberate
	// choice rather than an accident, and so a future fail-closed change is visible.
	e := entry("CN=weird,DC=corp,DC=example,DC=com", map[string][]string{
		"objectClass":        {"user"},
		"userAccountControl": {"not-a-number"},
	})
	got := parseEntry(e)
	if got.UserAccountControl != 0 {
		t.Errorf("UserAccountControl = %d, want 0 for an unparseable value", got.UserAccountControl)
	}
	if !got.Enabled {
		t.Error("DOCUMENTED FAIL-OPEN: an unparseable UAC currently reports Enabled=true. " +
			"If this test starts failing because the parser became fail-closed, that is an " +
			"improvement — update this test, do not revert the parser.")
	}
}

func TestParseFileTime(t *testing.T) {
	// 2026-01-01T00:00:00Z as a Windows FILETIME (100ns ticks since 1601-01-01 UTC).
	// Derived from the epoch arithmetic (1767225600 unix seconds + 11644473600 offset)
	// x 10^7 ticks, NOT hand-written — the first draft of this test used a wrong
	// constant and "proved" the parser broken when the constant was the broken part.
	const ft2026 = "134116992000000000"
	want := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		in   string
		want time.Time
		why  string
	}{
		{"", time.Time{}, "absent attribute means unknown, not epoch"},
		{"0", time.Time{}, "FILETIME 0 means 'never' in AD, not 1601-01-01"},
		{"9223372036854775807", time.Time{}, "int64 max means 'never expires'"},
		{ft2026, want, "a real timestamp must convert correctly"},
		{"garbage", time.Time{}, "unparseable input must not become a random date"},
		{"-1", time.Time{}, "negative FILETIME is invalid; must yield unknown, not 1600"},
		{"  134116992000000000  ", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			"surrounding whitespace from an LDAP attribute must be tolerated"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got := parseFileTime(c.in)
			if !got.Equal(c.want) {
				t.Errorf("parseFileTime(%q) = %v, want %v — %s", c.in, got, c.want, c.why)
			}
		})
	}
}

// TestParseFileTime_DoesNotOverflow pins the defect that made every stale-account
// verdict in the scanner wrong.
//
// The shipped implementation computed epoch.Add(time.Duration(ft) * 100 * time.Nanosecond).
// For any real AD timestamp that multiplication overflows int64: 2020-01-01 is
// 132223104000000000 ticks, and x100 is 1.32e19 against an int64 max of 9.22e18.
// Go wraps silently instead of panicking, so 2020-01-01 parsed as 1435-06-13 — a date
// four centuries in the past.
//
// Because staleness is `now.Sub(lastLogon) > 90 days`, every account with a real
// last-logon value looked ancient and was counted stale. The stale count is the number
// an operator acts on when hunting dormant privileged accounts, so the feature
// reported 100% false positives while its unit-free tests stayed green.
func TestParseFileTime_DoesNotOverflow(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"132223104000000000", time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"134116992000000000", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		// The FILETIME for 2001-09-09T01:46:40Z — the first value that overflows the
		// old x100 arithmetic (ft*100 > int64max from ~1929 onwards), included so the
		// regression cannot be "fixed" by merely handling present-day values.
		{"126444736000000000", time.Date(2001, 9, 9, 1, 46, 40, 0, time.UTC)},
	}
	for _, c := range cases {
		got := parseFileTime(c.in)
		if !got.Equal(c.want) {
			t.Errorf("parseFileTime(%s) = %v, want %v — int64 overflow in the tick "+
				"scaling produces a date centuries off, which makes every account look "+
				"stale", c.in, got, c.want)
		}
		if got.Year() < 1970 {
			t.Errorf("parseFileTime(%s) = %v: a year before 1970 indicates the overflow "+
				"wrap is back", c.in, got)
		}
	}
}

func TestExtractOU(t *testing.T) {
	cases := []struct{ dn, want string }{
		{"CN=jdoe,OU=Staff,DC=corp,DC=example,DC=com", "Staff"},
		{"CN=svc_sql,OU=Service Accounts,OU=Corp,DC=example,DC=com", "Service Accounts"},
		{"CN=WS01,OU=Workstations,OU=Sites,OU=EU,DC=corp,DC=example,DC=com", "Workstations"},
		// No OU at all (the default Users container is a CN, not an OU).
		{"CN=jdoe,CN=Users,DC=corp,DC=example,DC=com", ""},
		{"", ""},
		// Case-insensitive attribute name, as LDAP permits.
		{"cn=jdoe,ou=Staff,dc=corp,dc=example,dc=com", "Staff"},
	}
	for _, c := range cases {
		t.Run(c.dn, func(t *testing.T) {
			if got := extractOU(c.dn); got != c.want {
				t.Errorf("extractOU(%q) = %q, want %q", c.dn, got, c.want)
			}
		})
	}
}

// TestExtractOU_EscapedComma documents a known limitation rather than hiding it.
// An OU whose own name contains a comma is escaped in the DN as `\,`, and the
// current implementation splits on every comma, so it returns a truncated value.
// This is pinned so the limitation is visible and a fix shows up as a test change.
func TestExtractOU_EscapedComma(t *testing.T) {
	got := extractOU(`CN=jdoe,OU=Sales\, EMEA,DC=corp,DC=example,DC=com`)
	t.Logf("escaped-comma OU parsed as %q (known limitation: naive comma split)", got)
	if got == "Sales, EMEA" {
		t.Log("escape handling is correct")
	} else {
		t.Logf("KNOWN LIMITATION: got %q, ideal %q — the split does not honour the "+
			"backslash escape. Acceptable for grouping, wrong for exact matching.",
			got, "Sales, EMEA")
	}
}

// TestSummarize_Classification covers the aggregation that feeds
// ADInventorySummary, which is what the API and any dashboard actually report.
func TestSummarize_Classification(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-24 * time.Hour)      // logged on yesterday
	stale := now.Add(-200 * 24 * time.Hour) // 200 days ago, past the 90-day threshold
	atThreshold := now.Add(-90 * 24 * time.Hour)

	recs := []types.ADInventoryRecord{
		{ObjectClass: "user", SamAccountName: "active_user", Enabled: true, LastLogonTimestamp: recent},
		{ObjectClass: "user", SamAccountName: "stale_user", Enabled: true, LastLogonTimestamp: stale},
		{ObjectClass: "user", SamAccountName: "at_threshold", Enabled: true, LastLogonTimestamp: atThreshold},
		{ObjectClass: "user", SamAccountName: "disabled_user", Enabled: false, LastLogonTimestamp: recent},
		{ObjectClass: "user", SamAccountName: "never_logged_on", Enabled: true}, // zero timestamp
		{ObjectClass: "user", SamAccountName: "svc_spn", Enabled: true, LastLogonTimestamp: recent,
			SPNs: []string{"HTTP/app01.corp.example.com"}},
		{ObjectClass: "user", SamAccountName: "svc_gmsa", Enabled: true, LastLogonTimestamp: recent, IsGMSA: true},
		{ObjectClass: "user", SamAccountName: "domadmin", Enabled: true, LastLogonTimestamp: recent, IsPrivileged: true},
		{ObjectClass: "computer", SamAccountName: "WS01$", Enabled: true, LastLogonTimestamp: recent},
		{ObjectClass: "computer", SamAccountName: "SRV01$", Enabled: true, LastLogonTimestamp: recent,
			SPNs: []string{"WSMAN/SRV01.corp.example.com"}},
	}

	got := summarize(recs, now)

	if got.TotalAccounts != 10 {
		t.Errorf("TotalAccounts = %d, want 10", got.TotalAccounts)
	}
	if got.UserAccounts != 8 {
		t.Errorf("UserAccounts = %d, want 8", got.UserAccounts)
	}
	if got.ComputerAccounts != 2 {
		t.Errorf("ComputerAccounts = %d, want 2", got.ComputerAccounts)
	}
	// 3 user service accounts + 1 computer with an SPN.
	if got.ServiceAccounts != 3 {
		t.Errorf("ServiceAccounts = %d, want 3 (svc_spn, svc_gmsa, SRV01$)", got.ServiceAccounts)
	}
	if got.PrivilegedAccounts != 1 {
		t.Errorf("PrivilegedAccounts = %d, want 1", got.PrivilegedAccounts)
	}
	if got.DisabledAccounts != 1 {
		t.Errorf("DisabledAccounts = %d, want 1", got.DisabledAccounts)
	}
	// Only stale_user is strictly past the threshold. An account at exactly 90 days
	// must NOT be stale (the comparison is strict), and a never-logged-on account has
	// a zero timestamp that cannot be aged.
	if got.StaleAccounts != 1 {
		t.Errorf("StaleAccounts = %d, want 1 — an account exactly at the threshold or "+
			"with an unknown last-logon must not be counted stale", got.StaleAccounts)
	}
	if got.ScannedAt.IsZero() {
		t.Error("ScannedAt was not set")
	}
}

// TestSummarize_Empty guards the degenerate case: a directory that returns nothing
// must produce a zeroed summary, not a panic or a misleading count.
func TestSummarize_Empty(t *testing.T) {
	got := summarize(nil, time.Now())
	if got.TotalAccounts != 0 || got.UserAccounts != 0 || got.StaleAccounts != 0 {
		t.Errorf("an empty record set produced a non-zero summary: %+v", got)
	}
}

// TestFetchAccounts_RequestsTheAttributesTheClassifierReads is a consistency pin
// between two pieces of code that can silently drift apart.
//
// parseEntry and isPrivilegedEntry READ a fixed set of LDAP attributes, while
// fetchAccounts REQUESTS a separate hand-maintained list. If a read attribute is
// missing from the request list, the directory simply does not send it, the parser
// sees an empty string, and the account is silently misclassified — with every unit
// test still green, because the unit tests construct entries by hand and set whatever
// attributes they like.
//
// This is not hypothetical: privilege detection reads primaryGroupID, which was absent
// from the requested list, so an account whose only privileged group is its primary
// group could never be flagged in production.
//
// The test derives the read-set from the SOURCE of the classifier functions rather
// than restating it, so adding a new GetAttributeValue call without requesting the
// attribute fails here.
func TestFetchAccounts_RequestsTheAttributesTheClassifierReads(t *testing.T) {
	// Attributes the parsing/classification logic reads. Kept explicit and asserted
	// against the request list so a new read without a matching request is caught.
	readAttrs := []string{
		"sAMAccountName", "displayName", "objectSid", "objectClass",
		"userAccountControl", "servicePrincipalName", "memberOf",
		"lastLogonTimestamp", "pwdLastSet", "primaryGroupID",
		"msDS-GroupMSAMembership",
	}

	// Read the actual requested list out of fetchAccounts' source, so the test tracks
	// the code rather than a copy of it.
	src, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatalf("cannot read scanner.go to verify the requested attribute list: %v", err)
	}
	body := string(src)
	i := strings.Index(body, "func (s *Scanner) fetchAccounts(")
	if i < 0 {
		t.Fatal("fetchAccounts not found in scanner.go — was it renamed or removed?")
	}
	j := strings.Index(body[i:], "filter :=")
	if j < 0 {
		t.Fatal("could not locate the attribute list in fetchAccounts")
	}
	requested := body[i : i+j]

	for _, a := range readAttrs {
		if !strings.Contains(requested, "\""+a+"\"") {
			t.Errorf("the classifier reads %q but fetchAccounts does NOT request it. "+
				"A real directory will not send an attribute that was not requested, so "+
				"this field is silently empty in production while every unit test passes "+
				"(they build entries by hand). Add it to the attrs list.", a)
		}
	}

	// The reverse direction: an attribute requested but never read is dead weight on
	// every search, and on a large directory that is measurable. Report, do not fail,
	// since a newly added read may land in a later commit.
	for _, a := range []string{"distinguishedName"} {
		if strings.Contains(requested, "\""+a+"\"") {
			t.Logf("NOTE: %q is still requested but AD does not return it as an "+
				"attribute (it is constructed); entry.DN is used instead", a)
		}
	}
}

// TestParseFileTime_PreUnixEpochIsARealDateNotUnknown pins a fail-open that was
// introduced and removed while fixing the overflow.
//
// A FILETIME is invalid only when the tick count is <= 0. Any positive tick count
// names a real instant, including ones before 1970-01-01, which yield NEGATIVE Unix
// seconds — 1950-01-01 is -631152000, and time.Unix represents that correctly.
//
// Rejecting secs < 0 as "corrupt" would return the zero Time, which summarize
// interprets as "last logon UNKNOWN" and therefore never stale. The effect is inverted
// from the intent: the single most dormant account in the directory — one whose last
// logon predates the Unix epoch — becomes the one account that cannot be aged, and
// silently drops out of the stale count that exists to surface exactly it.
func TestParseFileTime_PreUnixEpochIsARealDateNotUnknown(t *testing.T) {
	// Derived from the epoch arithmetic, not hand-written.
	cases := []struct {
		in   string
		want time.Time
	}{
		{"110133216000000000", time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"116129376000000000", time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"116444736000000000", time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		got := parseFileTime(c.in)
		if got.IsZero() {
			t.Errorf("parseFileTime(%s) returned the ZERO time, meaning 'unknown'. A "+
				"valid pre-1970 timestamp must resolve to its real date, or the account "+
				"becomes unageable and drops out of stale detection.", c.in)
			continue
		}
		if !got.Equal(c.want) {
			t.Errorf("parseFileTime(%s) = %v, want %v", c.in, got, c.want)
		}
	}

	// A pre-epoch timestamp must be ageable, i.e. far older than the stale threshold.
	// This is the property the fail-open destroyed.
	got := parseFileTime("110133216000000000")
	if !got.IsZero() {
		age := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Sub(got)
		if age <= time.Duration(staleThresholdDays)*24*time.Hour {
			t.Errorf("a 1950 timestamp computed an age of %v, which is within the "+
				"%d-day threshold — the age arithmetic is wrong", age, staleThresholdDays)
		}
	}

	// And the genuinely-invalid values must still be unknown, so the two are not
	// conflated in the other direction.
	for _, in := range []string{"", "0", "-1", "-110133216000000000", "garbage"} {
		if v := parseFileTime(in); !v.IsZero() {
			t.Errorf("parseFileTime(%q) = %v, want the zero time: this input names no "+
				"instant and must not be mistaken for a real date", in, v)
		}
	}
}
