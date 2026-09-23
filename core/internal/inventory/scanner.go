// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/Schildkrote/oiaf/core/internal/storage"
	"github.com/Schildkrote/oiaf/core/internal/types"
)

const (
	uacAccountDisable       = 0x0002
	uacDontExpirePassword   = 0x10000
	uacServerTrustAccount   = 0x2000
	uacTrustedForDelegation = 0x80000
	staleThresholdDays      = 90
)

// privilegedGroupSuffixes are the well-known relative identifiers of AD's built-in
// privileged groups. They are compared against a RID extracted from a SID, never
// against a DN — see isPrivilegedEntry for the defect that motivated that rule.
// -520 (Group Policy Creator Owners) is included so this list and
// privilegedGroupNames classify the same set of groups; the two signals must not
// disagree, or an account is privileged depending on which attribute the directory
// happened to expose.
var privilegedGroupSuffixes = []string{
	"-512", // Domain Admins
	"-518", // Schema Admins
	"-519", // Enterprise Admins
	"-520", // Group Policy Creator Owners
	"-544", // Administrators
	"-548", // Account Operators
	"-549", // Server Operators
	"-550", // Print Operators
	"-551", // Backup Operators
}

type Config struct {
	LDAPURL            string
	BindDN             string
	BindPassword       string
	BaseDN             string
	InsecureSkipVerify bool
}

type Scanner struct {
	cfg   Config
	store storage.Store
}

func NewScanner(cfg Config, store storage.Store) *Scanner {
	return &Scanner{cfg: cfg, store: store}
}

func (s *Scanner) Scan(ctx context.Context) (types.ADInventorySummary, error) {
	records, err := s.fetchRecords(ctx)
	if err != nil {
		return types.ADInventorySummary{}, err
	}

	now := time.Now().UTC()
	summary := summarize(records, now)

	// Persist after classifying, so a mid-scan storage failure still reports the
	// counts that were observed rather than a half-populated summary.
	for i := range records {
		if err := s.upsertIdentity(ctx, &records[i]); err != nil {
			return summary, fmt.Errorf("upsert identity %s: %w", records[i].SamAccountName, err)
		}
	}

	return summary, nil
}

// summarize aggregates scanned records into the counts the API reports. It is a pure
// function of the records and a reference time so that classification can be tested
// without a directory server — previously this logic was inline in Scan and therefore
// could only be exercised end-to-end.
//
// `now` is a parameter rather than time.Now() for exactly that reason: staleness is
// relative to a moment, and a test that cannot pin the moment cannot pin the verdict.
func summarize(records []types.ADInventoryRecord, now time.Time) types.ADInventorySummary {
	summary := types.ADInventorySummary{ScannedAt: now}

	for i := range records {
		rec := &records[i]
		summary.TotalAccounts++

		switch rec.ObjectClass {
		case "user":
			summary.UserAccounts++
		case "computer":
			summary.ComputerAccounts++
		}

		if len(rec.SPNs) > 0 || rec.IsGMSA {
			summary.ServiceAccounts++
		}
		if rec.IsPrivileged {
			summary.PrivilegedAccounts++
		}
		if !rec.Enabled {
			summary.DisabledAccounts++
		}
		// Strictly greater-than, and only when the timestamp is known. An account at
		// exactly the threshold is not yet stale, and an account that has NEVER logged
		// on carries a zero FILETIME which cannot be aged — flagging it would report
		// every never-used account as stale and drown the real signal.
		if !rec.LastLogonTimestamp.IsZero() &&
			now.Sub(rec.LastLogonTimestamp) > time.Duration(staleThresholdDays)*24*time.Hour {
			summary.StaleAccounts++
		}
	}

	return summary
}

func (s *Scanner) connect() (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if strings.HasPrefix(s.cfg.LDAPURL, "ldaps://") {
		conn, err = ldap.DialURL(s.cfg.LDAPURL, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		}))
	} else {
		conn, err = ldap.DialURL(s.cfg.LDAPURL)
	}
	if err != nil {
		return nil, err
	}

	if s.cfg.BindDN != "" {
		if err := conn.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap bind: %w", err)
		}
	}

	return conn, nil
}

// fetchRecords connects, searches and parses, WITHOUT persisting. Scan calls it and
// then upserts; exposing it separately lets the integration tests assert on parsed
// values directly.
//
// That separation is deliberate rather than cosmetic. When a summary count is wrong,
// the question is whether parsing produced the wrong value or aggregation miscounted a
// correct one. Testing only Scan conflates the two and forces the diagnosis to be made
// by inference. It also means the tests do not need a store, so a storage failure
// cannot masquerade as a parsing failure.
func (s *Scanner) fetchRecords(ctx context.Context) ([]types.ADInventoryRecord, error) {
	conn, err := s.connect()
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	records, err := s.fetchAccounts(conn)
	if err != nil {
		return nil, fmt.Errorf("fetch accounts: %w", err)
	}
	return records, nil
}

func (s *Scanner) fetchAccounts(conn *ldap.Conn) ([]types.ADInventoryRecord, error) {
	// primaryGroupID is required for privilege detection: an account whose ONLY
	// privileged group is its primary group does not list it in memberOf, so the DN
	// scan misses it entirely. Without this attribute the SID-based signal in
	// isPrivilegedEntry can never fire.
	attrs := []string{
		"sAMAccountName", "displayName", "objectSid", "objectClass",
		"userAccountControl", "servicePrincipalName", "memberOf",
		"lastLogonTimestamp", "pwdLastSet", "primaryGroupID",
		"msDS-GroupMSAMembership",
	}

	filter := "(|(objectClass=user)(objectClass=computer))"
	req := ldap.NewSearchRequest(
		s.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, attrs, nil,
	)

	result, err := conn.Search(req)
	if err != nil {
		return nil, err
	}

	records := make([]types.ADInventoryRecord, 0, len(result.Entries))
	for _, entry := range result.Entries {
		rec := parseEntry(entry)
		records = append(records, rec)
	}
	return records, nil
}

// privilegedGroupNames are the CNs of AD's built-in privileged groups, matched
// case-insensitively against the CN component of each memberOf DN.
//
// WHY MATCHING IS BY NAME AND NOT BY RID SUFFIX: AD's memberOf attribute contains
// DISTINGUISHED NAMES ("CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=com"), not
// SIDs. The previous implementation assigned each DN to a variable named `sid` and
// tested strings.HasSuffix(sid, "-512"), which can never be true — a DN ends in a
// domain component, never a numeric RID. That whole branch was dead code, and the
// four operator groups below were silently unclassified as a result.
//
// This matters operationally: Account/Server/Print/Backup Operators are the standard
// lateral-movement targets (Backup Operators carries SeBackupPrivilege, which reads
// any file regardless of ACL; Print Operators can load drivers on a DC). An inventory
// that omits them understates the privileged surface, which is the one number an
// operator is meant to act on.
//
// The well-known RID list is retained — but applied to the account's OWN SID and
// primaryGroupID, which genuinely do carry RIDs.
var privilegedGroupNames = []string{
	"domain admins",               // RID 512
	"enterprise admins",           // RID 519
	"schema admins",               // RID 518
	"group policy creator owners", // RID 520 — can author GPOs that run on every host
	"administrators",              // RID 544 (BUILTIN\Administrators)
	"account operators",           // RID 548
	"server operators",            // RID 549
	"print operators",             // RID 550
	"backup operators",            // RID 551
}

// cnOf extracts the CN value from a distinguished name, lower-cased and trimmed.
// It returns "" when the DN has no CN component.
func cnOf(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if len(part) > 3 && strings.EqualFold(part[:3], "cn=") {
			return strings.ToLower(strings.TrimSpace(part[3:]))
		}
	}
	return ""
}

// ridSuffixOf returns the trailing "-<digits>" RID of a SID, or "" if the string is
// not shaped like a SID. This is what privilegedGroupSuffixes was always meant to be
// compared against.
func ridSuffixOf(sid string) string {
	i := strings.LastIndex(sid, "-")
	if i <= 0 || i == len(sid)-1 {
		return ""
	}
	rid := sid[i:] // includes the leading '-'
	for _, c := range rid[1:] {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return rid
}

// isPrivilegedEntry decides whether an account is privileged, from two independent
// signals:
//
//  1. membership of a built-in privileged GROUP, matched by CN name because that is
//     what memberOf actually contains;
//  2. a well-known privileged RID on the account's OWN objectSid or primaryGroupID,
//     which is the only place a numeric RID genuinely appears.
//
// Both signals are checked, because either alone misses real cases: a nested group
// membership may not appear in memberOf, and a directory export may omit objectSid.
func isPrivilegedEntry(entry *ldap.Entry, memberOf []string) bool {
	for _, group := range memberOf {
		cn := cnOf(group)
		if cn == "" {
			continue
		}
		for _, want := range privilegedGroupNames {
			if cn == want {
				return true
			}
		}
	}

	// Signal 2: well-known RIDs on the account itself.
	for _, sid := range []string{entry.GetAttributeValue("objectSid"),
		entry.GetAttributeValue("primaryGroupID")} {
		rid := ridSuffixOf(sid)
		if rid == "" {
			// primaryGroupID is a bare number, not a SID — normalise it.
			if strings.TrimLeft(sid, "0123456789") == "" && sid != "" {
				rid = "-" + strings.TrimLeft(sid, "0")
			}
		}
		if rid == "" {
			continue
		}
		for _, suffix := range privilegedGroupSuffixes {
			if rid == suffix {
				return true
			}
		}
	}
	return false
}

func parseEntry(entry *ldap.Entry) types.ADInventoryRecord {
	uac, _ := strconv.Atoi(entry.GetAttributeValue("userAccountControl"))
	enabled := uac&uacAccountDisable == 0

	objectClass := "user"
	for _, oc := range entry.GetAttributeValues("objectClass") {
		if oc == "computer" {
			objectClass = "computer"
		}
	}

	spns := entry.GetAttributeValues("servicePrincipalName")
	memberOf := entry.GetAttributeValues("memberOf")
	isGMSA := entry.GetAttributeValue("msDS-GroupMSAMembership") != ""

	isPrivileged := isPrivilegedEntry(entry, memberOf)

	// entry.DN is always populated by go-ldap from the search result. The previous
	// code read GetAttributeValue("distinguishedName"), which is empty against a real
	// AD: distinguishedName is a CONSTRUCTED attribute that AD does not return in
	// search results even when it is in the requested attribute list. So OU was always
	// "" in production and every account landed in the same empty group, while the unit
	// test that set the attribute by hand passed. Fixed to use entry.DN, with the
	// attribute kept as a fallback for LDIF imports and non-AD directories that do
	// expose it.
	dn := entry.DN
	if dn == "" {
		dn = entry.GetAttributeValue("distinguishedName")
	}
	ou := extractOU(dn)

	return types.ADInventoryRecord{
		SID:                entry.GetAttributeValue("objectSid"),
		SamAccountName:     entry.GetAttributeValue("sAMAccountName"),
		DisplayName:        entry.GetAttributeValue("displayName"),
		ObjectClass:        objectClass,
		UserAccountControl: uac,
		SPNs:               spns,
		MemberOf:           memberOf,
		LastLogonTimestamp: parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PwdLastSet:         parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		Enabled:            enabled,
		OU:                 ou,
		IsGMSA:             isGMSA,
		IsPrivileged:       isPrivileged,
	}
}

func (s *Scanner) upsertIdentity(ctx context.Context, rec *types.ADInventoryRecord) error {
	identityType := types.IdentityTypePerson
	if rec.ObjectClass == "computer" {
		identityType = types.IdentityTypeMachine
	} else if len(rec.SPNs) > 0 || rec.IsGMSA {
		identityType = types.IdentityTypeServiceAccount
	}

	existing, err := s.store.Identities(ctx).GetByUsername(ctx, rec.SamAccountName)
	if err == nil {
		existing.Type = identityType
		existing.Privileged = rec.IsPrivileged
		existing.Groups = rec.MemberOf
		existing.UpdatedAt = time.Now().UTC()
		if existing.Attributes == nil {
			existing.Attributes = make(map[string]string)
		}
		existing.Attributes["sid"] = rec.SID
		existing.Attributes["ou"] = rec.OU
		existing.Attributes["last_logon"] = rec.LastLogonTimestamp.Format(time.RFC3339)
		existing.Attributes["pwd_last_set"] = rec.PwdLastSet.Format(time.RFC3339)
		existing.Attributes["enabled"] = strconv.FormatBool(rec.Enabled)
		existing.Attributes["has_spn"] = strconv.FormatBool(len(rec.SPNs) > 0)
		existing.Attributes["is_gmsa"] = strconv.FormatBool(rec.IsGMSA)
		return s.store.Identities(ctx).Update(ctx, existing)
	}

	identity := &types.Identity{
		ID:          types.NewID(),
		Username:    rec.SamAccountName,
		DisplayName: rec.DisplayName,
		Type:        identityType,
		Groups:      rec.MemberOf,
		Privileged:  rec.IsPrivileged,
		Attributes: map[string]string{
			"sid":          rec.SID,
			"ou":           rec.OU,
			"last_logon":   rec.LastLogonTimestamp.Format(time.RFC3339),
			"pwd_last_set": rec.PwdLastSet.Format(time.RFC3339),
			"enabled":      strconv.FormatBool(rec.Enabled),
			"has_spn":      strconv.FormatBool(len(rec.SPNs) > 0),
			"is_gmsa":      strconv.FormatBool(rec.IsGMSA),
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	return s.store.Identities(ctx).Create(ctx, identity)
}

// fileTimeUnixDelta is the number of seconds between the Windows FILETIME epoch
// (1601-01-01 UTC) and the Unix epoch (1970-01-01 UTC).
const fileTimeUnixDelta = 11644473600

// parseFileTime converts a Windows FILETIME string — 100-nanosecond ticks since
// 1601-01-01 UTC — to a time.Time.
//
// THE BUG THIS FIXES: the previous implementation was
//
//	epoch.Add(time.Duration(ft) * 100 * time.Nanosecond)
//
// which OVERFLOWS int64 for every real timestamp. A FILETIME for 2020 is
// 132223104000000000 ticks; multiplied by 100 that is 1.32e19, against an int64
// maximum of 9.22e18. Go's integer multiplication wraps silently rather than
// panicking, so the result was not an error but a WRONG DATE — 2020-01-01 came back
// as 1435-06-13.
//
// The consequence was not cosmetic. Stale-account detection compares
// LastLogonTimestamp against a 90-day threshold, and every parsed timestamp landed
// centuries in the past, so EVERY account with a last-logon value was classified
// stale. The stale count — the number an operator is meant to act on when hunting
// dormant privileged accounts — was 100% false positives.
//
// The fix divides BEFORE scaling, so the intermediate value is seconds since 1601
// (at most ~9.2e11) and cannot overflow. Sub-second precision is dropped, which is
// irrelevant for a 90-day threshold.
//
// "0" and the int64 maximum both mean "never" in AD (never logged on / password never
// expires) and must yield the zero Time, not 1601 or a wrapped date. A zero Time is
// what lets summarize distinguish "unknown" from "old" — see the staleness comment
// there.
func parseFileTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || s == "9223372036854775807" {
		return time.Time{}
	}
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ft <= 0 {
		return time.Time{}
	}
	secs := ft/10000000 - fileTimeUnixDelta
	// NOTE: secs CAN be negative, and that is a legitimate value, not corruption. A
	// FILETIME is only invalid when ft <= 0 (handled above); any positive tick count
	// names a real instant, and one before 1970-01-01 simply yields negative Unix
	// seconds. time.Unix represents those correctly (1950-01-01 is -631152000).
	//
	// An earlier draft of this fix rejected secs < 0 as "corrupt". That was a fail-open
	// bug: it turned a genuinely ancient timestamp into the zero Time, which summarize
	// treats as "last logon UNKNOWN" and therefore never stale. So the most dormant
	// possible account — one whose last logon predates the Unix epoch — would have been
	// reported as the one account that cannot be aged. Rejection is correct only for
	// ft <= 0, where there is no instant to name at all.
	return time.Unix(secs, (ft%10000000)*100).UTC()
}

func extractOU(dn string) string {
	parts := strings.Split(dn, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToUpper(p), "OU=") {
			return p[3:]
		}
	}
	return ""
}
