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

var privilegedGroupSuffixes = []string{"-512", "-519", "-518", "-544", "-548", "-549", "-551", "-550"}

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
	conn, err := s.connect()
	if err != nil {
		return types.ADInventorySummary{}, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	records, err := s.fetchAccounts(conn)
	if err != nil {
		return types.ADInventorySummary{}, fmt.Errorf("fetch accounts: %w", err)
	}

	summary := types.ADInventorySummary{ScannedAt: time.Now().UTC()}
	now := time.Now().UTC()

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
		if !rec.LastLogonTimestamp.IsZero() && now.Sub(rec.LastLogonTimestamp) > time.Duration(staleThresholdDays)*24*time.Hour {
			summary.StaleAccounts++
		}

		if err := s.upsertIdentity(ctx, rec); err != nil {
			return summary, fmt.Errorf("upsert identity %s: %w", rec.SamAccountName, err)
		}
	}

	return summary, nil
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

func (s *Scanner) fetchAccounts(conn *ldap.Conn) ([]types.ADInventoryRecord, error) {
	attrs := []string{
		"sAMAccountName", "displayName", "objectSid", "objectClass",
		"userAccountControl", "servicePrincipalName", "memberOf",
		"lastLogonTimestamp", "pwdLastSet", "distinguishedName",
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

	isPrivileged := false
	for _, group := range memberOf {
		sid := group
		for _, suffix := range privilegedGroupSuffixes {
			if strings.HasSuffix(sid, suffix) {
				isPrivileged = true
				break
			}
		}
		if strings.Contains(strings.ToLower(group), "domain admins") ||
			strings.Contains(strings.ToLower(group), "enterprise admins") ||
			strings.Contains(strings.ToLower(group), "schema admins") ||
			strings.Contains(strings.ToLower(group), "administrators") {
			isPrivileged = true
		}
	}

	dn := entry.GetAttributeValue("distinguishedName")
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

func parseFileTime(s string) time.Time {
	if s == "" || s == "0" || s == "9223372036854775807" {
		return time.Time{}
	}
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ft == 0 {
		return time.Time{}
	}
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	return epoch.Add(time.Duration(ft) * 100 * time.Nanosecond)
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
