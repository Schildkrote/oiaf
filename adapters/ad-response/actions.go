// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

const uacAccountDisable = 0x0002

type Actions struct {
	cfg    *Config
	logger *slog.Logger
}

func NewActions(cfg *Config, logger *slog.Logger) (*Actions, error) {
	return &Actions{cfg: cfg, logger: logger}, nil
}

func (a *Actions) Close() {}

func (a *Actions) Handle(ctx context.Context, req DecisionWebhook) (ActionResult, error) {
	action := req.Action
	if action == "" {
		action = "disable_account"
	}

	result := ActionResult{
		Action:  action,
		Account: req.AccountName,
		DryRun:  a.cfg.DryRun,
	}

	a.logger.Info("handling decision",
		"account", req.AccountName,
		"sid", req.AccountSID,
		"decision", req.Decision,
		"risk_score", req.RiskScore,
		"action", action,
		"dry_run", a.cfg.DryRun,
	)

	if a.cfg.DryRun {
		result.Success = true
		result.Detail = "dry-run: action logged but not applied"
		return result, nil
	}

	conn, err := a.connect(ctx)
	if err != nil {
		return result, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	switch action {
	case "disable_account":
		err = a.disableAccount(conn, req.AccountSID)
	case "enable_account":
		err = a.enableAccount(conn, req.AccountSID)
	case "force_password_reset":
		err = a.forcePasswordReset(conn, req.AccountSID)
	case "remove_from_group":
		err = a.removeFromGroup(conn, req.AccountSID, req.Reasons)
	default:
		return result, fmt.Errorf("unknown action: %s", action)
	}

	if err != nil {
		return result, err
	}

	result.Success = true
	return result, nil
}

func (a *Actions) connect(_ context.Context) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	if strings.HasPrefix(a.cfg.LDAPURL, "ldaps://") {
		conn, err = ldap.DialURL(a.cfg.LDAPURL, ldap.DialWithTLSConfig(&tls.Config{
			InsecureSkipVerify: false,
		}))
	} else {
		conn, err = ldap.DialURL(a.cfg.LDAPURL)
	}
	if err != nil {
		return nil, err
	}

	if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap bind: %w", err)
	}

	return conn, nil
}

func (a *Actions) disableAccount(conn *ldap.Conn, sid string) error {
	dn, err := a.dnFromSID(conn, sid)
	if err != nil {
		return err
	}

	current, err := a.getUAC(conn, dn)
	if err != nil {
		return err
	}

	newUAC := current | uacAccountDisable
	return a.setUAC(conn, dn, newUAC)
}

func (a *Actions) enableAccount(conn *ldap.Conn, sid string) error {
	dn, err := a.dnFromSID(conn, sid)
	if err != nil {
		return err
	}

	current, err := a.getUAC(conn, dn)
	if err != nil {
		return err
	}

	newUAC := current &^ uacAccountDisable
	return a.setUAC(conn, dn, newUAC)
}

func (a *Actions) forcePasswordReset(conn *ldap.Conn, sid string) error {
	dn, err := a.dnFromSID(conn, sid)
	if err != nil {
		return err
	}

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("pwdLastSet", []string{"0"})
	return conn.Modify(mod)
}

func (a *Actions) removeFromGroup(conn *ldap.Conn, sid string, reasons []string) error {
	if len(reasons) == 0 {
		return fmt.Errorf("no group DN provided in reasons")
	}
	groupDN := reasons[len(reasons)-1]

	dn, err := a.dnFromSID(conn, sid)
	if err != nil {
		return err
	}

	mod := ldap.NewModifyRequest(groupDN, nil)
	mod.Delete("member", []string{dn})
	return conn.Modify(mod)
}

func (a *Actions) dnFromSID(conn *ldap.Conn, sid string) (string, error) {
	filter := fmt.Sprintf("(objectSid=%s)", ldap.EscapeFilter(sid))
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false,
		filter, []string{"distinguishedName"}, nil,
	)
	result, err := conn.Search(req)
	if err != nil {
		return "", fmt.Errorf("search by SID: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no account found for SID %s", sid)
	}
	return result.Entries[0].DN, nil
}

func (a *Actions) getUAC(conn *ldap.Conn, dn string) (int, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"userAccountControl"}, nil,
	)
	result, err := conn.Search(req)
	if err != nil {
		return 0, err
	}
	if len(result.Entries) == 0 {
		return 0, fmt.Errorf("entry not found: %s", dn)
	}
	uacStr := result.Entries[0].GetAttributeValue("userAccountControl")
	var uac int
	fmt.Sscanf(uacStr, "%d", &uac)
	return uac, nil
}

func (a *Actions) setUAC(conn *ldap.Conn, dn string, uac int) error {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("userAccountControl", []string{fmt.Sprintf("%d", uac)})
	return conn.Modify(mod)
}
