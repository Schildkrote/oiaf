// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
)

const sampleLogonSuccess = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-07-23T08:30:00.000000000Z"/>
    <Computer>DC01.corp.example.com</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">DC01$</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="TargetUserSid">S-1-5-21-1234567890-1234567890-1234567890-1105</Data>
    <Data Name="TargetUserName">svc-sql</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp</Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="IpAddress">10.0.1.50</Data>
    <Data Name="IpPort">49231</Data>
    <Data Name="Status">0x0</Data>
    <Data Name="SubStatus">0x0</Data>
  </EventData>
</Event>`

const sampleKerberosTGT = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4768</EventID>
    <TimeCreated SystemTime="2026-07-23T09:00:00.000000000Z"/>
    <Computer>DC01.corp.example.com</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">jsmith</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetSid">S-1-5-21-1234567890-1234567890-1234567890-1001</Data>
    <Data Name="IpAddress">::ffff:10.0.2.10</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>`

const sampleLogonFailure = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-07-23T10:15:00.000000000Z"/>
    <Computer>DC02.corp.example.com</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">administrator</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetUserSid">S-1-0-0</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32</Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="IpAddress">203.0.113.5</Data>
    <Data Name="IpPort">51022</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="SubStatus">0xc0000064</Data>
  </EventData>
</Event>`

const sampleNTLM = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/>
    <EventID>4776</EventID>
    <TimeCreated SystemTime="2026-07-23T11:00:00.000000000Z"/>
    <Computer>DC01.corp.example.com</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">svc-backup</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Workstation">FILESRV01</Data>
    <Data Name="LogonProcessName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>
    <Data Name="Status">0x0</Data>
  </EventData>
</Event>`

func TestParseLogonSuccess(t *testing.T) {
	rec, err := ParseEventXML([]byte(sampleLogonSuccess))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.EventID != 4624 {
		t.Errorf("EventID = %d, want 4624", rec.EventID)
	}
	if rec.AccountName != "svc-sql" {
		t.Errorf("AccountName = %q, want svc-sql", rec.AccountName)
	}
	if rec.AccountSID != "S-1-5-21-1234567890-1234567890-1234567890-1105" {
		t.Errorf("AccountSID = %q", rec.AccountSID)
	}
	if rec.LogonType != 3 {
		t.Errorf("LogonType = %d, want 3", rec.LogonType)
	}
	if rec.AuthPackage != "NTLM" {
		t.Errorf("AuthPackage = %q, want NTLM", rec.AuthPackage)
	}
	if rec.SourceIP != "10.0.1.50" {
		t.Errorf("SourceIP = %q, want 10.0.1.50", rec.SourceIP)
	}
	if rec.SourcePort != 49231 {
		t.Errorf("SourcePort = %d, want 49231", rec.SourcePort)
	}
	if rec.DCName != "DC01.corp.example.com" {
		t.Errorf("DCName = %q", rec.DCName)
	}
	if rec.EventType != "logon_success" {
		t.Errorf("EventType = %q, want logon_success", rec.EventType)
	}
	if rec.Timestamp.Hour() != 8 || rec.Timestamp.Minute() != 30 {
		t.Errorf("Timestamp = %v, want 08:30 UTC", rec.Timestamp)
	}
}

func TestParseKerberosTGT(t *testing.T) {
	rec, err := ParseEventXML([]byte(sampleKerberosTGT))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.EventID != 4768 {
		t.Errorf("EventID = %d, want 4768", rec.EventID)
	}
	if rec.AccountName != "jsmith" {
		t.Errorf("AccountName = %q, want jsmith", rec.AccountName)
	}
	if rec.AuthPackage != "kerberos" {
		t.Errorf("AuthPackage = %q, want kerberos", rec.AuthPackage)
	}
	if rec.EventType != "kerberos_tgt" {
		t.Errorf("EventType = %q, want kerberos_tgt", rec.EventType)
	}
}

func TestParseLogonFailure(t *testing.T) {
	rec, err := ParseEventXML([]byte(sampleLogonFailure))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.EventID != 4625 {
		t.Errorf("EventID = %d, want 4625", rec.EventID)
	}
	if rec.AccountName != "administrator" {
		t.Errorf("AccountName = %q, want administrator", rec.AccountName)
	}
	if rec.LogonType != 10 {
		t.Errorf("LogonType = %d, want 10", rec.LogonType)
	}
	if rec.SourceIP != "203.0.113.5" {
		t.Errorf("SourceIP = %q, want 203.0.113.5", rec.SourceIP)
	}
	if rec.Status != "0xc000006d" {
		t.Errorf("Status = %q, want 0xc000006d", rec.Status)
	}
	if rec.EventType != "logon_failure" {
		t.Errorf("EventType = %q, want logon_failure", rec.EventType)
	}
}

func TestParseNTLM(t *testing.T) {
	rec, err := ParseEventXML([]byte(sampleNTLM))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.EventID != 4776 {
		t.Errorf("EventID = %d, want 4776", rec.EventID)
	}
	if rec.AccountName != "svc-backup" {
		t.Errorf("AccountName = %q, want svc-backup", rec.AccountName)
	}
	if rec.SourceIP != "FILESRV01" {
		t.Errorf("SourceIP = %q, want FILESRV01", rec.SourceIP)
	}
	if rec.AuthPackage != "NTLM" {
		t.Errorf("AuthPackage = %q, want NTLM", rec.AuthPackage)
	}
	if rec.EventType != "ntlm_validation" {
		t.Errorf("EventType = %q, want ntlm_validation", rec.EventType)
	}
}

func TestParseInvalidXML(t *testing.T) {
	_, err := ParseEventXML([]byte("<not-xml"))
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}
