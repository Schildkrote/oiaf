// Copyright 2026 OIAF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"
)

type EventRecord struct {
	EventID       int       `json:"event_id"`
	Timestamp     time.Time `json:"timestamp"`
	AccountName   string    `json:"account_name"`
	AccountDomain string    `json:"account_domain"`
	AccountSID    string    `json:"account_sid"`
	LogonType     int       `json:"logon_type"`
	LogonProcess  string    `json:"logon_process"`
	AuthPackage   string    `json:"auth_package"`
	SourceIP      string    `json:"source_ip"`
	SourcePort    int       `json:"source_port"`
	TargetServer  string    `json:"target_server"`
	TargetSPN     string    `json:"target_spn"`
	Status        string    `json:"status"`
	SubStatus     string    `json:"sub_status"`
	DCName        string    `json:"dc_name"`
	EventType     string    `json:"event_type"`
}

type xmlEvent struct {
	XMLName   xml.Name     `xml:"Event"`
	System    xmlSystem    `xml:"System"`
	EventData xmlEventData `xml:"EventData"`
}

type xmlSystem struct {
	Provider    xmlProvider    `xml:"Provider"`
	EventID     int            `xml:"EventID"`
	TimeCreated xmlTimeCreated `xml:"TimeCreated"`
	Computer    string         `xml:"Computer"`
}

type xmlProvider struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type xmlTimeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type xmlEventData struct {
	Data []xmlData `xml:"Data"`
}

type xmlData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

func ParseEventXML(raw []byte) (EventRecord, error) {
	var ev xmlEvent
	if err := xml.Unmarshal(raw, &ev); err != nil {
		return EventRecord{}, err
	}

	data := make(map[string]string, len(ev.EventData.Data))
	for _, d := range ev.EventData.Data {
		data[d.Name] = strings.TrimSpace(d.Value)
	}

	ts := parseEventTime(ev.System.TimeCreated.SystemTime)

	rec := EventRecord{
		EventID:   ev.System.EventID,
		Timestamp: ts,
		DCName:    ev.System.Computer,
	}

	switch ev.System.EventID {
	case 4624, 4625:
		rec.AccountName = data["TargetUserName"]
		rec.AccountDomain = data["TargetDomainName"]
		rec.AccountSID = data["TargetUserSid"]
		rec.LogonType, _ = strconv.Atoi(data["LogonType"])
		rec.LogonProcess = data["LogonProcessName"]
		rec.AuthPackage = data["AuthenticationPackageName"]
		rec.SourceIP = data["IpAddress"]
		rec.SourcePort, _ = strconv.Atoi(data["IpPort"])
		rec.Status = data["Status"]
		rec.SubStatus = data["SubStatus"]
		if ev.System.EventID == 4624 {
			rec.EventType = "logon_success"
		} else {
			rec.EventType = "logon_failure"
		}

	case 4648:
		rec.AccountName = data["TargetUserName"]
		rec.AccountDomain = data["TargetDomainName"]
		rec.AccountSID = data["TargetSid"]
		rec.SourceIP = data["IpAddress"]
		rec.SourcePort, _ = strconv.Atoi(data["IpPort"])
		rec.TargetServer = data["TargetServerName"]
		rec.LogonProcess = data["LogonProcessName"]
		rec.EventType = "explicit_credentials"

	case 4672:
		rec.AccountName = data["SubjectUserName"]
		rec.AccountDomain = data["SubjectDomainName"]
		rec.AccountSID = data["SubjectUserSid"]
		rec.EventType = "special_privileges"

	case 4768:
		rec.AccountName = data["TargetUserName"]
		rec.AccountDomain = data["TargetDomainName"]
		rec.AccountSID = data["TargetSid"]
		rec.SourceIP = data["IpAddress"]
		rec.AuthPackage = "kerberos"
		rec.Status = data["Status"]
		rec.EventType = "kerberos_tgt"

	case 4769:
		rec.AccountName = data["TargetUserName"]
		rec.AccountDomain = data["TargetDomainName"]
		rec.AccountSID = data["TargetSid"]
		rec.SourceIP = data["IpAddress"]
		rec.TargetSPN = data["ServiceName"]
		rec.TargetServer = data["TargetServerName"]
		rec.AuthPackage = "kerberos"
		rec.Status = data["Status"]
		rec.EventType = "kerberos_tgs"

	case 4771:
		rec.AccountName = data["TargetUserName"]
		rec.AccountDomain = data["TargetDomainName"]
		rec.AccountSID = data["TargetSid"]
		rec.SourceIP = data["IpAddress"]
		rec.SourcePort, _ = strconv.Atoi(data["Port"])
		rec.AuthPackage = "kerberos"
		rec.Status = data["Status"]
		rec.EventType = "kerberos_preauth_failure"

	case 4776:
		rec.AccountName = data["TargetUserName"]
		rec.AccountDomain = data["TargetDomainName"]
		rec.SourceIP = data["Workstation"]
		rec.AuthPackage = "NTLM"
		rec.LogonProcess = data["LogonProcessName"]
		rec.Status = data["Status"]
		rec.EventType = "ntlm_validation"

	case 2887, 2889:
		rec.AccountName = data["AccountName"]
		rec.AccountDomain = data["AccountDomain"]
		rec.SourceIP = data["SourceAddress"]
		rec.AuthPackage = "NTLM"
		rec.EventType = "ntlm_audit"
	}

	return rec, nil
}

func parseEventTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Now().UTC()
	}
	formats := []string{
		"2006-01-02T15:04:05.000000000Z",
		"2006-01-02T15:04:05.000000000-07:00",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		time.RFC3339Nano,
		time.RFC3339,
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
