# DC Agent Adapter

## Purpose

The DC agent is a Windows Service that runs on each Domain Controller and
monitors all Active Directory authentication in real time using the official
Windows Event Log API (`EvtSubscribe`). It is protocol-agnostic: it captures
every authentication event regardless of whether it originated from RDP, SSH,
WMI, PowerShell, a scheduled task, or any other application — as long as it
authenticates via LDAP(S), NTLM, or Kerberos against AD. No agents are required
on application servers.

## Status

Implemented (M4a). Windows EvtSubscribe integration requires a Windows Server
DC. On non-Windows platforms the agent runs in stub mode (no event capture).

## Architecture

```
Domain Controller
  └── OIAFDCAgent (Windows Service)
        ├── EvtSubscribe → Security event log (real-time)
        ├── Event XML parser (4624, 4625, 4648, 4672, 4768, 4769, 4771, 4776)
        ├── Batch buffer (size + interval)
        └── HTTPS → POST /v1/ad/events → OIAF core
                                              ├── discovery engine (behavioural profiling)
                                              ├── risk engine
                                              ├── policy engine
                                              └── audit log
```

## Monitored Event IDs

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon with explicit credentials |
| 4672 | Special privileges assigned to new logon |
| 4768 | Kerberos TGT requested |
| 4769 | Kerberos TGS requested |
| 4771 | Kerberos pre-authentication failed |
| 4776 | NTLM credential validation |

## Configuration

| Env / Flag | Description | Default |
|------------|-------------|---------|
| `OIAF_SERVER` | OIAF core base URL | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN` | Adapter bearer token | required |
| `DC_AGENT_BATCH_SIZE` | Events per OIAF batch | `200` |
| `DC_AGENT_BATCH_INTERVAL` | Max batch flush interval (seconds) | `2` |
| `DC_AGENT_EVENT_IDS` | Comma-separated event IDs | `4624,4625,4648,4672,4768,4769,4771,4776` |
| `DC_AGENT_INVENTORY_ON_START` | Run AD inventory scan on startup | `true` |
| `DC_AGENT_LDAP_URL` | LDAPS URL for inventory | optional |
| `DC_AGENT_LDAP_BIND_DN` | Service account bind DN | optional |
| `DC_AGENT_LDAP_BIND_PASSWORD` | Service account password | optional |
| `DC_AGENT_LDAP_BASE_DN` | LDAP search base DN | optional |
| `DC_AGENT_ENFORCEMENT_MODE` | `monitor` / `response` / `wfp` | `monitor` |

## Installation (Windows)

```powershell
sc.exe create OIAFDCAgent binPath= "C:\Program Files\OIAF\oiaf-dc-agent.exe" start= auto
sc.exe description OIAFDCAgent "OIAF Domain Controller Authentication Monitor"
sc.exe start OIAFDCAgent
```

The service account requires `SeSecurityPrivilege` (read security event log).
Grant via Local Security Policy or Group Policy. No other elevated privileges
are needed in `monitor` mode.

## Security Considerations

- The agent never logs or transmits credential material, NTLM hashes, or
  Kerberos tickets. Only event metadata is forwarded.
- In `monitor` mode the agent is read-only and cannot block authentication.
- The adapter token grants event-ingestion rights; scope it to the `adapter`
  RBAC role only.
- Event data contains usernames, hostnames, and IPs; treat as sensitive PII.
- On non-Windows platforms the agent runs in stub mode and captures no events.

## Roadmap

- [x] EvtSubscribe real-time event capture (Windows)
- [x] Event XML parsing for all 8 event IDs
- [x] Batch buffering and HTTP sender
- [x] Integration with OIAF discovery engine
- [ ] AD inventory scan on startup (requires LDAP config)
- [ ] AD response action triggering (enforcement mode: response)
- [ ] WFP filter updates (enforcement mode: wfp)
- [ ] Direct ETW consumer for high-volume DCs (>10k events/sec)
- [ ] Multi-DC event deduplication
