# AD Monitor Adapter

## Purpose

The AD monitor adapter passively ingests Active Directory security event logs
(via Windows Event Log forwarding, WEF/WEC, or ETW) and converts them into OIAF
audit events and risk signals. It is read-only: it observes authentication and
authorization activity but does not block it.

## Status

Planned (M4).

## Architecture

```
Domain Controllers --WEF/WEC--> collector --> oiaf-ad-monitor --> OIAF core
                                                       |
                                                       +--> audit events + risk signals
```

- Subscribes to forwarded security events.
- Filters for the event IDs below and normalizes them into OIAF audit events.
- Feeds behavioral risk signals (impossible travel, privileged escalation,
  repeated failures) into the OIAF risk engine.

## Monitored Event IDs

| Event ID | Meaning                                              |
|----------|------------------------------------------------------|
| 4624     | An account was successfully logged on                |
| 4625     | An account failed to log on                         |
| 4648     | A logon was attempted using explicit credentials     |
| 4672     | Special privileges assigned to new logon             |
| 4768     | A Kerberos authentication ticket (TGT) was requested |
| 4769     | A Kerberos service ticket (TGS) was requested        |
| 4771     | Kerberos pre-authentication failed                   |
| 4776     | The DC attempted to validate credentials (NTLM)      |
| 2887     | NTLM relay / authentication auditing (client)        |
| 2889     | NTLM authentication details (server-side audit)      |

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `AD_EVENT_SOURCE`   | Event source (wef/etw/file)        | `wef`          |
| `AD_BATCH_SIZE`     | Events per OIAF batch              | `100`          |

## Security considerations

- The collector requires read access to sensitive security logs — scope it
  to a dedicated service account with minimal privileges.
- Event data contains usernames, hostnames, and IPs; treat as sensitive PII.
- Do not log raw credentials or ticket material.
- Ensure reliable delivery (buffering) so audit integrity is preserved.

## Roadmap

- [ ] Windows Event Log / WEF ingestion
- [ ] Event ID normalization to OIAF audit schema
- [ ] Risk signal extraction (4625 storms, 4672 escalation)
- [ ] Kerberos/NTLM anomaly detection
- [ ] Backpressure and at-least-once delivery
