# Active Directory Monitor Adapter

**Status: Planned**

The AD monitor adapter ingests Windows security events to feed risk signals and
detect attacks (lateral movement, privilege escalation, reconnaissance).

## Event IDs

Key Windows Security event IDs to monitor:

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff |
| 4672 | Special privileges assigned (admin logon) |
| 4720 / 4726 | User account created / deleted |
| 4728 / 4729 / 4732 / 4733 | Group membership changes |
| 4740 | Account locked out |
| 4768 / 4769 / 4771 | Kerberos TGT / TGS / pre-auth failure |
| 4776 | NTLM authentication |
| 4688 | Process creation (with command-line auditing) |

## WEF (Windows Event Forwarding)

- Use **WEF** with Windows Event Collector (WEC) to centrally aggregate events
  from domain controllers and servers.
- Configure source-initiated or collector-initiated subscriptions.
- The adapter reads from the WEC and translates events into OIAF risk signals
  and audit metadata.

## Sysmon

- **Sysmon** (Sysinternals) provides richer telemetry (process trees, network
  connections, DLL loads, credential usage) via its own event channel.
- Combine Sysmon with Security log events for stronger detection of credential
  theft (e.g., LSASS access) and lateral movement.

## Usage

- Feed events into the risk engine as contextual signals (e.g., recent failed
  logons, NTLM usage by admins, lockout spikes).
- Correlate with OIAF access decisions for unified identity telemetry.
- This adapter is planned and not yet implemented.
