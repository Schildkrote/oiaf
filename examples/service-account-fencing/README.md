# Service Account Fencing

Restricts and monitors service account usage to prevent credential abuse.

## Use Case

- Service accounts are scoped to specific resources, protocols, and time windows
- Any access outside the defined fence triggers denial and alerting
- Interactive use of service accounts is blocked by default
- All service account activity is logged for compliance auditing

## Relevant Adapters

- **AD Monitor Adapter** — detects service account authentication events
- **Windows Credential Provider Adapter** — enforces fencing at logon
- See `docs/adapters/ad-monitor.md` and `docs/adapters/windows-credential-provider.md` for configuration details
