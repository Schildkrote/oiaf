# Entra Adapter

## Purpose

The Entra (Microsoft Entra ID / Azure AD) adapter integrates OIAF with Entra ID.
It ingests sign-in and audit logs via Microsoft Graph as risk signals and can
enforce OIAF decisions through Conditional Access integration or token issuance
hooks.

## Status

Planned (M5).

## Architecture

```
Microsoft Graph (sign-in/audit logs) --> oiaf-entra --> OIAF core
Entra Conditional Access / token hook <-- oiaf-entra <-- OIAF decision
```

- Authenticates to Microsoft Graph with an app registration (client credentials).
- Polls sign-in and audit logs; normalizes them into OIAF audit/risk signals.
- Can integrate with Entra Conditional Access / custom authentication extensions
  to enforce OIAF decisions.

## Configuration

| Env / Flag              | Description                    | Default        |
|-------------------------|--------------------------------|----------------|
| `OIAF_SERVER`           | OIAF core base URL             | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`    | Adapter bearer token           | required       |
| `ENTRA_TENANT_ID`       | Entra tenant id                | required       |
| `ENTRA_CLIENT_ID`       | App registration client id     | required       |
| `ENTRA_CLIENT_SECRET`   | Client secret / cert (secret)  | required       |
| `ENTRA_POLL_INTERVAL`   | Graph log poll interval        | `60s`          |

## Security considerations

- Use certificate credentials over client secrets where possible.
- Grant least-privilege Graph permissions (e.g. `AuditLog.Read.All`).
- Store the adapter token and Entra credentials in a secret manager.
- Treat sign-in logs as sensitive PII.
- Fail-closed for any inline enforcement path.

## Roadmap

- [ ] Microsoft Graph log ingestion (sign-in + audit)
- [ ] Normalization to OIAF audit/risk schema
- [ ] Conditional Access / custom auth extension integration
- [ ] User/group sync to OIAF identities
- [ ] Risky user / sign-in signal ingestion
