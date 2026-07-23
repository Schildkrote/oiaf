# Okta Adapter

## Purpose

The Okta adapter integrates OIAF with Okta as an identity source and policy
enforcement point. It ingests Okta system logs (sign-ins, MFA, admin events) as
risk signals and can enforce OIAF decisions through Okta sign-on policies or
inline hooks.

## Status

Planned (M5).

## Architecture

```
Okta System Log --poll/webhook--> oiaf-okta --> OIAF core
Okta inline hook <--------------- oiaf-okta <-- OIAF decision
```

- Polls the Okta System Log API or receives event hooks.
- Normalizes sign-in and MFA events into OIAF audit/risk signals.
- Optionally serves an Okta inline hook that calls OIAF during authentication to
  allow/deny/challenge.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `OKTA_DOMAIN`       | Okta org domain                    | required       |
| `OKTA_API_TOKEN`    | Okta API token (secret)            | required       |
| `OKTA_POLL_INTERVAL`| Log poll interval                  | `30s`          |

## Security considerations

- The Okta API token grants broad access — scope and rotate it, store securely.
- Verify webhook signatures for event hooks.
- Treat sign-in logs as sensitive PII.
- Fail-closed for inline enforcement hooks.

## Roadmap

- [ ] System Log polling and normalization
- [ ] Event hook receiver with signature verification
- [ ] Inline hook enforcement (evaluate + challenge)
- [ ] User/group sync to OIAF identities
- [ ] Device posture signal ingestion
