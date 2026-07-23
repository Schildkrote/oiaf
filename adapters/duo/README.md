# Duo Adapter

## Purpose

The Duo adapter integrates OIAF with Duo Security. It can use Duo as an MFA
provider for OIAF challenges (push, passcode) and ingest Duo authentication logs
as risk signals.

## Status

Planned (M5).

## Architecture

```
OIAF challenge --> oiaf-duo --> Duo Auth API (push/passcode)
Duo Admin API logs --> oiaf-duo --> OIAF core (risk signals)
```

- Implements an OIAF MFA method backed by Duo push or passcode.
- Polls the Duo Admin API for authentication logs and forwards them as risk
  signals.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `DUO_IKEY`          | Duo integration key                | required       |
| `DUO_SKEY`          | Duo secret key (secret)            | required       |
| `DUO_API_HOST`      | Duo API hostname                   | required       |

## Security considerations

- Protect the Duo secret key; it can authorize MFA on behalf of users.
- Verify Duo signed responses and webhook signatures.
- Store all credentials in a secret manager.
- Fail-closed when Duo is unreachable for a required challenge.

## Roadmap

- [ ] Duo push/passcode as OIAF MFA method
- [ ] Duo Auth API request signing
- [ ] Admin API log ingestion as risk signals
- [ ] Device posture signal mapping
- [ ] Webhook receiver with signature verification
