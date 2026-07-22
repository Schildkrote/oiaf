# Webhook Adapter

## Purpose

The webhook adapter is a generic, low-effort integration point. It exposes an
HTTP endpoint that external systems call to obtain an OIAF access decision, and
it can also push OIAF events/decisions to configured downstream webhook URLs.
It is the recommended starting point for custom integrations.

## Status

Planned (M3).

## Architecture

```
external system --HTTP--> oiaf-webhook --> OIAF core (evaluate/challenge)
OIAF core --event--> oiaf-webhook --HTTP POST--> downstream URL
```

- Inbound: accepts an access request, calls OIAF, returns the decision.
- Outbound: subscribes to OIAF events and POSTs them to configured URLs with a
  signed payload.

## Configuration

| Env / Flag            | Description                      | Default        |
|-----------------------|----------------------------------|----------------|
| `OIAF_SERVER`         | OIAF core base URL               | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`  | Adapter bearer token             | required       |
| `WEBHOOK_LISTEN`      | Inbound listen address           | `:8081`        |
| `WEBHOOK_TARGET_URL`  | Outbound target URL              | optional       |
| `WEBHOOK_SIGNING_KEY` | HMAC signing key (secret)        | optional       |

## Security considerations

- Authenticate inbound callers; do not expose the endpoint publicly without
  auth.
- Sign outbound payloads (HMAC) so receivers can verify authenticity.
- Validate and size-limit inbound request bodies.
- Protect the adapter token and signing key.
- Fail-closed on OIAF errors for inbound decisions.

## Roadmap

- [ ] Inbound evaluate endpoint
- [ ] Outbound event fan-out with HMAC signing
- [ ] Configurable target URLs and retries
- [ ] Request validation and rate limiting
- [ ] Health and readiness probes
