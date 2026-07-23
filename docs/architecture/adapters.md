# Adapter Model

Adapters are protocol-specific agents that intercept authentication events and
forward them to the OIAF Decision API. They never make access decisions locally.

## Architecture

```
  +-------------------+          +-------------------+
  |  Protocol Source   |  event   |     Adapter       |
  |  (RADIUS, LDAP,    +--------->|  (protocol-specific|
  |   PAM, Windows)    |          |   translation)     |
  +-------------------+          +---------+---------+
                                           |
                                  POST /v1/access/evaluate
                                           |
                                           v
                                  +-------------------+
                                  |  OIAF Control     |
                                  |  Plane            |
                                  +-------------------+
```

## Adapter Lifecycle

1. **Register** — An admin creates an adapter via `POST /v1/adapters`. The
   server returns a one-time Bearer token.
2. **Authenticate** — The adapter includes the token in every API call.
3. **Evaluate** — On each auth event, the adapter builds an `AccessRequest`
   and calls `/v1/access/evaluate`.
4. **Act** — The adapter interprets the `AccessDecision`:
   - `allow` → grant access
   - `deny` → reject
   - `challenge` → initiate MFA flow, then re-evaluate or poll
5. **Rotate** — Token rotation via `POST /v1/adapters/{id}/rotate-token`.

## Adapter SDK (Planned)

A Go SDK will provide:
- Typed `AccessRequest` / `AccessDecision` structs
- HTTP client with retry and timeout
- Challenge polling helper
- Structured logging hooks

## Security Requirements for Adapters

- Adapters must **never** log or transmit plaintext credentials.
- Adapter tokens are bearer tokens; treat them as secrets.
- Adapters should fail closed: if the control plane is unreachable, deny access.
- Each adapter should run with minimal OS privileges.

## Current Adapter Status

| Adapter | Status |
|---------|--------|
| RADIUS | Experimental |
| Linux PAM | Experimental |
| LDAP Proxy | Planned |
| Windows Credential Provider | Planned |
| AD Monitor | Planned |
| Okta | Planned |
| Entra ID | Planned |
| Duo | Planned |
