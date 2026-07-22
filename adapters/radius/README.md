# RADIUS Adapter

## Purpose

The RADIUS adapter bridges legacy network access control (WiFi, VPN, switches,
802.1X) with OIAF. It acts as a RADIUS proxy/server that intercepts
Access-Request packets, forwards the access decision to the OIAF core via the
adapter SDK, and returns Access-Accept / Access-Reject / Access-Challenge based
on the OIAF decision.

## Status

Planned (M3).

## Architecture

```
NAS (AP/VPN/switch) --RADIUS--> oiaf-radius-adapter --HTTPS--> OIAF core
                                        |
                                        +--> RADIUS challenge (EAP) for MFA
```

- Listens on UDP `:1812` (auth) and `:1813` (accounting).
- Translates RADIUS attributes (User-Name, NAS-IP-Address, Called-Station-ID)
  into an OIAF `AccessRequest`.
- Maps OIAF `challenge` decisions to RADIUS `Access-Challenge` with EAP methods.
- Emits accounting events to the OIAF audit log.

## Configuration

| Env / Flag        | Description                          | Default        |
|-------------------|--------------------------------------|----------------|
| `OIAF_SERVER`     | OIAF core base URL                   | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN` | Adapter bearer token              | required       |
| `RADIUS_LISTEN`   | UDP listen address                   | `:1812`        |
| `RADIUS_SECRET`   | Shared secret with NAS clients       | required       |

## Security considerations

- RADIUS shared secrets must be stored outside the binary (secret manager / env).
- MD5-based RADIUS attributes are weak; prefer EAP-TLS where possible.
- Bind to internal interfaces only; never expose RADIUS to the public internet.
- Fail-closed: if OIAF core is unreachable, reject rather than accept.

## Roadmap

- [ ] RADIUS packet parsing and proxy loop
- [ ] Attribute mapping to OIAF AccessRequest
- [ ] EAP challenge flow for MFA
- [ ] Accounting (Start/Stop/Interim-Update) forwarding
- [ ] NAS client allow-list and rate limiting
