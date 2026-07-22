# RADIUS Adapter

**Status: Experimental**

The RADIUS adapter intercepts RADIUS Access-Request packets and gates
Access-Accept on an OIAF access decision, enabling MFA for VPN, Wi-Fi, and
network access.

## Architecture

```
  +---------+   Access-Request   +----------------+   evaluate   +----------+
  |  NAS /  +------------------->|  RADIUS Adapter+------------->|   OIAF   |
  |  VPN    |                    |  (proxy)       |              |  Control |
  |  client |<-------------------+                |<-------------+  Plane   |
  +---------+   Accept/Reject    +----------------+   decision   +----------+
```

- The adapter acts as a RADIUS proxy/server in front of (or alongside) the
  existing RADIUS infrastructure.
- On Access-Request, it builds an `AccessRequest` with
  `protocol.name: "radius"`, `resource.type: "vpn"` (or the appropriate type),
  the calling-station IP as `source.ip`, and calls `/v1/access/evaluate`.
- On `challenge`, it issues an Access-Challenge (RADIUS challenge) and drives
  the MFA flow before returning Access-Accept.

## Configuration

- Upstream RADIUS shared secret (per NAS client).
- OIAF adapter token (from `POST /v1/adapters`).
- Listen address and RADIUS port (default 1812).
- Fail mode: `closed` (default) or `open`.

## Security

- **Shared secret:** store in a secrets manager; use unique per-client secrets.
- Prefer **RadSec** (RADIUS over TLS, port 2083) to protect attributes in
  transit.
- Restrict RADIUS traffic by source IP.
- Never log User-Password or CHAP secrets.
- Fail closed by default; a reachable control plane is required for access.

## Warnings

- RADIUS has limited attribute size; large challenge payloads must be handled
  carefully.
- The adapter is experimental; validate against your NAS equipment before
  production use.
