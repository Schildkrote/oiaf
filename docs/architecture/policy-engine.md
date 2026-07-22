# Policy Engine

The policy engine evaluates declarative JSON policies against access requests
and returns the most restrictive matching effect.

## Policy Format

```json
{
  "id": "require-mfa-radius-vpn",
  "description": "Require MFA for RADIUS VPN access",
  "enabled": true,
  "priority": 90,
  "effect": "challenge",
  "conditions": {
    "all": [
      {"path": "resource.type", "op": "eq", "value": "vpn"},
      {"path": "protocol.name", "op": "eq", "value": "radius"}
    ]
  },
  "challenge": {"methods": ["totp", "push"]}
}
```

## Condition Operators

Conditions are a tree of `all`, `any`, `not`, and leaf nodes.

| Operator | Description |
|----------|-------------|
| `eq` | String equality (via `fmt.Sprintf("%v")`) |
| `neq` | Not equal |
| `in` | Value is in a list |
| `not_in` | Value is not in a list |
| `contains` | Array contains value, or string contains substring |
| `not_contains` | Negation of contains |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison |
| `regex` | RE2 regex match |
| `exists` / `not_exists` | Field presence check |

## Path Resolution

Paths use dot notation into the JSON-serialized `AccessRequest`:
`identity.username`, `resource.sensitivity`, `protocol.name`, `source.geo`,
`device.managed`, `context.interactive`, `identity.groups`, etc.

## Evaluation Order

1. All enabled policies are sorted by `priority` (descending — higher wins).
2. Each policy's conditions are evaluated against the request.
3. All matching policies are collected.
4. The most restrictive effect wins: **deny > challenge > alert > allow**.
5. If no policy matches, a default is applied based on resource sensitivity:
   - `high` / `critical` → deny
   - `low` → allow
   - otherwise → deny (fail-closed)

## Effects

| Effect | Behavior |
|--------|----------|
| `allow` | Grant access |
| `deny` | Reject access |
| `challenge` | Require MFA; methods from `challenge.methods` |
| `alert` | Allow access but log an alert event |

## OPA (Future)

An OPA/Rego engine stub exists at `core/internal/policy/opa/opa.go`. The
builtin JSON engine is the default and only active engine in the MVP.
