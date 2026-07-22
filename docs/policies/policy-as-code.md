# Policy as Code

OIAF policies are declarative JSON documents. Store them in version control and
apply them through the API for auditable, reviewable access rules.

## Policy Format

```json
{
  "id": "require-mfa-admin-ssh",
  "description": "Require MFA for SSH access by admins",
  "enabled": true,
  "priority": 100,
  "effect": "challenge",
  "conditions": {
    "all": [
      {"path": "resource.type", "op": "eq", "value": "ssh"},
      {"path": "identity.groups", "op": "contains", "value": "Admins"}
    ]
  },
  "challenge": {"methods": ["totp", "push"]}
}
```

| Field | Description |
|-------|-------------|
| `id` | Stable identifier |
| `description` | Human-readable intent |
| `enabled` | Whether the policy is active |
| `priority` | Higher is evaluated first (does not override effect ordering) |
| `effect` | `allow`, `deny`, `challenge`, or `alert` |
| `conditions` | Condition tree (see below) |
| `challenge.methods` | MFA methods when `effect` is `challenge` |

## Operators

Leaf conditions use `path`, `op`, `value`:

- `eq`, `neq` — equality / inequality
- `in`, `not_in` — membership in a list
- `contains`, `not_contains` — array membership or substring
- `gt`, `gte`, `lt`, `lte` — numeric comparison
- `regex` — RE2 match
- `exists`, `not_exists` — field presence

## Composition

Combine leaves with boolean nodes:

- `{"all": [ ... ]}` — logical AND
- `{"any": [ ... ]}` — logical OR
- `{"not": { ... }}` — logical NOT

These nest arbitrarily.

## Paths

Dot-notation into the serialized `AccessRequest`:
`identity.username`, `identity.type`, `identity.groups`, `identity.privileged`,
`resource.type`, `resource.name`, `resource.sensitivity`, `protocol.name`,
`source.ip`, `source.geo`, `source.reputation`, `device.managed`,
`device.compliant`, `context.mfa_recent`, `context.interactive`.

## Evaluation Order

1. Enabled policies sorted by `priority` (descending).
2. All matching policies collected.
3. Most restrictive effect wins: **deny > challenge > alert > allow**.
4. No match → default by resource sensitivity (high/critical → deny, low →
   allow, else deny). Fail-closed.

## Applying Policies

```bash
oiafctl policy apply policy/examples/require-mfa-admin-ssh.json
oiafctl policy list
```

Test before applying:

```bash
curl -H "Authorization: Bearer $OIAF_ADMIN_TOKEN" \
  -d '{"policy": {...}, "request": {...}}' \
  http://127.0.0.1:8080/v1/policies/test
```
