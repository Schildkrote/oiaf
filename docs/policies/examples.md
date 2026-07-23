# Policy Examples

Annotated examples from [`policy/examples/`](../../policy/examples/).

## Require MFA for RADIUS VPN

[`require-mfa-radius-vpn.json`](../../policy/examples/require-mfa-radius-vpn.json)

```json
{
  "id": "require-mfa-radius-vpn",
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

Any RADIUS VPN access must complete TOTP or push MFA.

## Require MFA for Admin SSH

[`require-mfa-admin-ssh.json`](../../policy/examples/require-mfa-admin-ssh.json)

Matches `resource.type == "ssh"` **and** membership in `Admins`, then requires
MFA. Higher priority (100) than the VPN rule.

## Deny Service Account Interactive Logon

[`deny-service-account-interactive-logon.json`](../../policy/examples/deny-service-account-interactive-logon.json)

```json
{
  "effect": "deny",
  "priority": 200,
  "conditions": {
    "all": [
      {"path": "identity.type", "op": "eq", "value": "service_account"},
      {"path": "context.interactive", "op": "eq", "value": true}
    ]
  }
}
```

Service accounts must never log on interactively; this is a strong indicator of
credential theft. High priority `deny` wins over lower-priority allows.

## Alert on NTLM by Admins

[`alert-ntlm-admin.json`](../../policy/examples/alert-ntlm-admin.json)

`effect: "alert"` allows access but logs an alert when an admin authenticates
via the weak NTLM protocol — useful for tracking legacy-protocol usage without
blocking it.

## Break-Glass Access

[`break-glass-access.json`](../../policy/examples/break-glass-access.json)

```json
{
  "effect": "alert",
  "priority": 300,
  "conditions": {
    "all": [
      {"path": "identity.groups", "op": "contains", "value": "BreakGlass"}
    ]
  }
}
```

Emergency accounts are allowed but generate a high-priority alert for immediate
SOC review. Highest priority here so it is evaluated first, but remember effect
ordering (deny still wins if another policy denies).
