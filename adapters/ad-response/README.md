# AD Response Adapter

## Purpose

The AD response adapter is the active enforcement counterpart to the DC agent.
It consumes OIAF deny/challenge decisions via webhook and performs privileged
LDAP actions in Active Directory: disabling accounts, forcing password resets,
removing group memberships, and revoking Kerberos tickets.

## Status

Implemented (M4c). Dry-run by default.

## Architecture

```
OIAF core --webhook--> oiaf-ad-response --LDAPS--> Active Directory
```

## Supported Actions

| Action | LDAP Operation |
|--------|---------------|
| `disable_account` | Set `userAccountControl \|= 0x0002` |
| `enable_account` | Clear `userAccountControl & ~0x0002` |
| `force_password_reset` | Set `pwdLastSet = 0` |
| `remove_from_group` | Remove `member` from group DN |

## Configuration

| Env / Flag | Description | Default |
|------------|-------------|---------|
| `AD_RESPONSE_LISTEN` | Webhook listen address | `:9090` |
| `OIAF_SERVER` | OIAF core base URL | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN` | Adapter bearer token | required |
| `AD_LDAP_URL` | Domain controller LDAPS URL | required |
| `AD_BIND_DN` | Service account bind DN | required |
| `AD_BIND_PASSWORD` | Service account password | required |
| `AD_DRY_RUN` | Log actions without applying | `true` |

## Webhook Format

```json
POST /webhook/oiaf-decision
{
  "request_id": "...",
  "account_name": "svc-compromised",
  "account_sid": "S-1-5-21-...",
  "decision": "deny",
  "risk_score": 100,
  "reasons": ["service_account_baseline_deviation"],
  "action": "disable_account"
}
```

## Security Considerations

- This adapter holds highly privileged AD credentials. Protect and rotate them.
- Default to dry-run (`AD_DRY_RUN=true`); require explicit enablement for
  destructive actions.
- Every response action is logged before execution.
- Use LDAPS only; never transmit bind credentials in cleartext.
- Require human approval (OIAF challenge) for high-impact actions like
  disabling privileged accounts.

## Roadmap

- [x] Webhook consumer for OIAF decisions
- [x] Account disable / enable actions
- [x] Forced password reset
- [x] Group membership removal
- [x] Dry-run mode
- [ ] Kerberos ticket revocation (klist purge on DC)
- [ ] Approval gating for privileged accounts
- [ ] Action rollback support
