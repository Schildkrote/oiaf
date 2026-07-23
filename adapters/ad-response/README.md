# AD Response Adapter

## Purpose

The AD response adapter is the active counterpart to the AD monitor adapter.
Given an OIAF decision or detected risk signal, it takes response actions in
Active Directory: disabling or locking accounts, forcing password resets,
revoking Kerberos tickets, removing group membership, or triggering step-up
re-authentication.

## Status

Planned (M4). Documentation only.

## Architecture

```
OIAF core --decision/webhook--> oiaf-ad-response --LDAP/Kerberos--> Active Directory
```

- Consumes OIAF decisions or risk-triggered webhooks.
- Performs privileged directory writes (disable account, reset password, remove
  from group, invalidate tickets via `klist`/`ktpass` or LDAP controls).
- Records every response action in the OIAF audit log for accountability.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `AD_LDAP_URL`       | Domain controller LDAPS URL        | required       |
| `AD_BIND_DN`        | Service account bind DN            | required       |
| `AD_BIND_PASSWORD`  | Service account password (secret)  | required       |
| `AD_DRY_RUN`        | Log actions without applying       | `true`         |

## Security considerations

- This adapter holds highly privileged AD credentials — protect and rotate them.
- Default to dry-run; require explicit enablement for destructive actions.
- Every response action must be audited and reversible where possible.
- Require human approval (OIAF challenge) for high-impact actions like
  disabling privileged accounts.
- Use LDAPS only; never transmit bind credentials in cleartext.

## Roadmap

- [ ] Webhook consumer for OIAF decisions
- [ ] Account disable / enable actions
- [ ] Forced password reset and group removal
- [ ] Kerberos ticket revocation
- [ ] Dry-run mode and approval gating
