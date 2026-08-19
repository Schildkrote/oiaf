# PAM Adapter

## Purpose

The PAM adapter integrates Linux/Unix authentication with OIAF. A small helper
binary (`oiaf-pam-helper`) is invoked from a `pam_exec` module during the auth
phase. It reads PAM environment variables, calls the OIAF core to evaluate the
access request, and exits with a status code that PAM interprets as success or
failure.

## Status

Experimental (M3) — the helper is implemented and covered by unit tests plus
the e2e suite (`make e2e`, steps 11–14). Not yet packaged or field-tested
behind a real PAM stack.

> **WARNING: PAM lockout risk.** Misconfiguring PAM can lock all users —
> including root — out of the system. Always:
>
> - Test changes in a VM or container first.
> - Keep an open root shell while editing PAM config.
> - Use `pam_exec` with a fallback (`pam_unix` sufficient) during rollout.
> - Prefer `optional`/`sufficient` over `required` until validated.
> - Never edit PAM over the only SSH session you have.

## How it works

```
sshd/sudo/login --> pam_exec.so --> oiaf-pam-helper --> OIAF core
                                          |
                                          +--> exit 0 (allow) / non-zero (deny)
```

The helper:

1. Reads `PAM_USER`, `PAM_SERVICE`, `PAM_TYPE`, `PAM_RHOST`, `PAM_TTY`.
   Non-auth PAM types (account/session) pass through without an evaluation.
2. Builds an `AccessRequest` (`resource.type` = the PAM service, `sudo` is
   escalated to high sensitivity) and calls `/v1/access/evaluate` with the
   adapter bearer token.
3. Maps the decision to a PAM exit code:
   - `allow` / `alert` → `PAM_SUCCESS` (0)
   - `deny` → `PAM_AUTH_ERR` (7)
   - `challenge` → prompts for a 6-digit TOTP code (on the PAM TTY, with a
     stdin fallback), verifies it via `/v1/challenge/{id}/verify`, then allows
     on approval or denies on rejection.
4. Fails **closed** (`PAM_SYSTEM_ERR`, 8) on any transport or server error
   unless `OIAF_PAM_FAIL_OPEN=true` is explicitly set (dangerous; use only for
   audited rollouts).

Group membership is not handed to PAM helpers by PAM itself. When known (e.g.
exported by a preceding module or wrapper), pass it via `OIAF_PAM_GROUPS`
(comma-separated) so group conditions can be evaluated server-side.

Example `/etc/pam.d/sshd` fragment (use with caution):

```
auth  [success=ok default=ignore]  pam_exec.so  expose_authtok  /usr/local/bin/oiaf-pam-helper
```

## Configuration

| Env / Flag           | Description                              | Default               |
|----------------------|------------------------------------------|-----------------------|
| `OIAF_SERVER`        | OIAF core base URL                       | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN` | Adapter bearer token                     | required              |
| `OIAF_PAM_TIMEOUT`   | Request timeout in seconds               | `5`                   |
| `OIAF_PAM_FAIL_OPEN` | Allow on OIAF error (dangerous)          | `false`               |
| `OIAF_PAM_GROUPS`    | Comma-separated groups to forward        | (none)                |
| `OIAF_PAM_TOTP_FILE` | File with the TOTP secret (dev/test only)| (none)                |

## Security considerations

- Default to fail-closed; fail-open should be an explicit, audited choice.
- The helper never logs passwords, TOTP codes, or PAM authtok values.
- Run the helper as a dedicated unprivileged user where possible.
- Protect the adapter token; it grants access-evaluation rights.
- Keep timeouts short to avoid hanging interactive logins.

## Roadmap

- [x] Read PAM env vars and build AccessRequest
- [x] Call OIAF evaluate and map decision to exit code
- [x] Interactive TOTP challenge via PAM TTY (stdin fallback)
- [x] Fail-open/fail-closed policy flag
- [ ] Packaging (systemd, /usr/local/bin install)
- [ ] Forward real group membership without a wrapper (PAM has no native
      group API; consider `pam_groups`-style integration or a getgrent pass)