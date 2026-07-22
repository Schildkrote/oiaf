# PAM Adapter

## Purpose

The PAM adapter integrates Linux/Unix authentication with OIAF. A small helper
binary (`oiaf-pam-helper`) is invoked from a `pam_exec` module during the auth
phase. It reads PAM environment variables, calls the OIAF core to evaluate the
access request, and exits with a status code that PAM interprets as success or
failure.

## Status

Experimental (M3).

> **WARNING: PAM lockout risk.** Misconfiguring PAM can lock all users —
> including root — out of the system. Always:
>
> - Test changes in a VM or container first.
> - Keep an open root shell while editing PAM config.
> - Use `pam_exec` with a fallback (`pam_unix` sufficient) during rollout.
> - Prefer `optional`/`sufficient` over `required` until validated.
> - Never edit PAM over the only SSH session you have.

## Architecture

```
sshd/sudo/login --> pam_exec.so --> oiaf-pam-helper --> OIAF core
                                          |
                                          +--> exit 0 (allow) / non-zero (deny)
```

- `oiaf-pam-helper` reads `PAM_USER`, `PAM_SERVICE`, `PAM_RHOST`, `PAM_TTY`.
- It builds an OIAF `AccessRequest` and calls `/v1/access/evaluate`.
- On `challenge`, it can prompt for a TOTP code (future) via `pam_exec` stdin.

Example `/etc/pam.d/sshd` fragment (use with caution):

```
auth  [success=ok default=ignore]  pam_exec.so  expose_authtok  /usr/local/bin/oiaf-pam-helper
```

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `OIAF_PAM_TIMEOUT`  | Request timeout in seconds         | `5`            |
| `OIAF_PAM_FAIL_OPEN`| Allow on OIAF error (dangerous)    | `false`        |

## Security considerations

- Default to fail-closed; fail-open should be an explicit, audited choice.
- The helper must never log passwords or PAM authtok values.
- Run the helper as a dedicated unprivileged user where possible.
- Protect the adapter token; it grants access-evaluation rights.
- Keep timeouts short to avoid hanging interactive logins.

## Roadmap

- [ ] Read PAM env vars and build AccessRequest
- [ ] Call OIAF evaluate and map decision to exit code
- [ ] Interactive TOTP challenge via pam_exec stdin
- [ ] Fail-open/fail-closed policy flag
- [ ] Packaging (systemd, /usr/local/bin install)
