# Linux PAM Adapter

**Status: Experimental**

The Linux PAM adapter adds OIAF-backed MFA to Linux logins, SSH, and sudo using
the `pam_exec` approach.

## pam_exec Approach

- A PAM module invokes an external helper script/binary via `pam_exec`.
- The helper builds an `AccessRequest` (username, host, service, source) and
  calls `/v1/access/evaluate`.
- On `challenge`, the helper prompts for a TOTP code (or drives push) and calls
  `/v1/challenge/{id}/verify`.
- PAM config example (conceptual):
  ```
  auth required pam_exec.so expose_authtok /usr/local/bin/oiaf-pam
  ```

## Configuration

- OIAF adapter token (stored root-only, mode 0600).
- Control plane URL.
- Fail mode and timeout.
- Which PAM services to protect (sshd, login, sudo).

## Warnings: Lockout Risk

- **A misconfigured PAM adapter can lock all users out of a host**, including
  root. This is the highest-risk adapter.
- Always keep an out-of-band recovery path (console, single-user mode, a
  non-OIAF admin account).
- Test on a non-production host and a non-critical service first.
- Set a sensible timeout and fail mode; a hung control plane must not wedge
  logins indefinitely.
- Roll out gradually (e.g., SSH for a test group before sudo everywhere).
- Monitor for repeated PAM failures that could indicate lockout or attack.
