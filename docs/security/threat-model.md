# Threat Model

This document applies STRIDE to OIAF's major components and integration
surfaces. OIAF is a high-trust identity-enforcement system; treat every
component as security-critical.

## Scope

- Control plane (`oiafd`, Decision API, storage)
- Adapters (RADIUS, LDAP, PAM, Windows, cloud)
- MFA orchestrator (TOTP, push)
- Audit log
- Policy and risk configuration

## STRIDE Summary

| # | Threat | Category | Component |
|---|--------|----------|-----------|
| 1 | Control plane compromise | Spoofing / EoP | Server |
| 2 | Adapter compromise | Spoofing | Adapters |
| 3 | MFA fatigue | Spoofing | MFA |
| 4 | Token replay | Spoofing | Auth |
| 5 | Audit tampering | Tampering | Audit |
| 6 | Credential exposure | Info Disclosure | Adapters |
| 7 | Policy bypass | EoP | Policy |
| 8 | Admin abuse | EoP | Control plane |
| 9 | Service account abuse | EoP | Identity |
| 10 | Supply-chain compromise | Tampering | Build |
| 11 | Windows PAM lockout | DoS | PAM adapter |
| 12 | LDAP password exposure | Info Disclosure | LDAP adapter |
| 13 | RADIUS shared secret theft | Info Disclosure | RADIUS adapter |

---

## 1. Control Plane Compromise

**STRIDE:** Spoofing, Elevation of Privilege, Tampering

**Attack:** An attacker gains code execution on the `oiafd` host or obtains the
admin token, allowing them to approve arbitrary access, modify policies, or
erase audit history.

**Mitigations:**
- Admin token is bcrypt-hashed at rest; only the hash is stored.
- All `/v1/*` endpoints require Bearer auth.
- Body limit (1 MiB), security headers, panic recovery.
- Run `oiafd` as a dedicated low-privilege OS user.
- Use TLS in production; bind to loopback by default.
- Audit log hash chain detects post-hoc tampering.

**Residual risk:** A root-level host compromise can bypass all controls.
Harden the host and monitor for anomalous admin actions.

## 2. Adapter Compromise

**STRIDE:** Spoofing

**Attack:** A compromised adapter sends forged `allow` decisions to clients or
floods the control plane with bogus evaluations.

**Mitigations:**
- Each adapter has a unique, rotatable token.
- Adapters should fail closed when the control plane is unreachable.
- Adapter tokens can be rotated independently via the API.
- Scope adapter tokens to the `adapter` role.

## 3. MFA Fatigue

**STRIDE:** Spoofing

**Attack:** An attacker repeatedly triggers push challenges hoping the user
approves out of annoyance.

**Mitigations:**
- Number matching: the user must confirm a displayed number.
- Max attempts per challenge (default 5); challenge fails after exhaustion.
- Challenge TTL (default 300s) limits the attack window.
- Failed challenges are audit-logged for alerting.

## 4. Token Replay

**STRIDE:** Spoofing

**Attack:** A captured Bearer token is replayed to impersonate an admin or
adapter.

**Mitigations:**
- TLS in transit (required in production).
- Tokens are long-lived secrets; rotate regularly.
- Token revocation support.
- Optional expiry (`expires_at`).

## 5. Audit Tampering

**STRIDE:** Tampering, Repudiation

**Attack:** An attacker modifies or deletes audit events to hide malicious
activity.

**Mitigations:**
- Hash chain: each event's hash includes the previous event's hash.
- `GET /v1/audit/verify` validates the full chain.
- Append-only store design; no update/delete on audit events.
- Forward audit logs to an external SIEM for independent retention.

## 6. Credential Exposure

**STRIDE:** Information Disclosure

**Attack:** Plaintext passwords or secrets leak via logs, memory, or API
responses.

**Mitigations:**
- TOTP secrets and device secrets are marked `json:"-"` (never serialized).
- Token hashes use bcrypt; raw tokens are never stored.
- Adapters must never forward plaintext passwords to the control plane.
- Structured logging avoids secret fields.

## 7. Policy Bypass

**STRIDE:** Elevation of Privilege

**Attack:** A misconfigured or low-priority allow policy overrides a deny, or
an attacker crafts a request that avoids matching conditions.

**Mitigations:**
- Most-restrictive-wins ordering (deny > challenge > alert > allow).
- Fail-closed default: unmatched requests to high/critical resources are denied.
- Policy test endpoint (`/v1/policies/test`) for validation before deploy.
- Review priority assignments; higher priority does not override effect ordering.

## 8. Admin Abuse

**STRIDE:** Elevation of Privilege, Repudiation

**Attack:** A malicious or coerced admin grants themselves access or disables
policies.

**Mitigations:**
- All admin actions are audit-logged with actor identity.
- Separate `admin` and `auditor` roles.
- Break-glass accounts monitored via `alert` policies.
- Require MFA for admin operations (planned).

## 9. Service Account Abuse

**STRIDE:** Elevation of Privilege

**Attack:** A service account is used for interactive logon, indicating
credential theft or lateral movement.

**Mitigations:**
- Risk engine adds +60 for `service_account_interactive`.
- Reference policy `deny-service-account-interactive-logon` denies this.
- Mark service accounts with `type: service_account`.

## 10. Supply-Chain Compromise

**STRIDE:** Tampering

**Attack:** A malicious dependency or build artifact injects backdoors.

**Mitigations:**
- Minimal dependency set; `go.sum` pins versions.
- Reproducible builds from source.
- Verify checksums of downloaded binaries.
- Review dependencies in CI.

## 11. Windows PAM Lockout Risk

**STRIDE:** Denial of Service

**Attack:** A misconfigured PAM/credential-provider adapter repeatedly fails
MFA, triggering AD account lockouts and denying legitimate users.

**Mitigations:**
- Bound MFA attempts per challenge (max 5).
- Fail-open vs. fail-closed must be a deliberate config choice.
- Monitor lockout events (4740) via the AD monitor adapter.
- Test in a non-production OU before broad rollout.

## 12. LDAP Password Exposure

**STRIDE:** Information Disclosure

**Attack:** The LDAP proxy handles user passwords; a cleartext simple bind or
plaintext logging exposes credentials.

**Mitigations:**
- Require LDAPS (TLS) for all LDAP traffic.
- Risk engine penalizes `ldap_simple_bind_cleartext` (+30).
- Never log bind passwords; prefer OTP-appended or SASL patterns.
- The proxy should validate, not persist, passwords.

## 13. RADIUS Shared Secret Theft

**STRIDE:** Information Disclosure, Spoofing

**Attack:** Theft of the RADIUS shared secret allows an attacker to forge
Access-Accept responses or decrypt attributes.

**Mitigations:**
- Store the shared secret in a secrets manager, not in config files.
- Use unique per-client secrets; rotate on suspicion.
- Restrict RADIUS traffic by source IP / network.
- Prefer RadSec (RADIUS over TLS) where supported.

---

## Recommendations

- Deploy behind TLS with a reverse proxy.
- Forward audit logs to an external, append-only SIEM.
- Rotate all tokens on a schedule and after personnel changes.
- Run the control plane on a hardened, minimal host.
- Perform an independent security review before any production use.
