# MFA Security

Guidance on MFA methods, fatigue protection, and recovery.

## MFA Fatigue Protection

- **Number matching:** push challenges include a random 0–99 number the user
  must confirm, preventing blind "approve" taps.
- **Attempt limiting:** each challenge allows a bounded number of attempts
  (default `totp_max_attempts: 5`); exceeding this marks the challenge `failed`.
- **TTL:** challenges expire (default `challenge_ttl_seconds: 300`).
- **Audit:** every failed attempt emits a `challenge.failed` event for alerting.

## Number Matching

- Generated per-challenge via `crypto/rand`.
- The device must echo the exact number in its signed approval; a mismatch
  rejects the challenge.

## Replay Protection

- Push approvals are HMAC-SHA256 signed over `challengeID|number|timestamp`.
- A timestamp skew window (default 60s) rejects stale or future-dated
  signatures.
- Each challenge has a unique nonce and ID; approvals are bound to that
  challenge and cannot be reused.
- TOTP codes are time-based (30s period) with a 1-period skew tolerance.

## Device Binding

- Push devices are registered per identity with a unique secret.
- The device secret is SHA-256 hashed at rest; approval signatures are verified
  against the bound device.
- Deleting a device revokes its ability to approve challenges.

## Phishing Resistance

- TOTP and push are **not** fully phishing-resistant (codes can be relayed).
- **WebAuthn / FIDO2 (planned)** provides phishing-resistant, origin-bound
  authentication and is the recommended method for high-risk identities.
- For privileged accounts, prefer WebAuthn once available.

## Recovery Flows

- Lost TOTP device: an admin revokes the factor and re-enrolls a new one.
- Lost push device: delete the device and register a replacement.
- Recovery actions are audit-logged and should require admin MFA.

## Helpdesk Abuse Prevention

- Helpdesk-driven MFA resets are a common social-engineering target.
- Require strong identity verification before resetting factors.
- Log and alert on all factor revocations and re-enrollments.
- Consider a cooling-off period or dual-approval for privileged account resets.
- Monitor for clusters of reset requests (possible targeted attack).
