# MFA Orchestration

The MFA orchestrator manages challenge lifecycle: creation, verification,
expiry, and attempt limiting.

## Supported Methods

| Method | Status | Description |
|--------|--------|-------------|
| TOTP | Active | RFC 6238, SHA-1, 6 digits, 30s period |
| Push | Active | HMAC-SHA256 signed approval with number matching |
| WebAuthn | Planned | FIDO2 / passkey support |
| Email | Planned | OTP via email |
| SMS | Planned | OTP via SMS (low security, last resort) |

## Challenge Lifecycle

1. **Create** — When the decision is `challenge`, the orchestrator creates a
   `Challenge` with a unique ID, nonce, allowed methods, TTL (default 300s),
   and max attempts (default 5).
2. **Verify** — The user submits a code or approval. The orchestrator checks:
   - Challenge is still `pending`
   - Not expired
   - Attempts remaining
3. **Resolve** — On success, status → `approved`. On max attempts, status →
   `failed`. On TTL expiry, status → `expired`.

## TOTP

- Enrollment: `POST /v1/identities/{id}/factors/totp/enroll` returns a secret
  and `otpauth://` URI. The factor starts as `pending_activation`.
- Activation: `POST /v1/identities/{id}/factors/totp/activate` with a valid
  code transitions the factor to `active`.
- Verification: validates the code against all active TOTP factors for the
  identity, with a 1-period skew tolerance.

## Push

- Device registration: `POST /v1/devices` returns a device record and a
  one-time secret. The secret is SHA-256 hashed at rest.
- Number matching: each push challenge includes a random 0–99 number that the
  user must confirm on their device.
- Signature: the device signs `challengeID|number|timestamp` with
  HMAC-SHA256 using the hashed secret.
- Timestamp skew: configurable (default 60s) to prevent replay.

## Method Preference

When a policy specifies `challenge.methods`, the orchestrator uses those
methods. If no methods are specified, TOTP is the default. The order in the
array indicates preference.

## WebAuthn (Future)

WebAuthn will provide phishing-resistant MFA using platform or roaming
authenticators. The `MFAMethod` enum already includes `webauthn`.
