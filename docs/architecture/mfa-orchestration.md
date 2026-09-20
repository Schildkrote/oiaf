# MFA Orchestration

The MFA orchestrator manages challenge lifecycle: creation, verification,
expiry, and attempt limiting.

## Supported Methods

| Method | Status | Description |
|--------|--------|-------------|
| TOTP | Active | RFC 6238, SHA-1, 6 digits, 30s period |
| Push | Active | HMAC-SHA256 signed approval with number matching |
| WebAuthn | Active | FIDO2 / passkey, phishing-resistant (ES256+ via go-webauthn) |
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

## WebAuthn

WebAuthn provides phishing-resistant MFA using platform or roaming
authenticators (passkeys, security keys). It is implemented via the
`github.com/go-webauthn/webauthn` library and follows the same
enroll/activate-style ceremony pattern as TOTP, adapted to WebAuthn's
challenge/response ceremonies.

- Configuration: Relying Party settings under `webauthn:` in `config.yaml`
  (`rp_id`, `rp_origins`, `rp_display_name`) with `OIAF_WEBAUTHN_RP_ID` /
  `OIAF_WEBAUTHN_RP_ORIGINS` / `OIAF_WEBAUTHN_RP_DISPLAY_NAME` env overrides.
  `rp_id` is the effective domain (no scheme/port); `rp_origins` is a
  comma-separated allowlist of fully qualified browser origins. Without both,
  the factor is disabled and its endpoints return `503`.
- Registration: `POST /v1/identities/{id}/factors/webauthn/registration/begin`
  creates a `pending_activation` factor and returns the WebAuthn
  `publicKey` creation options for the browser. The browser's raw
  `navigator.credentials.create()` result is POSTed to
  `.../registration/{factor_id}/finish`, which verifies the attestation and
  activates the factor.
- Verification (identity-scoped): `.../verification/begin` returns assertion
  options; the raw `navigator.credentials.get()` result goes to
  `.../verification/finish`.
- Verification (challenge-orchestrated / policy step-up):
  `POST /v1/challenge/{id}/webauthn/begin` then
  `POST /v1/challenge/{id}/webauthn/finish`. This path binds the ceremony to
  the challenge's TTL and attempt accounting and is the method a policy
  selecting `webauthn` drives end-to-end.
- Credential storage: each registered credential is a `types.Factor`
  (`method=webauthn`) whose opaque `Credentials` bytes hold the JSON
  credential record (public key, sign counter, flags). In-flight ceremony
  sessions ride on the pending factor (registration) or on the challenge
  (`WebAuthnSession`, verification), so no new storage interface is needed
  and the PostgresStore skeleton stays compatible (credentials → bytea).
- Attestation: `none` conveyance preference (low-friction MFA); user
  verification is `preferred`. The sign counter is persisted per assertion to
  support clone detection.

## Method Preference

When a policy specifies `challenge.methods`, the orchestrator uses those
methods. If no methods are specified, TOTP is the default. The order in the
array indicates preference.
