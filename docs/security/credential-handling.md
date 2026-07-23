# Credential Handling

OIAF is designed to minimize the storage and transmission of secrets.

## No Plaintext Passwords

- OIAF does not store user passwords. Authentication is delegated to upstream
  systems (AD, LDAP, RADIUS clients, IdPs).
- Adapters validate credentials locally or via the upstream directory and send
  only a structured `AccessRequest` to the control plane.
- The control plane never receives or persists user passwords.

## No Secret Logging

- TOTP secrets (`Factor.Secret`), device secrets (`Device.SecretHash`), and
  auth token hashes (`AuthToken.TokenHash`) are tagged `json:"-"` and are never
  serialized to API responses or logs.
- Structured logging avoids secret-bearing fields.

## Token Hashing

- Bearer tokens are 32-byte random hex strings.
- Stored as bcrypt hashes (`bcrypt.DefaultCost`).
- Validation uses `bcrypt.CompareHashAndPassword` (constant-time).

## TOTP Secret Encryption

- TOTP secrets are generated via `pquerna/otp` (RFC 6238).
- In the MVP memory store, secrets are held in process memory only.
- **Production (Postgres) should encrypt TOTP secrets at rest** using an
  envelope-encryption scheme with a KMS-backed data key. This is a planned
  hardening item.

## Key Management

- Device push secrets are SHA-256 hashed at rest; the raw secret is returned
  exactly once at registration.
- Admin and adapter tokens are bcrypt-hashed; the raw token is returned once at
  creation.
- Future: integrate with a KMS (AWS KMS, GCP KMS, Vault Transit) for envelope
  encryption of TOTP secrets and signing keys.

## Secret Rotation

- Adapter tokens: rotate via `POST /v1/adapters/{id}/rotate-token`. The old
  token is invalidated on rotation.
- Auth tokens: revoke via the auth store; issue a new token.
- Rotate all secrets on a schedule and immediately after suspected compromise
  or personnel changes.

## Break-Glass Handling

- Break-glass accounts are flagged via the `BreakGlass` group and an `alert`
  policy (`break-glass-access.json`).
- Use of a break-glass account logs an alert event for immediate review.
- Break-glass credentials should be stored in a sealed envelope / secrets
  manager and rotated after every use.
- Monitor break-glass usage with high-priority alerting to the SOC.
