# Secure Defaults

OIAF ships with security-conservative defaults. Insecure behavior must be
explicitly opted into.

## Fail-Closed

- If no policy matches a request, the default effect is `deny`
  (`policy.default_effect: deny`).
- Requests targeting `high` or `critical` sensitivity resources are denied when
  no policy matches.
- Adapters should deny access when the control plane is unreachable.

## Token Authentication

- Every `/v1/*` endpoint requires a `Authorization: Bearer <token>` header.
- Missing or malformed headers return `401 Unauthorized`.
- Tokens are bcrypt-hashed at rest; raw tokens are never stored.
- Roles (`admin`, `auditor`, `adapter`, `service`) scope access.

## TLS

- TLS is off by default for local development (`127.0.0.1:8080`).
- Enable TLS by setting `OIAF_TLS_CERT_FILE` and `OIAF_TLS_KEY_FILE` (or the
  `server.tls_cert_file` / `server.tls_key_file` YAML keys).
- **Production deployments must use TLS** (directly or via a reverse proxy).

## Body Limits

- Request bodies are capped at 1 MiB (`middleware.BodyLimit(1 << 20)`).
- Oversized bodies are rejected, mitigating memory-exhaustion attacks.

## Security Headers

The `SecurityHeaders` middleware sets:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; ...` |

## Panic Recovery

- A `Recover` middleware catches panics, logs them, and returns a generic
  `500` without leaking stack traces to clients.

## Logging

- Structured JSON logging by default (`log_format: json`).
- Secrets are excluded from log output via `json:"-"` struct tags.

## Insecure Dev Mode

- `OIAF_ALLOW_INSECURE_DEV=true` relaxes certain checks for local development.
- **Never** enable this in production.
