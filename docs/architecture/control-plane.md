# Control Plane

The control plane is the `oiafd` server binary (`core/cmd/oiafd`). It hosts the
Decision API, policy engine, risk engine, MFA orchestrator, and audit store.

## Server

- Built on Go's `net/http` with `http.ServeMux` (Go 1.22+ pattern routing).
- Middleware chain: RequestID → SecurityHeaders → Recover → BodyLimit (1 MiB) →
  RequestLogger.
- Health endpoints: `GET /healthz`, `GET /readyz`, `GET /version`.
- Optional Prometheus metrics at `GET /metrics` (placeholder in MVP).
- Optional TLS via `OIAF_TLS_CERT_FILE` / `OIAF_TLS_KEY_FILE`.
- Graceful shutdown on SIGINT/SIGTERM with a 15-second drain timeout.

## API Layer

All routes are registered in `core/internal/api/api.go`. Every `/v1/*` route is
wrapped with Bearer-token auth middleware.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/access/evaluate` | Evaluate an access request |
| POST | `/v1/challenge/{id}/verify` | Verify a TOTP or push challenge |
| GET/POST | `/v1/identities` | List / create identities |
| GET/PUT/DELETE | `/v1/identities/{id}` | Get / update / delete identity |
| POST | `/v1/identities/{id}/factors/totp/enroll` | Enroll TOTP factor |
| POST | `/v1/identities/{id}/factors/totp/activate` | Activate TOTP factor |
| GET/POST | `/v1/devices` | List / register push devices |
| GET/DELETE | `/v1/devices/{id}` | Get / delete device |
| POST | `/v1/devices/{id}/approve-challenge` | Approve push challenge |
| GET/POST | `/v1/policies` | List / create policies |
| POST | `/v1/policies/test` | Test a policy against a request |
| GET/PUT/DELETE | `/v1/policies/{id}` | Get / update / delete policy |
| GET/POST | `/v1/adapters` | List / create adapters |
| GET/DELETE | `/v1/adapters/{id}` | Get / delete adapter |
| POST | `/v1/adapters/{id}/rotate-token` | Rotate adapter token |
| GET | `/v1/audit/events` | Query audit events |
| GET | `/v1/audit/verify` | Verify audit hash chain |

## Storage Interface

`storage.Store` is a facade over typed sub-stores (IdentityStore, DeviceStore,
PolicyStore, ChallengeStore, FactorStore, AuthTokenStore, AuditEventStore).
The MVP implementation is `MemoryStore` (mutex-protected maps). A Postgres
implementation is planned for production use.

## Authentication

`auth.Authenticator` manages Bearer tokens. Tokens are 32-byte random hex,
stored as bcrypt hashes. Validation iterates non-revoked, non-expired tokens
and compares with `bcrypt.CompareHashAndPassword`. Roles are attached to each
token and available via `auth.TokenFromContext(ctx)`.
