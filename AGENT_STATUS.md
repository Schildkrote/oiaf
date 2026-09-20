# Agent Status

## Current Phase: PAM enforcement path (v0.2)

The PAM adapter is now a real, test-covered enforcement path:
`oiaf-pam-helper` reads the PAM environment, calls `/v1/access/evaluate`,
maps the decision to a PAM exit code, performs interactive TOTP challenges
(on the PAM TTY, stdin fallback), and fails closed by default. The e2e suite
covers allow / challenge / deny / fail-closed / fail-open (steps 11–14), and
the service-account discovery engine has unit tests for classification and
baseline deviation.

## Completed Work

### Phase 0 - Preparation
- Go 1.26.5 installed via Homebrew
- Branch `agent/oiaf-initial-build` created
- Repository scaffold: .gitignore, LICENSE (AGPL-3.0-only), go.mod, Makefile, config files

### Phase 1 - Core Types and Storage
- Domain types (core/internal/types)
- Storage interface + fully functional MemoryStore (core/internal/storage)

### Phase 2 - Config, Logging, Server
- Config loading (YAML + env overrides)
- Structured logging (slog)
- Server skeleton with graceful shutdown
- oiafd main entrypoint

### Phase 3 - Auth, Middleware, Audit
- Bearer token auth with bcrypt hashing
- RBAC (admin/auditor/adapter/service)
- HTTP middleware (request ID, security headers, panic recovery, body limit, logging)
- Audit service with SHA-256 hash chain

### Phase 4 - Policy and Risk Engines
- JSON policy engine (all/any/not, 13 operators, 4 effects, priority ordering)
- Rule-based risk engine (12 rules, 5 risk levels)
- 5 example policies
- OPA stub

### Phase 5 - MFA and Challenge Service
- TOTP (RFC 6238, enroll/activate/verify)
- Push MFA (device registration, HMAC, number matching, replay protection)
- Challenge orchestration (TTL, lockout, rate limiting)

### Phase 6 - REST API
- All /v1 endpoints: access/evaluate, challenge verify, identities, TOTP, devices, policies, adapters, audit

### Phase 7 - CLI
- oiafctl with all commands (version, server, seed, identity, adapter, policy, evaluate, challenge, totp, audit)

### Phase 8 - Admin UI
- Static admin console (dashboard, identities, policies, challenges, audit, adapters, settings)
- Embedded via go:embed

### Phase 9 - Adapters and SDK
- Adapter SDK (tools/adapter-sdk)
- RADIUS, PAM, LDAP proxy, AD monitor, Okta, Entra, Duo, webhook skeletons
- README skeletons for all planned adapters

### Phase 10 - Docker and Deploy
- Multi-stage Dockerfile
- docker-compose.yml + dev variant
- Helm, Terraform, Ansible skeletons
- Example access requests

### Phase 11 - Docs and Governance
- Full docs tree (architecture, security, adapters, deployment, operations, policies, contributing)
- Threat model, secure defaults, credential handling, MFA security, audit logging docs
- Governance files (CoC, CONTRIBUTING, SECURITY, GOVERNANCE, MAINTAINERS, ROADMAP, CHANGELOG, SUPPORT)
- OpenAPI spec and JSON schemas

### Phase 12 - Tests and E2E
- Unit tests for policy, risk, storage, audit, auth, TOTP, push
- E2E script (test/e2e/e2e.sh) - full MVP flow passes
- Simulator tool (tools/simulator)

### Phase 13 - CI and Finalization
- GitHub Actions workflows (ci, lint, security-scan, docs, release)
- Dependabot, issue/PR templates, CODEOWNERS
- .golangci.yml, .editorconfig

## Verification

```bash
go build ./...    # PASS
go vet ./...      # PASS
gofmt -l .        # no files
go test ./...     # all pass
make e2e          # ALL E2E TESTS PASSED
```

## Commands to Verify

```bash
make dev          # start server on 127.0.0.1:8080
make test         # run unit tests
make e2e          # run end-to-end test
make verify       # fmt + vet + test + e2e
```

## Known Limitations

- **Do not commit** `oiafctl` / `simulator` / `oiafd` binaries (gitignored). Build with Make/go.

- Storage: only MemoryStore is functional; PostgresStore is a documented skeleton
- MFA: TOTP and push simulator are functional; WebAuthn/email/SMS are skeletons
- Adapters: RADIUS/LDAP/Okta/Entra/Duo/webhook are skeletons/prototypes,
  not production-ready. The **PAM adapter is implemented** (evaluate +
  TOTP challenge + fail-closed, unit + e2e tested) but not packaged, and is
  not field-tested behind a real PAM stack.
- Metrics: /metrics returns placeholder (Prometheus integration pending)
- OPA policy engine: returns not implemented
- No Docker build verified (Docker may not be available)

## Security Warnings

- OIAF is experimental and not ready for production security enforcement
- Do not use as sole authentication control in production
- Misconfiguring PAM/LDAP/RADIUS/Windows auth can cause lockouts
- No unsupported domain-controller hooking is implemented

## Local Secrets

- Admin token: .oiaf/admin-token (mode 0600, gitignored)
- Adapter token: .oiaf/adapter-token (mode 0600, gitignored)

## Blockers

None.

## Suggested Next Issues

- Implement Prometheus metrics at /metrics
- Implement PostgresStore
- Add rate limiting middleware
- Implement WebAuthn factor
- Build working RADIUS adapter prototype
- Field-test oiaf-pam-helper in a Linux VM behind a real PAM stack
  (packaging is done: `make install-pam` / `make install-server`,
  `deploy/systemd/`, `adapters/pam/oiaf-pam-field-test.sh`)

## Suggested Next RFCs

- RFC-001: Policy engine pluggability (OPA/Cedar)
- RFC-002: Distributed audit log with external SIEM export
- RFC-003: ML-based risk scoring
