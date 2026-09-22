# Open Identity Access Firewall (OIAF)

[![CI](https://github.com/Schildkrote/oiaf/actions/workflows/ci.yml/badge.svg)](https://github.com/Schildkrote/oiaf/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/Schildkrote/oiaf)](https://goreportcard.com/report/github.com/Schildkrote/oiaf)
[![Docs](https://img.shields.io/badge/docs-schildkrote.github.io%2Foiaf-indigo)](https://schildkrote.github.io/oiaf/)
[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?logo=go&logoColor=white)](https://go.dev/)

> Risk-based access control and MFA orchestration for hybrid identity.

> [!WARNING]
> **Experimental / pre-release (current tag: `v0.2.1-security`).** OIAF is pre-release
> software. Interfaces, data formats, and behavior may change without notice. Do not
> deploy in production without independent security review. The v0.2.x tags mark
> security fixes and merged MFA work, not a stability promise.

> [!NOTE]
> OIAF is an independent open-source project. It is not affiliated with or
> endorsed by any commercial identity-security vendor.

OIAF is an open-source identity access firewall that evaluates authentication
risk and enforces adaptive MFA across Linux, Windows, RADIUS, LDAP, web apps,
cloud identity providers, and machine identities.

## What it replaces

Nothing in production — yet. OIAF targets the same problem space as commercial
identity-security platforms (Silverfort, CyberArk, Delinea, Duo, Okta,
Microsoft Entra ID Protection and others), but it is pre-release: the PAM
enforcement path is real and packaged, TOTP/push MFA are functional, WebAuthn
ceremonies are implemented and tested (29 test functions across the MFA and API
layers — against a **software** authenticator, not a hardware key), and the
cloud-IdP adapters are design-stage skeletons. Storage is still in-memory only,
so nothing survives a restart. For an honest, capability-by-capability comparison
against the commercial market — including what each maturity level does and does
not replace for you — see
**[OIAF vs commercial identity security](https://schildkrote.github.io/oiaf/comparison/)**
([docs/comparison.md](docs/comparison.md)).

## Architecture

```
            +-----------+
            | Adapters  |  (Linux PAM, RADIUS, LDAP, Web/OIDC, Cloud IdP, Machine)
            +-----+-----+
                  |
                  v
        +-------------------+
        |    Decision API   |  (evaluate, challenge, verify)
        +---------+---------+
                  |
        +---------+----------+
        |                    |
        v                    v
+---------------+    +---------------+
| Policy Engine |    |  Risk Engine  |
+-------+-------+    +-------+-------+
        |                    |
        +---------+----------+
                  |
                  v
        +-------------------+
        |  MFA Orchestrator |  (TOTP, Push, WebAuthn, ...)
        +---------+---------+
                  |
                  v
        +-------------------+
        |    Audit Store    |  (hash-chained, tamper-evident)
        +-------------------+
```

## Quickstart

```bash
git clone https://github.com/Schildkrote/oiaf.git
cd oiaf
make dev
```

## MVP Scope

- `oiafctl` CLI for administration (`go build -o oiafctl ./cli/oiafctl` — **binaries are not committed**)
- Admin UI
- Policy engine (declarative access policies)
- Risk engine (contextual risk scoring)
- TOTP and push MFA
- WebAuthn/passkey ceremonies (registration + assertion), tested against a software
  authenticator; hardware-key validation is still an open gate
- Audit logging with hash chain
- Adapter SDK with reference skeletons (**RADIUS/LDAP/Okta/Entra/Duo/webhook stubs exit 1**)
- **Storage today: MemoryStore only.** `OIAF_DATABASE_URL` / compose Postgres+Redis are **not** wired into a Postgres backend yet

## DC-Side Monitoring Scope

- Authentication monitoring on DCs via official Windows APIs
  (EvtSubscribe / ETW); no WEF/WEC infrastructure required
- No LSASS injection, no kernel credential interception,
  no modification of SAM or Kerberos/NTLM protocol implementations
- Inline enforcement via AD response actions (LDAPS) and
  WFP network filtering; no LSASS-resident code
- No agents required on application servers

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the project's
security posture. Treat all identity-enforcement components as high-trust and
review before deployment.

## License

[AGPL-3.0-only](LICENSE)

## Links

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [SECURITY.md](SECURITY.md)
