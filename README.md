# Open Identity Access Firewall (OIAF)

> Risk-based access control and MFA orchestration for hybrid identity.

> [!WARNING]
> **Experimental.** OIAF is pre-release software. Interfaces, data formats, and
> behavior may change without notice. Do not deploy in production without
> independent security review.

> [!NOTE]
> OIAF is an independent open-source project. It is not affiliated with or
> endorsed by any commercial identity-security vendor.

OIAF is an open-source identity access firewall that evaluates authentication
risk and enforces adaptive MFA across Linux, Windows, RADIUS, LDAP, web apps,
cloud identity providers, and machine identities.

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
git clone https://github.com/oiaf/oiaf.git
cd oiaf
make dev
```

## MVP Scope

- `oiafctl` CLI for administration
- Admin UI
- Policy engine (declarative access policies)
- Risk engine (contextual risk scoring)
- TOTP and push MFA
- Audit logging with hash chain
- Adapter SDK with reference skeletons

## Non-Goals

- No domain controller hooking
- No LSASS injection
- No kernel credential interception

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the project's
security posture. Treat all identity-enforcement components as high-trust and
review before deployment.

## License

[Apache-2.0](LICENSE)

## Links

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [SECURITY.md](SECURITY.md)
