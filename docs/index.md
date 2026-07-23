# OIAF Documentation

> Risk-based access control and MFA orchestration for hybrid identity.

OIAF (Open Identity Access Firewall) is an open-source identity access firewall
that evaluates authentication risk and enforces adaptive MFA across Linux,
Windows, RADIUS, LDAP, web apps, cloud identity providers, and machine
identities.

## Sections

| Section | Description |
|---------|-------------|
| [Quickstart](quickstart.md) | Get running in minutes |
| [Architecture](architecture/overview.md) | System design and components |
| [Security](security/threat-model.md) | Threat model, secure defaults, credential handling |
| [Adapters](adapters/radius.md) | Integration adapters for protocols and platforms |
| [Deployment](deployment/quickstart.md) | Docker Compose, production, air-gapped |
| [Operations](operations/backup-restore.md) | Backup, monitoring, disaster recovery |
| [Policies](policies/policy-as-code.md) | Policy format, operators, examples |
| [Contributing](contributing/getting-started.md) | Dev setup, coding standards, RFC process |
| [API Reference](../api/openapi/oiaf.openapi.yaml) | OpenAPI 3.0 spec |

## Key Concepts

- **Access Request** — A structured description of who is accessing what, how, and from where.
- **Policy Engine** — Evaluates declarative JSON policies against access requests.
- **Risk Engine** — Scores contextual risk (geo, protocol, device, privilege) on a 0–100 scale.
- **MFA Orchestrator** — Issues and verifies TOTP and push challenges.
- **Adapters** — Protocol-specific agents (RADIUS, LDAP, PAM, Windows) that call the Decision API.
- **Audit Log** — Hash-chained, tamper-evident event log.

## Status

OIAF is **experimental / pre-release**. Interfaces and data formats may change
without notice. Do not deploy in production without independent security review.

## Links

- [GitHub](https://github.com/Schildkrote/oiaf)
- [SECURITY.md](../SECURITY.md)
- [ROADMAP.md](../ROADMAP.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
