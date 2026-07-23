# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities **privately** using
[GitHub Security Advisories](https://github.com/oiaf/oiaf/security/advisories/new).
Do **not** open a public issue for security reports.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

Only the latest release line receives security fixes.

## Response Timeline

- **Acknowledgment:** within 48 hours.
- **Fix:** target within 90 days, depending on severity and complexity.

We will coordinate disclosure timing with you.

## Safe Harbor

Security research conducted in good faith and in accordance with this policy is
considered authorized. We will not pursue legal action against researchers who
act responsibly, avoid privacy violations, avoid data destruction, and report
findings privately before public disclosure.

## Scope

In scope:

- The OIAF codebase and its components (decision API, policy engine, risk
  engine, MFA orchestrator, audit store, adapters, CLI, admin UI).

Out of scope:

- Social engineering of maintainers or users.
- Attacks on third-party services or infrastructure not operated by the project.
- Reports for versions older than the latest release.
