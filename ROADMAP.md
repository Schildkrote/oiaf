# Roadmap

This roadmap is directional and may change as the project evolves.

## M0 — Foundations

- Repository scaffold and CI
- Project governance and documentation
- Core data models and interfaces

## M1 — MVP Core

- `oiafctl` CLI
- Admin UI
- Decision API
- Policy engine
- Audit logging with hash chain

## M2 — MFA

- TOTP
- Push notifications
- MFA orchestrator and challenge flow

## M3 — Core Adapters

- Adapter SDK
- Linux PAM adapter
- RADIUS adapter
- LDAP adapter

## M4 — DC Agent and Service Account Discovery

- DC agent Windows Service (EvtSubscribe real-time auth monitoring on DCs)
- AD inventory scanner (LDAP enumeration, privileged group mapping, SPN discovery)
- Service account behavioural discovery engine (digital fencing)
- Baseline deviation detection and policy enforcement
- AD response adapter (account disable, ticket revocation, group removal)
- WFP enforcement driver (separate repo, kernel-mode network filtering)

## M5 — Cloud Identity

- OIDC / SAML web app adapter
- Cloud identity provider integration
- Federated risk signals

## M6 — Identity Graph and Risk Analytics

- Identity graph
- Advanced risk analytics
- Behavioral and anomaly detection
