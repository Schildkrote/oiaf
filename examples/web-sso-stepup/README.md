# Web SSO with Step-Up Authentication

Adds risk-based step-up authentication to web SSO flows.

## Use Case

- User authenticates via SAML/OIDC SSO to a web application
- OIAF evaluates session risk (geo, device, sensitivity of target app)
- High-risk sessions trigger step-up MFA before SSO assertion is issued
- Low-risk sessions proceed without additional friction

## Relevant Adapters

- **Okta Adapter** — integrates with Okta for SSO policy enforcement
- **Entra ID Adapter** — integrates with Microsoft Entra ID
- See `docs/adapters/okta.md` and `docs/adapters/entra-id.md` for configuration details
