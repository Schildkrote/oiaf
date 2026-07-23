# RADIUS VPN with MFA

Adds adaptive MFA to VPN authentication via RADIUS protocol integration.

## Use Case

- Remote user authenticates to VPN concentrator
- RADIUS adapter forwards authentication to OIAF for policy evaluation
- OIAF applies risk-based policies and triggers MFA when required
- Approved sessions are granted; denied sessions are rejected at the RADIUS layer

## Relevant Adapters

- **RADIUS Adapter** — acts as a RADIUS proxy between the VPN and OIAF
- See `docs/adapters/radius.md` for configuration details
