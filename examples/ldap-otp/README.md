# LDAP Proxy with OTP

Enforces one-time password verification for LDAP-authenticated services.

## Use Case

- Application authenticates users via LDAP bind
- LDAP proxy intercepts bind requests and forwards to OIAF
- OIAF evaluates policy and issues OTP challenge for high-risk access
- Successful OTP verification completes the LDAP bind

## Relevant Adapters

- **LDAP Proxy Adapter** — transparent proxy for LDAP authentication flows
- See `docs/adapters/ldap-proxy.md` for configuration details
