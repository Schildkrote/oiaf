# LDAP Proxy Adapter

**Status: Planned**

The LDAP proxy adapter fronts an LDAP directory and enforces OIAF decisions on
bind operations, enabling step-up MFA for directory authentication.

## LDAPS Requirement

- **LDAPS (LDAP over TLS) is mandatory.** The proxy must never accept plaintext
  LDAP on a network where credentials traverse.
- Terminate TLS at the proxy with a valid certificate.
- The risk engine penalizes cleartext simple binds
  (`ldap_simple_bind_cleartext`, +30 risk).

## OTP Pattern

Two integration patterns are planned:

1. **OTP-appended bind:** the user appends a TOTP code to their password
   (e.g., `password123456`). The proxy splits the password and OTP, validates
   the password against the directory, and verifies the OTP via OIAF.
2. **Post-bind challenge:** the proxy completes the bind, then issues an OIAF
   challenge before granting the application session.

The OTP-appended pattern is simpler for legacy clients but requires careful
parsing and user education.

## Warnings

- **Never persist or log bind passwords.** The proxy validates and discards
  them immediately.
- Simple binds transmit the password (even over TLS); prefer SASL where clients
  support it.
- Service accounts binding interactively should be flagged (risk engine +60 for
  `service_account_interactive`).
- This adapter is planned and not yet implemented.
