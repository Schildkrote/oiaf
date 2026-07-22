# Entra ID Adapter

**Status: Planned**

The Entra ID (Azure AD) adapter ingests sign-in logs and aligns with
Conditional Access to enrich OIAF risk decisions.

## Sign-In Logs

- Use **Microsoft Graph** `auditLogs/signIns` (and `beta` for richer fields) or
  the Entra ID Log Analytics / Event Hub export.
- Extract: user, IP, location, device compliance, MFA detail, risk state
  (`riskLevelDuringSignIn`), application, conditional access status.

## Conditional Access

- Entra ID **Conditional Access** already evaluates device compliance, risk,
  and MFA. The adapter should:
  - Ingest Conditional Access outcomes as risk signals.
  - Avoid conflicting enforcement; treat OIAF as complementary for on-prem and
    hybrid surfaces Entra does not cover.
  - Reuse Entra risk levels (`low/medium/high`) as inputs to the OIAF risk
    engine.
- For hybrid identities, correlate on-prem events (AD monitor) with Entra
  sign-ins.

## Integration Notes

- Register an app with `AuditLog.Read.All` / `Directory.Read.All` (least
  privilege; prefer application permissions with a managed identity).
- Handle pagination (`@odata.nextLink`) and throttling.
- Use Event Hub export for high-volume, near-real-time streaming.
- This adapter is read-only (signals in); it is planned and not yet implemented.
