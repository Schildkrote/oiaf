# Duo Adapter

**Status: Planned**

The Duo adapter ingests Duo authentication logs and can front Duo as an MFA
proxy for consistent policy across environments.

## Auth Logs

- Use the **Duo Admin API** (`/admin/v2/logs/authentication`) to pull
  authentication attempts.
- Extract: username, factor, result (allow/deny/fraud), device, IP, location,
  application, timestamp.
- Stream or poll with a stateful offset to avoid gaps and duplicates.

## MFA Proxy

- OIAF can act as an MFA orchestration layer in front of Duo:
  - OIAF decides whether MFA is required and which method.
  - For Duo-backed push/phone, OIAF triggers the Duo Auth API and maps the
    result back to the challenge outcome.
- Alternatively, ingest Duo results purely as risk signals without proxying.

## Integration Notes

- Duo Admin API uses signed requests (integration key, secret key, API
  hostname); store keys in a secrets manager.
- Respect rate limits and paginate results.
- Correlate Duo usernames with OIAF identities.
- Detect MFA fatigue via repeated deny/fraud results and feed the risk engine.
- This adapter is planned and not yet implemented.
