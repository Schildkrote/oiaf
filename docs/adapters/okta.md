# Okta Adapter

**Status: Planned**

The Okta adapter ingests Okta sign-in and system logs to enrich risk scoring
and detect identity threats.

## Sign-In Logs

- Use the Okta **System Log API** (`/api/v1/logs`) to stream sign-in events.
- Relevant event types: `user.session.start`, `user.authentication.sso`,
  `user.mfa.okta_verify.deny`, `policy.evaluate_sign_on`.
- Extract: user, client IP, geolocation, device, authentication context, MFA
  factor used, outcome.

## Risk Signals

- Feed Okta signals into the OIAF risk engine:
  - Impossible travel / new geolocation
  - New device or unmanaged device
  - Failed MFA / MFA denial patterns (fatigue)
  - Legacy authentication (basic auth, IMAP)
  - Admin actions and privilege changes
- Correlate Okta identity with OIAF identities by username/email.

## Integration Notes

- Authenticate with an Okta API token scoped to log read (least privilege).
- Use a stateful cursor to avoid reprocessing or gaps.
- Respect Okta rate limits; paginate and back off.
- This adapter is read-only (signals in); it does not enforce decisions in Okta.
- This adapter is planned and not yet implemented.
