# Okta Adapter

## Purpose

The Okta adapter ingests Okta System Log events (`/api/v1/logs`), derives
identity risk signals from them, and feeds those signals to OIAF core for risk
scoring. It is strictly **read-only toward Okta**: it only issues
authenticated `GET` requests and never writes back to the tenant (no
enforcement, no user/policy mutation).

## Status

**Implemented** (read-only log ingestion + risk signals), **not yet proven
against a live Okta tenant**. The API client, cursor, detection and delivery
paths are unit-tested against mock Okta servers (`httptest`) and a committed
fixture, so CI runs fully offline — but nobody has pointed this at a real
`*.okta.com` org yet. Treat live-tenant behaviour as unverified.

## Architecture

```
Okta System Log --GET /api/v1/logs--> oiaf-okta --POST /v1/access/evaluate--> OIAF core (risk engine)
                                         |
                                    state file (JSON cursor + per-identity memory)
```

1. **Poll**: fetch System Log events after the persisted cursor
   (`sortOrder=ASCENDING`, Link-header pagination, `since` stepped 1 ms back
   so Okta's exclusive `since` can't skip boundary events).
2. **Dedupe**: events already processed are filtered by UUID (bounded recent-
   UUID window in the state file).
3. **Detect**: map events to risk signals (below), using per-identity memory
   (last geo/coords, seen devices, recent MFA failures, admin history).
4. **Emit**: each signal is translated into an OIAF `AccessRequest` and POSTed
   to the core's `/v1/access/evaluate` with the adapter bearer token — the
   same callback pattern the PAM helper and dc-agent use. Without
   `OIAF_ADAPTER_TOKEN`, signals are logged locally (offline/dev mode).
5. **Checkpoint**: the cursor advances only past events whose signals were
   delivered successfully (at-least-once + UUID dedupe); the state file is
   saved atomically after every cycle and on shutdown.

Rate limits: `429` responses honor `Retry-After` / `X-Rate-Limit-Reset`;
transient `5xx`/network errors retry with exponential backoff + jitter (cap
60 s, 5 attempts per page); `401`/`403` fail fast (never retried — a bad token
will not fix itself). A per-poll page cap (`OKTA_MAX_PAGES`) bounds runaway
catch-up; the cursor checkpoints and the next cycle continues.

## Risk Signals

| Signal             | Source events / logic                                                        |
|--------------------|------------------------------------------------------------------------------|
| `impossible_travel`| Consecutive sign-ins whose great-circle distance / time exceeds `OKTA_MAX_TRAVEL_SPEED_KMH` (default 900) |
| `new_geo`          | Sign-in from a geo label ("City, Country") not in the identity's bounded recent-geo set |
| `new_device`       | Device fingerprint (Okta client device + raw user agent) not seen before for the identity |
| `mfa_fail`         | Any `user.mfa.*` / `system.mfa.*` event with `outcome.result = FAILURE`       |
| `mfa_deny`         | `user.mfa.okta_verify.deny` (push rejection)                                  |
| `mfa_fatigue`      | ≥ `OKTA_MFA_FATIGUE_THRESHOLD` MFA failures/denies within `OKTA_MFA_FATIGUE_WINDOW` |
| `legacy_auth`      | `password`/`basic_auth` credential type, or legacy transports (IMAP/POP/SMTP, ROPC) in debug data |
| `admin_action`     | `user.account.*`, `user.role.*`, `system.role.*`, `group.user_membership.*`, `group.privilege.*`, `policy.lifecycle.*`, `policy.rule.*`, `application.user_management.*`, `user.session.clear`, `zone.*` |
| `auth_failure`     | Failed `user.session.*` / `user.authentication.*` / `policy.evaluate_sign_on` (non-MFA) |

Signals become `AccessRequest`s: the login maps to `identity.username`, admin
history sets `identity.privileged`, the identity's historical geo becomes
`identity.usual_geo` (so the core engine's `geo_mismatch` rule fires), event
IP/geo become `source`, and high-severity signals escalate
`resource.sensitivity` to `high`. The core risk engine
(`core/internal/risk`) does the scoring — the adapter never scores or
enforces on its own.

Identities are correlated by login (username/email), per the design doc.

## Configuration

Environment variables take precedence; an optional YAML file
(`OKTA_CONFIG_FILE`) provides defaults. **The Okta API token is only accepted
from the environment or the config file — never from argv, and it is never
logged.**

| Env / Flag                  | Description                                    | Default                 |
|-----------------------------|------------------------------------------------|-------------------------|
| `OIAF_OKTA_TOKEN`           | Okta API token (secret; preferred)             | required (live mode)    |
| `OKTA_API_TOKEN`            | Okta API token (fallback alias)                | —                       |
| `OKTA_BASE_URL`             | Okta org base URL (`https://acme.okta.com`)    | derived from domain     |
| `OKTA_DOMAIN`               | Okta org domain (`acme.okta.com`)              | required unless base URL|
| `OKTA_CONFIG_FILE`          | Optional YAML config (chmod 600; may hold `api_token`) | —               |
| `OKTA_STATE_FILE`           | Cursor/state JSON path                         | `.oiaf/okta-state.json` |
| `OKTA_POLL_INTERVAL`        | Poll interval (Go duration)                    | `30s`                   |
| `OKTA_TIMEOUT`              | HTTP timeout                                   | `30s`                   |
| `OKTA_LIMIT`                | Events per page (Okta max 1000)                | `500`                   |
| `OKTA_MAX_PAGES`            | Page cap per poll                              | `50`                    |
| `OKTA_ONCE`                 | Run one poll cycle and exit (cron/dev/CI)      | `false`                 |
| `OKTA_FIXTURE_FILE`         | Offline fixture mode: read events from JSON file (no network, no token) | — |
| `OKTA_MFA_FATIGUE_THRESHOLD`| MFA failures before `mfa_fatigue`              | `3`                     |
| `OKTA_MFA_FATIGUE_WINDOW`   | Fatigue counting window                        | `10m`                   |
| `OKTA_MAX_TRAVEL_SPEED_KMH` | Impossible-travel speed ceiling                | `900`                   |
| `OIAF_SERVER`               | OIAF core base URL                             | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`        | OIAF adapter bearer token (enables core scoring) | — (log-only without)  |

YAML config file shape (`OKTA_CONFIG_FILE`):

```yaml
api_token: "..."            # secret — chmod 600 this file; env overrides
base_url: https://acme.okta.com
state_file: /var/lib/oiaf/okta-state.json
poll_interval: 30s
limit: 500
max_pages: 50
mfa_fatigue_threshold: 3
mfa_fatigue_window: 10m
max_travel_speed_kmh: 900
```

## Offline / mock mode

CI and demos run with zero network:

```bash
OKTA_FIXTURE_FILE=adapters/okta/testdata/sample_okta_logs.json \
OKTA_STATE_FILE=/tmp/okta-state.json \
OKTA_ONCE=true \
go run ./adapters/okta
```

The fixture is a JSON array (or `{"events": [...]}`) of Okta System Log
events; the committed sample triggers every signal family. Unit tests use
`httptest.NewServer` to simulate Okta (pagination, auth failure, 429 backoff,
5xx retry) and the OIAF core (evaluate callback).

## Security considerations

- The Okta API token grants log-read access — use least privilege, rotate it,
  and keep it out of argv/shell history (env or chmod-600 config file only).
- The state file contains logins and IPs (PII-adjacent): it is written 0600
  in a 0700 directory.
- The adapter is read-only toward Okta by design; there is no enforcement
  path to misconfigure.
- Never log the `Authorization` header; error messages include at most a
  snippet of Okta's response body, never request headers.

## Roadmap

- [x] System Log polling and normalization (implemented; live-tenant proving pending)
- [x] Risk-signal detection + OIAF core delivery (evaluate callback)
- [x] Stateful cursor with dedupe + offline fixture mode
- [ ] Live-tenant validation against a real Okta org
- [ ] Event hook receiver with signature verification (push instead of poll)
- [ ] User/group sync to OIAF identities
- [ ] Device posture signal ingestion

Note: inline-hook enforcement from the original design is deliberately **not**
implemented — the adapter's contract is signals-in only.
