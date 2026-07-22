# Monitoring

OIAF exposes health and metrics endpoints for operational monitoring.

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /healthz` | Liveness (returns `{"status":"ok"}`) |
| `GET /readyz` | Readiness (returns `{"status":"ready"}`) |
| `GET /metrics` | Prometheus metrics (enable via `OIAF_METRICS_ENABLED=true`) |
| `GET /version` | Build/version info |

> The `/metrics` endpoint is a placeholder in the MVP and will emit real
> Prometheus series in a future release.

## Prometheus Metrics (Planned)

Expected series:

- `oiaf_access_evaluations_total{decision}` — count by decision
  (allow/deny/challenge/alert)
- `oiaf_risk_score` — histogram of risk scores
- `oiaf_challenge_total{method,status}` — challenges by method and outcome
- `oiaf_mfa_verify_total{method,result}` — MFA verification outcomes
- `oiaf_http_requests_total{code,method,path}` — HTTP request counts
- `oiaf_http_request_duration_seconds` — latency histogram

## Alerting Rules

Suggested alerts:

- **High deny rate:** `rate(oiaf_access_evaluations_total{decision="deny"}[5m])`
  above baseline — possible attack or misconfiguration.
- **MFA fatigue:** spike in `challenge.failed` / repeated denials for one
  identity.
- **Elevated risk:** sustained high `oiaf_risk_score` quantiles.
- **Control plane down:** `/healthz` failing or scrape down.
- **Audit chain broken:** `oiafctl audit verify` returns `valid:false` — page
  immediately.
- **Error rate:** 5xx rate above threshold.

## Logging

- Structured JSON logs (`log_format: json`) include `request_id`, method, path,
  status, and duration.
- Forward to a central pipeline and correlate via `X-Request-ID`.

## Dashboards

- Build dashboards for evaluation volume by decision, risk score distribution,
  MFA success rate, and API latency.
