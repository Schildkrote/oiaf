# Production Hardening Checklist

Run through this checklist before any production deployment.

## Network & TLS

- [ ] Terminate TLS (directly via `OIAF_TLS_CERT_FILE`/`OIAF_TLS_KEY_FILE` or a
      reverse proxy). Never serve the API over plaintext on a network.
- [ ] Bind to loopback or a private interface; front with a reverse proxy /
      load balancer.
- [ ] Restrict access to the admin API by network policy / firewall.
- [ ] Use RadSec / LDAPS for RADIUS and LDAP adapters.

## Secrets & Auth

- [ ] Set strong, unique `OIAF_ADMIN_TOKEN` and `OIAF_ADAPTER_TOKEN` via a
      secrets manager (not in shell history or files).
- [ ] Rotate adapter and admin tokens on a schedule and after personnel changes.
- [ ] Scope tokens to least-privilege roles.
- [ ] Never enable `OIAF_ALLOW_INSECURE_DEV` in production.

## Storage

- [ ] Use the Postgres backend (not memory) for persistence.
- [ ] Encrypt Postgres at rest; restrict network access.
- [ ] Back up the database regularly (see
      [backup-restore.md](../operations/backup-restore.md)).
- [ ] Plan TOTP secret envelope encryption with a KMS.

## Observability

- [ ] Enable metrics and scrape with Prometheus.
- [ ] Forward structured JSON logs to a central log pipeline.
- [ ] Forward audit events to an external append-only SIEM.
- [ ] Configure alerts (see [monitoring.md](../operations/monitoring.md)).

## Runtime

- [ ] Run as a dedicated, non-root OS user / container (`nonroot` image).
- [ ] Set resource limits and a restart policy.
- [ ] Keep the body limit and security headers enabled (default).
- [ ] Pin and verify image / binary checksums.

## Process

- [ ] Complete an independent security review.
- [ ] Document fail mode (closed) for each adapter.
- [ ] Test disaster recovery (see
      [disaster-recovery.md](../operations/disaster-recovery.md)).
