# Disaster Recovery

Procedures for recovering OIAF after an outage or compromise.

## RTO / RPO

- Define Recovery Time Objective (RTO) and Recovery Point Objective (RPO) for
  your deployment.
- With Postgres PITR/WAL archiving, RPO can be near-zero; with periodic
  `pg_dump`, RPO equals the backup interval.

## Failure Scenarios

### Control plane process crash

- The restart policy (`unless-stopped`) brings `oiafd` back.
- With the memory store, state is lost; with Postgres, state persists.

### Database loss

- Restore from the latest backup / PITR target (see
  [backup-restore.md](backup-restore.md)).
- Verify the audit chain after restore.
- Rotate all tokens created after the backup point.

### Host compromise

- Treat all secrets on the host as compromised.
- Rebuild the host from a known-good image.
- Rotate admin, adapter, device, and TOTP secrets.
- Review the audit log for the compromise window; reconcile with SIEM.

### Audit tampering detected

- `oiafctl audit verify` reports `valid:false`.
- Isolate the instance; compare against the externally forwarded SIEM copy.
- Restore from a known-good backup and investigate the tampering window.

## Recovery Steps (General)

1. Stop the affected instance.
2. Restore the database to the chosen recovery point.
3. Verify the audit hash chain.
4. Rotate secrets and tokens as appropriate.
5. Bring the control plane up and validate `/healthz` and a test evaluation.
6. Re-enable adapters and confirm decisions flow.
7. Document the incident and timeline.

## Fail Mode

- Adapters should fail **closed** during an outage unless a deliberate,
  documented fail-open decision exists for a specific surface.
- Ensure out-of-band recovery paths exist for PAM and Windows adapters to avoid
  total lockout.

## Testing

- Run DR drills regularly; validate restores, audit-chain verification, and
  token rotation under time pressure.
