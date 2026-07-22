# Backup & Restore

OIAF state lives in its storage backend. Back up the store, not the process.

## Memory Store

- The in-memory store is **ephemeral**; all state is lost on restart.
- It is for development only. Do not rely on it for any state you need to keep.
- There is nothing to back up; treat every restart as a fresh instance.

## Postgres Store (Production)

### Backup

- Use `pg_dump` for logical backups:
  ```bash
  pg_dump -Fc oiaf > oiaf-$(date +%F).dump
  ```
- Enable continuous archiving (WAL archiving / PITR) for point-in-time
  recovery.
- Store backups off-host and, ideally, in an immutable / object-locked bucket.
- Back up the audit log table with the same rigor as identity data.

### Restore

```bash
pg_restore -d oiaf oiaf-YYYY-MM-DD.dump
```

- After restore, verify the audit hash chain:
  ```bash
  oiafctl audit verify
  ```
- Rotate all tokens after restoring to an earlier point (tokens created after
  the backup will be missing).

## What to Back Up

- Identities, devices, factors (TOTP secrets), policies, adapters (token
  hashes), auth tokens, and the full audit event log.

## Secrets

- If TOTP secrets are envelope-encrypted, back up the KMS keys / data keys
  separately and test that you can decrypt after restore.
- A database backup without the encryption keys is unrecoverable for secrets.

## Testing

- Periodically perform a restore drill and validate the audit chain and a sample
  access evaluation.
