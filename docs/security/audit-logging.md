# Audit Logging

OIAF maintains a tamper-evident, append-only audit log of security-relevant
events.

## Hash Chain

- Each `AuditEvent` includes:
  - `previous_hash` — the hash of the preceding event (empty string for the
    first event).
  - `hash` — SHA-256 over `previous_hash` concatenated with the canonical JSON
    of the event (excluding the `hash` field itself).
- This forms a hash chain: altering any event breaks the chain from that point
  forward.

## Tamper Detection

- `GET /v1/audit/verify` recomputes the chain and returns:
  - `valid: true` and the event `count` if intact.
  - `valid: false` and the index of the first mismatch if tampered.
- The memory store's `Verify` walks the chain and validates each link.
- For stronger guarantees, forward events to an external append-only store /
  SIEM and periodically anchor the head hash.

## Event Types

| Type | Description |
|------|-------------|
| `access.evaluate` | An access request was evaluated (with decision, risk score, reasons) |
| `challenge.created` | An MFA challenge was created |
| `challenge.verified` | A challenge was successfully verified |
| `challenge.failed` | A challenge verification failed |

## Event Schema

Each event records:
- `id`, `timestamp`, `type`
- `actor` (`type` + `id`) — who triggered the event
- `target` (`type` + `id`) — what was acted upon
- `decision`, `risk_score`, `reasons`
- `metadata` (arbitrary key/value)
- `previous_hash`, `hash`

See [`audit_event.schema.json`](../../api/jsonschema/audit_event.schema.json).

## Querying

`GET /v1/audit/events` supports filters: `identity_id`, `resource_type`,
`decision`, `type`, `risk_score_min`, `since`, `until`, `limit`.

## Retention

- The MVP memory store does not persist across restarts.
- Production should persist to Postgres and export to a SIEM.
- Define a retention policy aligned with compliance requirements.
