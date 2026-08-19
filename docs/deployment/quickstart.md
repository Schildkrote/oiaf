# Deployment Quickstart (Docker Compose)

> **Honesty:** the running `oiafd` binary uses **MemoryStore** today. Postgres
> and Redis in compose are under profile `durable-preview` for future backends;
> they are **not** a working durable control plane yet. Prefer `make dev` for MVP.

This guide starts OIAF (and optionally Postgres/Redis sidecars) using Docker Compose.

## Prerequisites

- Docker and Docker Compose

## Start

```bash
export OIAF_ADMIN_TOKEN=$(openssl rand -hex 32)
export OIAF_ADAPTER_TOKEN=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)

make compose-up
```

Or directly:

```bash
docker compose -f deploy/docker/docker-compose.yml up -d
```

Default (`docker compose up`) exposes:
- OIAF core on `127.0.0.1:8080` (in-memory state)

Optional durable-preview sidecars (`--profile durable-preview`):
- Postgres on `127.0.0.1:5432` (not consumed by core yet)
- Redis on `127.0.0.1:6379` (not consumed by core yet)

All ports are bound to loopback by default.

## Verify

```bash
curl http://127.0.0.1:8080/healthz
curl -H "Authorization: Bearer $OIAF_ADMIN_TOKEN" \
  http://127.0.0.1:8080/v1/identities
```

## Logs

```bash
make logs
```

## Stop

```bash
make compose-down
```

## Notes

- The compose file wires `OIAF_DATABASE_URL` for Postgres persistence.
- Provide your own TLS termination (reverse proxy) for production; see
  [production.md](production.md).
- For disconnected environments, see [air-gapped.md](air-gapped.md).
