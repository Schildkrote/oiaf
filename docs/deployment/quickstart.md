# Deployment Quickstart (Docker Compose)

This guide starts OIAF with Postgres and Redis using Docker Compose.

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

The stack exposes:
- OIAF core on `127.0.0.1:8080`
- Postgres on `127.0.0.1:5432`
- Redis on `127.0.0.1:6379`

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
