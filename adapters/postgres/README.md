# Postgres Adapter

## Purpose

The Postgres adapter integrates OIAF with PostgreSQL authentication. Using
PostgreSQL's pluggable authentication (e.g. a custom auth method via an external
auth proxy or `pg_hba` with a RADIUS/LDAP shim), it gates database connections
through OIAF risk-based decisions and can require step-up MFA for privileged
roles.

## Status

Planned (M6). Documentation only.

## Architecture

```
psql/client --> auth proxy --> oiaf-postgres --> OIAF core
                                     |
                                     +--> forwards to PostgreSQL on allow
```

- Sits in front of PostgreSQL (or uses a custom auth hook).
- Translates connection attempts (user, database, source IP) into OIAF
  `AccessRequest`s.
- On `allow`, proxies the connection; on `challenge`, requires MFA first.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `PG_LISTEN`         | Frontend listen address            | `:5432`        |
| `PG_UPSTREAM`       | PostgreSQL connection string       | required       |
| `PG_TLS_CERT`       | TLS certificate path               | optional       |

## Security considerations

- Never log connection passwords or query contents.
- Use TLS for both frontend and upstream connections.
- Scope upstream credentials to the minimum required.
- Fail-closed for privileged roles; avoid fail-open on superuser connections.
- Protect the adapter token.

## Roadmap

- [ ] Postgres wire-protocol auth proxy
- [ ] OIAF evaluate gate on connection
- [ ] Role-based step-up MFA
- [ ] TLS termination and upstream pooling
- [ ] Audit of connection and privileged operations
