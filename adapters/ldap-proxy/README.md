# LDAP Proxy Adapter

## Purpose

The LDAP proxy adapter sits between LDAP clients (applications, OS login,
directory tools) and an upstream LDAP directory. It intercepts bind and search
operations, consults OIAF for access decisions and risk signals, and can enforce
step-up authentication before allowing privileged directory operations.

## Status

Planned (M3).

## Architecture

```
LDAP client --LDAP/LDAPS--> oiaf-ldap-proxy --LDAPS--> upstream directory
                                  |
                                  +--> OIAF core (access evaluate, challenge)
```

- Terminates LDAP (optionally StartTLS/LDAPS) on the frontend.
- Forwards authenticated operations to the configured upstream server.
- Intercepts `bindRequest` to gate authentication through OIAF.
- Can filter/authorize `searchRequest` based on OIAF policy.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `LDAP_LISTEN`       | Frontend listen address            | `:389`         |
| `LDAP_UPSTREAM`     | Upstream directory URL             | required       |
| `LDAP_TLS_CERT`     | TLS certificate path               | optional       |
| `LDAP_TLS_KEY`      | TLS key path                       | optional       |

## Security considerations

- Always prefer LDAPS; avoid transmitting bind credentials in cleartext.
- The proxy holds upstream credentials — protect them and scope them read-only
  where possible.
- Prevent LDAP injection by validating and re-encoding filters.
- Fail-closed on OIAF errors for privileged operations.

## Roadmap

- [ ] LDAP protocol frontend (bind/search/modify)
- [ ] Upstream connection pooling and TLS
- [ ] OIAF gating on bind and privileged operations
- [ ] Attribute-level authorization
- [ ] Audit of directory operations
