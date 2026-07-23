# Kubernetes Adapter

## Purpose

The Kubernetes adapter integrates OIAF with Kubernetes authentication and
authorization. It can act as an authenticating webhook (validating webhook /
authenticating proxy) and an authorizing webhook, gating API server access and
sensitive operations through OIAF risk-based decisions.

## Status

Planned (M6). Documentation only.

## Architecture

```
kube-apiserver --authn/authz webhook--> oiaf-kubernetes --> OIAF core
```

- Implements a TokenReview webhook (authn) and/or SubjectAccessReview webhook
  (authz).
- Translates Kubernetes review requests into OIAF `AccessRequest`s.
- Can enforce step-up for privileged operations (exec, port-forward, secrets).

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `K8S_LISTEN`        | Webhook listen address             | `:8443`        |
| `K8S_TLS_CERT`      | Webhook TLS cert                   | required       |
| `K8S_TLS_KEY`       | Webhook TLS key                    | required       |

## Security considerations

- The webhook is on the API server's auth path — keep latency low and
  availability high.
- Serve over TLS with a CA the API server trusts.
- Fail-closed for authz on sensitive verbs; consider fail-open for read-only
  to avoid cluster-wide outages (audited choice).
- Protect the adapter token.

## Roadmap

- [ ] TokenReview (authn) webhook
- [ ] SubjectAccessReview (authz) webhook
- [ ] Mapping of RBAC verbs/resources to OIAF requests
- [ ] Step-up for privileged operations
- [ ] Audit of API server access decisions
