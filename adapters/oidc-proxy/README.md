# OIDC Proxy Adapter

## Purpose

The OIDC proxy adapter protects web applications by acting as an OpenID Connect
relying party / reverse proxy. It authenticates users against an upstream IdP,
then consults OIAF for a risk-based access decision before issuing a session to
the protected application. It can inject step-up MFA challenges mid-flow.

## Status

Planned (M5). Documentation only.

## Architecture

```
Browser --> oiaf-oidc-proxy --> upstream IdP (OIDC)
                 |
                 +--> OIAF core (evaluate + challenge)
                 +--> protected application (reverse proxy)
```

- Implements the OIDC authorization code flow with PKCE.
- After IdP authentication, calls OIAF `/v1/access/evaluate`.
- On `challenge`, runs the OIAF MFA flow before completing login.
- Issues a session cookie/JWT to the downstream application.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `OIDC_ISSUER`       | Upstream IdP issuer URL            | required       |
| `OIDC_CLIENT_ID`    | OIDC client id                     | required       |
| `OIDC_CLIENT_SECRET`| OIDC client secret                 | required       |
| `OIDC_REDIRECT_URL` | OAuth redirect URL                 | required       |
| `OIDC_UPSTREAM`     | Protected app URL                  | required       |

## Security considerations

- Enforce PKCE, state, and nonce to prevent CSRF and replay.
- Validate ID token signature, issuer, audience, and expiry.
- Store the OIDC client secret and adapter token in a secret manager.
- Use secure, HttpOnly, SameSite cookies for sessions.
- Fail-closed on OIAF errors for protected routes.

## Roadmap

- [ ] OIDC authorization code + PKCE flow
- [ ] OIAF evaluate gate after IdP auth
- [ ] Mid-flow MFA challenge
- [ ] Session management and reverse proxy
- [ ] SAML support (stretch)
