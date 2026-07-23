# SSH CA Adapter

## Purpose

The SSH CA adapter issues short-lived SSH certificates signed by an OIAF-managed
certificate authority. Instead of long-lived SSH keys, users and hosts request
certificates; OIAF evaluates the request (identity, device posture, risk) before
signing, enabling just-in-time, risk-gated SSH access.

## Status

Planned (M5). Documentation only.

## Architecture

```
ssh client --> oiaf-ssh-ca --> OIAF core (evaluate + challenge)
                    |
                    +--> signs user/host certificate (short TTL)
```

- Operates an `ssh-keygen`-compatible signing endpoint or CA service.
- Validates the principal's public key and identity.
- Calls OIAF `/v1/access/evaluate`; on `allow`, signs a certificate with a
  short validity and constrained principals/force-command.
- On `challenge`, requires MFA before signing.

## Configuration

| Env / Flag          | Description                        | Default        |
|---------------------|------------------------------------|----------------|
| `OIAF_SERVER`       | OIAF core base URL                 | `http://127.0.0.1:8080` |
| `OIAF_ADAPTER_TOKEN`| Adapter bearer token               | required       |
| `SSH_CA_KEY`        | CA private key path (secret)       | required       |
| `SSH_CERT_TTL`      | Certificate validity               | `1h`           |
| `SSH_LISTEN`        | Signing service listen address     | `:8443`        |

## Security considerations

- The CA private key is extremely sensitive — store it in an HSM/KMS and never
  expose it to the application layer.
- Issue short-lived certificates and restrict principals/commands.
- Authenticate certificate requests to a verified identity before signing.
- Audit every signing operation in OIAF.
- Fail-closed: never sign on OIAF error.

## Roadmap

- [ ] Certificate signing endpoint (user + host certs)
- [ ] OIAF evaluate gate before signing
- [ ] MFA challenge for privileged principals
- [ ] Short-TTL and principal-constraint enforcement
- [ ] HSM/KMS-backed CA key storage
