# Architecture Overview

OIAF is a control-plane server that sits between identity-consuming adapters
and the policy/risk decision logic. Adapters never make access decisions
themselves; they forward structured access requests to the Decision API and
act on the response.

## Component Diagram

```
                +------------------+
                |    Adapters      |
                | (RADIUS, LDAP,   |
                |  PAM, Windows,   |
                |  Cloud IdP)      |
                +--------+---------+
                         |  POST /v1/access/evaluate
                         v
              +---------------------+
              |    Decision API     |
              |  (core/internal/api)|
              +----------+----------+
                         |
            +------------+-------------+
            |                          |
            v                          v
   +----------------+        +------------------+
   | Policy Engine  |        |   Risk Engine    |
   | (JSON rules,   |        | (rule-based      |
   |  priority-     |        |  scoring 0-100)  |
   |  ordered)      |        +------------------+
   +----------------+
            |
            v
   +---------------------+
   |  MFA Orchestrator   |
   |  (TOTP, Push)       |
   +---------------------+
            |
            v
   +---------------------+
   |    Audit Store      |
   | (hash-chained log)  |
   +---------------------+
```

## Data Flow

1. An adapter intercepts an authentication or authorization event.
2. The adapter builds an `AccessRequest` (identity, resource, protocol, source,
   device, context) and POSTs it to `/v1/access/evaluate`.
3. The Risk Engine scores the request (0–100) based on privilege, geo, protocol
   weakness, device posture, and IP reputation.
4. The Policy Engine evaluates all enabled policies in priority order and
   returns the most restrictive matching effect (deny > challenge > alert > allow).
5. If the decision is `challenge`, the MFA Orchestrator creates a challenge with
   the policy-specified methods (TOTP, push).
6. The adapter receives an `AccessDecision` and either grants access, denies it,
   or initiates an MFA challenge flow.
7. Every evaluation is appended to the hash-chained audit log.

## Storage

The MVP ships with an in-memory store (`storage.MemoryStore`). The `Store`
interface is designed to support a Postgres backend for production persistence.

## Authentication

All `/v1/*` endpoints require a Bearer token. Tokens are bcrypt-hashed at rest.
Roles: `admin`, `auditor`, `adapter`, `service`.

## Configuration

Configuration is loaded from an optional YAML file, then overridden by
environment variables (`OIAF_LISTEN_ADDR`, `OIAF_ADMIN_TOKEN`, etc.).
See `config.example.yaml`.
